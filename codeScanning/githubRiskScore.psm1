function Get-GitHubRiskScore {
    param (
        [Parameter(Mandatory=$true)]
        [string]$GitHubUrl
    )

    # --- 1. SETUP PATHS ---
    $RootFolder      = Resolve-Path "$PSScriptRoot\.."
    $ScanFolder      = "$PSScriptRoot"
    
    # Outputs
    $ScorecardCsv    = Join-Path -Path $ScanFolder -ChildPath "scorecardScanResults.csv"
    $YaraCsv         = Join-Path -Path $ScanFolder -ChildPath "yaraScanResults.csv"
    
    # Tools
    $ScorecardExe    = Join-Path -Path $ScanFolder -ChildPath "scorecard.exe"
    $YaraExe         = Join-Path -Path $ScanFolder -ChildPath "yara64.exe"
    $YaraRulesFolder = Join-Path -Path $RootFolder -ChildPath "detections\yara"

    # --- 2. ENSURE TOOLS EXIST ---
    # (Scorecard Download Logic - Same as before)
    if (-not (Test-Path -Path $ScorecardExe)) {
        Write-Host " [INSTALL] Scorecard missing. Downloading..." -ForegroundColor Yellow
        try {
            $Headers = @{}
            if ($env:GITHUB_AUTH_TOKEN) { $Headers["Authorization"] = "token $env:GITHUB_AUTH_TOKEN" }
            $ReleaseUrl = "https://api.github.com/repos/ossf/scorecard/releases/latest"
            $ReleaseInfo = Invoke-RestMethod -Uri $ReleaseUrl -Headers $Headers -Method Get
            $Asset = $ReleaseInfo.assets | Where-Object { $_.name -like "*windows_amd64.exe" } | Select-Object -First 1
            Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $ScorecardExe -PassThru | Out-Null
        } catch { Write-Warning "Failed to download Scorecard." }
    }

    # (YARA Download Logic - Same as before)
    if (-not (Test-Path -Path $YaraExe)) {
        Write-Host " [INSTALL] YARA missing. Downloading..." -ForegroundColor Yellow
        try {
            $YaraZip = Join-Path $ScanFolder "yara.zip"
            $YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.0/yara-v4.5.0-2298-win64.zip"
            Invoke-WebRequest -Uri $YaraUrl -OutFile $YaraZip
            Expand-Archive -Path $YaraZip -DestinationPath $ScanFolder -Force
            $ExtractedExe = Get-ChildItem -Path $ScanFolder -Recurse -Filter "yara64.exe" | Select-Object -First 1
            if ($ExtractedExe.DirectoryName -ne $ScanFolder) { Move-Item -Path $ExtractedExe.FullName -Destination $YaraExe -Force }
            Remove-Item $YaraZip -Force
            Get-ChildItem -Path $ScanFolder -Directory | Where-Object { $_.Name -like "yara-*" } | Remove-Item -Recurse -Force
        } catch { Write-Warning "Failed to download YARA." }
    }

    # --- 3. PARSE URL & DETECT DOMAIN ---
    try {
        $Uri = [System.Uri]$GitHubUrl
        $Domain = $Uri.Host.ToLower()
        $Segments = $Uri.Segments
        
        # Basic validation for git structure (needs at least /user/repo)
        if ($Segments.Count -lt 3) { throw }

        $Owner = $Segments[1].Trim('/')
        $Repo = $Segments[2].Trim('/')
    } catch { 
        Write-Error "Invalid or unsupported URL format: $GitHubUrl"
        return 
    }

    Write-Host "Checking $Domain ($Owner/$Repo)..." -NoNewline

    # =========================================================================
    # PART A: OPENSSF SCORECARD (GITHUB ONLY)
    # =========================================================================
    $Score = "N/A"
    
    if ($Domain -like "*github.com*") {
        try {
            # 1. API Check
            $ApiUrl = "https://api.securityscorecards.dev/projects/github.com/$Owner/$Repo"
            $Response = Invoke-RestMethod -Uri $ApiUrl -Method Get -ErrorAction Stop
            $Score = $Response.score
            Write-Host " [SCORECARD] API: $Score" -ForegroundColor Green
        }
        catch {
            # 2. Local Check
            if (Test-Path $ScorecardExe) {
                try {
                    $SecretToken = Get-Secret -Name 'Github_Access_Token' -AsPlainText
                    $env:GITHUB_AUTH_TOKEN = $SecretToken
                    $ProcInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcInfo.FileName = $ScorecardExe
                    $ProcInfo.Arguments = "--repo=github.com/$Owner/$Repo --format=json"
                    $ProcInfo.RedirectStandardOutput = $true
                    $ProcInfo.UseShellExecute = $false
                    $Process = [System.Diagnostics.Process]::Start($ProcInfo)
                    $JsonOutput = $Process.StandardOutput.ReadToEnd()
                    $Process.WaitForExit()
                    $env:GITHUB_AUTH_TOKEN = $null
                    $LocalData = $JsonOutput | ConvertFrom-Json
                    $Score = $LocalData.score
                    Write-Host " [SCORECARD] Local: $Score" -ForegroundColor Cyan
                } catch { 
                    Write-Host " [SCORECARD] Failed/Private" -ForegroundColor DarkGray 
                    $env:GITHUB_AUTH_TOKEN = $null
                }
            }
        }
    } else {
        Write-Host " [SCORECARD] Skipped (Not GitHub)" -ForegroundColor Gray
        $Score = "NotSupported"
    }

    # >> SAVE SCORECARD RESULTS <<
    $ScoreObj = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Repo      = "$Owner/$Repo"
        Domain    = $Domain
        Score     = $Score
        Risk      = if ($Score -eq "N/A" -or $Score -eq "NotSupported") { "Unknown" } elseif ($Score -lt 5) { "High" } elseif ($Score -lt 8) { "Medium" } else { "Low" }
        URL       = $GitHubUrl
    }
    $ScoreObj | Export-Csv -Path $ScorecardCsv -Append -NoTypeInformation -Force

    # =========================================================================
    # PART B: YARA MALWARE SCAN (ANY GIT REPO)
    # =========================================================================
    if ((Test-Path $YaraExe) -and (Test-Path $YaraRulesFolder)) {
        
        # 1. Build Master Rule File
        $MasterRuleFile = Join-Path $ScanFolder "temp_master_rules.yar"
        $RuleFiles = Get-ChildItem -Path $YaraRulesFolder -Filter "*.yar" -Recurse
        
        if ($RuleFiles.Count -gt 0) {
            Set-Content -Path $MasterRuleFile -Value "// Auto-Generated Master Rule File"
            foreach ($Rule in $RuleFiles) {
                $EscapedPath = $Rule.FullName.Replace("\", "\\")
                Add-Content -Path $MasterRuleFile -Value "include `"$EscapedPath`""
            }

            # 2. Clone Repo
            Write-Host " [CLONING]" -NoNewline -ForegroundColor Gray
            $Guid = New-Guid
            $ClonePath = Join-Path $ScanFolder "temp_clone_$Guid"
            
            try {
                # Generic Git Clone (Works for GitHub, GitLab, Bitbucket)
                $GitArgs = "clone --depth 1 $GitHubUrl $ClonePath"
                Start-Process "git" -ArgumentList $GitArgs -NoNewWindow -Wait -ErrorAction Stop
                
                if (Test-Path $ClonePath) {
                    Write-Host " [SCANNING]" -NoNewline -ForegroundColor Gray
                    
                    # 3. Run YARA
                    $YaraProc = New-Object System.Diagnostics.ProcessStartInfo
                    $YaraProc.FileName = $YaraExe
                    $YaraProc.Arguments = "-w -r `"$MasterRuleFile`" `"$ClonePath`""
                    $YaraProc.RedirectStandardOutput = $true
                    $YaraProc.UseShellExecute = $false
                    
                    $YaraProcess = [System.Diagnostics.Process]::Start($YaraProc)
                    $YaraOutput = $YaraProcess.StandardOutput.ReadToEnd()
                    $YaraProcess.WaitForExit()
                    
                    # 4. Cleanup
                    Remove-Item -Path $ClonePath -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $MasterRuleFile -Force -ErrorAction SilentlyContinue

                    # 5. Parse Matches
                    $YaraHits = "Clean"
                    if (-not [string]::IsNullOrWhiteSpace($YaraOutput)) {
                        $Lines = $YaraOutput -split "`r`n"
                        $HitRules = @()
                        foreach ($Line in $Lines) {
                            if (-not [string]::IsNullOrWhiteSpace($Line)) {
                                $RuleName = $Line.Split(" ")[0]
                                $HitRules += $RuleName
                            }
                        }
                        $UniqueHits = $HitRules | Select-Object -Unique
                        $YaraHits = ($UniqueHits -join "; ")
                        Write-Host " [YARA DETECT] $YaraHits" -ForegroundColor Red
                    } else {
                        Write-Host " [YARA] Clean" -ForegroundColor Green
                    }

                    # >> SAVE YARA RESULTS <<
                    $YaraObj = [PSCustomObject]@{
                        Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Repo        = "$Owner/$Repo"
                        Domain      = $Domain
                        YaraMatches = $YaraHits
                        URL         = $GitHubUrl
                    }
                    $YaraObj | Export-Csv -Path $YaraCsv -Append -NoTypeInformation -Force

                } else { Write-Host " [ERROR] Clone Failed" -ForegroundColor Red }
            } catch { Write-Host " [ERROR] Git failure" -ForegroundColor Red }
        } else { Write-Host " [YARA] No .yar files found" -ForegroundColor Yellow }
    }
    
    Write-Host ""
}