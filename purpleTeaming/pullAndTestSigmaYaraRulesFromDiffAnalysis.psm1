function Get-HighFidelitySigmaYaraRules {
    param (
        [Parameter(Mandatory=$false)] [string]$GitHubToken,
        [string]$RootPath = ".\apt\c6g",
        [string]$BaseOutputDir = ".\detections"
    )

    # --- SETUP ---
    $SigmaDir = Join-Path $BaseOutputDir "sigma"
    $YaraDir  = Join-Path $BaseOutputDir "yara"
    foreach ($p in @($SigmaDir, $YaraDir)) { if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

    # --- AUTH ---
    if ([string]::IsNullOrWhiteSpace($GitHubToken) -and (Get-Module -ListAvailable Microsoft.PowerShell.SecretManagement)) {
        try { $GitHubToken = Get-Secret -Name 'Github_Access_Token' -AsPlainText -ErrorAction SilentlyContinue } catch {}
    }
    
    $GhHeaders = @{ "Accept" = "application/vnd.github.v3+json" }
    if ($GitHubToken) { $GhHeaders["Authorization"] = "token $GitHubToken" }

    # --- SEARCH HELPER ---
    function Search-GitHub {
        param ($Query)
        # GitHub Code Search API
        $Uri = "https://api.github.com/search/code?q=$([uri]::EscapeDataString($Query))"
        try {
            $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $GhHeaders -ErrorAction Stop
            if ($Response.total_count -gt 0) {
                # Return the Raw URL of the first result
                return $Response.items[0].html_url -replace "github.com", "raw.githubusercontent.com" -replace "/blob/", "/"
            }
        } catch {
            if ($_.Exception.Response.StatusCode -eq 403) { 
                Write-Warning " [!] GitHub Rate Limit. Waiting 60s..."
                Start-Sleep 60
                # Simple retry once
                return (Search-GitHub -Query $Query)
            }
        }
        return $null
    }

    # --- EXECUTION ---
    $SigmaFiles = Get-ChildItem -Path $RootPath -Filter "TargetedSigmaDifferentialAnalysis.json" -Recurse -ErrorAction SilentlyContinue

    if ($SigmaFiles.Count -eq 0) { Write-Warning "No Analysis files found."; return }

    foreach ($File in $SigmaFiles) {
        $Data = Get-Content $File.FullName -Raw | ConvertFrom-Json
        $HighFidelity = $Data | Where-Object { $_.Type -eq "Sigma Rule" -and $_.Baseline_Count -eq 0 }

        foreach ($Item in $HighFidelity) {
            $RuleName = $Item.Item_Name
            $SafeName = $RuleName -replace '[\\/:*?"<>|]', '_'
            $DestPath = Join-Path $SigmaDir "$SafeName.yml"

            if (Test-Path $DestPath) { Write-Host " [Skip] $SafeName" -ForegroundColor DarkGray; continue }

            Write-Host " [Find] $RuleName" -NoNewline
            
            $Url = $null

            # --- STRATEGY 1: Official Repo Title Search ---
            # Fast, high fidelity.
            if (-not $Url) {
                $Query = "repo:SigmaHQ/sigma in:title `"$RuleName`" language:yaml"
                $Url = Search-GitHub -Query $Query
            }

            # --- STRATEGY 2: Global Content Search (The "Deep Search") ---
            # Searches inside the YAML file for 'title: Rule Name'
            # This fixes cases where filename != rule name
            if (-not $Url) {
                $Query = "`"title: $RuleName`" language:yaml"
                $Url = Search-GitHub -Query $Query
            }

            # --- STRATEGY 3: "Fuzzy" Search (Stripping Noise) ---
            # Removes (...) and "LOLBAS" to find the core rule name
            if (-not $Url) {
                # Regex to strip parens and common prefixes
                $CleanName = $RuleName -replace '\(.*\)', '' -replace 'LOLBAS', '' -replace 'Sysmon', ''
                $CleanName = $CleanName.Trim()
                
                if ($CleanName.Length -gt 5) { # Only run if we have enough text left
                    # Search global title with loose matching
                    $Query = "in:title `"$CleanName`" language:yaml"
                    $Url = Search-GitHub -Query $Query
                }
            }

            # --- SAVE RESULT ---
            if ($Url) {
                try {
                    Invoke-WebRequest -Uri $Url -OutFile $DestPath -ErrorAction Stop
                    Write-Host " -> Downloaded" -ForegroundColor Green
                } catch {
                    Write-Host " -> Error Saving" -ForegroundColor Red
                }
            } else {
                Write-Host " -> Not Found (All Strategies Failed)" -ForegroundColor Red
            }
            
            # Rate limit protection (very important for bulk search)
            Start-Sleep -Milliseconds 1000 
        }
    }
}