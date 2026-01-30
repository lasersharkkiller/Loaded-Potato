function Find-GitHubReposInMetadata {
    param (
        # Default: Looks for metadata in output-baseline\IntezerStrings (relative to root)
        [string]$MetadataPath = "$PSScriptRoot\..\output-baseline\IntezerStrings",
        [switch]$ScanFoundRepos = $true
    )

    # --- 1. LOCATE & IMPORT SCANNER MODULE ---
    # The scanner file is named 'githubRiskScore.psm1'
    $ModuleName = "githubRiskScore.psm1"
    
    # Resolve the 'Know Normal' root folder relative to this script
    # (Assuming this script is in Know Normal\NewProcsModules)
    $RootFolder = Resolve-Path "$PSScriptRoot\.."
    
    $PathInCodeScanning = Join-Path -Path $RootFolder -ChildPath "codeScanning\$ModuleName"
    $PathInCurrent      = Join-Path -Path $PSScriptRoot -ChildPath $ModuleName

    if (Test-Path $PathInCodeScanning) {
        Import-Module $PathInCodeScanning -ErrorAction Stop
        Write-Host " [MODULE] Loaded $ModuleName from codeScanning folder." -ForegroundColor Gray
    } 
    elseif (Test-Path $PathInCurrent) {
        Import-Module $PathInCurrent -ErrorAction Stop
        Write-Host " [MODULE] Loaded $ModuleName from current folder." -ForegroundColor Gray
    } 
    else {
        Write-Warning "Could not find '$ModuleName' in:"
        Write-Warning " 1. $PathInCodeScanning"
        Write-Warning " 2. $PathInCurrent"
        Write-Warning "Scanning disabled (Dry Run only)."
        $ScanFoundRepos = $false
    }

    # --- 2. CHECK METADATA PATH ---
    if (-not (Test-Path $MetadataPath)) {
        Write-Error "Metadata path not found: $MetadataPath"
        return
    }

    # --- 3. CHECK OFFLINE HISTORY (CSV) ---
    # Updated to look for 'scorecardScanResults.csv' per your latest change
    $CsvPath = Join-Path -Path $RootFolder -ChildPath "codeScanning\scorecardScanResults.csv"
    $AlreadyScanned = @()

    if (Test-Path $CsvPath) {
        Write-Host "Loading history from: $CsvPath" -ForegroundColor Gray
        try {
            $CsvData = Import-Csv -Path $CsvPath
            $AlreadyScanned = $CsvData.URL
            Write-Host "Loaded $($AlreadyScanned.Count) previously scanned repos." -ForegroundColor Gray
        } catch { }
    }

    # --- 4. PARSE FILES ---
    Write-Host "Searching for JSON files in: $MetadataPath" -ForegroundColor Cyan
    $JsonFiles = Get-ChildItem -Path $MetadataPath -Filter "*.json" -Recurse
    $AllFoundRepos = @()

    foreach ($File in $JsonFiles) {
        try {
            $JsonContent = Get-Content -Path $File.FullName -Raw | ConvertFrom-Json
            
            # Helper to extract strings from various Intezer export formats
            $StringsToCheck = if ($JsonContent.result.strings) { $JsonContent.result.strings.string_value }
                              elseif ($JsonContent.strings) { $JsonContent.strings.string_value }
                              elseif ($JsonContent.string_value) { $JsonContent.string_value }
                              else { $JsonContent | ConvertTo-Json -Depth 5 }

            # Regex to capture Owner/Repo from github.com URLs
            $GitHubRegex = 'github\.com[:\/]([a-zA-Z0-9-._]+)\/([a-zA-Z0-9-._]+)'
            $MatchesInFile = $StringsToCheck | Select-String -Pattern $GitHubRegex -AllMatches

            foreach ($match in $MatchesInFile.Matches) {
                $Owner = $match.Groups[1].Value
                $Repo  = $match.Groups[2].Value -replace '\.git$', ''
                
                # Clean URL
                $CleanUrl = "https://github.com/$Owner/$Repo"
                $AllFoundRepos += [PSCustomObject]@{ URL = $CleanUrl }
            }
        }
        catch { Write-Host " [x] Error reading $($File.Name)" -ForegroundColor Red }
    }

    # --- 5. EXECUTE SCAN ---
    $UniqueRepos = $AllFoundRepos | Select-Object -ExpandProperty URL | Select-Object -Unique

    if ($UniqueRepos) {
        Write-Host "`nFound $($UniqueRepos.Count) unique GitHub links." -ForegroundColor Cyan
        
        foreach ($TargetUrl in $UniqueRepos) {
            # Skip if already in CSV
            if ($AlreadyScanned -contains $TargetUrl) {
                Write-Host " [SKIP] Known: $TargetUrl" -ForegroundColor DarkGray
                continue
            }

            if ($ScanFoundRepos) {
                # Calls the loaded module
                Get-GitHubRiskScore -GitHubUrl $TargetUrl
            } else {
                Write-Host " [NEW] $TargetUrl (Dry Run)" -ForegroundColor White
            }
        }
    } else {
        Write-Host "No GitHub repositories found." -ForegroundColor Green
    }
}