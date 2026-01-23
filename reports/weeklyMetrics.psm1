function Get-WeeklyMetrics {
    param (
        [string]$AptRootPath = ".\apt\c6g",
        
        # Raw Data Paths (For volume counts)
        [string]$BaselineRootPath = "output-baseline\VirusTotal-main",
        [string]$MaliciousStoragePath = "output-baseline\VirusTotal-main\malicious",
        
        # Internal Baseline Files
        [string]$DriversPath        = "output\driversBaseline.json",
        [string]$UnverifiedPath     = "output\unverifiedProcsBaseline.json",
        [string]$UnsignedWinPath    = "output\unsignedWinProcsBaseline.json",
        [string]$UnsignedLinPath    = "output\unsignedLinuxProcsBaseline.json",
        [string]$SignedVerifiedPath = "output\signedVerifiedProcsBaseline.json",
        [string]$PublishersPath     = "output\winPublishersBaseline.json",
        [string]$MaliciousProcsPath = "output\maliciousProcsBaseline.json"
    )

    Write-Host "Generating Weekly Metrics Report (v3.1 - Added Memory/IDS)..." -ForegroundColor Cyan

    # --- 1. DATASET VOLUMETRICS ---
    Write-Host "  [1/3] Checking Raw Dataset Sizes..." -NoNewline
    $BaseVT = (Get-ChildItem -Path $BaselineRootPath -File -ErrorAction SilentlyContinue).Count
    $MalVT  = (Get-ChildItem -Path $MaliciousStoragePath -File -ErrorAction SilentlyContinue).Count
    Write-Host " Done." -ForegroundColor Green

    # --- 2. INTERNAL BASELINE STATS ---
    Write-Host "  [2/3] Reading Internal Baselines..." -NoNewline
    function Get-JsonCount ($Path) {
        if (Test-Path $Path) {
            try {
                $data = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($data) { return $data.Count } else { return 0 }
            } catch { return 0 }
        } else { return 0 }
    }

    $cDrivers        = Get-JsonCount $DriversPath
    $cUnverified     = Get-JsonCount $UnverifiedPath
    $cUnsignedWin    = Get-JsonCount $UnsignedWinPath
    $cUnsignedLin    = Get-JsonCount $UnsignedLinPath
    $cSigned         = Get-JsonCount $SignedVerifiedPath
    $cPublishers     = Get-JsonCount $PublishersPath
    $cMaliciousProcs = Get-JsonCount $MaliciousProcsPath
    Write-Host " Done." -ForegroundColor Green

    # --- 3. FORENSICS AGGREGATION (CATEGORIZED) ---
    Write-Host "  [3/3] Aggregating Unique Artifacts from APT Analysis..." 
    
    # Initialize separate HashSets for categorical uniqueness
    $Sets = @{
        "Windows API"            = [System.Collections.Generic.HashSet[string]]::new()
        "ELF Symbols"            = [System.Collections.Generic.HashSet[string]]::new()
        "Sigma Rules"            = [System.Collections.Generic.HashSet[string]]::new()
        "Yara Rules"             = [System.Collections.Generic.HashSet[string]]::new()
        "IDS Rules"              = [System.Collections.Generic.HashSet[string]]::new() # NEW
        "Certificates"           = [System.Collections.Generic.HashSet[string]]::new()
        "VT Tags"                = [System.Collections.Generic.HashSet[string]]::new()
        "MITRE ATT&CK"           = [System.Collections.Generic.HashSet[string]]::new()
        "Mutexes"                = [System.Collections.Generic.HashSet[string]]::new()
        "Registry Keys"          = [System.Collections.Generic.HashSet[string]]::new()
        "Processes"              = [System.Collections.Generic.HashSet[string]]::new()
        "Memory Pattern URLs"    = [System.Collections.Generic.HashSet[string]]::new() # NEW
        "Memory Pattern Domains" = [System.Collections.Generic.HashSet[string]]::new() # NEW
    }

    # Map File Names to Categories
    $FileMap = @{
        "TargetedAPIDifferentialAnalysis.json"           = "Windows API"
        "TargetedElfDifferentialAnalysis.json"           = "ELF Symbols"
        "TargetedSigmaDifferentialAnalysis.json"         = "Sigma Rules"
        "TargetedYaraDifferentialAnalysis.json"          = "Yara Rules"
        "TargetedIDSDifferentialAnalysis.json"           = "IDS Rules" # NEW
        "TargetedCertificateDifferentialAnalysis.json"   = "Certificates"
        "TargetedTagsDifferentialAnalysis.json"          = "VT Tags"
        "TargetedMitreDifferentialAnalysis.json"         = "MITRE ATT&CK"
        "TargetedMutexDifferentialAnalysis.json"         = "Mutexes"
        "TargetedRegistryDifferentialAnalysis.json"      = "Registry Keys"
        "TargetedProcessDifferentialAnalysis.json"       = "Processes"
        "TargetedMemoryPatternDifferentialAnalysis.json" = "Memory Pattern URLs"    # NEW
        "TargetedMemoryDomainDifferentialAnalysis.json"  = "Memory Pattern Domains" # NEW
    }

    if (Test-Path $AptRootPath) {
        $CountryFolders = Get-ChildItem -Path $AptRootPath -Directory
        $TotalProcessedFiles = 0

        foreach ($cFolder in $CountryFolders) {
            $AptFolders = Get-ChildItem -Path $cFolder.FullName -Directory
            
            foreach ($aFolder in $AptFolders) {
                foreach ($FileName in $FileMap.Keys) {
                    $FullPath = Join-Path $aFolder.FullName $FileName
                    
                    if (Test-Path $FullPath) {
                        $TotalProcessedFiles++
                        try {
                            $Content = Get-Content $FullPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            $CatName = $FileMap[$FileName]

                            foreach ($Item in $Content) {
                                # CRITICAL CHECK: Unique to Malware (Score 100)
                                if ($Item.Baseline_Rarity_Score -eq 100) {
                                    [void]$Sets[$CatName].Add($Item.Item_Name)
                                }
                            }
                        } catch {}
                    }
                }
            }
        }
    }
    
    Write-Host "  Done." -ForegroundColor Green

    # --- 4. FINAL REPORT ---
    Clear-Host
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "      KNOW NORMAL: WEEKLY METRICS"
    Write-Host "==============================================" -ForegroundColor Cyan

    Write-Host " [1] DATASET VOLUMETRICS" -ForegroundColor Yellow
    Write-Host " -----------------------" -ForegroundColor DarkGray
    Write-Host " Baseline Samples (Clean):    $BaseVT"
    Write-Host " Malicious Samples (Target):  $MalVT"
    Write-Host " Total Analysis Files:        $($BaseVT + $MalVT)" -ForegroundColor Green

    Write-Host "`n [2] INTERNAL BASELINES" -ForegroundColor Yellow
    Write-Host " ----------------------" -ForegroundColor DarkGray
    Write-Host " Drivers Loaded:              $cDrivers"
    Write-Host " Signed/Verified Processes:   $cSigned"
    Write-Host " Unique Windows Publishers:   $cPublishers"
    Write-Host " Unverified Processes:        $cUnverified" -ForegroundColor DarkYellow
    Write-Host " Unsigned Windows Processes:  $cUnsignedWin" -ForegroundColor DarkYellow
    Write-Host " Unsigned Linux Processes:    $cUnsignedLin" -ForegroundColor DarkYellow
    Write-Host " Malicious Processes (Live):  $cMaliciousProcs" -ForegroundColor Red

    Write-Host "`n [3] HIGH-FIDELITY THREAT INTEL (Unique to Malware)" -ForegroundColor Yellow
    Write-Host " ----------------------------------------------------" -ForegroundColor DarkGray
    
    # Sort and Display Categories
    $Sets.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $Count = $_.Value.Count
        if ($Count -gt 0) {
            Write-Host " Unique $($_.Key):".PadRight(30) + "$Count" -ForegroundColor Red
        } else {
            Write-Host " Unique $($_.Key):".PadRight(30) + "0" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n==============================================`n" -ForegroundColor Cyan
}