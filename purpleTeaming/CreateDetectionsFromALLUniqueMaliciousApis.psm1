<#
.SYNOPSIS
    1. Reads the APIDifferentialAnalysis.json to find APIs that NEVER appear in the baseline.
    2. Maps these APIs to specific malicious files (CSV output).
    3. Generates optimized SentinelOne queries (FUNCTION NAME ONLY) for these unique indicators, 
       saved to 'output\detections'.
#>
function Get-CreateDetectionsFromUniqueMaliciousApis {
    param (
        [string]$DifferentialJsonPath = ".\baseline\APIDifferentialAnalysis.json",
        [string]$MaliciousPath = ".\output-baseline\VirusTotal-main\malicious",
        [string]$CsvExportPath = ".\output\Unique_Malicious_API_Map.csv",
        # MODIFIED: Output to 'detections' subfolder
        [string]$S1QueryBasePath = ".\output\detections\S1_UniqueAPI_Query"
    )

    Write-Host "Starting Unique API Mapping & Query Generation..." -ForegroundColor Cyan

    # --- 1. LOAD & FILTER DIFFERENTIAL ANALYSIS ---
    if (-not (Test-Path $DifferentialJsonPath)) {
        Write-Error "Differential analysis file not found: $DifferentialJsonPath"
        return
    }

    $DiffData = Get-Content -Path $DifferentialJsonPath -Raw | ConvertFrom-Json
    
    # Filter: Baseline Count must be 0, Malicious Count >= 1
    # Sort: Greatest Malicious_Count first (prioritize high-impact indicators)
    $UniqueApis = $DiffData | Where-Object { $_.Baseline_Count -eq 0 -and $_.Malicious_Count -ge 1 } | Sort-Object Malicious_Count -Descending
    
    if ($UniqueApis.Count -eq 0) {
        Write-Warning "No unique malicious APIs found in the analysis file."
        return
    }

    Write-Host "  Loaded $($UniqueApis.Count) unique APIs." -ForegroundColor Gray

    # --- 2. GENERATE SENTINELONE QUERIES ---
    Write-Host "  Generating SentinelOne Queries..." -ForegroundColor Cyan
    
    # S1 limits logic (Batch size of 95)
    $BatchSize = 95
    $BatchCount = 1
    $ApiCounter = 0
    $CurrentBatch = @()

    foreach ($Item in $UniqueApis) {
        # MODIFIED: Extract ONLY the function name (Right side of the '!')
        # Input: "ADVAPI32.dll!LsaQuerySecret" -> Output: "LsaQuerySecret"
        $ApiParts = $Item.API_Name -split '!'
        
        if ($ApiParts.Count -gt 1) {
            $ApiString = $ApiParts[1]
        } else {
            # Fallback if no '!' exists
            $ApiString = $Item.API_Name 
        }

        $CurrentBatch += "'$ApiString'"
        $ApiCounter++

        # If batch is full, save and reset
        if ($CurrentBatch.Count -eq $BatchSize) {
            $QueryString = "indicator.metadata contains (" + ($CurrentBatch -join ",") + ")"
            $FileName = "${S1QueryBasePath}_${BatchCount}.txt"
            
            # Ensure output directory exists (.\output\detections\)
            $QueryDir = Split-Path $FileName -Parent
            if (-not (Test-Path $QueryDir)) { New-Item -ItemType Directory -Force -Path $QueryDir | Out-Null }

            Set-Content -Path $FileName -Value $QueryString
            Write-Host "    Saved Batch $BatchCount to $FileName" -ForegroundColor Gray
            
            $BatchCount++
            $CurrentBatch = @()
        }
    }

    # Save any remaining items in the final batch
    if ($CurrentBatch.Count -gt 0) {
        $QueryString = "indicator.metadata contains (" + ($CurrentBatch -join ",") + ")"
        $FileName = "${S1QueryBasePath}_${BatchCount}.txt"
        
        # Ensure output directory exists
        $QueryDir = Split-Path $FileName -Parent
        if (-not (Test-Path $QueryDir)) { New-Item -ItemType Directory -Force -Path $QueryDir | Out-Null }

        Set-Content -Path $FileName -Value $QueryString
        Write-Host "    Saved Batch $BatchCount to $FileName" -ForegroundColor Gray
    }

    # --- 3. MAP FILES (CSV Generation) ---
    Write-Host "  Mapping APIs to specific files..." -ForegroundColor Cyan
    
    # Create HashSet for fast lookup during file scan
    $TargetApiSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $UniqueApis) {
        [void]$TargetApiSet.Add($Item.API_Name)
    }

    if (-not (Test-Path $MaliciousPath)) {
        Write-Error "Malicious folder not found: $MaliciousPath"
        return
    }

    $MaliciousFiles = Get-ChildItem -Path $MaliciousPath -Filter "*.json"
    $Results = @()
    $FileCount = 0

    foreach ($File in $MaliciousFiles) {
        $FileCount++
        if ($FileCount % 50 -eq 0) { Write-Host "." -NoNewline }

        try {
            $Json = Get-Content -Path $File.FullName -Raw | ConvertFrom-Json
            $Imports = $Json.data.attributes.pe_info.import_list

            # Grab Family Name
            $AVResults = $Json.data.attributes.last_analysis_results
            $FamilyName = "Unknown"
            if ($AVResults.Microsoft.result) { $FamilyName = $AVResults.Microsoft.result }
            elseif ($AVResults.Kaspersky.result) { $FamilyName = $AVResults.Kaspersky.result }
            elseif ($AVResults.CrowdStrike.result) { $FamilyName = $AVResults.CrowdStrike.result }

            if ($Imports) {
                foreach ($Dll in $Imports) {
                    $DllName = $Dll.library_name
                    foreach ($Func in $Dll.imported_functions) {
                        $Key = "$DllName!$Func"

                        # CHECK: Is this import in our "Unique" list?
                        if ($TargetApiSet.Contains($Key)) {
                            $Results += [PSCustomObject]@{
                                Unique_API      = $Key
                                File_Hash       = $File.BaseName
                                Malware_Family  = $FamilyName
                                Meaningful_Name = $Json.data.attributes.meaningful_name
                            }
                        }
                    }
                }
            }
        }
        catch { }
    }
    Write-Host " Done." -ForegroundColor Green

    # --- 4. EXPORT CSV ---
    if ($Results.Count -gt 0) {
        $SortedResults = $Results | Sort-Object Unique_API, Malware_Family
        
        $OutDir = Split-Path $CsvExportPath -Parent
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

        $SortedResults | Export-Csv -Path $CsvExportPath -NoTypeInformation
        
        Write-Host "`nAnalysis Complete." -ForegroundColor Cyan
        Write-Host "  Found $($Results.Count) total matches in files." -ForegroundColor Yellow
        Write-Host "  CSV Map saved to: $CsvExportPath" -ForegroundColor Gray
    }
    else {
        Write-Host "No files found containing the unique APIs." -ForegroundColor Red
    }
}