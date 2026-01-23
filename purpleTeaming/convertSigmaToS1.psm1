<#
.SYNOPSIS
    Sigma to SentinelOne PowerQuery V2 Translator Module
.DESCRIPTION
    Wraps the conversion logic in a callable function to prevent auto-execution on Import-Module.
#>

# --- INTERNAL HELPER FUNCTION (Does the syntax translation) ---
function Get-S1QueryFromSigma {
    param([string]$YamlContent)

    try {
        $sigma = $YamlContent | ConvertFrom-Yaml
    } catch { return "ERROR_PARSING_YAML" }

    # S1 V2 Field Mapping
    $map = @{
        "Image"             = "tgt.process.image.path"
        "OriginalFileName"  = "tgt.process.image.name"
        "CommandLine"       = "tgt.process.cmdline"
        "CurrentDirectory"  = "tgt.process.work_dir"
        "User"              = "tgt.process.user"
        "ParentImage"       = "src.process.image.path"
        "ParentCommandLine" = "src.process.cmdline"
        "IntegrityLevel"    = "tgt.process.integrityLevel"
        "Hashes"            = "tgt.process.image.sha1"
        "TargetObject"      = "registry.keyPath"
        "Details"           = "registry.value"
        "TargetFilename"    = "tgt.file.path"
    }

    $queryParts = @()

    if ($sigma.detection.selection) {
        foreach ($key in $sigma.detection.selection.Keys) {
            $parts = $key -split '\|'
            $field = $parts[0]
            $mod   = if ($parts.Count -gt 1) { $parts[1] } else { "equals" }
            $s1Field = if ($map.ContainsKey($field)) { $map[$field] } else { $field }

            $operator = switch ($mod) {
                "endswith"   { "endswith" }
                "startswith" { "startswith" }
                "contains"   { "contains" }
                "re"         { "matches" }
                Default      { "=" }
            }

            $values = $sigma.detection.selection[$key]
            
            if ($values -is [array]) {
                $orGroup = $values | ForEach-Object { 
                    if ($operator -eq "=") { "$s1Field = `"$($_)`"" } 
                    else { "$s1Field $operator `"$($_)`"" }
                }
                $queryParts += "($($orGroup -join ' OR '))"
            } else {
                if ($operator -eq "=") { $queryParts += "$s1Field = `"$values`"" }
                else { $queryParts += "$s1Field $operator `"$values`"" }
            }
        }
    } else {
        return "SKIP_COMPLEX_LOGIC"
    }

    $category = $sigma.logsource.category
    $eventType = ""
    if ($category -match "process_creation") { $eventType = "event.type = `"Process Creation`"" }
    elseif ($category -match "registry") { $eventType = "event.type in (`"Registry Value Modified`", `"Registry Key Create`")" }
    elseif ($category -match "file_event") { $eventType = "event.type = `"File Creation`"" }

    $mainQuery = $queryParts -join " AND "
    if ($eventType -and $mainQuery) { return "$eventType AND $mainQuery" }
    elseif ($mainQuery) { return $mainQuery }
    
    return "ERROR_EMPTY_QUERY"
}

# --- MAIN EXPORTED FUNCTION (This is what Option 9 calls) ---
function Convert-SigmaToS1V2 {
    param (
        [string]$SigmaRulesPath = ".\detections\sigma",
        [string]$OutputFolderPath = ".\detections\sigma_rules_translated_to_s1"
    )

    if (-not (Get-Module -ListAvailable PowerShell-Yaml)) {
        Write-Warning "Error: The 'PowerShell-Yaml' module is required."
        return
    }

    if (-not (Test-Path $SigmaRulesPath)) {
        Write-Error "Input folder not found: $SigmaRulesPath"
        return
    }

    if (-not (Test-Path $OutputFolderPath)) {
        New-Item -ItemType Directory -Path $OutputFolderPath -Force | Out-Null
        Write-Host "[*] Created output folder: $OutputFolderPath" -ForegroundColor Cyan
    }

    $sigmaFiles = Get-ChildItem -Path $SigmaRulesPath -Filter "*.yml"
    Write-Host "Found $($sigmaFiles.Count) Sigma rules. Starting translation...`n" -ForegroundColor Cyan

    $successCount = 0
    $failCount = 0

    foreach ($file in $sigmaFiles) {
        $rawContent = Get-Content $file.FullName -Raw
        
        # Call the internal helper function
        $s1Query = Get-S1QueryFromSigma -YamlContent $rawContent

        $outputFile = Join-Path $OutputFolderPath "$($file.BaseName).txt"

        if ($s1Query -match "^ERROR" -or $s1Query -match "^SKIP") {
            Write-Host " [X] Failed/Skipped: $($file.Name)" -ForegroundColor DarkGray
            $failCount++
        } else {
            $s1Query | Set-Content $outputFile -Force
            Write-Host " [V] Translated:     $($file.Name)" -ForegroundColor Green
            $successCount++
        }
    }

    Write-Host "`n--------------------------------------------------"
    Write-Host "Conversion Complete." -ForegroundColor Cyan
    Write-Host "Translated: $successCount" -ForegroundColor Green
    Write-Host "Skipped:    $failCount" -ForegroundColor Red
    Write-Host "Output Dir: $OutputFolderPath" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------`n"
}

# Explicitly export ONLY the main function
Export-ModuleMember -Function Convert-SigmaToS1V2