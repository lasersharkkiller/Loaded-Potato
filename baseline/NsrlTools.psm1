# NsrlEnrichment.psm1
# Module for enriching NSRL hashes with VirusTotal metadata.

function Update-NsrlBaseline {
    <#
    .SYNOPSIS
        Iterates through the local NSRL SQLite database (Safe List).
        - Checks offline folders (Root/Malicious/NSRL/ExistsInBoth).
        - COPIES valid NSRL files to 'existsInBoth' if they are also flagged malicious.
        - Moves files to 'NSRL' if they are safe.
        - Downloads missing metadata from VirusTotal.
        - Generates the final 'nsrlBaseline.json'.

    .PARAMETER MaxHashes
        Limit the number of hashes to process (Default 1000). Set to -1 for ALL.
    #>
    [CmdletBinding()]
    param (
        [string]$BaselineRootPath = "output-baseline\VirusTotal-main",
        [string]$OutputNsrlFile = "output\nsrlBaseline.json",
        [int]$MaxHashes = 1000,
        [int]$MaliciousThreshold = 5
    )

    # --- 1. AUTHENTICATION ---
    if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
    }
    try {
        $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
        if (-not $VTApi) { throw "Secret 'VT_API_Key_3' not found." }
    } catch {
        Write-Error "Authentication Failed: $_"; return
    }
    $VT_headers = @{ "x-apikey" = $VTApi; "Content-Type" = "application/json" }

    # --- 2. FOLDER SETUP ---
    $NsrlDir      = Join-Path $BaselineRootPath "NSRL"
    $MaliciousDir = Join-Path $BaselineRootPath "malicious"
    $BothDir      = Join-Path $BaselineRootPath "existsInBoth"
    
    foreach ($Path in @($NsrlDir, $MaliciousDir, $BothDir, (Split-Path $OutputNsrlFile -Parent))) {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    }

    # --- 3. CONNECT TO NIST DB ---
    $PotentialDb = Get-ChildItem -Path ".\NSRL" -Filter "*.db" -Recurse | Select-Object -First 1
    
    if (-not $PotentialDb) { 
        Write-Error "NSRL Database not found. Please run 'Install-NsrlDatabase' from NsrlTools first."
        return 
    }
    
    if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
        Write-Error "PSSQLite module is required. Run 'Install-Module PSSQLite'."
        return
    }
    Import-Module PSSQLite
    $DbPath = $PotentialDb.FullName
    Write-Host "Source DB: $($PotentialDb.Name)" -ForegroundColor Green

    # --- 4. QUERY HASHES ---
    Write-Host "Querying NSRL Hashes..." -ForegroundColor Cyan
    $LimitClause = if ($MaxHashes -gt 0) { "LIMIT $MaxHashes" } else { "" }
    
    $Query = "SELECT DISTINCT sha256, file_name FROM FILE WHERE sha256 IS NOT NULL $LimitClause"
    $Hashes = Invoke-SqliteQuery -DataSource $DbPath -Query $Query

    $BaselineList = @()
    $ProcessedHashes = [System.Collections.Generic.HashSet[string]]::new()

    # --- 5. PROCESSING LOOP ---
    foreach ($Row in $Hashes) {
        $Hash = $Row.sha256.ToLower()
        $DbFileName = $Row.file_name 

        # Define Paths
        $PathNsrl      = Join-Path $NsrlDir "$Hash.json"
        $PathRoot      = Join-Path $BaselineRootPath "$Hash.json"
        $PathMalicious = Join-Path $MaliciousDir "$Hash.json"
        $PathBoth      = Join-Path $BothDir "$Hash.json"

        $JsonContent = $null

        # --- STEP A: LOCATE OR DOWNLOAD ---
        if (Test-Path $PathBoth) {
            # Case 1: Already handled (Exists in Both)
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
        }
        elseif (Test-Path $PathNsrl) {
            # Case 2: Already Safe
            $JsonContent = Get-Content $PathNsrl -Raw | ConvertFrom-Json
        }
        elseif (Test-Path $PathRoot) {
            # Case 3: In Root -> Check & Move
            $JsonContent = Get-Content $PathRoot -Raw | ConvertFrom-Json
            $Score = if ($JsonContent.data.attributes.last_analysis_stats.malicious) { $JsonContent.data.attributes.last_analysis_stats.malicious } else { 0 }
            
            if ($Score -ge $MaliciousThreshold) {
                # High Score + In NSRL = Exists in Both
                # Since it was in root, we move to 'existsInBoth' (and optionally copy to malicious if you want strict parity, but usually root implies unsorted)
                Move-Item -Path $PathRoot -Destination $PathBoth -Force
                Write-Host "Moved $Hash from Root -> existsInBoth (Score: $Score)" -ForegroundColor Magenta
                
                # Also ensure it exists in Malicious for your other scripts
                if (-not (Test-Path $PathMalicious)) {
                    Copy-Item -Path $PathBoth -Destination $PathMalicious -Force
                }
            } else {
                # Low Score + In NSRL = Safe
                Move-Item -Path $PathRoot -Destination $PathNsrl -Force
                Write-Host "Moved $Hash from Root -> NSRL" -ForegroundColor Gray
            }
        }
        elseif (Test-Path $PathMalicious) {
            # Case 4: In Malicious -> CONFLICT -> COPY to existsInBoth
            # We leave the original in 'malicious' so your malware scripts don't break.
            Copy-Item -Path $PathMalicious -Destination $PathBoth -Force
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
            Write-Host "Conflict! Copied $Hash from Malicious -> existsInBoth" -ForegroundColor Red
        }
        else {
            # Case 5: Missing -> Download from VT
            Write-Host "Downloading $Hash..." -ForegroundColor Cyan
            try {
                $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers $VT_headers -Method Get
                
                $Score = if ($r.data.attributes.last_analysis_stats.malicious) { $r.data.attributes.last_analysis_stats.malicious } else { 0 }
                
                if ($Score -ge $MaliciousThreshold) {
                    # Save to BOTH locations
                    $r | ConvertTo-Json -Depth 10 | Set-Content -Path $PathBoth -Force
                    $r | ConvertTo-Json -Depth 10 | Set-Content -Path $PathMalicious -Force
                    Write-Host "  -> Saved to existsInBoth AND malicious (Score: $Score)" -ForegroundColor Magenta
                } else {
                    $r | ConvertTo-Json -Depth 10 | Set-Content -Path $PathNsrl -Force
                }
                
                $JsonContent = $r
                Start-Sleep -Milliseconds 500
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) { 
                    Write-Warning "Quota Exceeded."; break 
                }
                if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                    if (-not $ProcessedHashes.Contains($Hash)) {
                        $BaselineList += [PSCustomObject]@{ value = @($DbFileName, "unknown", $Hash, 1) }
                        [void]$ProcessedHashes.Add($Hash)
                    }
                    continue
                }
            }
        }

        # --- STEP B: ADD TO BASELINE ---
        # Include files from both Safe (NSRL) and Conflict (ExistsInBoth) folders
        if ($JsonContent -and -not $ProcessedHashes.Contains($Hash)) {
            $Attr = $JsonContent.data.attributes
            
            # Name Logic
            $Name = $DbFileName
            if ($Attr.meaningful_name) { $Name = $Attr.meaningful_name }
            elseif ($Attr.names) { $Name = $Attr.names[0] }

            # Status Logic
            $Status = "unsigned unverified"
            if ($Attr.signature_info -and $Attr.signature_info.verified -eq $true) {
                $Status = "signedVerified"
            }

            $BaselineList += [PSCustomObject]@{
                value = @(
                    $Name,
                    $Status,
                    $Hash,
                    1
                )
            }
            [void]$ProcessedHashes.Add($Hash)
        }
    }

    # --- 6. SAVE OUTPUT ---
    if ($BaselineList.Count -gt 0) {
        Write-Host "Saving $($BaselineList.Count) entries to $OutputNsrlFile..." -ForegroundColor Cyan
        $BaselineList | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputNsrlFile -Force
        Write-Host "Done." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Update-NsrlBaseline