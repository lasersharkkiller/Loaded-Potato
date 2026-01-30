# NsrlEnrichment.psm1
# Module for enriching NSRL hashes with VirusTotal metadata.
# UPDATED: Caches 404s to prevent infinite download loops.

function Update-NsrlBaseline {
    <#
    .SYNOPSIS
        Iterates through the local NSRL SQLite database.
        - Prioritizes local files (Root/NSRL/Malicious/ExistsInBoth).
        - Copies malicious files to 'existsInBoth'.
        - Downloads missing metadata.
        - CACHES "Not Found" errors to prevent repeat API calls.
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
    if (-not $PotentialDb) { Write-Error "NSRL Database not found."; return }
    
    if (-not (Get-Module -ListAvailable -Name PSSQLite)) { Write-Error "PSSQLite module is required."; return }
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

        $PathNsrl      = Join-Path $NsrlDir "$Hash.json"
        $PathRoot      = Join-Path $BaselineRootPath "$Hash.json"
        $PathMalicious = Join-Path $MaliciousDir "$Hash.json"
        $PathBoth      = Join-Path $BothDir "$Hash.json"

        $JsonContent = $null

        # --- STEP A: CHECK LOCAL CACHE ---
        if (Test-Path $PathBoth) {
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
        }
        elseif (Test-Path $PathNsrl) {
            $JsonContent = Get-Content $PathNsrl -Raw | ConvertFrom-Json
        }
        elseif (Test-Path $PathRoot) {
            # In Root: Check if malicious, copy if so. Leave if safe.
            $JsonContent = Get-Content $PathRoot -Raw | ConvertFrom-Json
            $Score = if ($JsonContent.data.attributes.last_analysis_stats.malicious) { $JsonContent.data.attributes.last_analysis_stats.malicious } else { 0 }
            
            if ($Score -ge $MaliciousThreshold) {
                Copy-Item -Path $PathRoot -Destination $PathBoth -Force
                Write-Host "Conflict! Copied $Hash from Root -> existsInBoth" -ForegroundColor Magenta
                if (-not (Test-Path $PathMalicious)) { Copy-Item -Path $PathBoth -Destination $PathMalicious -Force }
            }
        }
        elseif (Test-Path $PathMalicious) {
            # In Malicious: Copy to Both
            Copy-Item -Path $PathMalicious -Destination $PathBoth -Force
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
            Write-Host "Conflict! Copied $Hash from Malicious -> existsInBoth" -ForegroundColor Red
        }
        else {
            # --- STEP B: DOWNLOAD (With 404 Caching) ---
            Write-Host "Downloading $Hash..." -ForegroundColor Cyan
            try {
                $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers $VT_headers -Method Get
                
                $Score = if ($r.data.attributes.last_analysis_stats.malicious) { $r.data.attributes.last_analysis_stats.malicious } else { 0 }
                
                if ($Score -ge $MaliciousThreshold) {
                    $r | ConvertTo-Json -Depth 10 | Set-Content -Path $PathBoth -Force
                    $r | ConvertTo-Json -Depth 10 | Set-Content -Path $PathMalicious -Force
                    Write-Host "  -> Saved to existsInBoth AND malicious" -ForegroundColor Magenta
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
                
                # --- FIX: HANDLE 404 NOT FOUND ---
                if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                    Write-Host "  [404] Not in VT. Caching local placeholder..." -ForegroundColor DarkGray
                    
                    # Create a "Fake" VT Object so we don't download it again
                    # We rely on NSRL data for the name
                    $Placeholder = @{
                        data = @{
                            id = $Hash
                            attributes = @{
                                meaningful_name = $DbFileName
                                last_analysis_stats = @{ malicious = 0 }
                                signature_info = @{ verified = $false }
                                tags = @("nsrl_only", "vt_missing")
                            }
                        }
                    }
                    
                    $JsonContent = [PSCustomObject]$Placeholder
                    
                    # Save it to NSRL folder so 'Test-Path $PathNsrl' passes next time
                    $JsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $PathNsrl -Force
                }
            }
        }

        # --- STEP C: ADD TO BASELINE ---
        if ($JsonContent -and -not $ProcessedHashes.Contains($Hash)) {
            $Attr = $JsonContent.data.attributes
            
            # Name Logic
            $Name = $DbFileName
            if ($Attr.meaningful_name) { $Name = $Attr.meaningful_name }
            elseif ($Attr.names) { $Name = $Attr.names[0] }

            # Status Logic
            $Status = "unsigned unverified"
            # If it's our fake placeholder, verification is false
            if ($Attr.signature_info -and $Attr.signature_info.verified -eq $true) {
                $Status = "signedVerified"
            } elseif ($Attr.tags -contains "vt_missing") {
                $Status = "NSRL_Only_No_VT"
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

    # --- SAVE ---
    if ($BaselineList.Count -gt 0) {
        $BaselineList | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputNsrlFile -Force
        Write-Host "Saved $($BaselineList.Count) entries to $OutputNsrlFile" -ForegroundColor Green
    }
}

Export-ModuleMember -Function Update-NsrlBaseline