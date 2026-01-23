function Get-picusCleanup {
    <#
        .SYNOPSIS
        Cleans up malicious baselines based on Certificate Info (Picus Security) and SentinelOne data.
        Also updates a daily IOC CSV file with confirmed Picus hashes.

        .PARAMETER S1SecretName
        The SecretManagement name for the S1 API Token. Defaults to 'S1_API_Key_2'.
    #>
    param (
        [string]$S1SecretName = 'S1_API_Key_2'
    )

    # ---------------- CONFIGURATION ----------------
    
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    
    # Baseline Paths
    $BasePath               = Join-Path $ProjectRoot "output"
    $MaliciousBaselinePath  = Join-Path $BasePath "maliciousProcsBaseline.json"
    $VTMainPath             = Join-Path $ProjectRoot "output-baseline\VirusTotal-main"
    $VTBehaviorsPath        = Join-Path $ProjectRoot "output-baseline\VirusTotal-behaviors"

    # IOC CSV Path Configuration
    $TodayDate    = (Get-Date).ToString("yyyy-MM-dd")
    $IocFolder    = Join-Path $ProjectRoot "apt\c6g\Picus\Picus"
    $IocFileName  = "picus_IOCs_$TodayDate.csv"
    $IocFilePath  = Join-Path $IocFolder $IocFileName

    # SentinelOne API Config
    $S1_BaseUrl      = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
    $S1_QueryUrl     = "$S1_BaseUrl/dv/events/pq"
    $PollingInterval = 10 

    # ---------------- SECRET RETRIEVAL ----------------
    
    $S1_Token = $null
    try {
        if (Get-Command Get-Secret -ErrorAction SilentlyContinue) {
            Write-Host "[-] Retrieving secret '$S1SecretName'..." -NoNewline
            $S1_Token = Get-Secret -Name $S1SecretName -AsPlainText -ErrorAction Stop
            
            if ([string]::IsNullOrWhiteSpace($S1_Token)) {
                Write-Host " Failed (Empty)." -ForegroundColor Red; return
            } else {
                Write-Host " OK." -ForegroundColor Green
            }
        } else {
            Write-Warning "SecretManagement module not found. Cannot proceed with S1 query."
            return
        }
    } catch {
        Write-Warning "Could not retrieve secret. Error: $($_.Exception.Message)"
        return
    }

    $headers = @{
        'Authorization' = "ApiToken $S1_Token"
        'Content-Type'  = 'application/json'
    }

    # ---------------- PREPARATION ----------------

    Write-Host "[-] Loading Baselines..." -ForegroundColor Cyan

    if (-not (Test-Path $BasePath)) { Write-Error "Output folder not found: $BasePath"; return }

    # Load Malicious Baseline
    $MaliciousList = [System.Collections.ArrayList]::new()
    if (Test-Path $MaliciousBaselinePath) {
        try {
            $raw = Get-Content $MaliciousBaselinePath -Raw | ConvertFrom-Json
            if ($raw) { $MaliciousList.AddRange(@($raw)) }
        } catch { Write-Error "Error loading malicious baseline: $_" }
    }

    # Load Other Baselines
    $OtherBaselines = @{}
    $OtherFiles = Get-ChildItem -Path $BasePath -Filter "*baseline.json" | Where-Object { $_.FullName -ne (Resolve-Path $MaliciousBaselinePath).Path }
    foreach ($file in $OtherFiles) {
        try {
            $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $list = [System.Collections.ArrayList]::new()
            if ($content) { $list.AddRange(@($content)) }
            $OtherBaselines[$file.FullName] = $list
        } catch {}
    }

    # Prepare IOC CSV
    if (-not (Test-Path $IocFolder)) { New-Item -ItemType Directory -Path $IocFolder -Force | Out-Null }
    
    # Load existing IOCs to prevent duplicates
    $ExistingIOCs = [System.Collections.Generic.HashSet[string]]::new()
    if (Test-Path $IocFilePath) {
        Import-Csv $IocFilePath | ForEach-Object { $ExistingIOCs.Add($_.IOC) | Out-Null }
    } else {
        # Initialize file with headers if it doesn't exist
        Set-Content -Path $IocFilePath -Value '"IOC","Type","Sources","Max confidence","Last Seen","Detection count"' -Encoding UTF8
    }

    # ---------------- HELPER FUNCTIONS ----------------
    
    function Add-IocEntry {
        param ($Hash)
        
        if (-not $ExistingIOCs.Contains($Hash)) {
            $timestamp = (Get-Date).ToString("MM/dd/yyyy-HH:mm:ss")
            # CSV Format: "IOC","Type","Sources","Max confidence","Last Seen","Detection count"
            $line = "`"$Hash`",`"Hash`",`"SentinelOne`",`"100`",`"$timestamp`",`"1`""
            Add-Content -Path $IocFilePath -Value $line -Encoding UTF8
            $ExistingIOCs.Add($Hash) | Out-Null
            Write-Host "    [+] Added IOC to CSV: $Hash" -ForegroundColor Cyan
        }
    }

    function Process-MaliciousHash {
        param ($Hash, $Filename = "Unknown", $Signer = "PICUS SECURITY", $OriginSource)
        $Hash = $Hash.ToLower()
        $found = $false
        
        # 1. Update Baseline JSON
        foreach ($entry in $MaliciousList) { 
            if ($entry.value -is [Array] -and $entry.value.Count -ge 3 -and $entry.value[2] -eq $Hash) { 
                $found = $true; break 
            } 
        }

        if (-not $found) {
            Write-Host "    [+] Adding $Hash ($Filename) to Malicious ($OriginSource)" -ForegroundColor Green
            $new = [PSCustomObject]@{ value = @($Filename, "unverified", $Hash, $Signer, 1) }
            $MaliciousList.Add($new) | Out-Null
        }

        # 2. Clean Other Baselines
        foreach ($key in $OtherBaselines.Keys) {
            $list = $OtherBaselines[$key]
            for ($i = $list.Count - 1; $i -ge 0; $i--) {
                if ($list[$i].value -is [Array] -and $list[$i].value.Count -ge 3 -and $list[$i].value[2] -eq $Hash) {
                    Write-Host "    [!] Removing $Hash from $(Split-Path $key -Leaf)" -ForegroundColor Yellow
                    $list.RemoveAt($i)
                }
            }
        }

        # 3. Move VT Metadata Files
        $pathsToCheck = @($VTMainPath, $VTBehaviorsPath)
        foreach ($p in $pathsToCheck) {
            $tf = Join-Path $p "$Hash.json"
            if (Test-Path $tf) {
                $md = Join-Path $p "malicious"
                if (-not (Test-Path $md)) { New-Item -ItemType Directory -Path $md | Out-Null }
                Move-Item -Path $tf -Destination (Join-Path $md "$Hash.json") -Force
                # Write-Host "    [>] Moved JSON to malicious folder" -ForegroundColor Gray
            }
        }

        # 4. Update IOC CSV (Only for SentinelOne sourced or highly confident Picus hits)
        if ($OriginSource -eq "SentinelOne" -or $Signer -match "PICUS") {
            Add-IocEntry -Hash $Hash
        }
    }

    # ---------------- 1. VIRUSTOTAL CHECK ----------------
    
    Write-Host "[-] Scanning VirusTotal Metadata..." -ForegroundColor Cyan
    if (Test-Path $VTMainPath) {
        Get-ChildItem -Path $VTMainPath -Filter "*.json" -File | ForEach-Object {
            try {
                $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
                $sig = if ($j.data.attributes.signature_info) { $j.data.attributes.signature_info | ConvertTo-Json -Depth 2 -Compress } else { "" }
                
                if ($sig -match "PICUS SECURITY") {
                    $name = if ($j.data.attributes.names) { $j.data.attributes.names[0] } else { "Unknown" }
                    Process-MaliciousHash -Hash $_.BaseName -Filename $name -Signer "PICUS SECURITY" -OriginSource "VTMetadata"
                }
            } catch {}
        }
    }

    # ---------------- 2. SENTINELONE QUERY ----------------

    Write-Host "[-] Querying SentinelOne PowerQuery..." -ForegroundColor Cyan

    $toDate   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $fromDate = (Get-Date).AddDays(-45).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $pqQuery = 'src.process.publisher contains "picus" or src.process.parent.publisher contains "picus" | columns src.process.image.sha256, src.process.name, src.process.publisher, src.process.parent.publisher | limit 20000'

    $body = @{
        "query"    = $pqQuery
        "fromDate" = $fromDate
        "toDate"   = $toDate
    } | ConvertTo-Json

    try {
        $initResponse = Invoke-RestMethod -Uri $S1_QueryUrl -Method Post -Headers $headers -Body $body
        $queryId = $initResponse.data.queryId

        if ($queryId) {
            Write-Host "    Query ID: $queryId" -ForegroundColor DarkGray
            
            $status = 'running'
            $statusUrl = "$S1_BaseUrl/dv/events/pq-ping?queryId=$queryId"
            $retryCount = 0
            
            while ($status -ne 'FINISHED') {
                Start-Sleep -Seconds $PollingInterval
                try {
                    $pingResponse = Invoke-RestMethod -Uri $statusUrl -Method Get -Headers $headers
                    $status = $pingResponse.data.status
                    $retryCount = 0 
                    if ($status -eq 'FAILED' -or $status -eq 'ABORTED') { Write-Error "S1 Query Failed or Aborted."; break }
                    Write-Host "    Status: $status... (Progress: $($pingResponse.data.progress)%)" -ForegroundColor Gray
                }
                catch {
                    $retryCount++
                    Write-Warning "S1 API Error ($($_.Exception.Message)). Retrying ($retryCount/5)..."
                    if ($retryCount -ge 5) { throw "Max retries reached. API is unavailable." }
                }
            }

            if ($status -eq 'FINISHED') {
                $data = $pingResponse.data.data 
                
                if ($data) {
                    Write-Host "    Processing $($data.Count) events..." -ForegroundColor Green
                    foreach ($row in $data) {
                        if ($row -is [Array] -and $row.Count -gt 0 -and -not [string]::IsNullOrEmpty($row[0])) {
                            
                            $hash = $row[0]
                            $name = if ($row.Count -gt 1) { $row[1] } else { "Unknown" }
                            $pub  = if ($row.Count -gt 2) { $row[2] } else { $null }
                            $parentPub = if ($row.Count -gt 3) { $row[3] } else { $null }

                            # --- FILTER LOGIC ---
                            $shouldAdd = $false
                            $inferredSigner = "Picus Security (Inferred)"

                            if ($pub -match "PICUS") {
                                $shouldAdd = $true
                                $inferredSigner = $pub
                            }
                            # Parent is Picus, Process is Unsigned/Empty -> Add
                            elseif ($parentPub -match "PICUS" -and [string]::IsNullOrWhiteSpace($pub)) {
                                $shouldAdd = $true
                            }
                            # Parent is Picus, Process HAS valid publisher -> Skip
                            elseif ($parentPub -match "PICUS" -and -not [string]::IsNullOrWhiteSpace($pub)) {
                                $shouldAdd = $false
                            }

                            if ($shouldAdd) {
                                Process-MaliciousHash -Hash $hash -Filename $name -Signer $inferredSigner -OriginSource "SentinelOne"
                            }
                        }
                    }
                } else {
                    Write-Host "    No Picus events found in S1." -ForegroundColor Gray
                }
            }
        }
    } catch {
        Write-Error "S1 API Error: $($_.Exception.Message)"
    }

    # ---------------- SAVE CHANGES ----------------

    Write-Host "[-] Saving databases..." -ForegroundColor Cyan
    $MaliciousList | ConvertTo-Json -Depth 5 | Set-Content $MaliciousBaselinePath -Encoding UTF8
    foreach ($key in $OtherBaselines.Keys) {
        $OtherBaselines[$key] | ConvertTo-Json -Depth 5 | Set-Content $key -Encoding UTF8
    }
    
    Write-Host "    IOC CSV Updated: $IocFilePath" -ForegroundColor Green
    Write-Host "[v] Cleanup Complete."
}