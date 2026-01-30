function Get-CheckBulkIpsApiVoid {

    param (
        [Parameter(Mandatory=$false)]
        [string]$InputFile = "input_ips.csv"
    )

    # 1. FORCE TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # 2. DETERMINE ROOT PATH & LOAD MODULES
    $scriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

    if ($PSScriptRoot) {
        Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckBlockedCountries.psm1" -ErrorAction SilentlyContinue
        Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckSuspiciousASNs.psm1" -ErrorAction SilentlyContinue
    }

    # 3. LOCATE INPUT FILE
    $fileNameOnly = [System.IO.Path]::GetFileName($InputFile)
    $resolvedInput = $null

    $pathsToCheck = @(
        $InputFile,
        (Join-Path $scriptPath $fileNameOnly)
    )

    if ($scriptPath -notmatch "\\nsm$") {
        $pathsToCheck += (Join-Path $scriptPath "nsm\$fileNameOnly")
    }

    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            $resolvedInput = $path
            break
        }
    }

    if (-not $resolvedInput) {
        Write-Error "Input file not found. Checked locations:"
        $pathsToCheck | ForEach-Object { Write-Error " - $_" }
        return
    }

    # 4. SETUP OUTPUT PATH
    if ($scriptPath -match "\\nsm$") {
        $outputPath = $scriptPath
    } else {
        $outputPath = Join-Path -Path $scriptPath -ChildPath "nsm"
        if (-not (Test-Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
        }
    }

    $filenameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($resolvedInput)
    $outputCsv = Join-Path -Path $outputPath -ChildPath "$($filenameNoExt)_apivoid.csv"

    # 5. API KEY CHECK
    $ApiVoidApi = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText
    if ([string]::IsNullOrWhiteSpace($ApiVoidApi)) { 
        Write-Error "STOPPING: API Key 'APIVoid_API_Key' is null or empty. Check your SecretStore."
        return 
    }

    $apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
    $ApiVoid_headers = @{
        "X-API-Key"    = $ApiVoidApi
        "Content-Type" = "application/json"
    }

    # 6. PARSE INPUT
    try {
        if ($resolvedInput.EndsWith(".csv")) { $rawItems = Import-Csv $resolvedInput }
        else { $rawItems = Get-Content $resolvedInput -Raw | ConvertFrom-Json }
    } catch {
        Write-Error "Failed to parse input file: $($_.Exception.Message)"; return
    }

    $results = @()
    $privateIpRegex = '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)'

    # --- PROGRESS BAR ---
    $counter = 0
    $totalIps = $rawItems.Count
    Write-Host "Starting APIVoid check on $totalIps IPs..." -ForegroundColor Cyan
    Write-Host "Output will be saved to: $outputCsv" -ForegroundColor Gray

    foreach ($item in $rawItems) {
        $counter++
        
        # --- SMART IP EXTRACTION ---
        $targetIp = $null
        if ($item -is [String]) {
            $targetIp = $item
        } elseif ($item -is [PSCustomObject] -or $item -is [System.Collections.IDictionary]) {
            if ($null -ne $item.'dst.ip.address') { $targetIp = $item.'dst.ip.address' }
            elseif ($null -ne $item.ip) { $targetIp = $item.ip }
            elseif ($null -ne $item.value) {
                if ($item.value -is [Array]) { $targetIp = $item.value[0] } else { $targetIp = $item.value }
            }
            if ([string]::IsNullOrWhiteSpace($targetIp)) {
                foreach ($prop in $item.PSObject.Properties) {
                    if ($prop.Value -as [string] -and $prop.Value -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        $targetIp = $prop.Value; break
                    }
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($targetIp)) { continue }

        $percent = ($counter / $totalIps) * 100
        Write-Progress -Activity "Checking IP Reputation" -Status "Processing $targetIp ($counter/$totalIps)" -PercentComplete $percent

        # Loop Defaults
        $riskScore = 0; $countryCode = ""; $countryName = "Unknown"; $isp = "Unknown"; $asn = "Unknown"; $asnOrg = "Unknown"
        $isProxy = $false; $isWebProxy = $false; $isVpn = $false; $isHosting = $false
        $isTor = $false; $isResidential = $false; $isRelay = $false
        $existsInCountryBlockList = $false; $existsInASNList = $false

        # --- PRIVATE IP CHECK ---
        if ($targetIp -match $privateIpRegex) {
            $isp = "Private/Local Network"
            $countryName = "Local"
            $asn = "Private"
            $asnOrg = "Internal"
        } 
        else {
            # --- API CALL ---
            try {
                $ApiVoid_body = @{ ip = $targetIp } | ConvertTo-Json -Depth 3
                $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body -ErrorAction Stop
                
                if ($response -and $response.information) {
                    $countryCode = if ($response.information.country_code) { $response.information.country_code } else { "" }
                    $countryName = if ($response.information.country_name) { $response.information.country_name } else { "Unknown" }
                    $asn         = if ($response.information.asn) { $response.information.asn } else { "Unknown" }
                    $isp         = if ($response.information.isp) { $response.information.isp } else { "Unknown" }
                    $riskScore   = if ($response.risk_score.result) { $response.risk_score.result } else { 0 }
                    
                    if ($response.information.asn_organization) { $asnOrg = $response.information.asn_organization }
                    elseif ($response.information.owner_name) { $asnOrg = $response.information.owner_name }

                    if ($response.anonymity) {
                        $isProxy       = [bool]$response.anonymity.is_proxy
                        $isWebProxy    = [bool]$response.anonymity.is_webproxy
                        $isVpn         = [bool]$response.anonymity.is_vpn
                        $isHosting     = [bool]$response.anonymity.is_hosting
                        $isTor         = [bool]$response.anonymity.is_tor
                        $isResidential = [bool]$response.anonymity.is_residential_proxy
                        $isRelay       = [bool]$response.anonymity.is_relay
                    }
                }
            } catch {
                Write-Warning "API Error querying IP ${targetIp}: $($_.Exception.Message)"
            }

            # --- LOCAL CHECKS ---
            try {
                if ($countryName -ne "Unknown" -and (Get-Command Get-CheckBlockedCountries -ErrorAction SilentlyContinue)) {
                    $existsInCountryBlockList = Get-CheckBlockedCountries -country $countryName.Trim().ToLower()
                }
                if ($asn -ne "Unknown" -and (Get-Command Get-CheckSuspiciousASNs -ErrorAction SilentlyContinue)) {
                    $existsInASNList = Get-CheckSuspiciousASNs -asn $asn
                }
            } catch { }
        }

        # --- OUTPUT OBJECT ---
        $output = [PSCustomObject]@{
            ip              = $targetIp
            RiskScore       = $riskScore
            Country         = $countryCode
            CountryName     = $countryName
            IsGeoBlocked    = $existsInCountryBlockList
            ISP             = $isp
            ASN             = $asn
            ASN_Org         = $asnOrg
            IsASNSuspicious = $existsInASNList
            IsProxy         = $isProxy
            IsWebProxy      = $isWebProxy
            IsVPN           = $isVpn
            IsHosting       = $isHosting
            IsTor           = $isTor
            IsResidential   = $isResidential
            IsRelay         = $isRelay
        }

        # --- ALERTS ---
        if ($riskScore -ge 90) { 
            Write-Host "`n[HIGH RISK] $targetIp ($RiskScore)" -ForegroundColor Red 
        }
        if ($existsInCountryBlockList) { 
            Write-Host "`n[GEO BLOCK] $targetIp ($countryName) is in your Blocked Country list!" -ForegroundColor Red 
        }

        $results += $output
    }
    
    Write-Progress -Activity "Checking IP Reputation" -Completed

    # EXPORT
    $results | Export-Csv -Path $outputCsv -NoTypeInformation
    Write-Host "Results saved to: $outputCsv" -ForegroundColor Green

    # --- SUMMARY ROLLUPS ---

    # 1. GeoBlocked Hits (RESTORED)
    $geoBlockedHits = $results | Where-Object { $_.IsGeoBlocked -eq $true }
    if ($geoBlockedHits) {
        Write-Host "`n--- Geo-Blocked Country Hits ---" -ForegroundColor Red
        $geoBlockedHits | Group-Object CountryName | Sort-Object Count -Descending |
            ForEach-Object { [PSCustomObject]@{ Country=$_.Name; Count=$_.Count } } | Format-Table -AutoSize
    }

    # 2. Anonymity Flags
    Write-Host "`n--- Anonymity Category Counts ---" -ForegroundColor Cyan
    $categorySummary = @(
        [PSCustomObject]@{ Category = 'Proxy'; Count = ($results | Where-Object IsProxy -eq $true).Count },
        [PSCustomObject]@{ Category = 'Web Proxy'; Count = ($results | Where-Object IsWebProxy -eq $true).Count },
        [PSCustomObject]@{ Category = 'VPN'; Count = ($results | Where-Object IsVPN -eq $true).Count },
        [PSCustomObject]@{ Category = 'Hosting / Data Center'; Count = ($results | Where-Object IsHosting -eq $true).Count },
        [PSCustomObject]@{ Category = 'Tor Node'; Count = ($results | Where-Object IsTor -eq $true).Count },
        [PSCustomObject]@{ Category = 'Residential Proxy'; Count = ($results | Where-Object IsResidential -eq $true).Count },
        [PSCustomObject]@{ Category = 'Relay'; Count = ($results | Where-Object IsRelay -eq $true).Count }
    )
    $categorySummary | Format-Table -AutoSize

    # 3. ISP / ASN
    Write-Host "`n--- ISP / ASN Distribution (Top 20) ---" -ForegroundColor Cyan
    $ispGroups = $results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ISP) -and $_.ISP -ne "Unknown" } | 
                  Group-Object ISP | Sort-Object Count -Descending | Select-Object -First 20
    
    $formatStr = "{0,-40} {1,-10} {2,-30} {3,5}"
    Write-Host ($formatStr -f "ISP Name", "ASN", "Organization", "Count") -ForegroundColor Cyan
    Write-Host ("-" * 90) -ForegroundColor Cyan

    foreach ($group in $ispGroups) {
        $name = $group.Name; $asn = $group.Group[0].ASN; $org = $group.Group[0].ASN_Org; $cnt = $group.Count
        if ($group.Group[0].IsASNSuspicious) { Write-Host ($formatStr -f $name, $asn, $org, $cnt) -ForegroundColor Yellow }
        else { Write-Host ($formatStr -f $name, $asn, $org, $cnt) -ForegroundColor Gray }
    }
}