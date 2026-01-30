function Get-ProcessBulkIps {

    param (
        [Parameter(Mandatory=$true)]
        $process
    )

    # 1. FORCE TLS 1.2 (Required for most modern APIs)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Use $PSScriptRoot to locate modules relative to this script
    if ($PSScriptRoot) {
        Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckBlockedCountries.psm1" -ErrorAction SilentlyContinue
        Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckSuspiciousASNs.psm1" -ErrorAction SilentlyContinue
        Import-Module -Name "$PSScriptRoot\S1IPtoDNS.psm1" -ErrorAction SilentlyContinue
    }

    # Define paths
    $basePath = ".\output\$($process)-dstIps"
    if (Test-Path "$basePath.csv") { $inputFile = "$basePath.csv"; $isCsv = $true }
    elseif (Test-Path "$basePath.json") { $inputFile = "$basePath.json"; $isCsv = $false }
    else { 
        # Fallback: Try looking for the file directly
        if (Test-Path ".\input_ips.csv") { $inputFile = ".\input_ips.csv"; $isCsv = $true }
        else { Write-Error "Input file not found at $basePath (checked .json/.csv)"; return }
    }

    $outputCsv = ".\output\$($process)-ip_results_apivoid.csv"

    # API Key Check
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

    # Collect results
    $results = @()

    # --- READ INPUT ---
    try {
        if ($isCsv) {
            $rawItems = Import-Csv $inputFile
        } else {
            $rawItems = Get-Content $inputFile -Raw | ConvertFrom-Json
        }
    } catch {
        Write-Error "Failed to parse input file: $($_.Exception.Message)"
        return
    }

    # --- PROGRESS BAR SETUP ---
    $counter = 0
    $totalIps = $rawItems.Count
    Write-Host "Starting check on $totalIps IPs from $inputFile..." -ForegroundColor Cyan

    foreach ($item in $rawItems) {
        $counter++
        
        # --- SMART IP EXTRACTION ---
        $targetIp = $null
        
        if ($item -is [String]) {
            $targetIp = $item
        } elseif ($item -is [PSCustomObject] -or $item -is [System.Collections.IDictionary]) {
            
            # 1. Try Known Headers First (Priority)
            # We explicitly check 'dst.ip.address' and other common names
            $possibleHeaders = @('dst.ip.address', 'ip', 'ipaddress', 'sourceip', 'destinationip', 'host', 'value')
            foreach ($h in $possibleHeaders) {
                if ($null -ne $item.$h -and $item.$h -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
                    $targetIp = $item.$h
                    if ($targetIp -is [Array]) { $targetIp = $targetIp[0] } # Handle array 'value'
                    break
                }
            }

            # 2. Smart Fallback: If no known header found, scan ALL columns for an IP format
            if ([string]::IsNullOrWhiteSpace($targetIp)) {
                foreach ($prop in $item.PSObject.Properties) {
                    $val = $prop.Value
                    # Simple Regex for IPv4
                    if ($val -as [string] -and $val -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        $targetIp = $val
                        break
                    }
                }
            }
        }

        # DEBUG: Verify first row read
        if ($counter -eq 1) {
            if ([string]::IsNullOrWhiteSpace($targetIp)) {
                Write-Warning "Could not find an IP in the first row! Headers detected: $($item.PSObject.Properties.Name -join ', ')"
            } else {
                Write-Host "Debug: First IP detected is '$targetIp'" -ForegroundColor DarkGray
            }
        }

        if ([string]::IsNullOrWhiteSpace($targetIp)) { continue }

        $percent = ($counter / $totalIps) * 100
        Write-Progress -Activity "Checking IP Reputation" -Status "Processing $targetIp ($counter/$totalIps)" -PercentComplete $percent

        # Initialize Variables
        $riskScore     = 0
        $countryName   = "Unknown"
        $isp           = "Unknown"
        $asn           = "Unknown"
        $isProxy       = $false
        $isWebProxy    = $false
        $isVpn         = $false
        $isHosting     = $false
        $isTor         = $false
        $isResidential = $false
        $isRelay       = $false
        $existsInCountryBlockList = $false
        $existsInASNList = $false

        try {
            $ApiVoid_body = @{ ip = $targetIp } | ConvertTo-Json -Depth 3
            $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body -ErrorAction Stop
            
            if ($response -and $response.information) {
                $countryName = if ($response.information.country_name) { $response.information.country_name } else { "Unknown" }
                $asn         = if ($response.information.asn) { $response.information.asn } else { "Unknown" }
                $isp         = if ($response.information.isp) { $response.information.isp } else { "Unknown" }
                $riskScore   = if ($response.risk_score.result) { $response.risk_score.result } else { 0 }
                
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
            Write-Warning "API Failure for $targetIp : $($_.Exception.Message)"
        }

        # Check Blocklists
        try {
            if ($countryName -ne "Unknown" -and (Get-Command Get-CheckBlockedCountries -ErrorAction SilentlyContinue)) {
                $existsInCountryBlockList = Get-CheckBlockedCountries -country $countryName.Trim().ToLower()
            }
            if ($asn -ne "Unknown" -and (Get-Command Get-CheckSuspiciousASNs -ErrorAction SilentlyContinue)) {
                $existsInASNList = Get-CheckSuspiciousASNs -asn $asn
            }
        } catch { }

        # --- BUILD OUTPUT ---
        $output = [PSCustomObject]@{
            ip              = $targetIp
            RiskScore       = $riskScore
            Country         = $countryName
            CountryName     = $countryName
            IsGeoBlocked    = $existsInCountryBlockList
            ISP             = $isp
            ASN             = $asn
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
        if ($riskScore -eq 100) {
            Write-Host "`n[CRITICAL] $targetIp Risk Score: 100." -ForegroundColor Red
            if (Get-Command Get-S1IPtoDNS -ErrorAction SilentlyContinue) { Get-S1IPtoDNS -process $process -ip $targetIp }
        }
        if ($existsInCountryBlockList) {
            Write-Host "`n[GEO BLOCK] $targetIp ($countryName)." -ForegroundColor Red
        }

        $results += $output
    }
    
    Write-Progress -Activity "Checking IP Reputation" -Completed

    # Export CSV
    $results | Export-Csv -Path $outputCsv -NoTypeInformation
    Write-Host "Results saved to $outputCsv" -ForegroundColor Green

    # --- SUMMARY ---
    Write-Host "`n--- ISP Distribution (Top 20) ---" -ForegroundColor Cyan
    $ispGroups = $results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ISP) } | 
                  Group-Object ISP | Sort-Object Count -Descending | Select-Object -First 20
    
    $formatStr = "{0,-45} {1,-15} {2,10}"
    Write-Host ($formatStr -f "ISP Name", "ASN", "Count") -ForegroundColor Cyan
    Write-Host ("-" * 75) -ForegroundColor Cyan

    foreach ($group in $ispGroups) {
        $name = $group.Name
        $asn  = $group.Group[0].ASN
        $cnt  = $group.Count
        Write-Host ($formatStr -f $name, $asn, $cnt) -ForegroundColor Gray
    }

    Write-Host "`n--- Risk Score Distribution ---" -ForegroundColor Cyan
    if ($results) {
        $results | Group-Object RiskScore | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ RiskScore=$_.Name; Count=$_.Count } } | Format-Table -AutoSize
    }
}