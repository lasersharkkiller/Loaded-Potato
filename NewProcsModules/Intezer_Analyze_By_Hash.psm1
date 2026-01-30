function Get-IntezerHash {
    param (
        #[Parameter(Mandatory=$true)]
        $checkHash,
        $fileName,
        $baseline,
        $signatureStatus,
        $publisher
    )
    
    # --- 1. UPDATE: Correct Import Path for the Scanner ---
    # We now look in the 'codeScanning' folder for 'githubRiskScore.psm1'
    if (Test-Path ".\codeScanning\githubRiskScore.psm1") {
        Import-Module -Name ".\codeScanning\githubRiskScore.psm1" -ErrorAction SilentlyContinue
    } else {
        Write-Warning "Could not find 'githubRiskScore.psm1' in .\codeScanning\. GitHub scanning will fail."
    }
    
    Import-Module -Name ".\NewProcsModules\DomainCleanup.psm1"
    Import-Module -Name ".\NewProcsModules\IntezerCheckUrl.psm1"
    Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"
    
    $intezerAPI = Get-Secret -Name 'Intezer_API_Key' -AsPlainText

    # Load Allow/Block Lists
    $trustedDomains = Import-Csv -Path "output\trustedDomains.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true}
    $SuspiciousDomains = Import-Csv -Path "output\suspiciousDomains.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true}
    $trustedIPs = Import-Csv -Path "output\trustedIPs.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true }
    $blockedIPs = "output\misp_ip_blocklist.txt" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true }

    $base_url = 'https://analyze.intezer.com/api/v2-0'

    $intezer_body = @{ 'api_key' = $intezerAPI }
    $hash = @{ 'hash' = $checkHash }
    $global:intezer_headers = @{ 'Authorization' = '' }

    # Get Token
    $queryCreateUrl = $base_url + '/get-access-token'
    try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($base_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
    catch {
        Write-Host "Error retrieving JWT"
        return $false
    }

    # Get Analysis Result
    try{
        $response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $intezer_headers -ContentType "application/json" -ErrorAction silentlycontinue
    } catch {
        Write-Host "Intezer does not have that analysis."
        if ($response.error -eq "Analysis expired"){
            Write-Host $response.result_url
            $newresponse = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/analyze-by-hash/' + $checkHash) -Headers $intezer_headers -ContentType "application/json" -ErrorAction silentlycontinue
            Start-Sleep -Seconds 15
        }
    }
    
    $result_url = $base_url + $response.result_url
    [bool]$checkIfPending = $true

    while ($checkIfPending) {
        try{
            $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $intezer_headers -ErrorAction silentlycontinue
        }
        catch {
            Write-Host "Intezer doesn't already have" $($fileName) ", next trying VT."
            return $false
        }

        if ($result.status -eq "queued"){
            continue
        } else {
            $textColor = "White"
            
            # --- BASELINE LOGIC ---
            if ($result.result.verdict -eq "trusted") {
                $textColor = "Green"
                $updateBaseline = Get-Content $baseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $updateBaseline += $newEntry
                $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
            } elseif ($result.result.verdict -eq "no_threats"){
                $textColor = "Green"
                $updateBaseline = Get-Content $baseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $updateBaseline += $newEntry
                $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
            } elseif ($result.result.verdict -eq "unknown"){
                $updateBaseline = Get-Content $baseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $textColor = "White"
                $updateBaseline += $newEntry
                $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
            } elseif ($result.result.verdict -eq "not_supported"){
                $updateBaseline = Get-Content $baseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $textColor = "White"
                $updateBaseline += $newEntry
                $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
            } elseif ($result.result.verdict -eq "suspicious"){
                $updateBaseline = Get-Content $baseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $textColor = "Yellow"
                $updateBaseline += $newEntry
                $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
            } elseif ($result.result.verdict -eq "malicious"){
                $maliciousBaseline = "output\maliciousProcsBaseline.json"
                $updateMaliciousBaseline = Get-Content $maliciousBaseline | ConvertFrom-Json
                $newEntry = @{ value = @($fileName, $signatureStatus, $checkHash, $publisher, 1.0) }
                $textColor = "Red"
                $updateMaliciousBaseline += $newEntry
                $updateMaliciousBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $maliciousBaseline
            }
            
            Write-Host "---" -ForegroundColor $textColor
            Write-Host "File Name: " $fileName -ForegroundColor $textColor
            Write-Host "Verdict: " $result.result.verdict -ForegroundColor $textColor
            
            $analysis_id = $result.result.analysis_id
            
            # --- DYNAMIC ARTIFACTS ---
            $dynamicTTPUrl = $base_url + '/analyses/' + $analysis_id + '/behavior'
            $dynamicTTPs = Invoke-RestMethod -Uri $dynamicTTPUrl -Headers $intezer_headers -ErrorAction silentlycontinue
            
            Write-Host "Intezer dynamic network artifacts: "
            if ($dynamicTTPs.result.network.dns.Count -gt 0){
                Write-Host "Network DNS: " $dynamicTTPs.result.network.dns
                $ApiVoidResults = Get-CheckApiVoid -artifacts $dynamicTTPs.result.network.dns -type "DomainName"
            }
            if ($dynamicTTPs.result.network.http.Count -gt 0){
                Write-Host "Network HTTP: " $dynamicTTPs.result.network.http
                $ApiVoidResults = Get-CheckApiVoid -artifacts $dynamicTTPs.result.network.http -type "DomainName"
            }
            if ($dynamicTTPs.result.network.tcp.Count -gt 0){
                Write-Host "Network TCP: " $dynamicTTPs.result.network.tcp
                $ApiVoidResults = Get-CheckApiVoid -artifacts $dynamicTTPs.result.network.tcp.ip -type "IPAddress"
            }
            if ($dynamicTTPs.result.network.udp.Count -gt 0){
                Write-Host "Network UDP: " $dynamicTTPs.result.network.udp
                $ApiVoidResults = Get-CheckApiVoid -artifacts $dynamicTTPs.result.network.udp.ip -type "IPAddress"
            }

            # --- STATIC ARTIFACTS (Sub-Analysis) ---
            $subAnalysisUrl = $base_url + '/analyses/' + $analysis_id + '/sub-analyses'
            $subAnalysisIdReport = Invoke-RestMethod -Uri $subAnalysisUrl -Headers $intezer_headers
            
            if ($subAnalysisIdReport.sub_analyses.Count -eq 1) {
                $subAnalysisId = $subAnalysisIdReport.sub_analyses.sub_analysis_id
            } else {
                $subAnalysisId = $subAnalysisIdReport.sub_analyses[-1].sub_analysis_id
            }

            foreach ($subid in $subAnalysisIdReport.sub_analyses.sub_analysis_id) {
                $stringsUrl = $subAnalysisUrl + '/' + $subid + '/strings'
                try{
                    $checkForNetworkStrings = (Invoke-RestMethod -Uri $stringsUrl -Headers $intezer_headers -ContentType "application/json").result.strings
                    break
                } catch {
                    Write-Host "Couldn't get sub-analysis $subid" -ForegroundColor Yellow
                }
            }

            Write-Host "Intezer extracted network artifacts from strings: "
            $artifactDedupList = @()
            
            foreach ($string in $checkForNetworkStrings) {
                if ($string.tags -eq "network_artifact") {
                    $artifact = $string.string_value
                    $patterns = @("http","://",".com",".org",".io")
                    
                    if ($artifact -match "\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b") {
                        # IP Logic (simplified for brevity)
                        # ...
                    } 
                    elseif ($patterns | Where-Object {$artifact -like "*$_*"}) {
                        # Domain Logic
                        $trimmedartifact = Get-DomainCleanup -domain $artifact
                        
                        $isValid = $true
                        try{ Resolve-DNSName -Name $trimmedartifact | Out-Null } catch { $isValid = $false }

                        if ($artifactDedupList -contains $trimmedartifact) { continue }
                        elseif ($isValid -eq $false) { continue }
                        else {
                            $existsInTrustedDomains = $false
                            foreach ($row in $trustedDomains) {
                                if ($trimmedartifact -match $row.domain) { $existsInTrustedDomains = $true; continue }
                            }

                            $existsInSuspiciousDomains = $false
                            if ($existsInTrustedDomains -eq $false) {
                                foreach ($row in $SuspiciousDomains) {
                                    if ($trimmedartifact -match $row.domain) { $existsInSuspiciousDomains = $true; continue }
                                }
                            }

                            $extractedUrlRegex = 'https?:\/\/[^\s"]+'
                            $extractedUrl = [regex]::Matches($artifact, $extractedUrlRegex).Value

                            if ($existsInTrustedDomains -eq $true){
                                Write-Host "$trimmedartifact is in the Trusted Domains" -ForegroundColor "Green"
                            } 
                            elseif ($existsInSuspiciousDomains -eq $true){
                                Write-Host "-"
                                Write-Host "$trimmedartifact is in the Suspicious Domains" -ForegroundColor "Yellow"
                                
                                # --- 2. UPDATE: SCAN LOGIC ---
                                if ($trimmedartifact -match "github") {
                                    Write-Host " [ACTION] GitHub detected. Initiating Risk Scan..." -ForegroundColor Cyan
                                    # Use extracted URL if available, else construct from artifact
                                    $targetUrl = if ($extractedUrl) { $extractedUrl } else { "https://" + $trimmedartifact }
                                    
                                    # Call the function from the imported module
                                    Get-GitHubRiskScore -GitHubUrl $targetUrl
                                } 
                                else {
                                    Write-Host "Conducting Deeper Analysis on full url:" -ForegroundColor "Yellow"
                                    Get-IntezerCheckUrl -url $extractedUrl
                                }
                                # -----------------------------

                            } else {
                                $ApiVoidResults = Get-CheckApiVoid -artifacts $trimmedartifact -type "DomainName"
                            }
                            $artifactDedupList += $trimmedartifact
                        }
                    } 
                }
            }
            Write-Host "---" -ForegroundColor $textColor
            return $true
        }
    }
}