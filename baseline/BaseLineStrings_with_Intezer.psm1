function Get-StringsBaseline {
    # --- 1. SETUP & CONFIGURATION ---
    $intezerAPI = Get-Secret -Name 'Intezer_API_Key' -AsPlainText

    # Load Baselines
    $unverifiedProcsBaseline      = Get-Content output\unverifiedProcsBaseline.json      | ConvertFrom-Json
    $unsignedWinProcsBaseline     = Get-Content output\unsignedWinProcsBaseline.json     | ConvertFrom-Json
    $unsignedLinuxProcsBaseline   = Get-Content output\unsignedLinuxProcsBaseline.json   | ConvertFrom-Json
    $signedVerifiedProcsBaseline  = Get-Content output\signedVerifiedProcsBaseline.json  | ConvertFrom-Json
    #$maliciousProcsBaseline      = Get-Content output\maliciousProcsBaseline.json       | ConvertFrom-Json
    $driversBaseline              = Get-Content output\driversBaseline.json              | ConvertFrom-Json
    
    # Define Output Folders
    $RootOutput      = ".\output-baseline\IntezerStrings"
    #$MaliciousOutput = ".\output-baseline\IntezerStrings\malicious"

    # Create Directories
    if (-not (Test-Path $RootOutput)) { New-Item -ItemType Directory -Force -Path $RootOutput | Out-Null }
    #if (-not (Test-Path $MaliciousOutput)) { New-Item -ItemType Directory -Force -Path $MaliciousOutput | Out-Null }

    # Get Existing Hashes (Recursive check)
    $existingHashes = (Get-ChildItem -Path $RootOutput -Recurse -File).BaseName

    # --- 2. INTEZER AUTHENTICATION ---
    $base_url = 'https://analyze.intezer.com/api/v2-0'
    $intezer_body = @{ 'api_key' = $intezerAPI }
    $intezer_headers = @{ 'Authorization' = '' }

    try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($base_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
    catch {
        Write-Host "Error retrieving JWT"
        return $false
    }

    # ---------------------------------------------------------
    # HELPER FUNCTION: Process-IntezerHash
    # Includes logic to loop through ALL sub-analyses and handle Trusted files
    # ---------------------------------------------------------
    function Process-IntezerHash {
        param ($checkHash, $headers, $OutputFolder)

        # Safety Check: If hash is empty/null, skip immediately
        if ([string]::IsNullOrWhiteSpace($checkHash)) { return }

        Write-Host "Trying $checkHash"
        $base_url = 'https://analyze.intezer.com/api/v2-0'

        # Ensure output directory exists (Safety check)
        if ($null -ne $OutputFolder -and -not (Test-Path $OutputFolder)) { 
            New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null 
        }

        # Initial Attempt to get existing analysis
        try {
            $response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $headers -ContentType "application/json" -ErrorAction Stop
            $result_url = $base_url + $response.result_url
        }
        catch {
            Write-Host "  Initial lookup failed. Preparing to Analyze..." -ForegroundColor Yellow
            $result_url = $null 
        }

        # Submit for analysis if not found
        if ($null -eq $result_url) {
            try {
                $analyzeBody = @{ hash = $checkHash }
                $analyzeResponse = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $headers -Body ($analyzeBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                $result_url = $base_url + $analyzeResponse.result_url
                Write-Host "  Submitted for analysis..." -ForegroundColor Cyan
            }
            catch {
                Write-Warning "  Could not submit $checkHash for analysis. Skipping."
                return
            }
        }

        [bool]$checkIfPending = $true
        $retryCount = 0
        $maxRetries = 1 

        while ($checkIfPending) {
            try {
                $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $headers -ErrorAction Stop
            }
            catch {
                Write-Warning "  Error checking status for $checkHash"
                break
            }

            # Check Status
            if ($result.status -eq "queued" -or $result.status -eq "in_progress") {
                Start-Sleep -Seconds 5
                continue
            } else {
                # Analysis Done. Check Verdict.
                $verdict = $result.verdict
                $stringsFound = $false
                
                try {
                    $subAnalysesResponse = Invoke-RestMethod -Method "GET" -Uri ($result_url + '/sub-analyses') -Headers $headers -ErrorAction Stop
                    $subAnalyses = $subAnalysesResponse.sub_analyses
                    if ($subAnalyses -isnot [array]) { $subAnalyses = @($subAnalyses) }

                    # Try to pull strings from ANY sub-analysis
                    foreach ($analysis in $subAnalyses) {
                        $currentId = $analysis.sub_analysis_id
                        $finalURL  = "$result_url/sub-analyses/$currentId/strings"

                        try {
                            $queryStrings = Invoke-RestMethod -Method "GET" -Uri $finalURL -Headers $headers -ErrorAction Stop
                            
                            $savePath = Join-Path -Path $OutputFolder -ChildPath "$checkHash.json"
                            $queryStrings | ConvertTo-Json -Depth 10 | Out-File -FilePath $savePath
                            
                            Write-Host "  Saved Strings to: $savePath" -ForegroundColor DarkGray
                            $stringsFound = $true
                            break 
                        }
                        catch {
                            # Silently fail for this specific sub-ID, try next
                        }
                    }

                    if ($stringsFound) { return }
                    
                    # === IF WE ARE HERE, NO STRINGS WERE FOUND ===
                    
                    # Logic: If Trusted, Intezer likely didn't extract strings. Do NOT retry.
                    if ($verdict -eq "trusted") {
                         Write-Host "  Verdict is 'Trusted' and no strings found. Saving empty record to stop loop." -ForegroundColor Green
                         $dummyData = @{ 
                            hash = $checkHash
                            verdict = "trusted"
                            strings = @()
                            note = "Intezer did not provide extracted strings for this trusted file."
                         }
                         $savePath = Join-Path -Path $OutputFolder -ChildPath "$checkHash.json"
                         $dummyData | ConvertTo-Json | Out-File -FilePath $savePath
                         return
                    }

                    throw "No strings found in any sub-analysis"
                }
                catch {
                    # --- RE-ANALYSIS / FAILURE HANDLING ---
                    
                    # If we haven't retried yet, and it's NOT trusted, try once.
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "  Failed to retrieve strings. Triggering Re-Analysis..." -ForegroundColor Yellow
                        $retryCount++
                        
                        try {
                            $analyzeBody = @{ hash = $checkHash }
                            $analyzeResponse = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $headers -Body ($analyzeBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                            $result_url = $base_url + $analyzeResponse.result_url
                            Start-Sleep -Seconds 2
                            continue 
                        }
                        catch {
                            Write-Warning "  Re-analysis request failed: $_"
                        }
                    }
                    
                    # === CRITICAL FIX: SAVE FILE EVEN ON FAILURE ===
                    # If we exhausted retries, save a 'Failed' JSON so we don't loop forever.
                    Write-Warning "  Permanent failure to retrieve strings for $checkHash. Saving error log."
                    $errorData = @{
                        hash = $checkHash
                        error = "Failed to retrieve strings after retry"
                        verdict = $verdict
                    }
                    $savePath = Join-Path -Path $OutputFolder -ChildPath "$checkHash.json"
                    $errorData | ConvertTo-Json | Out-File -FilePath $savePath
                    break
                }
            }
        }
    }

    # --- 4. FILTERING LOGIC ---

    # Helper scriptblock for filtering
    $FilterBlock = {
        param($list, $existing)
        foreach ($proc in $list){
            foreach ($hash in $existing){
                if($proc.value[2] -eq $hash){ $proc.value[-1] = 8675309 }
            }
        }
        return $list | Where-Object {$_.value[-1] -ne 8675309}
    }

    # Apply Filters
    $filteredUnverifiedProcs      = & $FilterBlock -list $unverifiedProcsBaseline -existing $existingHashes
    $filteredUnsignedWinProcs     = & $FilterBlock -list $unsignedWinProcsBaseline -existing $existingHashes
    $filteredUnsignedLinuxProcs   = & $FilterBlock -list $unsignedLinuxProcsBaseline -existing $existingHashes
    $filteredsignedVerifiedProcs  = & $FilterBlock -list $signedVerifiedProcsBaseline -existing $existingHashes
    $filteredDriversProcs         = & $FilterBlock -list $driversBaseline -existing $existingHashes

    # --- 5. PROCESSING LOOPS ---

    Write-Host "Processing Unverified..." -ForegroundColor Cyan
    foreach ($needsStrings in $filteredUnverifiedProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    Write-Host "Processing Unsigned Win..." -ForegroundColor Cyan
    foreach ($needsStrings in $filteredUnsignedWinProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    Write-Host "Processing Unsigned Linux..." -ForegroundColor Cyan
    foreach ($needsStrings in $filteredUnsignedLinuxProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    Write-Host "Processing Signed Verified..." -ForegroundColor Cyan
    foreach ($needsStrings in $filteredsignedVerifiedProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    Write-Host "Processing Drivers..." -ForegroundColor Cyan
    foreach ($needsStrings in $filteredDriversProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }
}