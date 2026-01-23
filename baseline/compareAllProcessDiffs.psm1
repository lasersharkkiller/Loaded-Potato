function Get-CompareAllProcessDiffs {

    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$BehaviorsFilesPath = ".\output-baseline\VirusTotal-behaviors\"
    [string]$OutputFilePath = ".\output\process_differentials.txt"

    # --- ANSI Color Codes ---
    $esc = "$([char]27)"
    $colors = @{ Green = "$([char]27)[92m"; Yellow = "$([char]27)[93m"; Red = "$([char]27)[91m"; Magenta = "$([char]27)[95m"; Cyan = "$([char]27)[96m"; Reset = "$([char]27)[0m" }

    # --- Step 1: Validate paths ---
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) { Write-Error "Directory for main hash files not found at: $HashFilesPath"; return }
    if (-not (Test-Path -Path $BehaviorsFilesPath -PathType Container)) { Write-Error "Directory for behavior hash files not found at: $BehaviorsFilesPath"; return }

    Write-Host "Starting automated analysis for all processes..." -ForegroundColor Cyan

    try {
        # --- Step 2: Dynamically discover all processes and their hashes ---
        Write-Host "Discovering processes from reports in '$HashFilesPath'..."
        $processToHashesMap = @{}
        $reportFiles = Get-ChildItem -Path $HashFilesPath -Filter "*.json"

        foreach ($file in $reportFiles) {
            $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($null -eq $jsonContent -or $null -eq $jsonContent.data -or $null -eq $jsonContent.data.attributes -or $null -eq $jsonContent.data.attributes.names) {
                continue
            }
            # A file can have multiple names; we associate the hash with each name.
            foreach ($processName in $jsonContent.data.attributes.names) {
                if (-not $processToHashesMap.ContainsKey($processName)) {
                    $processToHashesMap[$processName] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $processToHashesMap[$processName].Contains($file.BaseName)) {
                    $processToHashesMap[$processName].Add($file.BaseName)
                }
            }
        }
        
        Write-Host "Found $($processToHashesMap.Keys.Count) unique processes to analyze."
        $allProcessResults = [System.Collections.Generic.List[object]]::new()

        # --- Loop through each unique process ---
        foreach ($processName in $processToHashesMap.Keys | Sort-Object) {
            $hashes = $processToHashesMap[$processName]

            if ($hashes.Count -lt 2) { continue } # Skip processes with only one hash

            # --- Step 3: Data Collection ---
            $allData = @{
                Imports         = [System.Collections.Generic.List[psobject]]::new()
                Certs           = [System.Collections.Generic.List[psobject]]::new()
                IPs             = [System.Collections.Generic.List[psobject]]::new()
                DnsLookups      = [System.Collections.Generic.List[psobject]]::new()
                ProcsCreated    = [System.Collections.Generic.List[psobject]]::new()
                ProcsTerminated = [System.Collections.Generic.List[psobject]]::new()
                Urls            = [System.Collections.Generic.List[psobject]]::new()
                FilesOpened     = [System.Collections.Generic.List[psobject]]::new()
                MemPatternUrls  = [System.Collections.Generic.List[psobject]]::new() # NEW
                MemPatternDoms  = [System.Collections.Generic.List[psobject]]::new() # NEW
                IdsRules        = [System.Collections.Generic.List[psobject]]::new() # NEW
            }
            $foundHashFiles = @{}

            foreach ($hash in $hashes) {
                # Process Main Report
                $mainHashFilePath = Join-Path -Path $HashFilesPath -ChildPath "$($hash).json"
                if (Test-Path $mainHashFilePath) {
                    $mainJson = Get-Content -Path $mainHashFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($null -ne $mainJson -and $null -ne $mainJson.data -and $null -ne $mainJson.data.attributes) {
                        # Imports
                        if ($null -ne $mainJson.data.attributes.pe_info -and $null -ne $mainJson.data.attributes.pe_info.import_list) {
                            if (-not $foundHashFiles.ContainsKey('Imports')) { $foundHashFiles['Imports'] = [System.Collections.Generic.List[string]]::new() }
                            if (-not $foundHashFiles['Imports'].Contains($hash)) { $foundHashFiles['Imports'].Add($hash) }
                            $mainJson.data.attributes.pe_info.import_list | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'library_name') { $allData.Imports.Add([PSCustomObject]@{ Property = $_.library_name; SourceHash = $hash }) } }
                        }
                        # Certs
                        if ($null -ne $mainJson.data.attributes.signature_info) {
                            if (-not $foundHashFiles.ContainsKey('Certs')) { $foundHashFiles['Certs'] = [System.Collections.Generic.List[string]]::new() }
                            if (-not $foundHashFiles['Certs'].Contains($hash)) { $foundHashFiles['Certs'].Add($hash) }
                            if($mainJson.data.attributes.signature_info.PSObject.Properties.Name -contains 'verified') { $allData.Certs.Add([PSCustomObject]@{ Property = "Verified Status = $($mainJson.data.attributes.signature_info.verified)"; SourceHash = $hash }) }
                            if ($null -ne $mainJson.data.attributes.signature_info.'signers details') {
                                $mainJson.data.attributes.signature_info.'signers details' | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'name') { $allData.Certs.Add([PSCustomObject]@{ Property = "Signer Name = $($_.name)"; SourceHash = $hash }) } }
                            }
                        }
                    }
                }

                # Process Behaviors Report
                $behaviorsFilePath = Join-Path -Path $BehaviorsFilesPath -ChildPath "$($hash).json"
                if (Test-Path $behaviorsFilePath) {
                    $behaviorsJson = Get-Content -Path $behaviorsFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($null -ne $behaviorsJson -and $null -ne $behaviorsJson.data) {
                        # Handle array or single object structure
                        $reports = if ($behaviorsJson.data -is [array]) { $behaviorsJson.data } else { @($behaviorsJson.data) }
                        
                        foreach ($sandboxReport in $reports) {
                            if ($null -ne $sandboxReport -and $null -ne $sandboxReport.attributes) {
                                $attr = $sandboxReport.attributes

                                # IP Traffic
                                if ($attr.ip_traffic) {
                                    if (-not $foundHashFiles.ContainsKey('IPs')) { $foundHashFiles['IPs'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['IPs'].Contains($hash)) { $foundHashFiles['IPs'].Add($hash) }
                                    $attr.ip_traffic | ForEach-Object { if($_.destination_ip) { $allData.IPs.Add([PSCustomObject]@{ Property = $_.destination_ip; SourceHash = $hash }) } }
                                }
                                # Processes Created
                                if ($attr.processes_created) {
                                    if (-not $foundHashFiles.ContainsKey('ProcsCreated')) { $foundHashFiles['ProcsCreated'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['ProcsCreated'].Contains($hash)) { $foundHashFiles['ProcsCreated'].Add($hash) }
                                    $attr.processes_created | ForEach-Object { if($_) { $allData.ProcsCreated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                                # Processes Terminated
                                if ($attr.processes_terminated) {
                                    if (-not $foundHashFiles.ContainsKey('ProcsTerminated')) { $foundHashFiles['ProcsTerminated'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['ProcsTerminated'].Contains($hash)) { $foundHashFiles['ProcsTerminated'].Add($hash) }
                                    $attr.processes_terminated | ForEach-Object { if($_) { $allData.ProcsTerminated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                                # DNS Lookups
                                if ($attr.dns_lookups) {
                                    if (-not $foundHashFiles.ContainsKey('DnsLookups')) { $foundHashFiles['DnsLookups'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['DnsLookups'].Contains($hash)) { $foundHashFiles['DnsLookups'].Add($hash) }
                                    foreach($lookup in $attr.dns_lookups) {
                                        if ($lookup.hostname) {
                                            $allData.DnsLookups.Add([PSCustomObject]@{ Property = "Hostname: $($lookup.hostname)"; SourceHash = $hash })
                                            if ($lookup.resolved_ips) {
                                                $lookup.resolved_ips | ForEach-Object { if($_) { $allData.DnsLookups.Add([PSCustomObject]@{ Property = "Resolved IP: $_"; SourceHash = $hash }) } }
                                            }
                                        }
                                    }
                                }
                                # URLs Found In Memory (Sig #238)
                                if ($attr.signature_matches) {
                                    $urlSignature = $attr.signature_matches | Where-Object { $_.id -eq "238" }
                                    if ($urlSignature) {
                                        if (-not $foundHashFiles.ContainsKey('Urls')) { $foundHashFiles['Urls'] = [System.Collections.Generic.List[string]]::new() }
                                        if (-not $foundHashFiles['Urls'].Contains($hash)) { $foundHashFiles['Urls'].Add($hash) }
                                        $urlSignature.match_data | ForEach-Object { if($_) { $allData.Urls.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                    }
                                }
                                # Files Opened
                                if ($attr.files_opened) {
                                    if (-not $foundHashFiles.ContainsKey('FilesOpened')) { $foundHashFiles['FilesOpened'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['FilesOpened'].Contains($hash)) { $foundHashFiles['FilesOpened'].Add($hash) }
                                    foreach ($file_path in $attr.files_opened) {
                                        if ($file_path -and ($file_path.EndsWith(".exe") -or $file_path.EndsWith(".dll"))) {
                                            $allData.FilesOpened.Add([PSCustomObject]@{ Property = $file_path; SourceHash = $hash })
                                        }
                                    }
                                }
                                
                                # --- NEW: Memory Pattern URLs ---
                                if ($attr.memory_pattern_urls) {
                                    if (-not $foundHashFiles.ContainsKey('MemPatternUrls')) { $foundHashFiles['MemPatternUrls'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['MemPatternUrls'].Contains($hash)) { $foundHashFiles['MemPatternUrls'].Add($hash) }
                                    $attr.memory_pattern_urls | ForEach-Object { if($_) { $allData.MemPatternUrls.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }

                                # --- NEW: Memory Pattern Domains ---
                                if ($attr.memory_pattern_domains) {
                                    if (-not $foundHashFiles.ContainsKey('MemPatternDoms')) { $foundHashFiles['MemPatternDoms'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['MemPatternDoms'].Contains($hash)) { $foundHashFiles['MemPatternDoms'].Add($hash) }
                                    $attr.memory_pattern_domains | ForEach-Object { if($_) { $allData.MemPatternDoms.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }

                                # --- NEW: IDS Rules (Suricata/Snort) ---
                                if ($attr.suricata_alerts) {
                                    if (-not $foundHashFiles.ContainsKey('IdsRules')) { $foundHashFiles['IdsRules'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['IdsRules'].Contains($hash)) { $foundHashFiles['IdsRules'].Add($hash) }
                                    $attr.suricata_alerts | ForEach-Object { if($_.alert) { $allData.IdsRules.Add([PSCustomObject]@{ Property = "Suricata: $($_.alert)"; SourceHash = $hash }) } }
                                }
                                if ($attr.snort_alerts) {
                                    if (-not $foundHashFiles.ContainsKey('IdsRules')) { $foundHashFiles['IdsRules'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['IdsRules'].Contains($hash)) { $foundHashFiles['IdsRules'].Add($hash) }
                                    $attr.snort_alerts | ForEach-Object { if($_.alert) { $allData.IdsRules.Add([PSCustomObject]@{ Property = "Snort: $($_.alert)"; SourceHash = $hash }) } }
                                }
                            }
                        }
                    }
                }
            }

            # --- Analysis Function ---
            function Get-DifferentialAnalysis($dataList, $totalFiles) {
                if ($totalFiles -lt 2) { return @{ HasDifferences = $false; Results = $null } }
                $analysis = @{ HasDifferences = $false; Results = [System.Collections.Generic.List[object]]::new() }
                $groupedData = $dataList | Group-Object -Property Property
                foreach ($group in $groupedData) {
                    $sourceHashes = @($group.Group | Select-Object -ExpandProperty SourceHash -Unique)
                    $count = $sourceHashes.Count
                    $result = [PSCustomObject]@{ Property = $group.Name; Count = $count; SourceHashes = $sourceHashes; Color = 'Green'; Type = '[COMMON] ' }
                    if ($count -ne $totalFiles) {
                        $analysis.HasDifferences = $true
                        $result.Type = if ($count -eq 1) { '[UNIQUE] ' } else { '[PARTIAL]' }
                        $result.Color = if ($count -eq 1) { 'Red' } else { 'Yellow' }
                    }
                    $analysis.Results.Add($result)
                }
                return $analysis
            }

            # --- Run Dynamic Analysis ---
            $processResult = @{ ProcessName = $processName; AnyDifferences = $false; AnalysisResults = @{} }
            $analysisConfig = @{
                Imports         = "Analysis of 'import_list'"
                Certs           = "Analysis of 'signature_info'"
                IPs             = "Analysis of 'destination_ip'"
                DnsLookups      = "Analysis of 'dns_lookups'"
                ProcsCreated    = "Analysis of 'processes_created'"
                ProcsTerminated = "Analysis of 'processes_terminated'"
                Urls            = "Analysis of URLs Found in Memory (Sig#238)"
                FilesOpened     = "Analysis of Files Opened (.exe/.dll)"
                MemPatternUrls  = "Analysis of Memory Pattern URLs"    # NEW
                MemPatternDoms  = "Analysis of Memory Pattern Domains" # NEW
                IdsRules        = "Analysis of IDS Rules (Suricata/Snort)" # NEW
            }

            foreach($category in $analysisConfig.Keys){
                $fileCount = if($foundHashFiles.ContainsKey($category)){ ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
                $result = Get-DifferentialAnalysis $allData[$category] $fileCount
                $processResult.AnalysisResults[$category] = @{ Result = $result; FileCount = $fileCount }
                if($result -and $result.HasDifferences){
                    $processResult.AnyDifferences = $true
                }
            }

            if($processResult.AnyDifferences){
                $allProcessResults.Add($processResult)
            }
        }
        
        # --- Step 4: Dynamic Reporting ---
        if ($allProcessResults.Count -gt 0) {
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
            $fileHeader = "Differential Analysis Report - $(Get-Date)"; Set-Content -Path $OutputFilePath -Value $fileHeader; Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)
            
            function Write-AnalysisSection($analysis, $title, $totalFiles, $colors, $OutputFilePath) {
                if ($analysis -and $analysis.Results) {
                    $subHeader = "--- $title (Compared across $totalFiles files) ---"
                    Write-Host "`n$subHeader" -ForegroundColor Cyan; Add-Content -Path $OutputFilePath -Value "`n$($colors.Cyan)$subHeader$($colors.Reset)"
                    foreach ($item in $analysis.Results) {
                        $line1 = "$($item.Type) $($item.Property)"; Write-Host $line1 -ForegroundColor $item.Color; Add-Content -Path $OutputFilePath -Value "$($colors[$item.Color])$line1$($colors.Reset)"
                        if ($item.Color -ne 'Green') {
                            $line2 = if ($item.Color -eq 'Red') { "       └─ Found only in: $($item.SourceHashes[0])" } else { "        └─ Found in $($item.Count) of $totalFiles files: $($item.SourceHashes -join ', ')" }
                            Write-Host $line2; Add-Content -Path $OutputFilePath -Value $line2
                        }
                    }
                }
            }

            foreach($processResult in $allProcessResults){
                $header = "DIFFERENCES FOUND for Process: $($processResult.ProcessName)"; $separator = '=' * $header.Length
                Write-Host "`n$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "`n$($colors.Magenta)$separator$($colors.Reset)"
                Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$header$($colors.Reset)"
                Write-Host "$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$separator$($colors.Reset)"

                foreach($category in $processResult.AnalysisResults.Keys){
                    $categoryResult = $processResult.AnalysisResults[$category]
                    if($categoryResult.Result -and $categoryResult.Result.HasDifferences){
                        Write-AnalysisSection $categoryResult.Result $analysisConfig[$category] $categoryResult.FileCount $colors $OutputFilePath
                    }
                }
            }
            
            Write-Host "`n--- Full Analysis Complete. Report saved to '$OutputFilePath' ---" -ForegroundColor Green
        } else {
            Write-Host "`n--- Full Analysis Complete. No differences found in any processes. ---" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
    }
}