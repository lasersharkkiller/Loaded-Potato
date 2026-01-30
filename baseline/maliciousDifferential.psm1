function Get-MaliciousDifferentialAnalysis {
    <#
    .SYNOPSIS
        Iterates through all APT subfolders in PARALLEL background jobs.
    .DESCRIPTION
        - Launches child processes (Jobs) for each Master_Intel.csv found.
        - Checks LOCAL DISK first to save VT Quota.
        - Checks MissingHashes.csv to skip known 404s.
        - Merges global hash resolutions safely after all jobs complete.
    #>
    param (
        [string]$SearchPath = "apt\c6g",
        [string]$GlobalResolutionPath = "output\Global_Hash_Resolution.csv",
        [string]$BaselineRootPath = "output-baseline\VirusTotal-main",
        [string]$BaselineBehavePath = "output-baseline\VirusTotal-behaviors",
        [string]$MaliciousStoragePath = "output-baseline\VirusTotal-main\malicious",
        [string]$BehaviorsStoragePath = "output-baseline\VirusTotal-behaviors\malicious",
        # Central location for the ignore list
        [string]$MissingHashesPath = "output\MissingHashes.csv",
        [int]$MinDetections = 5,
        [int]$ThrottleLimit = 10  # Runs 10 APTs at once
    )

    # --- 1. SETUP & PATH RESOLUTION ---
    $CurrentDir = Get-Location
    function Get-Abs ($p) { if([System.IO.Path]::IsPathRooted($p)){return $p} return Join-Path $CurrentDir $p }

    $SearchPath           = Get-Abs $SearchPath
    $GlobalResolutionPath = Get-Abs $GlobalResolutionPath
    $BaselineRootPath     = Get-Abs $BaselineRootPath
    $BaselineBehavePath   = Get-Abs $BaselineBehavePath
    $MaliciousStoragePath = Get-Abs $MaliciousStoragePath
    $BehaviorsStoragePath = Get-Abs $BehaviorsStoragePath
    $MissingHashesPath    = Get-Abs $MissingHashesPath

    # Create Directories
    $GlobalDir = Split-Path -Path $GlobalResolutionPath -Parent
    if (-not (Test-Path $GlobalDir)) { New-Item -ItemType Directory -Path $GlobalDir -Force | Out-Null }
    if (-not (Test-Path $MaliciousStoragePath)) { New-Item -ItemType Directory -Force -Path $MaliciousStoragePath | Out-Null }
    if (-not (Test-Path $BehaviorsStoragePath)) { New-Item -ItemType Directory -Force -Path $BehaviorsStoragePath | Out-Null }

    # API Key
    if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) { Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue }
    try {
        $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
        if (-not $VTApi) { throw "Secret 'VT_API_Key_3' not found." }
    } catch { Write-Error "Authentication Failed: $_"; return }

    # Load Missing Hashes (Parent Scope)
    $MissingHashes = @()
    if (Test-Path $MissingHashesPath) {
        $MissingHashes = (Import-Csv $MissingHashesPath).Hash
        Write-Host "Loaded $($MissingHashes.Count) known missing hashes to ignore." -ForegroundColor Gray
    }

    # Find Targets
    $AnalysisTargets = Get-ChildItem -Path $SearchPath -Recurse -Filter "*_Master_Intel.csv"
    if ($AnalysisTargets.Count -eq 0) { Write-Warning "No targets found."; return }

    Write-Host "Found $($AnalysisTargets.Count) targets. Starting Parallel Analysis ($ThrottleLimit threads)..." -ForegroundColor Cyan

    # --- 2. WORKER BLOCK (Runs inside Child Process) ---
    $WorkerBlock = {
        param (
            $TargetFile, $VTApi, $GlobalResolutionPath, 
            $BaselineRootPath, $BaselineBehavePath, 
            $MaliciousStoragePath, $BehaviorsStoragePath, $MinDetections,
            $MissingHashArray # Passed from parent
        )

        # Helper Functions
        function Get-BehaviorAttributes ($Path) {
            if (-not (Test-Path $Path)) { return $null }
            try {
                $json = Get-Content $Path -Raw | ConvertFrom-Json
                if ($json.data -is [array]) { return $json.data[0].attributes } else { return $json.data.attributes } 
            } catch { return $null }
        }
        function Add-Hit($dict, $map, $key, $c) { if(!$dict[$key]){$dict[$key]=0}; $dict[$key]++; if(!$map[$key]){$map[$key]=@()}; $map[$key]+=$c }

        $CsvPath = $TargetFile.FullName
        $TargetDir = $TargetFile.DirectoryName
        $BaseName = $TargetFile.BaseName
        $VT_headers = @{ "x-apikey" = $VTApi; "Content-Type" = "application/json" }
        
        # Return object container
        $JobResult = [PSCustomObject]@{
            NewResolutions = @()
            NewMissingHashes = @()
        }

        # Build local HashSet for fast lookup
        $IgnoreSet = [System.Collections.Generic.HashSet[string]]::new()
        if ($MissingHashArray) { foreach($h in $MissingHashArray) { [void]$IgnoreSet.Add($h) } }

        Write-Host "Processing: $BaseName"

        # A. LOAD TARGET DATA
        $IocData = Import-Csv -Path $CsvPath
        if (-not $IocData) { return $null }

        $Row1 = $IocData | Select-Object -First 1; $Props = $Row1.PSObject.Properties.Name
        $TypeCol = $Props | Where-Object { $_ -match "IOCType|Type" } | Select-Object -First 1
        $ValCol  = $Props | Where-Object { ($_ -match "IOCValue|IOC") -and ($_ -ne $TypeCol) } | Select-Object -First 1
        $DateCol = $Props | Where-Object { $_ -match "Date" } | Select-Object -First 1

        $InputQueue = @()
        foreach ($row in $IocData) {
            $v = $row.$ValCol
            if ($row.$TypeCol -match "SHA256|MD5|SHA1|Hash" -and -not [string]::IsNullOrWhiteSpace($v)) {
                $d = if ($DateCol -and $row.$DateCol) { $row.$DateCol } else { "1970-01-01" }
                if ($d -match "(\d{4}-\d{2}-\d{2})") { $d = $matches[1] } 
                $InputQueue += [PSCustomObject]@{ Hash=$v; Date=$d }
            }
        }
        $InputQueue = $InputQueue | Sort-Object Hash -Unique

        # B. LOAD GLOBAL MAP (Read Only)
        $GlobalMap = @{} 
        if (Test-Path $GlobalResolutionPath) {
            Import-Csv $GlobalResolutionPath | ForEach-Object { $GlobalMap[$_.Input_Hash] = @{ SHA256=$_.Canonical_SHA256; Date=$_.Date_Found } }
        }

        $TargetDateMap = @{}
        $ProcessedSHA256 = [System.Collections.Generic.HashSet[string]]::new()

        # C. RESOLUTION & DOWNLOAD
        foreach ($Item in $InputQueue) {
            $Input = $Item.Hash; $Date = $Item.Date; $RealSHA256 = $null

            # [CHECK 1] IGNORE LIST
            if ($IgnoreSet.Contains($Input)) { continue }

            if ($GlobalMap.ContainsKey($Input)) {
                $RealSHA256 = $GlobalMap[$Input].SHA256
                if ($Date -eq "1970-01-01" -and $GlobalMap[$Input].Date -ne "1970-01-01") { $Date = $GlobalMap[$Input].Date }
            } else {
                # --- CHECK DISK FIRST ---
                $DiskPath = Join-Path $MaliciousStoragePath "$Input.json"
                if (Test-Path $DiskPath) {
                    $RealSHA256 = $Input
                } else {
                    # --- API CALL ---
                    try {
                        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Input" -Headers $VT_headers -Method Get
                        $RealSHA256 = $r.data.id
                        if ($Date -eq "1970-01-01") {
                            $ts = $r.data.attributes.first_submission_date
                            if ($ts) { $Date = [DateTimeOffset]::FromUnixTimeSeconds($ts).DateTime.ToString("yyyy-MM-dd") }
                        }
                        $r | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $MaliciousStoragePath "$RealSHA256.json")
                    } catch {
                        $code = $_.Exception.Response.StatusCode.value__
                        if ($code -eq 404) {
                            # Not found in VT -> Add to results so parent can save to MissingHashes.csv
                            $JobResult.NewMissingHashes += $Input
                            [void]$IgnoreSet.Add($Input) # Ignore for rest of this job run
                        }
                        elseif ($code -eq 429) { Write-Host "[$BaseName] VT Rate Limit"; break }
                    }
                    Start-Sleep -Milliseconds 250 
                }
                if ($RealSHA256) { $JobResult.NewResolutions += [PSCustomObject]@{ Input_Hash=$Input; Canonical_SHA256=$RealSHA256; Date_Found=$Date } }
            }

            if ($RealSHA256) {
                [void]$ProcessedSHA256.Add($RealSHA256)
                if (-not $TargetDateMap.ContainsKey($RealSHA256) -or $Date -gt $TargetDateMap[$RealSHA256]) { $TargetDateMap[$RealSHA256] = $Date }
                
                # Behavior Download
                $bFile = Join-Path $BehaviorsStoragePath "$RealSHA256.json"
                $bBase = Join-Path $BaselineBehavePath "$RealSHA256.json"
                if (-not (Test-Path $bFile) -and -not (Test-Path $bBase)) {
                    try {
                        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$RealSHA256/behaviour_summary" -Headers $VT_headers -Method Get
                        $r | ConvertTo-Json -Depth 10 | Set-Content -Path $bFile
                    } catch { 
                        if ($_.Exception.Response.StatusCode.value__ -eq 429) { break }
                    }
                    Start-Sleep -Milliseconds 100
                }
            }
        }

        # [UPDATED FIX] CHECK IF WE HAVE ANYTHING TO ANALYZE
        if ($ProcessedSHA256.Count -eq 0) {
            Write-Host "  -> No valid/present hashes to analyze (All missing or filtered). Skipping Phases 2 & 3." -ForegroundColor DarkGray
            return $JobResult
        }

        # D. DIFFERENTIAL ANALYSIS (Baseline vs Target)
        $Base = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }
        $Targ = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }
        $Maps = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }

        $BaseTotal = 0
        $BaseFiles = Get-ChildItem -Path $BaselineRootPath -File -Filter "*.json"
        foreach ($file in $BaseFiles) {
            $BaseTotal++
            try {
                $j = Get-Content $file.FullName -Raw | ConvertFrom-Json; $a = $j.data.attributes
                if($a.pe_info.import_list){foreach($d in $a.pe_info.import_list){foreach($f in $d.imported_functions){Add-Hit $Base.WinAPI $Maps.WinAPI "$($d.library_name)!$f" $null}}}
                if($a.elf_info.imported_symbols){foreach($s in $a.elf_info.imported_symbols){Add-Hit $Base.Elf $Maps.Elf "ELF!$s" $null}}
                if($a.sigma_analysis_results){foreach($r in $a.sigma_analysis_results){Add-Hit $Base.Sigma $Maps.Sigma $r.rule_title $null}}
                if($a.crowdsourced_yara_results){foreach($r in $a.crowdsourced_yara_results){Add-Hit $Base.Yara $Maps.Yara $r.rule_name $null}}
                if($a.tags){foreach($t in $a.tags){Add-Hit $Base.Tags $Maps.Tags $t $null}}
                $sig=$a.signature_info; if($sig){$s=if($sig.signers){$sig.signers}elseif($sig.product){$sig.product}else{"Unsigned"};if($s -is [array]){$s=$s -join ", "};$v=if($sig.verified){"Verified"}else{"Unverified"};Add-Hit $Base.Cert $Maps.Cert "$s ($v)" $null}
                
                $bAttr = Get-BehaviorAttributes (Join-Path $BaselineBehavePath "$($file.BaseName).json")
                if ($bAttr) {
                    if($bAttr.mitre_attack_techniques){foreach($m in $bAttr.mitre_attack_techniques){Add-Hit $Base.Mitre $Maps.Mitre "$($m.id): $($m.signature_description)" $null}}
                    if($bAttr.mutexes_created){foreach($m in $bAttr.mutexes_created){Add-Hit $Base.Mutex $Maps.Mutex $m $null}}
                    $rl=@(); if($bAttr.registry_keys_set){$rl+=$bAttr.registry_keys_set}; if($bAttr.registry_keys_opened){$rl+=$bAttr.registry_keys_opened}
                    foreach($r in $rl){Add-Hit $Base.Reg $Maps.Reg $r $null}
                    if($bAttr.processes_created){foreach($p in $bAttr.processes_created){Add-Hit $Base.Proc $Maps.Proc $p $null}}
                    if($bAttr.memory_pattern_urls){foreach($u in $bAttr.memory_pattern_urls){Add-Hit $Base.MemUrls $Maps.MemUrls $u $null}}
                    if($bAttr.memory_pattern_domains){foreach($d in $bAttr.memory_pattern_domains){Add-Hit $Base.MemDomains $Maps.MemDomains $d $null}}
                    if($bAttr.suricata_alerts){foreach($s in $bAttr.suricata_alerts){Add-Hit $Base.IdsRules $Maps.IdsRules $s.alert $null}}
                    if($bAttr.snort_alerts){foreach($s in $bAttr.snort_alerts){Add-Hit $Base.IdsRules $Maps.IdsRules $s.alert $null}}
                }
            } catch {}
        }

        # Analyze Target Hashes
        foreach ($HashSHA256 in $ProcessedSHA256) {
            $file = Join-Path $MaliciousStoragePath "$($HashSHA256).json"
            if (-not (Test-Path $file)) { $file = Join-Path $BaselineRootPath "$($HashSHA256).json" }
            if (-not (Test-Path $file)) { continue }

            try {
                $j = Get-Content $file -Raw | ConvertFrom-Json; $a = $j.data.attributes
                if (($a.last_analysis_stats.malicious) -lt $MinDetections) { continue }
                
                $ObsDate = if ($TargetDateMap.ContainsKey($HashSHA256)) { $TargetDateMap[$HashSHA256] } else { "Unknown" }
                $ctx = [PSCustomObject]@{
                    Hash=$HashSHA256; 
                    Family=if($a.last_analysis_results.Microsoft.result){$a.last_analysis_results.Microsoft.result}else{"Unknown"}; 
                    Name=$a.meaningful_name;
                    ObservationDate=$ObsDate
                }

                function Add-Hit($dict, $map, $key, $c) { if(!$dict[$key]){$dict[$key]=0}; $dict[$key]++; if(!$map[$key]){$map[$key]=@()}; $map[$key]+=$c }

                if($a.pe_info.import_list){foreach($d in $a.pe_info.import_list){foreach($f in $d.imported_functions){Add-Hit $Targ.WinAPI $Maps.WinAPI "$($d.library_name)!$f" $ctx}}}
                if($a.elf_info.imported_symbols){foreach($s in $a.elf_info.imported_symbols){Add-Hit $Targ.Elf $Maps.Elf "ELF!$s" $ctx}}
                if($a.sigma_analysis_results){foreach($r in $a.sigma_analysis_results){Add-Hit $Targ.Sigma $Maps.Sigma $r.rule_title $ctx}}
                if($a.crowdsourced_yara_results){foreach($r in $a.crowdsourced_yara_results){Add-Hit $Targ.Yara $Maps.Yara $r.rule_name $ctx}}
                if($a.tags){foreach($t in $a.tags){Add-Hit $Targ.Tags $Maps.Tags $t $ctx}}
                $sig=$a.signature_info; if($sig){$s=if($sig.signers){$sig.signers}elseif($sig.product){$sig.product}else{"Unsigned"};if($s -is [array]){$s=$s -join ", "};$v=if($sig.verified){"Verified"}else{"Unverified"};Add-Hit $Targ.Cert $Maps.Cert "$s ($v)" $ctx}
                
                $bPath = Join-Path $BehaviorsStoragePath "$($HashSHA256).json"
                if(-not(Test-Path $bPath)){ $bPath = Join-Path $BaselineBehavePath "$($HashSHA256).json" }
                $bAttr = Get-BehaviorAttributes $bPath
                if ($bAttr) {
                    if($bAttr.mitre_attack_techniques){foreach($m in $bAttr.mitre_attack_techniques){Add-Hit $Targ.Mitre $Maps.Mitre "$($m.id): $($m.signature_description)" $ctx}}
                    if($bAttr.mutexes_created){foreach($m in $bAttr.mutexes_created){Add-Hit $Targ.Mutex $Maps.Mutex $m $ctx}}
                    $rl=@(); if($bAttr.registry_keys_set){$rl+=$bAttr.registry_keys_set}; if($bAttr.registry_keys_opened){$rl+=$bAttr.registry_keys_opened}
                    foreach($r in $rl){Add-Hit $Targ.Reg $Maps.Reg $r $ctx}
                    if($bAttr.processes_created){foreach($p in $bAttr.processes_created){Add-Hit $Targ.Proc $Maps.Proc $p $ctx}}
                    if($bAttr.memory_pattern_urls){foreach($u in $bAttr.memory_pattern_urls){Add-Hit $Targ.MemUrls $Maps.MemUrls $u $ctx}}
                    if($bAttr.memory_pattern_domains){foreach($d in $bAttr.memory_pattern_domains){Add-Hit $Targ.MemDomains $Maps.MemDomains $d $ctx}}
                    if($bAttr.suricata_alerts){foreach($s in $bAttr.suricata_alerts){Add-Hit $Targ.IdsRules $Maps.IdsRules $s.alert $ctx}}
                    if($bAttr.snort_alerts){foreach($s in $bAttr.snort_alerts){Add-Hit $Targ.IdsRules $Maps.IdsRules $s.alert $ctx}}
                }
            } catch {}
        }

        # Export
        $CsvResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $CatMap = @{ "Windows API"="TargetedAPIDifferentialAnalysis.json"; "Sigma Rule"="TargetedSigmaDifferentialAnalysis.json"; "Yara Rule"="TargetedYaraDifferentialAnalysis.json"; "IDS Rule"="TargetedIDSDifferentialAnalysis.json"; "MITRE Technique"="TargetedMitreDifferentialAnalysis.json"; "Registry Key"="TargetedRegistryDifferentialAnalysis.json"; "VT Tag"="TargetedTagsDifferentialAnalysis.json"; "Mutex"="TargetedMutexDifferentialAnalysis.json"; "Process"="TargetedProcessDifferentialAnalysis.json"; "Memory URL"="TargetedMemoryPatternDifferentialAnalysis.json"; "Memory Domain"="TargetedMemoryDomainDifferentialAnalysis.json"; "Certificate"="TargetedCertificateDifferentialAnalysis.json"; "ELF Symbol"="TargetedElfDifferentialAnalysis.json" }
        $Dicts = @{ "Windows API"=$Targ.WinAPI; "Sigma Rule"=$Targ.Sigma; "Yara Rule"=$Targ.Yara; "IDS Rule"=$Targ.IdsRules; "MITRE Technique"=$Targ.Mitre; "Registry Key"=$Targ.Reg; "VT Tag"=$Targ.Tags; "Mutex"=$Targ.Mutex; "Process"=$Targ.Proc; "Memory URL"=$Targ.MemUrls; "Memory Domain"=$Targ.MemDomains; "Certificate"=$Targ.Cert; "ELF Symbol"=$Targ.Elf }
        $BaseDicts = @{ "Windows API"=$Base.WinAPI; "Sigma Rule"=$Base.Sigma; "Yara Rule"=$Base.Yara; "IDS Rule"=$Base.IdsRules; "MITRE Technique"=$Base.Mitre; "Registry Key"=$Base.Reg; "VT Tag"=$Base.Tags; "Mutex"=$Base.Mutex; "Process"=$Base.Proc; "Memory URL"=$Base.MemUrls; "Memory Domain"=$Base.MemDomains; "Certificate"=$Base.Cert; "ELF Symbol"=$Base.Elf }
        $MapDicts = @{ "Windows API"=$Maps.WinAPI; "Sigma Rule"=$Maps.Sigma; "Yara Rule"=$Maps.Yara; "IDS Rule"=$Maps.IdsRules; "MITRE Technique"=$Maps.Mitre; "Registry Key"=$Maps.Reg; "VT Tag"=$Maps.Tags; "Mutex"=$Maps.Mutex; "Process"=$Maps.Proc; "Memory URL"=$Maps.MemUrls; "Memory Domain"=$Maps.MemDomains; "Certificate"=$Maps.Cert; "ELF Symbol"=$Maps.Elf }

        foreach ($cat in $CatMap.Keys) {
            $Res = @(); $T=$Dicts[$cat]; $B=$BaseDicts[$cat]; $M=$MapDicts[$cat]
            foreach ($k in $T.Keys) {
                $mc=$T[$k]; $bc=if($B[$k]){$B[$k]}else{0}
                $bfRaw = if($BaseTotal-gt 0){$bc/$BaseTotal}else{0}; $bf=[Math]::Round($bfRaw*100,4); $rar=100-$bf
                $Dates = $M[$k] | Select -ExpandProperty ObservationDate -ErrorAction SilentlyContinue
                $MaxDate = ($Dates | Sort -Descending | Select -First 1)
                
                $safeKey = $k; if($k -is [PSCustomObject] -or $k -is [hashtable]){$safeKey = $k | ConvertTo-Json -Depth 1 -Compress}

                $Res += [PSCustomObject]@{ Item_Name=$safeKey; Type=$cat; Baseline_Rarity_Score=$rar; Malicious_Count=$mc; Last_Seen=$MaxDate }
                foreach ($f in $M[$k]) { 
                    if ($f) { $CsvResults.Add([PSCustomObject]@{ Indicator_Type=$cat; Unique_Item=$safeKey; File_Hash=$f.Hash; Malware_Family=$f.Family; Meaningful_Name=$f.Name; Last_Observation_Date=$f.ObservationDate }) }
                }
            }
            $Res | Sort Baseline_Rarity_Score -Descending | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $TargetDir $CatMap[$cat])
        }
        
        if ($CsvResults.Count -gt 0) {
            $CsvResults | Sort Indicator_Type, Unique_Item | Export-Csv -Path (Join-Path $TargetDir "Targeted_Analysis_Map.csv") -NoTypeInformation -Encoding UTF8
        }

        # IMPORTANT: Only return the data object
        return $JobResult
    }

    # --- 3. JOB MANAGER ---
    $Jobs = @(); $GlobalNewHashes = @(); $GlobalMissingHashes = @()
    
    foreach ($File in $AnalysisTargets) {
        # Throttle
        while (($Jobs | Where {$_.State -eq 'Running'}).Count -ge $ThrottleLimit) {
            $Done = $Jobs | Where {$_.State -ne 'Running'}
            foreach ($j in $Done) { 
                # [UPDATED FIX] Loop through all output objects to find the correct data payload
                $Results = Receive-Job $j
                if ($Results) {
                    foreach ($res in $Results) {
                        # Check if this object looks like our $JobResult structure
                        if ($res.PSObject.Properties.Match("NewResolutions").Count -gt 0) {
                            if ($res.NewResolutions) { $GlobalNewHashes += $res.NewResolutions }
                            if ($res.NewMissingHashes) { $GlobalMissingHashes += $res.NewMissingHashes }
                        }
                    }
                }
                Remove-Job $j; $Jobs = $Jobs | Where {$_.Id -ne $j.Id}
            }
            Start-Sleep -Seconds 2
        }
        
        # Start Job
        Write-Host " [Queue] $($File.BaseName)" -ForegroundColor Yellow
        $j = Start-Job -ScriptBlock $WorkerBlock -ArgumentList $File, $VTApi, $GlobalResolutionPath, $BaselineRootPath, $BaselineBehavePath, $MaliciousStoragePath, $BehaviorsStoragePath, $MinDetections, $MissingHashes
        $Jobs += $j
    }

    # Wait for remaining
    Wait-Job $Jobs | Out-Null
    foreach ($j in $Jobs) { 
        $Results = Receive-Job $j
        if ($Results) {
            foreach ($res in $Results) {
                if ($res.PSObject.Properties.Match("NewResolutions").Count -gt 0) {
                    if ($res.NewResolutions) { $GlobalNewHashes += $res.NewResolutions }
                    if ($res.NewMissingHashes) { $GlobalMissingHashes += $res.NewMissingHashes }
                }
            }
        }
        Remove-Job $j 
    }

    # Merge Global Resolutions
    if ($GlobalNewHashes.Count -gt 0) {
        Write-Host "Saving $($GlobalNewHashes.Count) new resolutions..." -ForegroundColor Cyan
        $GlobalNewHashes | Select Input_Hash, Canonical_SHA256, Date_Found | Export-Csv -Path $GlobalResolutionPath -Append -NoTypeInformation -Encoding UTF8
    }

    # Save NEW Missing Hashes (404s)
    if ($GlobalMissingHashes.Count -gt 0) {
        Write-Host "Saving $($GlobalMissingHashes.Count) new MISSING hashes (to ignore next time)..." -ForegroundColor Magenta
        $Today = (Get-Date).ToString("yyyy-MM-dd")
        $GlobalMissingHashes | Select-Object -Unique | ForEach-Object {
            [PSCustomObject]@{ Hash=$_; DateChecked=$Today }
        } | Export-Csv -Path $MissingHashesPath -Append -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`nAll Parallel Tasks Complete." -ForegroundColor Green
}
Export-ModuleMember -Function Get-MaliciousDifferentialAnalysis