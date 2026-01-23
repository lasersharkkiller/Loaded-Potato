function Get-MaliciousDifferentialAnalysis {
    <#
    .SYNOPSIS
        Iterates through all APT subfolders, performing differential malware analysis.
        FEATURES:
         - Detection Score Filtering
         - Memory Pattern URLs/Domains & IDS Rules
         - Last Seen Date Propagation
         - STABILITY FIX: Uses Generic Lists and PSCustomObjects
    #>
    param (
        [string]$SearchPath = "apt\c6g",
        [string]$GlobalResolutionPath = "output\Global_Hash_Resolution.csv",
        [string]$BaselineRootPath = "output-baseline\VirusTotal-main",
        [string]$BaselineBehavePath = "output-baseline\VirusTotal-behaviors",
        [string]$MaliciousStoragePath = "output-baseline\VirusTotal-main\malicious",
        [string]$BehaviorsStoragePath = "output-baseline\VirusTotal-behaviors\malicious",
        [int]$MinDetections = 5
    )

    # --- 1. SETUP & AUTHENTICATION ---
    if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
    }
    
    try {
        $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
        if (-not $VTApi) { throw "Secret 'VT_API_Key_3' not found." }
    } catch {
        Write-Error "Authentication Failed: $_"
        return
    }

    # Validate Paths
    if (-not (Test-Path $SearchPath)) { Write-Error "Search path '$SearchPath' not found."; return }
    $GlobalDir = Split-Path -Path $GlobalResolutionPath -Parent
    if (-not (Test-Path $GlobalDir)) { New-Item -ItemType Directory -Path $GlobalDir -Force | Out-Null }
    
    if (-not (Test-Path $MaliciousStoragePath)) { New-Item -ItemType Directory -Force -Path $MaliciousStoragePath | Out-Null }
    if (-not (Test-Path $BehaviorsStoragePath)) { New-Item -ItemType Directory -Force -Path $BehaviorsStoragePath | Out-Null }

    # Find Targets
    $AnalysisTargets = Get-ChildItem -Path $SearchPath -Recurse -Filter "*_Master_Intel.csv"
    
    if ($AnalysisTargets.Count -eq 0) {
        Write-Warning "No '*_Master_Intel.csv' files found in $SearchPath."
        return
    }

    Write-Host "Found $($AnalysisTargets.Count) targets. Starting Analysis (Sequential)..." -ForegroundColor Cyan

    # --- HELPER FUNCTION ---
    function Get-BehaviorAttributes ($Path) {
        if (-not (Test-Path $Path)) { return $null }
        try {
            $json = Get-Content $Path -Raw | ConvertFrom-Json
            if ($json.data -is [array]) { return $json.data[0].attributes } else { return $json.data.attributes } 
        } catch { return $null }
    }

    # --- 2. PROCESSING LOOP ---
    foreach ($TargetFile in $AnalysisTargets) {
        $CsvPath    = $TargetFile.FullName
        $TargetDir  = $TargetFile.DirectoryName
        
        Write-Host " [Start] $($TargetFile.BaseName)" -ForegroundColor Yellow

        # --- LOAD & NORMALIZE INPUT ---
        $IocData = Import-Csv -Path $CsvPath
        if (-not $IocData) { continue }
        
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

        # --- LOAD GLOBAL CACHE ---
        $GlobalMap = @{} 
        if (Test-Path $GlobalResolutionPath) {
            Import-Csv $GlobalResolutionPath | ForEach-Object {
                $GlobalMap[$_.Input_Hash] = @{ SHA256=$_.Canonical_SHA256; Date=$_.Date_Found }
            }
        }

        # SHA256 -> Date Map (Stores LAST SEEN date)
        $TargetDateMap = @{}

        $VT_headers = @{ "x-apikey" = $VTApi; "Content-Type" = "application/json" }

        # --- PHASE 1: RESOLUTION ---
        $NewEntries = @()
        $QuotaHit = $false
        $ProcessedSHA256 = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($Item in $InputQueue) {
            if ($QuotaHit) { break }
            $Input = $Item.Hash
            $Date  = $Item.Date
            $RealSHA256 = $null

            if ($GlobalMap.ContainsKey($Input)) {
                $RealSHA256 = $GlobalMap[$Input].SHA256
                if ($Date -eq "1970-01-01" -and $GlobalMap[$Input].Date -ne "1970-01-01") { $Date = $GlobalMap[$Input].Date }
            } else {
                $DiskPath = Join-Path $MaliciousStoragePath "$Input.json"
                if (Test-Path $DiskPath) {
                    $RealSHA256 = $Input
                } else {
                    try {
                        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Input" -Headers $VT_headers -Method Get
                        $RealSHA256 = $r.data.id
                        if ($Date -eq "1970-01-01") {
                            $ts = $r.data.attributes.first_submission_date
                            if ($ts) { $Date = [DateTimeOffset]::FromUnixTimeSeconds($ts).DateTime.ToString("yyyy-MM-dd") }
                        }
                        $r | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $MaliciousStoragePath "$RealSHA256.json")
                    } catch {
                        if ($_.Exception.Response.StatusCode.value__ -eq 429) { 
                             Write-Warning " [$($TargetFile.BaseName)] Quota Exceeded."; $QuotaHit = $true; break 
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }

                if ($RealSHA256) {
                    $GlobalMap[$Input] = @{ SHA256=$RealSHA256; Date=$Date }
                    $NewEntries += [PSCustomObject]@{ Input_Hash=$Input; Canonical_SHA256=$RealSHA256; Date_Found=$Date }
                }
            }

            if ($RealSHA256) {
                [void]$ProcessedSHA256.Add($RealSHA256)
                
                # STORE LATEST DATE
                if (-not $TargetDateMap.ContainsKey($RealSHA256)) {
                    $TargetDateMap[$RealSHA256] = $Date
                } else {
                    if ($Date -gt $TargetDateMap[$RealSHA256]) { $TargetDateMap[$RealSHA256] = $Date }
                }

                $bFile = Join-Path $BehaviorsStoragePath "$RealSHA256.json"
                $bBase = Join-Path $BaselineBehavePath "$RealSHA256.json"
                if (-not (Test-Path $bFile) -and -not (Test-Path $bBase)) {
                    try {
                        $url = "https://www.virustotal.com/api/v3/files/$RealSHA256/behaviour_summary"
                        $r = Invoke-RestMethod -Uri $url -Headers $VT_headers -Method Get
                        $r | ConvertTo-Json -Depth 10 | Set-Content -Path $bFile
                    } catch { if ($_.Exception.Response.StatusCode.value__ -eq 429) { $QuotaHit = $true; break } }
                    Start-Sleep -Milliseconds 300
                }
            }
        }

        if ($NewEntries.Count -gt 0) {
            $NewEntries | Export-Csv -Path $GlobalResolutionPath -Append -NoTypeInformation -Encoding UTF8
        }

        # --- PHASE 2: DIFFERENTIAL ANALYSIS ---
        $Base = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }
        $Targ = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }
        $Maps = @{ WinAPI=@{}; Elf=@{}; Sigma=@{}; Yara=@{}; Cert=@{}; Tags=@{}; Mitre=@{}; Mutex=@{}; Reg=@{}; Proc=@{}; MemUrls=@{}; MemDomains=@{}; IdsRules=@{} }

        # A. LOAD BASELINE
        $BaseTotal = 0; $BaseFiles = Get-ChildItem -Path $BaselineRootPath -File -Filter "*.json"
        foreach ($file in $BaseFiles) {
            $BaseTotal++
            try {
                $j = Get-Content $file.FullName -Raw | ConvertFrom-Json; $a = $j.data.attributes
                if($a.pe_info.import_list){foreach($d in $a.pe_info.import_list){foreach($f in $d.imported_functions){$k="$($d.library_name)!$f"; if(!$Base.WinAPI[$k]){$Base.WinAPI[$k]=0};$Base.WinAPI[$k]++}}}
                if($a.elf_info.imported_symbols){foreach($s in $a.elf_info.imported_symbols){$k="ELF!$s"; if(!$Base.Elf[$k]){$Base.Elf[$k]=0};$Base.Elf[$k]++}}
                if($a.sigma_analysis_results){foreach($r in $a.sigma_analysis_results){$k=$r.rule_title; if(!$Base.Sigma[$k]){$Base.Sigma[$k]=0};$Base.Sigma[$k]++}}
                if($a.crowdsourced_yara_results){foreach($r in $a.crowdsourced_yara_results){$k=$r.rule_name; if(!$Base.Yara[$k]){$Base.Yara[$k]=0};$Base.Yara[$k]++}}
                if($a.tags){foreach($t in $a.tags){if(!$Base.Tags[$t]){$Base.Tags[$t]=0};$Base.Tags[$t]++}}
                $sig=$a.signature_info; if($sig){$s=if($sig.signers){$sig.signers}elseif($sig.product){$sig.product}else{"Unsigned"};if($s -is [array]){$s=$s -join ", "};$v=if($sig.verified){"Verified"}else{"Unverified"};$k="$s ($v)";if(!$Base.Cert[$k]){$Base.Cert[$k]=0};$Base.Cert[$k]++}else{$k="No Sig";if(!$Base.Cert[$k]){$Base.Cert[$k]=0};$Base.Cert[$k]++}
                
                $bAttr = Get-BehaviorAttributes (Join-Path $BaselineBehavePath "$($file.BaseName).json")
                if ($bAttr) {
                    if($bAttr.mitre_attack_techniques){foreach($m in $bAttr.mitre_attack_techniques){$k="$($m.id): $($m.signature_description)"; if(!$Base.Mitre[$k]){$Base.Mitre[$k]=0};$Base.Mitre[$k]++}}
                    if($bAttr.mutexes_created){foreach($m in $bAttr.mutexes_created){if(!$Base.Mutex[$m]){$Base.Mutex[$m]=0};$Base.Mutex[$m]++}}
                    $rl=@(); if($bAttr.registry_keys_set){$rl+=$bAttr.registry_keys_set}; if($bAttr.registry_keys_opened){$rl+=$bAttr.registry_keys_opened}
                    foreach($r in $rl){if(!$Base.Reg[$r]){$Base.Reg[$r]=0};$Base.Reg[$r]++}
                    if($bAttr.processes_created){foreach($p in $bAttr.processes_created){if(!$Base.Proc[$p]){$Base.Proc[$p]=0};$Base.Proc[$p]++}}
                    if($bAttr.memory_pattern_urls){foreach($u in $bAttr.memory_pattern_urls){if(!$Base.MemUrls[$u]){$Base.MemUrls[$u]=0};$Base.MemUrls[$u]++}}
                    if($bAttr.memory_pattern_domains){foreach($d in $bAttr.memory_pattern_domains){if(!$Base.MemDomains[$d]){$Base.MemDomains[$d]=0};$Base.MemDomains[$d]++}}
                    if($bAttr.suricata_alerts){foreach($s in $bAttr.suricata_alerts){$k=$s.alert; if(!$Base.IdsRules[$k]){$Base.IdsRules[$k]=0};$Base.IdsRules[$k]++}}
                    if($bAttr.snort_alerts){foreach($s in $bAttr.snort_alerts){$k=$s.alert; if(!$Base.IdsRules[$k]){$Base.IdsRules[$k]=0};$Base.IdsRules[$k]++}}
                }
            } catch {}
        }

        # B. PROCESS TARGETS
        foreach ($HashSHA256 in $ProcessedSHA256) {
            $file = Join-Path $MaliciousStoragePath "$($HashSHA256).json"
            if (-not (Test-Path $file)) { $file = Join-Path $BaselineRootPath "$($HashSHA256).json" }
            if (-not (Test-Path $file)) { continue }

            try {
                $j = Get-Content $file -Raw | ConvertFrom-Json; $a = $j.data.attributes
                
                # --- DETECTION SCORE FILTER ---
                $Score = 0
                if ($a.last_analysis_stats.malicious) { $Score = $a.last_analysis_stats.malicious }
                if ($Score -lt $MinDetections) { continue } 
                
                # --- RETRIEVE DATE ---
                $ObsDate = if ($TargetDateMap.ContainsKey($HashSHA256)) { $TargetDateMap[$HashSHA256] } else { "Unknown" }

                # [FIX 1] Cast to PSCustomObject
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
                $sig=$a.signature_info; if($sig){$s=if($sig.signers){$sig.signers}elseif($sig.product){$sig.product}else{"Unsigned"};if($s -is [array]){$s=$s -join ", "};$v=if($sig.verified){"Verified"}else{"Unverified"};Add-Hit $Targ.Cert $Maps.Cert "$s ($v)" $ctx}else{Add-Hit $Targ.Cert $Maps.Cert "No Sig" $ctx}
                
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

        # --- PHASE 3: EXPORT ---
        $OutputJsonPath_WinAPI = Join-Path $TargetDir "TargetedAPIDifferentialAnalysis.json"
        $OutputJsonPath_Elf    = Join-Path $TargetDir "TargetedElfDifferentialAnalysis.json"
        $OutputJsonPath_Sigma  = Join-Path $TargetDir "TargetedSigmaDifferentialAnalysis.json"
        $OutputJsonPath_Yara   = Join-Path $TargetDir "TargetedYaraDifferentialAnalysis.json"
        $OutputJsonPath_Cert   = Join-Path $TargetDir "TargetedCertificateDifferentialAnalysis.json"
        $OutputJsonPath_Tags   = Join-Path $TargetDir "TargetedTagsDifferentialAnalysis.json"
        $OutputJsonPath_Mitre  = Join-Path $TargetDir "TargetedMitreDifferentialAnalysis.json"
        $OutputJsonPath_Mutex  = Join-Path $TargetDir "TargetedMutexDifferentialAnalysis.json"
        $OutputJsonPath_Reg    = Join-Path $TargetDir "TargetedRegistryDifferentialAnalysis.json"
        $OutputJsonPath_Proc   = Join-Path $TargetDir "TargetedProcessDifferentialAnalysis.json"
        $OutputJsonPath_MemUrls = Join-Path $TargetDir "TargetedMemoryPatternDifferentialAnalysis.json"
        $OutputJsonPath_MemDoms = Join-Path $TargetDir "TargetedMemoryDomainDifferentialAnalysis.json"
        $OutputJsonPath_Ids     = Join-Path $TargetDir "TargetedIDSDifferentialAnalysis.json"
        $OutputCsvPath         = Join-Path $TargetDir "Targeted_Analysis_Map.csv"
        
        # [FIX 2] Use List instead of Array to prevent "op_Addition" errors
        $CsvResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        function Process-Category ($Type, $TDict, $BDict, $Map, $OutPath) {
            $Res = @()
            foreach ($k in $TDict.Keys) {
                $mc=$TDict[$k]; $bc=if($BDict[$k]){$BDict[$k]}else{0}
                $bfRaw = if($BaseTotal-gt 0){$bc/$BaseTotal}else{0}; $bf=[Math]::Round($bfRaw*100,4); $rar=100-$bf
                
                $safeKey = $k
                if ($k -is [PSCustomObject] -or $k -is [System.Collections.Hashtable]) {
                    if ($k.key) { 
                        $safeKey = $k.key
                        if ($k.value) { $safeKey = "$($k.key) = $($k.value)" }
                    } else { $safeKey = $k | ConvertTo-Json -Depth 1 -Compress }
                }

                # LAST SEEN DATE LOGIC
                $AllDates = $Map[$k] | Select-Object -ExpandProperty ObservationDate -ErrorAction SilentlyContinue
                $MaxDate = ($AllDates | Sort-Object -Descending | Select-Object -First 1)

                $Res += [PSCustomObject]@{ 
                    Item_Name=$safeKey; 
                    Type=$Type; 
                    Baseline_Rarity_Score=$rar; 
                    Baseline_Frequency="$bf%"; 
                    Baseline_Count=$bc; 
                    Malicious_Count=$mc;
                    Last_Seen=$MaxDate # NEW
                }
                foreach ($f in $Map[$k]) { 
                    # [FIX 2] Use .Add() for list
                    $CsvResults.Add([PSCustomObject]@{ 
                        Indicator_Type=$Type; 
                        Unique_Item=$safeKey; 
                        File_Hash=$f.Hash; 
                        Malware_Family=$f.Family; 
                        Meaningful_Name=$f.Name; 
                        Baseline_Count=$bc;
                        Last_Observation_Date=$f.ObservationDate # NEW
                    })
                }
            }
            $Res | Sort-Object Baseline_Rarity_Score -Descending | ConvertTo-Json -Depth 4 | Set-Content $OutPath
        }

        Process-Category "Windows API" $Targ.WinAPI $Base.WinAPI $Maps.WinAPI $OutputJsonPath_WinAPI
        Process-Category "ELF Symbol"  $Targ.Elf    $Base.Elf    $Maps.Elf    $OutputJsonPath_Elf
        Process-Category "Sigma Rule"  $Targ.Sigma  $Base.Sigma  $Maps.Sigma  $OutputJsonPath_Sigma
        Process-Category "Yara Rule"   $Targ.Yara   $Base.Yara   $Maps.Yara   $OutputJsonPath_Yara
        Process-Category "Certificate" $Targ.Cert   $Base.Cert   $Maps.Cert   $OutputJsonPath_Cert
        Process-Category "VT Tag"      $Targ.Tags   $Base.Tags   $Maps.Tags   $OutputJsonPath_Tags
        Process-Category "MITRE Technique" $Targ.Mitre $Base.Mitre $Maps.Mitre $OutputJsonPath_Mitre
        Process-Category "Mutex"       $Targ.Mutex  $Base.Mutex  $Maps.Mutex  $OutputJsonPath_Mutex
        Process-Category "Registry Key" $Targ.Reg   $Base.Reg    $Maps.Reg    $OutputJsonPath_Reg
        Process-Category "Process"     $Targ.Proc   $Base.Proc   $Maps.Proc   $OutputJsonPath_Proc
        Process-Category "Memory URL"    $Targ.MemUrls    $Base.MemUrls    $Maps.MemUrls    $OutputJsonPath_MemUrls
        Process-Category "Memory Domain" $Targ.MemDomains $Base.MemDomains $Maps.MemDomains $OutputJsonPath_MemDoms
        Process-Category "IDS Rule"      $Targ.IdsRules   $Base.IdsRules   $Maps.IdsRules   $OutputJsonPath_Ids

        if ($CsvResults.Count -gt 0) {
            $CsvResults | Sort-Object Indicator_Type, Unique_Item | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
        }
        
        Write-Host " [Done]  $($TargetFile.BaseName)" -ForegroundColor Green
    }

    Write-Host "`nAll Tasks Complete." -ForegroundColor Green
}
Export-ModuleMember -Function Get-MaliciousDifferentialAnalysis