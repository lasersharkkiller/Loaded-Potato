<#
.SYNOPSIS
    Smart Repair for VirusTotal Baselines (Fault Tolerant).
    1. Checks if Behavior file is in old (Array) format.
    2. Attempts to fetch new 'behaviour_summary' from VirusTotal.
    3. FALLBACK: If VT returns no data, it CONVERTS the old local array.
       * Handles Registry Object flattening correctly.
#>
function Repair-VTBaseline {
    
    $BasePath = ".\output-baseline"
    $MainRoot = Join-Path $BasePath "VirusTotal-main"
    $BehaveRoot = Join-Path $BasePath "VirusTotal-behaviors"
    
    $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
    $Headers = @{ "x-apikey" = $VTApi; "Content-Type" = "application/json" }

    Write-Host "Starting Hybrid VirusTotal Repair (Fault Tolerant)..." -ForegroundColor Cyan
    $MainFiles = Get-ChildItem -Path $MainRoot -Recurse -Filter "*.json"
    
    $Total = $MainFiles.Count
    $Current = 0
    $FixedDownload = 0
    $FixedConvert = 0
    $Skipped = 0

    foreach ($File in $MainFiles) {
        $Current++
        $Hash = $File.BaseName
        
        $ParentName = $File.Directory.Name
        $TargetFolder = if ($ParentName -eq "malicious") { Join-Path $BehaveRoot "malicious" } else { $BehaveRoot }
        if (-not (Test-Path $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }
        
        $BehaveFile = Join-Path $TargetFolder "$Hash.json"
        $NeedRepair = $false
        $LocalContent = $null

        # 1. Check Condition
        if (-not (Test-Path $BehaveFile)) {
            $NeedRepair = $true
        } else {
            try {
                $LocalContent = Get-Content -Path $BehaveFile -Raw | ConvertFrom-Json
                if ($LocalContent.data -is [Array]) { $NeedRepair = $true }
                elseif (-not $LocalContent.data.attributes) { $Skipped++; continue }
            } catch { $NeedRepair = $true }
        }

        if ($NeedRepair) {
            Write-Host "[$Current/$Total] Processing $Hash ... " -NoNewline
            
            # --- STRATEGY A: TRY DOWNLOAD ---
            $DownloadSuccess = $false
            try {
                $Url = "https://www.virustotal.com/api/v3/files/$Hash/behaviour_summary"
                $Response = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
                
                if ($Response.data -and $Response.data.attributes) {
                    $Response | ConvertTo-Json -Depth 10 | Set-Content -Path $BehaveFile
                    Write-Host "Downloaded (New)" -ForegroundColor Green
                    $FixedDownload++
                    $DownloadSuccess = $true
                }
                Start-Sleep -Milliseconds 250
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                if ($code -eq 429) {
                    Write-Host "QUOTA HIT (Waiting 60s)..." -ForegroundColor Red
                    Start-Sleep -Seconds 60
                }
            }

            # --- STRATEGY B: LOCAL CONVERSION (Fallback) ---
            if (-not $DownloadSuccess) {
                if ($LocalContent -and ($LocalContent.data -is [Array])) {
                    Write-Host "VT Empty -> Converting Local Data... " -NoNewline -ForegroundColor Yellow
                    
                    $Summary = @{ data = @{ id = $Hash; type = "file_behaviour_summary"; attributes = @{
                        mitre_attack_techniques = @(); mutexes_created = @(); 
                        registry_keys_set = @(); registry_keys_opened = @(); processes_created = @()
                    }}}
                    
                    $UniqueMitre = [System.Collections.Generic.HashSet[string]]::new()
                    $UniqueMutex = [System.Collections.Generic.HashSet[string]]::new()
                    $UniqueReg   = [System.Collections.Generic.HashSet[string]]::new()
                    $UniqueProc  = [System.Collections.Generic.HashSet[string]]::new()

                    foreach ($run in $LocalContent.data) {
                        $attr = $run.attributes
                        if ($attr.mitre_attack_techniques) { foreach ($m in $attr.mitre_attack_techniques) { [void]$UniqueMitre.Add(($m | ConvertTo-Json -Compress)) } }
                        if ($attr.mutexes_created) { foreach ($m in $attr.mutexes_created) { [void]$UniqueMutex.Add("$m") } }
                        if ($attr.processes_created) { foreach ($p in $attr.processes_created) { [void]$UniqueProc.Add("$p") } }
                        
                        # --- SAFE REGISTRY BLOCK ---
                        try {
                            $RegList = @()
                            if ($attr.registry_keys_set) { $RegList += $attr.registry_keys_set }
                            if ($attr.registry_keys_opened) { $RegList += $attr.registry_keys_opened }
                            
                            foreach ($r in $RegList) {
                                try {
                                    $val = $null
                                    # SYNTAX FIX: Handle Object vs String correctly
                                    if ($r -is [PSCustomObject] -or $r -is [System.Collections.Hashtable]) {
                                        if ($r.key) { 
                                            $val = $r.key 
                                            if ($r.value) { $val += " = " + $r.value }
                                        } else { 
                                            $val = $r | ConvertTo-Json -Depth 1 -Compress 
                                        }
                                    } else {
                                        $val = "$r"
                                    }

                                    if ($val) { [void]$UniqueReg.Add([string]$val) }
                                } catch {}
                            }
                        } catch {}
                    }

                    $Summary.data.attributes.mitre_attack_techniques = $UniqueMitre | ForEach-Object { $_ | ConvertFrom-Json }
                    $Summary.data.attributes.mutexes_created = [string[]]$UniqueMutex
                    $Summary.data.attributes.registry_keys_set = [string[]]$UniqueReg
                    $Summary.data.attributes.processes_created = [string[]]$UniqueProc

                    $Summary | ConvertTo-Json -Depth 10 | Set-Content -Path $BehaveFile
                    Write-Host "Success" -ForegroundColor Green
                    $FixedConvert++
                } 
                else {
                    Write-Host "No Data Anywhere" -ForegroundColor DarkGray
                    @{"data"=@{"attributes"=@{}}} | ConvertTo-Json | Set-Content -Path $BehaveFile
                }
            }
        } else {
            if ($Current % 50 -eq 0) { Write-Host "." -NoNewline }
            $Skipped++
        }
    }

    Write-Host "`n--------------------------------"
    Write-Host "Repair Complete." -ForegroundColor Cyan
    Write-Host "Downloaded New:  $FixedDownload" -ForegroundColor Green
    Write-Host "Converted Local: $FixedConvert" -ForegroundColor Yellow
    Write-Host "Unchanged/Empty: $Skipped" -ForegroundColor Gray
}