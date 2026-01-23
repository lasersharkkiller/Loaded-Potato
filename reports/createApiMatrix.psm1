function New-ApiMatrixDashboard {
    param (
        [string]$RootPath = ".\apt\c6g",
        [string]$OutputHtmlPath = ".\output\API_Capabilities_Matrix.html",
        [string]$GlobalResolutionPath = "output\Global_Hash_Resolution.csv",
        [string]$ReportTitle = "Malware API Capabilities Matrix"
    )

    Write-Host "Generating API Matrix (v9.1 - Explicit Scope Hardening)..." -ForegroundColor Cyan

    if (-not (Test-Path $RootPath)) { Write-Error "Root path not found."; return }
    $AbsRoot = (Resolve-Path $RootPath).Path

    # --- 1. THE "JOIN TABLE" (Defined Locally) ---
    $AptToolMap = @{
        "UAT-8837"      = @("GoTokenTheft", "EarthWorm", "DWAgent", "SharpHound", "Impacket", "GoExec", "Rubeus", "Certipy")
        "Salt Typhoon"  = @("GhostSpider", "Demodex", "ShadowPad")
        "Storm-2603"    = @("AK47 C2", "ToolShell", "Impacket")
        "Earth Krahang" = @("RESHELL", "XDealer", "Cobalt Strike")
        "UAT-7290"      = @("RushDrop", "SilentRaid", "ShadowPad")
        "UNC3886"       = @("TinyShell", "Reptile", "Medusa")
        "Volt Typhoon"  = @("KV-Botnet", "Impacket", "EarthWorm")
        "APT1"          = @("PoisonIvy", "PlugX")
        "APT10"         = @("PlugX", "QuasarRAT")
        "APT27"         = @("PlugX", "HyperBro")
        "APT31"         = @("SOGU", "LuckyBird")
        "APT41"         = @("ShadowPad", "Cobalt Strike", "Winnti")
        "Aquatic Panda" = @("ShadowPad", "Winnti")
        "BlackTech"     = @("Kivars", "Pled")
        "Gallium"       = @("PingPull", "Gh0st RAT")
        "Hafnium"       = @("China Chopper", "Tarrask")
        "Ke3chang"      = @("Okrum", "Ketrican")
        "Mustang Panda" = @("PlugX", "Cobalt Strike")
        "APT28"         = @("Mimikatz", "Impacket")
        "APT29"         = @("Cobalt Strike", "Mimikatz")
        "Sandworm"      = @("BlackEnergy", "Industroyer")
        "Wizard Spider" = @("TrickBot", "Ryuk", "Cobalt Strike")
        "Scattered Spider" = @("BlackCat", "Rubeus", "Mimikatz")
    }

    # --- 2. LOAD GLOBAL HASH MAP ---
    $DateMap = @{}
    if (Test-Path $GlobalResolutionPath) {
        Write-Host "  Loading Global Hash Map..." -NoNewline
        Import-Csv $GlobalResolutionPath | ForEach-Object {
            $d = $_.Date_Found
            if ($d -and $d -ne "1970-01-01") {
                if ($_.Canonical_SHA256) { $DateMap[$_.Canonical_SHA256] = $d }
                if ($_.MD5) { $DateMap[$_.MD5] = $d }
                if ($_.SHA1) { $DateMap[$_.SHA1] = $d }
            }
        }
        Write-Host " Done ($($DateMap.Count) hashes)." -ForegroundColor Green
    }

    # --- 3. CATEGORY DEFINITIONS ---
    $ApiMatrix = [ordered]@{
        "Kernel & Driver Ops" = @("Ke", "Io", "Ob", "Zw", "Ps", "Hal", "ExAllocate", "ExFree", "Rtl", "Mm", "FsRtl", "Cc")
        "Self Defense & Evasion" = @("GetTickCount", "QueryPerformance", "GetLocalTime", "GetSystemTime", "GlobalMemoryStatus", "IsDebuggerPresent", "CheckRemoteDebugger", "OutputDebugString", "NtDelayExecution", "Sleep", "BlockInput", "GetForegroundWindow", "GetCursorPos", "SetUnhandledExceptionFilter", "RaiseException", "RtlAdjustPrivilege", "NtSetInformationThread", "timeGetTime")
        "Code Injection & Execution" = @("CreateRemoteThread", "NtCreateThread", "ZwCreateThread", "QueueUserAPC", "WriteProcessMemory", "VirtualAlloc", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "SetWindowsHook", "UnhookWindowsHook", "SetThreadContext", "ResumeThread", "NtQueueApcThread", "RtlCreateUserThread", "OpenProcess", "ShellExecute", "WinExec", "CreateProcess", "NtCreateUserProcess", "Wow64")
        "Credential Access & Recon" = @("Sam", "Lsa", "NetUser", "NetLocalGroup", "NetShare", "NetSession", "NetWksta", "DsGet", "Secur32", "LogonUser", "CredRead", "WNet", "WTS", "Enumerate", "GetUserName", "GetComputerName", "LookupAccount", "GetAdapters", "GetNetworkParams", "WhoAmI", "GetEnvironmentVariable", "DnsQuery", "Icmp", "GetIpAddr")
        "File Operations" = @("CreateFile", "WriteFile", "ReadFile", "CopyFile", "DeleteFile", "MoveFile", "FindFirst", "FindNext", "NtCreateSection", "NtMapViewOfSection", "SHFileOperation", "fopen", "fwrite", "fget", "fput", "mbstowcs", "wcstombs", "GetTemp", "GetModuleFileName", "SetFilePointer", "FlushFileBuffers", "DeviceIoControl")
        "Registry & Persistence" = @("RegOpen", "RegCreate", "RegSet", "RegDelete", "RegQuery", "NtOpenKey", "NtSetValueKey", "SHReg", "StartService", "CreateService", "OpenSCManager", "ControlService")
        "Network C2" = @("Internet", "Http", "Ftp", "Socket", "Connect", "Send", "Recv", "WSA", "GetHost", "WinHttp", "URLDownload", "InternetOpen", "InternetConnect")
        "Cryptography & Encoding" = @("Crypt", "MD5", "SHA", "AES", "RC4", "Des", "Hash", "Bcrypt", "RtlCompress", "RtlDecompress", "SystemFunction", "Encoding", "Base64")
        "C++ & Frameworks" = @("?", "Qt", "Q", "mfc", "atl", "vba")
        "String & Memory Ops" = @("str", "wcs", "mem", "alloc", "free", "cpy", "cmp", "len", "cat", "print", "itoa", "atoi", "ZeroMemory", "RtlMoveMemory", "RtlZeroMemory", "LocalAlloc", "GlobalAlloc")
        "Import by Ordinal" = @("Ord(")
        "Internal & CRT" = @("_", "__", "crt", "dll")
        "UI & GDI" = @("Gdi", "Draw", "Window", "Menu", "Dialog", "Msg", "SendInput", "PostMessage", "LoadIcon", "LoadBitmap", "BitBlt", "GetDC", "ReleaseDC")
    }

    # --- 4. INIT STORAGE (Main Scope) ---
    $AggregatedMetadata = @{}
    $Hierarchy = @{}
    $ApiEventsList = [System.Collections.Generic.List[PSObject]]::new()

    # --- 5. DATA PROCESSING FUNCTION (With Explicit Map Passing) ---
    function Process-TargetFolder {
        param (
            $TargetFolder, 
            $CountryLabel, 
            $GroupLabel,
            $IsAPT,
            $ListRef, 
            $HierRef, 
            $MetaRef, 
            $MatrixRef,
            $MapRef,        # <--- We pass the Tool Map IN here
            $RootRef        # <--- We pass the Root Path IN here
        )

        # Update Hierarchy
        if (-not $HierRef.ContainsKey($CountryLabel)) { 
            $HierRef[$CountryLabel] = [System.Collections.Generic.HashSet[string]]::new() 
        }
        [void]$HierRef[$CountryLabel].Add($GroupLabel)

        # 1. IDENTIFY FOLDERS TO SCAN (Data Fusion)
        $FoldersToScan = @(@{ Path=$TargetFolder; Label="Direct" })

        # Use the passed Map Reference ($MapRef) instead of script scope
        if ($IsAPT -and $MapRef.ContainsKey($GroupLabel)) {
            $MalwareRoot = Join-Path $RootRef "Malware Families"
            foreach ($ToolName in $MapRef[$GroupLabel]) {
                $ToolPath = Join-Path $MalwareRoot $ToolName
                if (Test-Path $ToolPath) {
                    $FoldersToScan += @{ Path=$ToolPath; Label="Tool: $ToolName" }
                }
            }
        }

        # 2. SCAN ALL FOLDERS
        foreach ($Source in $FoldersToScan) {
            $Path = $Source.Path
            $SourceLabel = $Source.Label

            # Determine Date
            $FolderContextDate = (Get-Item $Path).CreationTime.ToString("yyyy-MM-dd")
            $IntelFile = Get-ChildItem -Path $Path -Filter "*Master_Intel*.csv" | Select-Object -First 1
            if ($IntelFile) {
                try {
                    $csv = Import-Csv $IntelFile.FullName
                    $dateCol = $csv[0].PSObject.Properties.Name | Where-Object { $_ -match "Date" } | Select-Object -First 1
                    if ($dateCol) {
                        $earliest = $csv | Where-Object { $_.$dateCol -as [DateTime] } | Sort-Object { [DateTime]$_.$dateCol } | Select-Object -First 1
                        if ($earliest) { $FolderContextDate = $earliest.$dateCol }
                    }
                } catch {}
            }

            # Find JSON Files
            $TargetFile = Join-Path $Path "TargetedAPIDifferentialAnalysis.json"
            $FilesToProcess = @()
            if (Test-Path $TargetFile) { $FilesToProcess += (Get-Item $TargetFile) }
            else { $FilesToProcess += Get-ChildItem -Path $Path -Filter "*TargetedAPIDifferentialAnalysis.json" }

            foreach ($jFile in $FilesToProcess) {
                if ($jFile.Length -lt 5) { continue }

                try {
                    $content = Get-Content $jFile.FullName -Raw | ConvertFrom-Json
                    $items = @($content)
                    
                    if ($items.Count -gt 0) {
                        if ($SourceLabel -eq "Direct") {
                            Write-Host "    + Found $($items.Count) API calls (Direct)" -ForegroundColor Gray
                        } else {
                            Write-Host "    + Merged $($items.Count) API calls from $($SourceLabel)" -ForegroundColor DarkGray
                        }
                        
                        foreach ($row in $items) {
                            $rawName = $row.Item_Name
                            if (-not $rawName) { continue }
                            
                            $cleanName = if ($rawName -match '!(.*)') { $matches[1] } else { $rawName }
                            
                            # Metadata Check
                            if (-not $MetaRef.ContainsKey($cleanName)) {
                                $foundCat = "Other"
                                foreach ($cat in $MatrixRef.Keys) {
                                    foreach ($keyword in $MatrixRef[$cat]) {
                                        $safeKeyword = [Regex]::Escape($keyword)
                                        if ($cleanName -match "(?i)$safeKeyword") { $foundCat = $cat; break }
                                    }
                                    if ($foundCat -ne "Other") { break }
                                }
                                $MetaRef[$cleanName] = @{ Cat = $foundCat; Rar = if($row.Baseline_Rarity_Score){$row.Baseline_Rarity_Score}else{0} }
                            }

                            # Add Event
                            $count = if ($row.Malicious_Count) { $row.Malicious_Count } else { 1 }
                            $limit = if ($count -gt 20) { 20 } else { $count } 
                            
                            for ($i=0; $i -lt $limit; $i++) {
                                $ListRef.Add([PSCustomObject]@{ 
                                    Api  = $cleanName
                                    Date = $FolderContextDate
                                    C    = $CountryLabel
                                    A    = $GroupLabel
                                    Src  = $SourceLabel
                                })
                            }
                        }
                    }
                } catch {
                    Write-Warning "    ! Error in $($jFile.Name): $($_.Exception.Message)"
                }
            }
        }
    }

    # --- 6. TRAVERSE STRUCTURE ---
    
    # Process APTs (With Fusion)
    $AptRoot = Join-Path $AbsRoot "APTs"
    if (Test-Path $AptRoot) {
        Write-Host "  Processing APT Structure..." -ForegroundColor Gray
        $Countries = Get-ChildItem -Path $AptRoot -Directory
        foreach ($cntry in $Countries) {
            $Groups = Get-ChildItem -Path $cntry.FullName -Directory
            foreach ($grp in $Groups) {
                # Passing ALL References
                Process-TargetFolder -TargetFolder $grp.FullName -CountryLabel $cntry.Name -GroupLabel $grp.Name -IsAPT $true -ListRef $ApiEventsList -HierRef $Hierarchy -MetaRef $AggregatedMetadata -MatrixRef $ApiMatrix -MapRef $AptToolMap -RootRef $AbsRoot
            }
        }
    }

    # Process Malware (No Fusion)
    $MalRoot = Join-Path $AbsRoot "Malware Families"
    if (Test-Path $MalRoot) {
        Write-Host "  Processing Malware Families..." -ForegroundColor Gray
        $Families = Get-ChildItem -Path $MalRoot -Directory
        foreach ($fam in $Families) {
            # Passing ALL References
            Process-TargetFolder -TargetFolder $fam.FullName -CountryLabel "Malware Family" -GroupLabel $fam.Name -IsAPT $false -ListRef $ApiEventsList -HierRef $Hierarchy -MetaRef $AggregatedMetadata -MatrixRef $ApiMatrix -MapRef $AptToolMap -RootRef $AbsRoot
        }
    }

    $EventCount = $ApiEventsList.Count
    Write-Host "  Processed $EventCount total events." -ForegroundColor Green

    # --- 7. GENERATE OUTPUT ---
    $OutputDir = Split-Path $OutputHtmlPath -Parent
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    
    $FinalArray = $ApiEventsList.ToArray()

    $JsonEvents = $FinalArray | ConvertTo-Json -Depth 100 -Compress
    $BytesEvents = [System.Text.Encoding]::UTF8.GetBytes($JsonEvents)
    $B64Events = [Convert]::ToBase64String($BytesEvents)
    
    $JsonMeta = $AggregatedMetadata | ConvertTo-Json -Depth 100 -Compress
    $BytesMeta = [System.Text.Encoding]::UTF8.GetBytes($JsonMeta)
    $B64Meta = [Convert]::ToBase64String($BytesMeta)
    
    $HierObj = @{}; foreach ($k in $Hierarchy.Keys) { $HierObj[$k] = ($Hierarchy[$k] | Sort-Object) }
    $JsonHier = $HierObj | ConvertTo-Json -Depth 100
    
    $CatListJS = ($ApiMatrix.Keys | ForEach-Object { "'$_'" }) -join ","; $CatListJS = "$CatListJS,'Other'" 

    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$ReportTitle</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f0f2f5; font-family: 'Segoe UI', system-ui, sans-serif; display: flex; }
        .sidebar { width: 260px; height: 100vh; background: #111827; color: #e2e8f0; position: fixed; top: 0; left: 0; overflow-y: auto; z-index: 1000; }
        .sidebar-brand { padding: 20px; font-size: 1.2rem; font-weight: bold; border-bottom: 1px solid #374151; color: white; cursor: pointer; }
        .nav-link { color: #9ca3af; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; text-decoration: none; border-left: 4px solid transparent; cursor: pointer; font-size: 0.9rem; }
        .nav-link:hover { background: #1f2937; color: white; }
        .nav-link.active { background: #1f2937; color: #60a5fa; border-left-color: #60a5fa; }
        .main-content { margin-left: 260px; width: calc(100% - 260px); min-height: 100vh; display: flex; flex-direction: column; }
        .topbar { background: white; padding: 15px 30px; border-bottom: 1px solid #e5e7eb; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 900; }
        .form-select { width: auto; min-width: 150px; font-size: 0.9rem; }
        .view-pane { padding: 30px; display: none; }
        .view-pane.active { display: block; }
        .matrix-grid { display: flex; overflow-x: auto; gap: 15px; padding-bottom: 20px; }
        .tactic-column { min-width: 260px; max-width: 260px; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; display: flex; flex-direction: column; max-height: 80vh; }
        .tactic-header { background: #0f172a; color: white; padding: 10px; text-align: center; font-weight: bold; border-radius: 6px 6px 0 0; font-size: 0.9rem; }
        .tactic-body { overflow-y: auto; flex-grow: 1; }
        .matrix-cell { padding: 6px 10px; border-bottom: 1px solid #f3f4f6; font-size: 0.8rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .matrix-cell:hover { background: #eff6ff; }
        .cell-red { border-left: 3px solid #ef4444; } 
        .table-sm td { font-size: 0.85rem; vertical-align: middle; }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="sidebar-brand" onclick="switchView('MATRIX')">API Call Matrix</div>
        <div class="p-3 text-uppercase text-muted" style="font-size: 0.75rem; font-weight: bold;">Categories</div>
        <div id="nav-container"></div>
    </div>

    <div class="main-content">
        <div class="topbar">
            <h5 class="m-0 fw-bold text-dark" id="page-title">Global Overview (Matrix)</h5>
            <div class="d-flex gap-2">
                <select id="filter-time" class="form-select" onchange="renderCurrentView()">
                    <option value="ALL" selected>All Time</option>
                    <option value="7">Past Week</option>
                    <option value="30">Past Month</option>
                    <option value="365">Past Year</option>
                </select>
                <select id="filter-country" class="form-select" onchange="countryChanged()"><option value="ALL">All Countries</option></select>
                <select id="filter-apt" class="form-select" onchange="renderCurrentView()"><option value="ALL">All Groups</option></select>
            </div>
        </div>

        <div id="view-MATRIX" class="view-pane active">
            <div class="alert alert-info py-2 small">
                <strong>Showing Top 20 Unique to Malware APIs per category.</strong>
            </div>
            <div class="matrix-grid" id="matrix-container"></div>
        </div>

        <div id="view-LIST" class="view-pane">
            <div class="row">
                <div class="col-lg-4 mb-4"><div class="card h-100 border-danger"><div class="card-header bg-danger text-white fw-bold">Unique to Malware</div><div class="card-body p-0 overflow-auto" style="max-height: 75vh;"><table class="table table-hover table-sm mb-0" id="table-red"><tbody></tbody></table></div></div></div>
                <div class="col-lg-4 mb-4"><div class="card h-100 border-warning"><div class="card-header bg-warning text-dark fw-bold">Rare (> 95%)</div><div class="card-body p-0 overflow-auto" style="max-height: 75vh;"><table class="table table-hover table-sm mb-0" id="table-yellow"><tbody></tbody></table></div></div></div>
                <div class="col-lg-4 mb-4"><div class="card h-100 border-success"><div class="card-header bg-success text-white fw-bold">Common</div><div class="card-body p-0 overflow-auto" style="max-height: 75vh;"><table class="table table-hover table-sm mb-0" id="table-green"><tbody></tbody></table></div></div></div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="drillModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="modalTitle"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body"><table class="table table-striped"><thead><tr><th>Date</th><th>Country</th><th>APT</th><th>Source</th><th>Count</th></tr></thead><tbody id="modalBody"></tbody></table></div>
            </div>
        </div>
    </div>

    <textarea id="store_events" style="display:none;">$B64Events</textarea>
    <textarea id="store_meta" style="display:none;">$B64Meta</textarea>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        const hierarchy = $JsonHier;
        const categories = [$CatListJS];
        
        let apiEvents = [];
        let apiMeta   = {};
        let currentView = 'MATRIX';
        let currentCategory = '';

        function safeDecode(id) {
            try {
                const b64 = document.getElementById(id).value;
                if(!b64) return [];
                const bin = window.atob(b64);
                const bytes = new Uint8Array(bin.length);
                for(let i=0; i<bin.length; i++) bytes[i] = bin.charCodeAt(i);
                const dec = new TextDecoder('utf-8');
                return JSON.parse(dec.decode(bytes));
            } catch(e) { console.error("Decode Error " + id, e); return []; }
        }

        window.onload = function() {
            apiEvents = safeDecode('store_events');
            apiMeta   = safeDecode('store_meta');

            const nav = document.getElementById('nav-container');
            categories.forEach(cat => {
                const div = document.createElement('div');
                div.className = 'nav-link';
                div.innerHTML = '<span>' + cat + '</span>'; 
                div.onclick = () => switchView('LIST', cat);
                nav.appendChild(div);
            });

            const cSel = document.getElementById('filter-country');
            if (hierarchy && Object.keys(hierarchy).length > 0) {
                Object.keys(hierarchy).sort().forEach(c => cSel.add(new Option(c, c)));
            }
            renderCurrentView();
        };

        function countryChanged() {
            const cSel = document.getElementById('filter-country');
            const aSel = document.getElementById('filter-apt');
            const selC = cSel.value;
            
            aSel.innerHTML = '<option value="ALL">All Groups</option>';
            if(selC !== 'ALL' && hierarchy[selC]) {
                hierarchy[selC].sort().forEach(a => aSel.add(new Option(a, a)));
            } else if (hierarchy) {
                 const set = new Set();
                 Object.values(hierarchy).forEach(arr => arr.forEach(x => set.add(x)));
                 Array.from(set).sort().forEach(a => aSel.add(new Option(a, a)));
            }
            renderCurrentView();
        }

        function switchView(mode, category = '') {
            currentView = mode;
            currentCategory = category;
            
            document.querySelectorAll('.view-pane').forEach(el => el.classList.remove('active'));
            document.getElementById('view-' + mode).classList.add('active');
            
            document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
            if(mode === 'LIST') {
                Array.from(document.querySelectorAll('.nav-link')).find(el => el.innerText.includes(category)).classList.add('active');
                document.getElementById('page-title').innerText = category;
            } else {
                document.getElementById('page-title').innerText = "Global Overview (Matrix)";
            }
            renderCurrentView();
        }

        function checkDate(dateStr, days) {
            if (!dateStr || dateStr === '1970-01-01') return (days === 'ALL'); 
            if (days === 'ALL') return true;
            
            const target = new Date();
            target.setDate(target.getDate() - parseInt(days));
            const itemDate = new Date(dateStr);
            return itemDate >= target;
        }

        function getFilteredData() {
            const selC = document.getElementById('filter-country').value;
            const selA = document.getElementById('filter-apt').value;
            const selT = document.getElementById('filter-time').value;

            const filteredEvents = apiEvents.filter(e => {
                if (selC !== 'ALL' && e.C !== selC) return false;
                if (selA !== 'ALL' && e.A !== selA) return false;
                if (!checkDate(e.Date, selT)) return false;
                return true;
            });

            const agg = {};
            filteredEvents.forEach(e => {
                if (!agg[e.Api]) {
                    const meta = apiMeta[e.Api] || { Cat: 'Other', Rar: 0 };
                    agg[e.Api] = { Api: e.Api, Category: meta.Cat, Rarity: meta.Rar, Count: 0, Hits: [] };
                }
                agg[e.Api].Count++;
                agg[e.Api].Hits.push(e);
            });
            return Object.values(agg);
        }

        function renderCurrentView() {
            if(currentView === 'MATRIX') renderMatrix(); else renderList();
        }

        function renderMatrix() {
            const data = getFilteredData();
            const container = document.getElementById('matrix-container');
            container.innerHTML = '';

            categories.forEach(cat => {
                const col = document.createElement('div');
                col.className = 'tactic-column';
                col.innerHTML = '<div class="tactic-header">' + cat + '</div>';
                
                const body = document.createElement('div');
                body.className = 'tactic-body';

                const relevant = data.filter(item => item.Category === cat && item.Rarity >= 100);
                relevant.sort((a, b) => b.Count - a.Count);
                const top20 = relevant.slice(0, 20);

                top20.forEach(api => {
                    const row = document.createElement('div');
                    row.className = 'matrix-cell cell-red';
                    row.innerHTML = '<span class="text-truncate" style="max-width:180px" title="'+api.Api+'">' + api.Api + '</span> <strong>' + api.Count + '</strong>';
                    row.onclick = () => showDrill(api);
                    body.appendChild(row);
                });
                col.appendChild(body);
                container.appendChild(col);
            });
        }

        function renderList() {
            const data = getFilteredData();
            const tRed = document.getElementById('table-red').querySelector('tbody');
            const tYel = document.getElementById('table-yellow').querySelector('tbody');
            const tGrn = document.getElementById('table-green').querySelector('tbody');
            [tRed, tYel, tGrn].forEach(t => t.innerHTML = '');

            const catItems = data.filter(item => item.Category === currentCategory);
            catItems.sort((a, b) => b.Count - a.Count);

            catItems.forEach(api => {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + api.Api + '</td><td class="text-end fw-bold">' + api.Count + '</td>';
                tr.style.cursor = 'pointer';
                tr.onclick = () => showDrill(api);
                if (api.Rarity >= 100) tRed.appendChild(tr); else if (api.Rarity >= 95) tYel.appendChild(tr); else tGrn.appendChild(tr);
            });
        }

        function showDrill(api) {
            document.getElementById('modalTitle').innerText = api.Api;
            const body = document.getElementById('modalBody');
            body.innerHTML = '';
            
            // Group by Signature + Source
            const grouped = {};
            api.Hits.forEach(h => {
                const src = h.Src || "Direct";
                const key = h.C + '|' + h.A + '|' + h.Date + '|' + src;
                if(!grouped[key]) grouped[key] = { C: h.C, A: h.A, D: h.Date, S: src, N: 0 };
                grouped[key].N++;
            });

            const rows = Object.values(grouped).sort((a,b) => new Date(b.D) - new Date(a.D));

            rows.forEach(r => {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + r.D + '</td><td>' + r.C + '</td><td>' + r.A + '</td><td>' + r.S + '</td><td>' + r.N + '</td>';
                body.appendChild(tr);
            });
            new bootstrap.Modal(document.getElementById('drillModal')).show();
        }
    </script>
</body>
</html>
"@

    $HtmlContent | Set-Content -Path $OutputHtmlPath -Encoding UTF8
    Write-Host "Success! Dashboard saved to: $OutputHtmlPath" -ForegroundColor Green
}