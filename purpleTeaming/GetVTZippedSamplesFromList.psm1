function Get-VTSamplesFromList {
<#
SYNOPSIS
  VirusTotal Downloader v13.3 (Flexible Input Edition).
  - INPUT RESTORED: Accepts Files (CSV/TXT), Comma-Separated Strings, or Interactive Input.
  - SMART CSV: Auto-detects 'IOC', 'IOCValue', 'Hash', etc.
  - INSPECTS downloads to filter out API Garbage (HTML/JSON).
  - Generates 'file_map.csv' for the Detonator.
#>

param(
  [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
  [object]$Targets,  # Can be a Path, a String "h1,h2", or an Array @("h1","h2")

  [string]$OutDir = ".\VT_Samples",

  [int]$Threads = 5
)

# ---------- 1. FLEXIBLE INPUT HANDLER (Restored Logic) ----------
$hashes = @()

# A. Interactive Mode (No params provided)
if ([string]::IsNullOrWhiteSpace($Targets)) {
    $InputStr = Read-Host "[?] Enter Targets (File Path OR Comma-Separated Hashes)"
    if ([string]::IsNullOrWhiteSpace($InputStr)) { Write-Error "No targets provided."; return }
    $Targets = $InputStr
}

# B. File or Raw String?
$IsFile = $false
try {
    if ($Targets -is [string] -and (Test-Path $Targets -ErrorAction SilentlyContinue)) { 
        $IsFile = $true 
    }
} catch {}

if ($IsFile) {
    # --- FILE MODE ---
    $FilePath = (Resolve-Path $Targets).Path
    Write-Host "Reading input from file: $FilePath" -ForegroundColor Cyan
    $ext = [IO.Path]::GetExtension($FilePath).ToLowerInvariant()

    if ($ext -eq ".csv") {
        $CsvData = Import-Csv $FilePath
        if ($CsvData.Count -gt 0) {
            # Smart Column Detection
            $Props = $CsvData[0].PSObject.Properties.Name
            $Col = ($Props | Where-Object { $_ -match '^(IOC|IOCValue|Hash|SHA256|FileHash)$' } | Select-Object -First 1)
            
            if ($Col) {
                Write-Host " -> Detected hash column: '$Col'" -ForegroundColor DarkGray
                $hashes = $CsvData | ForEach-Object { $_.$Col.Trim() }
            } else {
                Write-Error "CSV must contain a column named 'IOC', 'IOCValue', 'Hash', or 'SHA256'."
                return
            }
        }
    } else {
        # TXT Mode
        $hashes = Get-Content $FilePath | ForEach-Object { $_.Trim() }
    }
} else {
    # --- DIRECT LIST MODE (The "Comma Logic") ---
    Write-Host "Reading input from provided list/string..." -ForegroundColor Cyan
    if ($Targets -is [array]) {
        $hashes = $Targets
    } elseif ($Targets -is [string]) {
        $hashes = $Targets -split ","
    }
}

# C. Normalize & Validate
$hashes = $hashes | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -Unique

if ($hashes.Count -eq 0) { Write-Error "No valid SHA256 hashes found in input."; return }

# ---------- 2. SETUP & KEYS ----------
if ($env:VT_API_KEY) { $VTApiKey = $env:VT_API_KEY } 
else { 
    try { $VTApiKey = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText).Trim() } catch { }
}
if (-not $VTApiKey) { $VTApiKey = Read-Host "Enter your VirusTotal API key (visible input)" }

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
$ReviewDir = Join-Path $OutDir "_Review"
New-Item -ItemType Directory -Force -Path $ReviewDir | Out-Null

Write-Host "Target: $OutDir" -ForegroundColor Cyan
Write-Host "Loaded $($hashes.Count) valid hashes. Starting Smart Download..." -ForegroundColor Yellow

# ---------- 3. WORKER LOGIC (Same Robust Engine) ----------
$WorkerScript = {
    param($HashList, $ApiKey, $DestinationDir, $ReviewDir)

    Add-Type -AssemblyName System.Net.Http
    $Client = New-Object System.Net.Http.HttpClient
    $Client.DefaultRequestHeaders.Add("x-apikey", $ApiKey)
    $Client.Timeout = [TimeSpan]::FromMinutes(2)

    $Results = @()

    foreach ($Hash in $HashList) {
        $Url = "https://www.virustotal.com/api/v3/files/$Hash/download"
        $FilePath = Join-Path $DestinationDir $Hash
        $Status = "Failed"
        $FinalType = "Unknown"

        try {
            $Response = $Client.GetAsync($Url).Result
            
            if ($Response.IsSuccessStatusCode) {
                # Save
                $FileStream = [System.IO.File]::Create($FilePath)
                $HttpStream = $Response.Content.ReadAsStreamAsync().Result
                $HttpStream.CopyTo($FileStream)
                $FileStream.Close()
                $HttpStream.Close()
                
                # Inspect Content
                $ContentHeader = Get-Content $FilePath -TotalCount 10 -ErrorAction SilentlyContinue
                $HeaderString = $ContentHeader -join "`n"
                
                # Garbage Filter (API Errors)
                if ($HeaderString -match '"error":\s*\{' -or 
                    $HeaderString -match '<title>Error 404' -or 
                    $HeaderString -match 'QuotaExceeded' -or 
                    $HeaderString -match 'NotFoundError' -or 
                    $HeaderString -match 'AccessDenied') {
                    
                    $MovePath = Join-Path $ReviewDir "$Hash.txt"
                    Move-Item -Path $FilePath -Destination $MovePath -Force
                    $Status = "Quarantined (API Error)"
                } 
                else {
                    $Status = "OK"
                    # Sniff Type
                    $Bytes = Get-Content $FilePath -Encoding Byte -TotalCount 4 -ErrorAction SilentlyContinue
                    $Hex = ($Bytes | ForEach-Object { $_.ToString("X2") }) -join " "
                    
                    if ($Hex -match "^4D 5A") { $FinalType = "exe" }
                    elseif ($Hex -match "^7F 45 4C 46") { $FinalType = "elf" }
                    elseif ($Hex -match "^50 4B") { $FinalType = "zip" }
                    elseif ($Hex -match "^25 50 44 46") { $FinalType = "pdf" }
                    elseif ($Hex -match "^3C 21" -or $HeaderString -match "<html|<head|<body") { $FinalType = "html" }
                    else { 
                        if ($HeaderString -match "function|var|dim|echo|powershell|wscript|cscript") { $FinalType = "js" } 
                        else { $FinalType = "bin" }
                    }
                }
            } 
            elseif ($Response.StatusCode -eq 404) { $Status = "Missing" }
            else { $Status = "Error: " + $Response.StatusCode }
        } catch {
            $Status = "NetError"
        }
        $Results += [PSCustomObject]@{ Hash=$Hash; Status=$Status; DetectedType=$FinalType }
        Start-Sleep -Milliseconds 200
    }
    $Client.Dispose()
    return $Results
}

# ---------- 4. EXECUTION ----------
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$RunspacePool.Open()
$Jobs = @()
$ChunkSize = [Math]::Ceiling($hashes.Count / $Threads)
$CurrentIndex = 0

for ($i = 0; $i -lt $Threads; $i++) {
    if ($CurrentIndex -ge $hashes.Count) { break }
    $Subset = $hashes | Select-Object -Skip $CurrentIndex -First $ChunkSize
    $CurrentIndex += $ChunkSize
    
    if ($Subset) {
        $PsCmd = [PowerShell]::Create().AddScript($WorkerScript)
        $PsCmd.AddArgument($Subset)
        $PsCmd.AddArgument($VTApiKey)
        $PsCmd.AddArgument($OutDir)
        $PsCmd.AddArgument($ReviewDir)
        $PsCmd.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{ Pipe = $PsCmd; Handle = $PsCmd.BeginInvoke(); Id = $i }
    }
}

while (($Jobs | Where-Object { $_.Handle.IsCompleted -eq $false }).Count -gt 0) { Start-Sleep -Seconds 1 }

$FinalResults = @()
foreach ($Job in $Jobs) {
    try { $FinalResults += $Job.Pipe.EndInvoke($Job.Handle) } catch { }
    $Job.Pipe.Dispose()
}
$RunspacePool.Dispose()

# ---------- 5. REPORTING ----------
$TotalOK = ($FinalResults | Where-Object { $_.Status -eq "OK" }).Count
Write-Host "`n[Download Summary]" -ForegroundColor Cyan
Write-Host "  Valid Samples: $TotalOK" -ForegroundColor Green
Write-Host "  Quarantined:   $(($FinalResults | Where-Object { $_.Status -match "Quarantined" }).Count)" -ForegroundColor Yellow

$fileMap = $FinalResults | Where-Object { $_.Status -eq "OK" } | Select-Object Hash, @{N='Extension';E={$_.DetectedType}}, @{N='TypeDescription';E={"Verified Content"}}
$mapPath = Join-Path $OutDir "file_map.csv"
$fileMap | Export-Csv -Path $mapPath -NoTypeInformation -Encoding UTF8

Write-Host "File Map generated: $mapPath" -ForegroundColor Gray
}