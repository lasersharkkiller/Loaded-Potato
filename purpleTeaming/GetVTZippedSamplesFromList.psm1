function Get-VTSamplesFromList {
<#
SYNOPSIS
  Downloads samples individually from VirusTotal (bypassing the ZIP API requirement).
  Generates the necessary DLL Entry Point reports for the Detonation script.

REQUIREMENTS
  - VT API key with standard 'file download' permissions.
  - PowerShell 5.1+ or 7+.

OUTPUTS:
  - Folder containing samples (named by Hash).
  - <OutDir>\stats.json
  - <OutDir>\filetypes.csv
  - <OutDir>\dll_entrypoints.csv
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$InputPath,

  [string]$OutDir = ".\VT_Samples",

  [int]$DelaySeconds = 1  # Rate limiting buffer
)

# ---------- Helpers ----------
function Get-VTApiKey {
  try { return (Get-Secret -Name 'VT_API_Key_1' -AsPlainText) } catch { }
  if ($env:VT_API_KEY) { return $env:VT_API_KEY }
  return (Read-Host "Enter your VirusTotal API key (visible input)")
}

function Load-Hashes {
  param([string]$Path)
  if (-not (Test-Path $Path)) { throw "Input not found: $Path" }
  $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
  if ($ext -eq ".csv") {
    $csv = Import-Csv -Path $Path
    if ($csv.Count -eq 0) { throw "CSV is empty." }
    if (-not ($csv[0].PSObject.Properties.Name -contains "IOC")) {
      throw "CSV must contain a column named 'IOC'."
    }
    return $csv | ForEach-Object { $_.IOC.Trim() } | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -Unique
  } else {
    return Get-Content -Path $Path -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -Unique
  }
}

function VT-GET {
  param([string]$Uri, [hashtable]$Headers)
  return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
}

# ---------- Setup ----------
$VTApiKey = Get-VTApiKey
if (-not $VTApiKey) { Write-Error "No VT API key provided."; exit 1 }
$headers = @{ "x-apikey" = $VTApiKey }

$hashes = Load-Hashes -Path $InputPath
if ($hashes.Count -eq 0) { Write-Error "No valid SHA256 hashes found."; exit 1 }

# Prepare Output Directory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "Target Directory: $OutDir" -ForegroundColor Cyan
Write-Host "Loaded $($hashes.Count) unique hashes." -ForegroundColor Cyan

# ---------- 1) Pre-validate hashes ----------
$validHashes   = @()
$missingHashes = @()

Write-Host "Validating existence in VT..." -ForegroundColor Cyan

foreach ($h in $hashes) {
  try {
    $resp = Invoke-RestMethod -Method Get -Uri "https://www.virustotal.com/api/v3/files/$h" -Headers $headers -ErrorAction Stop
    if ($resp.data.id) { $validHashes += $h }
  } catch {
    $missingHashes += $h
    Write-Warning "  [!] Missing/Error: $h"
  }
  Start-Sleep -Milliseconds 200
}

if ($validHashes.Count -eq 0) { Write-Error "No valid hashes found in VT. Exiting."; exit 1 }
Write-Host "Validation Complete. Valid: $($validHashes.Count) | Missing: $($missingHashes.Count)" -ForegroundColor Green

# ---------- 2) Download Loop ----------
$okSha256s     = @()
$failedSha256s = @()

Write-Host "Starting Individual Downloads ($($validHashes.Count) files)..." -ForegroundColor Yellow

foreach ($hash in $validHashes) {
    $url = "https://www.virustotal.com/api/v3/files/$hash/download"
    $outFile = Join-Path $OutDir "$hash" # No extension, consistent with VT behavior
    
    try {
        Invoke-RestMethod -Uri $url -Headers $headers -Method Get -OutFile $outFile -ErrorAction Stop
        Write-Host "  [+] Downloaded: $hash" -ForegroundColor Green
        $okSha256s += $hash
    } catch {
        Write-Warning "  [!] Download Failed: $hash - $($_.Exception.Message)"
        $failedSha256s += $hash
    }
    
    # Respect Rate Limit (Individual downloads consume quota faster than ZIPs)
    if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }
}

# ---------- 3) Generate Reports (File Types & DLL Entry Points) ----------
Write-Host "`nGenerating Metadata Reports..." -ForegroundColor Cyan

$typeCounts = @{}            
$dllRows    = New-Object System.Collections.Generic.List[object]

function Bump-TypeCount {
  param([string]$desc)
  if ([string]::IsNullOrWhiteSpace($desc)) { $desc = "Unknown" }
  if ($typeCounts.ContainsKey($desc)) { $typeCounts[$desc]++ } else { $typeCounts[$desc] = 1 }
}

foreach ($sha in $okSha256s) {
  try {
    # We fetch metadata again to get the type and entry points
    $meta = VT-GET -Uri ("https://www.virustotal.com/api/v3/files/{0}" -f $sha) -Headers $headers
    $attr = $meta.data.attributes

    $typeDesc = $attr.type_description
    Bump-TypeCount -desc $typeDesc

    # Logic to identify DLLs for the detonation script
    $isDll = $false
    if ($typeDesc -match 'dll' -or $typeDesc -match 'DLL') { $isDll = $true }

    $entry = $null
    if ($attr.pe_info) {
      if ($attr.pe_info.entry_point)       { $entry = $attr.pe_info.entry_point }
      elseif ($attr.pe_info.entrypoint)    { $entry = $attr.pe_info.entrypoint }

      if (-not $isDll -and $attr.pe_info.characteristics) {
        try { if ([int]$attr.pe_info.characteristics -band 0x2000) { $isDll = $true } } catch { }
      }
    }

    if ($isDll) {
      $dllRows.Add([PSCustomObject]@{
        sha256          = $sha
        meaningful_name = $attr.meaningful_name
        entry_point     = $entry
      })
    }
  } catch {
    Write-Warning "Metadata fetch failed for $sha"
  }
  Start-Sleep -Milliseconds 200
}

# ---------- 4) Save Reports ----------
$timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Stats JSON
$statsObject = [PSCustomObject]@{
  requested             = $hashes.Count
  downloaded_ok         = $okSha256s.Count
  download_failed       = $failedSha256s.Count
  created_at            = $timestamp
  output_dir            = $OutDir
}
$statsPath = Join-Path $OutDir "stats.json"
$statsObject | ConvertTo-Json -Depth 4 | Out-File -FilePath $statsPath -Encoding UTF8

# File Types CSV
$typeCsvPath = Join-Path $OutDir "filetypes.csv"
$typeCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
    [PSCustomObject]@{ type_description = $_.Key; count = $_.Value }
} | Export-Csv -Path $typeCsvPath -NoTypeInformation -Encoding UTF8

# DLL Entry Points CSV (Crucial for Detonation Script)
$dllCsvPath = Join-Path $OutDir "dll_entrypoints.csv"
if ($dllRows.Count -gt 0) {
  $dllRows | Export-Csv -Path $dllCsvPath -NoTypeInformation -Encoding UTF8
} else {
  @([PSCustomObject]@{ sha256 = "none"; meaningful_name = "none"; entry_point = "none" }) | 
  Select-Object sha256, meaningful_name, entry_point | Export-Csv -Path $dllCsvPath -NoTypeInformation
}

Write-Host "`n[COMPLETED]" -ForegroundColor Green
Write-Host "Samples: $OutDir"
Write-Host "DLL Map: $dllCsvPath"
}