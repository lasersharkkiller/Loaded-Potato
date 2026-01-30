# NsrlDownloadBundle.psm1
# Module to create a download bundle of samples from the existsInBoth folder.

function Get-VtExistsInBothBundle {
    <#
    .SYNOPSIS
        Scans the 'existsInBoth' folder for hashes and requests a ZIP bundle 
        of the actual file samples from VirusTotal Intelligence.

    .DESCRIPTION
        1. Iterates through *.json files in 'output-baseline\VirusTotal-main\existsInBoth'.
        2. Extracts the SHA256 hashes.
        3. Sends the list to VirusTotal's Intelligence Download endpoint.
        4. Downloads the resulting ZIP file containing the malware samples.
        
        WARNING: This requires a VirusTotal Enterprise/Intelligence API Key.

    .PARAMETER ExistsInBothPath
        Path to the folder containing the conflict JSONs.
        Default: "output-baseline\VirusTotal-main\existsInBoth"
        
    .PARAMETER OutputZip
        Path where the bundled zip should be saved.
        Default: "output\NSRL_Conflict_Samples.zip"
    #>
    [CmdletBinding()]
    param (
        [string]$ExistsInBothPath = "output-baseline\VirusTotal-main\existsInBoth",
        [string]$OutputZip = "output\NSRL_Conflict_Samples.zip"
    )

    # --- 1. AUTHENTICATION ---
    if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
    }
    try {
        $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
        if (-not $VTApi) { throw "Secret 'VT_API_Key_3' not found." }
    } catch {
        Write-Error "Authentication Failed: $_"; return
    }
    
    # --- 2. GATHER HASHES ---
    if (-not (Test-Path $ExistsInBothPath)) {
        Write-Error "Folder not found: $ExistsInBothPath"
        return
    }

    Write-Host "Scanning $ExistsInBothPath for hashes..." -ForegroundColor Cyan
    $JsonFiles = Get-ChildItem -Path $ExistsInBothPath -Filter "*.json"
    $HashList = @()

    foreach ($File in $JsonFiles) {
        try {
            # We can grab the filename (which is the hash) removing the .json extension
            # This is faster than reading the file content
            $Hash = $File.BaseName
            if ($Hash.Length -eq 64) { # Basic SHA256 check
                $HashList += $Hash
            }
        } catch {}
    }

    $Count = $HashList.Count
    if ($Count -eq 0) {
        Write-Warning "No hashes found in $ExistsInBothPath."
        return
    }
    
    Write-Host "Found $Count unique hashes." -ForegroundColor Green

    # --- 3. REQUEST BUNDLE ---
    # VT Endpoint: POST /intelligence/downloads
    # Body: hashes[] = ...
    
    $Url = "https://www.virustotal.com/api/v3/intelligence/downloads"
    $Headers = @{ "x-apikey" = $VTApi }
    
    # Create output directory if needed
    $OutputDir = Split-Path $OutputZip -Parent
    if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

    Write-Host "Requesting download bundle from VirusTotal..." -ForegroundColor Cyan
    
    try {
        # Convert list to compatible query
        # For large lists, we might need to verify max limits (usually 100-1000 depending on tier)
        # We'll try to send all; if it fails, user might need to batch manually or we update logic.
        
        $Body = @{
            hashes = $HashList
        } | ConvertTo-Json

        # 1. Get the Download URL (This endpoint generates a customized link)
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Headers $Headers -Body $Body -ContentType "application/json"
        
        if ($Response.data.type -eq "download_link") {
            $DownloadUrl = $Response.data.attributes.url
            Write-Host "Bundle generated successfully!" -ForegroundColor Green
            Write-Host "Downloading to $OutputZip..." -ForegroundColor Cyan
            
            # 2. Download the Zip
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutputZip
            
            Write-Host "Success. File saved." -ForegroundColor Green
        }
        else {
            Write-Error "Unexpected response from VirusTotal: $($Response | ConvertTo-Json -Depth 5)"
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Error "Access Denied (403). Your API key may not support Bulk Intelligence Downloads (Enterprise Feature)."
            Write-Host "Fallback option: You can use 'Get-FileSample' loop to download individually if permitted." -ForegroundColor Gray
        }
        else {
            Write-Error "API Error: $_"
        }
    }
}

Export-ModuleMember -Function Get-VtExistsInBothBundle