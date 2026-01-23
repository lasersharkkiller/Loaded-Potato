function Get-ThreatAttribution {
    <#
    .SYNOPSIS
        Attribution Engine: Correlates observed TTPs against the known APT/Malware database.
    .EXAMPLE
        Get-ThreatAttribution -Observations @("T1027", "Delete Volume Shadow Copies")
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Observations,

        [string]$RootPath = ".\apt\c6g",
        [string]$OutputHtmlPath = ".\output\Attribution_Report.html",
        [int]$MinRarityScore = 90
    )

    Write-Host "Starting Threat Attribution Analysis..." -ForegroundColor Cyan
    Write-Host "Searching for: $($Observations -join ', ')" -ForegroundColor Yellow

    if (-not (Test-Path $RootPath)) { Write-Error "Root path not found: $RootPath"; return }
    $AbsRoot = (Resolve-Path $RootPath).Path
    
    # --- 1. BUILD THE SEARCH INDEX ---
    # Structure: @{ "IndicatorName" = @( {Actor="APT41"; Type="APT"; Source="Sigma"} ) }
    $GlobalIndex = @{}
    $ActorProfiles = @{} # Cache unique items per actor for recommendations

    Write-Host "  Building Threat Index from Repository..." -NoNewline
    
    $JsonFiles = Get-ChildItem -Path $AbsRoot -Filter "Targeted*DifferentialAnalysis.json" -Recurse
    $TotalIndexed = 0

    foreach ($File in $JsonFiles) {
        # Determine Actor/Family based on folder structure
        $Parent = $File.Directory.Name
        $GrandParent = $File.Directory.Parent.Name
        
        $ActorName = $Parent
        $ActorType = "Malware"
        if ($GrandParent -ne "Malware Families" -and $GrandParent -ne "APTs") {
            # Handle deep APT paths like APTs/China/APT41
            if ($File.FullName -match "\\APTs\\") { $ActorType = "APT" }
        }

        try {
            $Data = Get-Content $File.FullName -Raw | ConvertFrom-Json
            if (-not $Data) { continue }
            $Items = @($Data)

            foreach ($Row in $Items) {
                # FILTER: Only index Unique/High Rarity items
                $Score = [double]$Row.Baseline_Rarity_Score
                if ($Score -lt $MinRarityScore) { continue }

                # Normalize Key
                $Key = $Row.Item_Name -replace '"','' -replace '^\s+','' -replace '\s+$',''
                
                # Add to Search Index
                if (-not $GlobalIndex.ContainsKey($Key)) { $GlobalIndex[$Key] = @() }
                $GlobalIndex[$Key] += [PSCustomObject]@{
                    Actor = $ActorName
                    Type  = $ActorType
                    Source = $Row.Type # e.g., "Sigma Rule", "Windows API"
                    Score = $Score
                }

                # Add to Profile (For Recommendations)
                if (-not $ActorProfiles.ContainsKey($ActorName)) { $ActorProfiles[$ActorName] = @() }
                $ActorProfiles[$ActorName] += [PSCustomObject]@{ Name=$Key; Type=$Row.Type; Score=$Score }
                
                $TotalIndexed++
            }
        } catch {}
    }
    Write-Host " [Done] ($TotalIndexed high-rarity artifacts indexed)" -ForegroundColor Green

    # --- 2. EXECUTE QUERY ---
    $Candidates = @{} # Key=ActorName, Value={ Matches=@(); Score=0 }

    foreach ($SearchTerm in $Observations) {
        # Fuzzy Match: Check if any indexed key contains the search term
        $Matches = $GlobalIndex.Keys | Where-Object { $_ -match [regex]::Escape($SearchTerm) }
        
        foreach ($MatchKey in $Matches) {
            foreach ($Hit in $GlobalIndex[$MatchKey]) {
                $Name = $Hit.Actor
                if (-not $Candidates.ContainsKey($Name)) {
                    $Candidates[$Name] = @{ 
                        Actor = $Name
                        Type = $Hit.Type
                        Matches = @()
                        MatchCount = 0
                    }
                }
                
                # Avoid duplicate hits for the same term on the same actor
                $AlreadyMatched = $Candidates[$Name].Matches | Where-Object { $_.Term -eq $SearchTerm }
                if (-not $AlreadyMatched) {
                    $Candidates[$Name].Matches += [PSCustomObject]@{
                        Term = $SearchTerm
                        Indicator = $MatchKey
                        Source = $Hit.Source
                    }
                    $Candidates[$Name].MatchCount++
                }
            }
        }
    }

    # --- 3. RANKING & RECOMMENDATIONS ---
    $Results = $Candidates.Values | Sort-Object MatchCount -Descending
    
    # Generate HTML Report
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attribution Analysis</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a1a1a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 30px; }
        .card { background-color: #2d2d2d; border: 1px solid #444; margin-bottom: 20px; }
        .card-header { font-weight: bold; }
        .tier-badge { font-size: 0.9rem; margin-left: 10px; }
        .match-highlight { color: #86efac; font-family: monospace; }
        .rec-item { font-size: 0.85rem; color: #94a3b8; border-bottom: 1px solid #444; padding: 4px 0; }
        .badge-apt { background-color: #dc3545; }
        .badge-mal { background-color: #fd7e14; }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mb-4 text-center">Attribution Analysis Report</h2>
        <div class="alert alert-secondary">
            <strong>Observations Analyzed:</strong> $($Observations -join ", ")
        </div>

        <h4 class="text-success border-bottom pb-2 mt-4">Tier 1: Multi-Indicator Matches (High Confidence)</h4>
        <div class="row">
"@

    $Tier1Count = 0
    foreach ($Res in $Results) {
        if ($Res.MatchCount -gt 1) {
            $Tier1Count++
            $Recs = $ActorProfiles[$Res.Actor] | 
                    Sort-Object Score -Descending | 
                    Select-Object -First 20 | 
                    Get-Random -Count 5 # Random 5 from top 20 for variety
            
            $TypeBadge = if($Res.Type -eq "APT"){"badge-apt"}else{"badge-mal"}
            
            $HtmlContent += @"
            <div class="col-md-6">
                <div class="card h-100 border-success">
                    <div class="card-header bg-success text-white d-flex justify-content-between">
                        <span>$($Res.Actor)</span>
                        <span class="badge $TypeBadge">$($Res.Type)</span>
                    </div>
                    <div class="card-body">
                        <h6>Matched Indicators:</h6>
                        <ul>
"@
            foreach ($m in $Res.Matches) {
                $HtmlContent += "<li><span class='text-muted'>[$($m.Source)]</span> <span class='match-highlight'>$($m.Indicator)</span></li>"
            }
            $HtmlContent += @"
                        </ul>
                        <hr>
                        <h6 class="text-warning">Hunting Recommendations (Pivot):</h6>
                        <p class="small text-muted">If this is $($Res.Actor), look for these unique artifacts next:</p>
                        <div class="list-group list-group-flush">
"@
            foreach ($r in $Recs) {
                $HtmlContent += "<div class='rec-item'><strong>[$($r.Type)]</strong> $($r.Name)</div>"
            }
            $HtmlContent += "</div></div></div></div>"
        }
    }

    if ($Tier1Count -eq 0) { $HtmlContent += "<p class='text-muted'>No multi-indicator matches found.</p>" }

    $HtmlContent += @"
        </div>
        
        <h4 class="text-warning border-bottom pb-2 mt-5">Tier 2: Single Indicator Matches (Leads)</h4>
        <div class="row">
"@

    foreach ($Res in $Results) {
        if ($Res.MatchCount -eq 1) {
            $TypeBadge = if($Res.Type -eq "APT"){"badge-apt"}else{"badge-mal"}
            $HtmlContent += @"
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between">
                        <span>$($Res.Actor)</span>
                        <span class="badge $TypeBadge">$($Res.Type)</span>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <span class='text-muted'>[$($Res.Matches[0].Source)]</span><br>
                            <span class='match-highlight'>$($Res.Matches[0].Indicator)</span>
                        </div>
                    </div>
                </div>
            </div>
"@
        }
    }

    $HtmlContent += @"
        </div>
    </div>
</body>
</html>
"@

    $HtmlContent | Set-Content -Path $OutputHtmlPath -Encoding UTF8
    Write-Host "Analysis Complete. Report: $OutputHtmlPath" -ForegroundColor Green
}