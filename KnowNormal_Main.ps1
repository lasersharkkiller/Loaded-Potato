#Requirements
#Install-Module -Name powershell-yaml -Scope CurrentUser -Force
#Install-Module -Scope CurrentUser Microsoft.PowerShell.SecretManagement, Microsoft.Powershell.SecretStore -Force
#Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
#Set-Secret -Name 'S1_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'S1_API_Key_2' -Secret 'API_Key_Here'
#Set-Secret -Name 'Intezer_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'VT_API_Key_1' -Secret 'API_Key_Here'
#Set-Secret -Name 'VT_API_Key_2' -Secret 'API_Key_Here'
#Set-Secret -Name 'VT_API_Key_3' -Secret 'API_Key_Here'
#Set-Secret -Name 'APIVoid_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'ThreatGrid_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'Cyber6Gil_Client_Id' -Secret 'API_Key_Here'
#Set-Secret -Name 'Cyber6Gil_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'Devo_Access_Token' -Secret 'API_Key_Here'
#Set-Secret -Name 'Github_Access_Token' -Secret 'API_Key_Here'

#Install-Module -Name PSSQLite -Scope CurrentUser -Force


Import-Module -Name ".\AlertsModules\AgentsLessThan24-1.psm1"
Import-Module -Name ".\AlertsModules\Alerts_Main.psm1"
Import-Module -Name ".\AlertsModules\Get-ThreatAttribution.psm1"
Import-Module -Name ".\AlertsModules\S1StatsAlertsThreats.psm1"
Import-Module -Name ".\AlertsModules\SyntaxConversion.psm1"
Import-Module -Name ".\asciiArt\resizeConsole.psm1"
Import-Module -Name ".\asciiArt\sashaPotato.psm1"
Import-Module -Name ".\baseline\BaseLineStrings_with_Intezer.psm1"
Import-Module -Name ".\baseline\compareAllProcessDiffs.psm1"
Import-Module -Name ".\baseline\compareSingleProcessDiffs.psm1"
Import-Module -Name ".\baseline\REDACTED_KEY.psm1"
Import-Module -Name ".\baseline\maliciousDifferential.psm1"
Import-Module -Name ".\baseline\NsrlDownloadExistsInBoth.psm1"
Import-Module -Name ".\baseline\NsrlEnrichment.psm1"
Import-Module -Name ".\baseline\NsrlTools.psm1"
Import-Module -Name ".\baseline\OrganizeBaselines.psm1"
Import-Module -Name ".\baseline\StringsSearchLocalBaseline.psm1"
Import-Module -Name ".\baseline\REDACTED_KEY.psm1"
Import-Module -Name ".\baseline\UploadDiffsToVT.psm1"
Import-Module -Name ".\baseline\VTBaseline.psm1"
Import-Module -Name ".\certificateHunting\certGapHuntVT.psm1"
Import-Module -Name ".\certificateHunting\certGapHuntLocalBaseline.psm1"
Import-Module -Name ".\certificateHunting\revokedCertHunt.psm1"
Import-Module -Name ".\codeScanning\REDACTED_KEY.psm1"
Import-Module -Name ".\NewProcsModules\BlockedCountryPull.psm1"
Import-Module -Name ".\NewProcsModules\CheckAgainstVT.psm1"
Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"
Import-Module -Name ".\NewProcsModules\CheckThreatGrid.psm1"
Import-Module -Name ".\NewProcsModules\DriversMinusBenignExcluded_Main.psm1"
Import-Module -Name ".\NewProcsModules\GetASN-Cymru.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\IntezerCheckUrl.psm1"
Import-Module -Name ".\NewProcsModules\MispPull.psm1"
Import-Module -Name ".\NewProcsModules\newWinPublishers_Main.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"
Import-Module -Name ".\NewProcsModules\SpecialCharsProcs_Main.psm1"
Import-Module -Name ".\NewProcsModules\SpecificProc_Main.psm1"
Import-Module -Name ".\NewProcsModules\UnsignedProcs_Main.psm1"
Import-Module -Name ".\NewProcsModules\UnverifiedProcs_Main.psm1"
Import-Module -Name ".\nsm\bulkipcheck.psm1"
Import-Module -Name ".\nsm\CheckDevoWAFNetworkAttacks.psm1"
Import-Module -Name ".\nsm\deduplicateIpsBySlash24.psm1"
Import-Module -Name ".\nsm\DevoGenericQuery.psm1"
Import-Module -Name ".\nsm\processBulkIps.psm1"
Import-Module -Name ".\nsm\S1PullIpsForProcess.psm1"
Import-Module -Name ".\purpleTeaming\aptIocs.psm1"
Import-Module -Name ".\purpleTeaming\GetForensicLongTailAnalysis.psm1"
Import-Module -Name ".\purpleTeaming\GetSingleVTZippedSample.psm1"
Import-Module -Name ".\purpleTeaming\GetVTZippedSamplesFromList.psm1"
Import-Module -Name ".\purpleTeaming\IndicatorsforRuleDevelopment.psm1"
Import-Module -Name ".\purpleTeaming\massMalwareDetonation.psm1"
Import-Module -Name ".\purpleTeaming\picusCleanup.psm1"
Import-Module -Name ".\purpleTeaming\REDACTED_KEY.psm1"
Import-Module -Name ".\purpleTeaming\REDACTED_KEY.psm1"
Import-Module -Name ".\reports\checkVTUsage.psm1"
Import-Module -Name ".\reports\createApiMatrix.psm1"
Import-Module -Name ".\reports\createMalwareReport.psm1"
Import-Module -Name ".\reports\repairVTBaseline.psm1"
Import-Module -Name ".\reports\weeklyMetrics.psm1"

Resize-Console -Width 150
Get-SashaPotato

#Get Updates from MISP
try {
    Get-MispPull
    Get-BlockedCountryList
} catch {
    Write-Host "Unable to download the latest internal block lists"
}

Write-Host "Choose which function you would like to use:"
Write-Host "$([char]27)[4mAnalyze Artifacts for An Alert:$([char]27)[24m" -ForegroundColor Red
Write-Host "1) Alerts and Threats" -ForegroundColor Red
Write-Host "2) Alerts and Threats Stats (for Tuning)" -ForegroundColor Red
Write-Host "3) Agents < 24.1 Stats (Hashes above 30MB will be incorrect)" -ForegroundColor Red
Write-Host "4) Convert S1 v1 Syntax to v2 Syntax" -ForegroundColor Red
Write-Host "5) Get Threat Attribution" -ForegroundColor Red
Write-Host ""
Write-Host "$([char]27)[4mPurple Teaming Analysis:$([char]27)[24m" -ForegroundColor Magenta
Write-Host "6) Analyze Indicators" -ForegroundColor Magenta
Write-Host "7) Forensic Artifacts Long Tail Analysis for Single Host" -ForegroundColor Magenta
Write-Host "8) Pull a Single SHA256 from VT" -ForegroundColor Magenta
Write-Host "9) Pull Detections from VT from a List" -ForegroundColor Magenta
Write-Host "10) Picus Cleanup for Know Normal Baseline" -ForegroundColor Magenta
Write-Host ""
Write-Host "$([char]27)[4mPurple Teaming APT/Malware Family Emulation & Detonation:$([char]27)[24m" -ForegroundColor Magenta
Write-Host "11) Pull APT IOCs Update from VirusTotal & C6G" -ForegroundColor Magenta
Write-Host "12) Pull/Update High Fidelity Sigma Yara Detections From Differential Analysis" -ForegroundColor Magenta
Write-Host "13) Prepare a List of Hashes to be DLd Based on APT(s) and-or Malware Familes" -ForegroundColor Magenta
Write-Host "14) Pull Samples from VT from a List" -ForegroundColor Magenta
Write-Host "15) Mass Malware Detonation" -ForegroundColor Magenta
Write-Host ""
Write-Host "$([char]27)[4mBaseline New Processes in the Environment:$([char]27)[24m" -ForegroundColor Yellow
Write-Host "16) Specific Processes Name" -ForegroundColor Yellow
Write-Host "17) New Drivers in the Env (Minus Benign and Excluded))" -ForegroundColor Yellow
Write-Host "18) New Unverified Processes" -ForegroundColor Yellow
Write-Host "19) New Unsigned Windows Processes" -ForegroundColor Yellow
Write-Host "20) New Unsigned Linux Processes" -ForegroundColor Yellow
Write-Host ""
Write-Host "$([char]27)[4mBuild Process Baseline:$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "21) Baseline Proc Strings with Intezer" -ForegroundColor DarkYellow
Write-Host "22) Baseline Procs with VirusTotal" -ForegroundColor DarkYellow
Write-Host "23) Upload Allowed Diffs to VT after Previous Two" -ForegroundColor DarkYellow
Write-Host "24) Separate Malicious Analysis (Cleanup, Shouldn't Normally Need)" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "$([char]27)[4mNSRL:$([char]27)[24m" -ForegroundColor White
Write-Host "25) Set up NSRL Database and Bloom Filter" -ForegroundColor White
Write-Host "26) NSRL Enrichment" -ForegroundColor White
Write-Host "27) Download Sample Bundle That Exist in Both NSRL & Malware (from VT)" -ForegroundColor White
Write-Host ""
Write-Host "$([char]27)[4mNetwork Security Monitoring Integration:$([char]27)[24m" -ForegroundColor DarkGreen
Write-Host "28) Bulk IP Reference Reputation" -ForegroundColor DarkGreen
Write-Host "29) Deduplicate Ips (in a csv) By /24" -ForegroundColor DarkGreen
Write-Host "30) Bulk Ips for a Source Process" -ForegroundColor DarkGreen
Write-Host "31) Top WAF perimeter Attackers" -ForegroundColor DarkGreen
Write-Host "32) Run Generic Devo Query" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "$([char]27)[4mCertificate Hunting:$([char]27)[24m" -ForegroundColor Green
Write-Host "33) Revoked Cert Hunt (Against Offline static-dynamic db)" -ForegroundColor Green
Write-Host "34) Processes with Special Characters in the Publisher Name" -ForegroundColor Green
Write-Host "35) New Windows Code Signing Publishers in the Environment" -ForegroundColor Green
Write-Host "36) Top Certificate Gaps Across VT Public" -ForegroundColor Green
Write-Host "37) Certificate Gap Hunt w/Local Baseline" -ForegroundColor Green
Write-Host ""
Write-Host "$([char]27)[4mStatic/Dynamic Module:$([char]27)[24m" -ForegroundColor Blue
Write-Host "38) Look for a string across local baseline" -ForegroundColor Blue
Write-Host "39) Look at Differentials for a Single Process" -ForegroundColor Blue
Write-Host "40) Look at Differentials for a Single Process but focus on one hash's differences" -ForegroundColor Blue
Write-Host "41) Look at Differentials for ALL Processes in Baseline" -ForegroundColor Blue
Write-Host "42) Malicious API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor Blue
Write-Host "43) Specified API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor Blue
Write-Host ""
Write-Host "$([char]27)[4mCode Scanning:$([char]27)[24m" -ForegroundColor Yellow
Write-Host "44) Find Github Repos (and similar domains) in Offline Baseline and Analyze" -ForegroundColor Yellow
Write-Host ""
Write-Host "$([char]27)[4mReport Creation:$([char]27)[24m" -ForegroundColor Gray
Write-Host "45) Repair VT Metadata Baseline" -ForegroundColor Gray
Write-Host "46) Iterate through APT Analyses and Create Forensics Hunting Report" -ForegroundColor Gray
Write-Host "47) Iterate through APT Analyses and Create API Matrix" -ForegroundColor Gray
Write-Host "48) Check Weekly Metrics" -ForegroundColor Gray
Write-Host "49) Check VT Usage" -ForegroundColor Gray
Write-Host ""

$functionChoice = Read-Host "Please listen closely as our options may have changed. Enter an option"
    
    if ($functionChoice -eq 1){
        Get-AlertsandThreatsFunction
    }
    elseif ($functionChoice -eq 2){
        Get-AlertsandThreatsStats
    }
    elseif ($functionChoice -eq 3){
        Get-AgentsLessThan24_1
    }
    elseif ($functionChoice -eq 4){
        Get-SyntaxConversion
    }
    elseif ($functionChoice -eq 5){
        Get-ThreatAttribution
    }
    elseif ($functionChoice -eq 6){
        Get-IndicatorsforRuleDevelopment
    }
    elseif ($functionChoice -eq 7){
        Get-ForensicLongTailAnalysis
    }
    elseif ($functionChoice -eq 8){
        Get-SingleVTZippedSample
    }
    elseif ($functionChoice -eq 9){
        Get-VTDetectionsFromList
    }
    elseif ($functionChoice -eq 10){
        Get-picusCleanup
    }
    elseif ($functionChoice -eq 11){
        Get-ThreatActorIOCs
    }
    elseif ($functionChoice -eq 12){
        Get-HighFidelitySigmaYaraRules
    }
    elseif ($functionChoice -eq 13){
        Get-REDACTED_KEY
    }
    elseif ($functionChoice -eq 14){
        Get-VTZippedSamplesFromList
    }
    elseif ($functionChoice -eq 15){
        Invoke-MalwareDetonation
    }
    elseif ($functionChoice -eq 16){
        $procToQuery = Read-Host -Prompt "Enter process name (i.e. lsass.exe)"
        Get-SpecificProc -procName $procToQuery
    }
    elseif ($functionChoice -eq 17){
        Get-DriversMinusBenignExcluded
    }
    elseif ($functionChoice -eq 18){
        Get-UnverifiedProcs
    }
    elseif ($functionChoice -eq 19){
        Get-UnsignedProcs -os "windows"
    }
    elseif ($functionChoice -eq 20){
        Get-UnsignedProcs -os "linux"
    }
    elseif ($functionChoice -eq 21){
        Get-StringsBaseline
    }
    elseif ($functionChoice -eq 22){
        Get-VTBaseline
    }
    elseif ($functionChoice -eq 23){
        Get-UploadDiffsToVT
    }
    elseif ($functionChoice -eq 24){
        Move-OrganizeBaselines
    }
    elseif ($functionChoice -eq 25){
        Install-NsrlDatabase
    }
    elseif ($functionChoice -eq 26){
        Update-NsrlBaseline
    }
    elseif ($functionChoice -eq 27){
        Get-VtExistsInBothBundle
    }
    elseif ($functionChoice -eq 28){
        Get-CheckBulkIpsApiVoid
    }
    elseif ($functionChoice -eq 29){
        Get-DeduplicateIpsBySlash24
    }
    elseif ($functionChoice -eq 30){
        Get-S1PullIpsForProcess
    }
    elseif ($functionChoice -eq 31){
        Get-CheckWAFPerimeterAttacks
    }
    elseif ($functionChoice -eq 32){
        Get-DevoGenericQuery
    }
    elseif ($functionChoice -eq 33){
        Get-revokedCertHunt
    }
    elseif ($functionChoice -eq 34){
        Get-SpecialCharsProcs
    }
    elseif ($functionChoice -eq 35){
        Get-NewWinPublishers
    }
    elseif ($functionChoice -eq 36){
        Get-CertGapHuntVT
    } 
    elseif ($functionChoice -eq 37){
        Get-CertGapHuntLocalBaseline
    }
    elseif ($functionChoice -eq 38){
        Get-StringsSearchLocalBaseline
    }
    elseif ($functionChoice -eq 39){
        $procToDiff = Read-Host -Prompt "Enter process with extension (i.e. lsass.exe)"
        Get-CompareSingleProcessDiffs -ProcessName $procToDiff
    }
    elseif ($functionChoice -eq 40){
        $procToDiff = Read-Host -Prompt "Enter process with extension (i.e. lsass.exe)"
        $targetHash = Read-Host -Prompt "Enter SHA256 to focus results"
        Get-REDACTED_KEY -ProcessName $procToDiff -TargetHash $targetHash
    }
    elseif ($functionChoice -eq 41){
        Get-CompareAllProcessDiffs
    }
    elseif ($functionChoice -eq 42){
        Get-MaliciousDifferentialAnalysis
    }
    elseif ($functionChoice -eq 43){
        Get-TargetedMalwareAnalysis
    }
    elseif ($functionChoice -eq 44){
        Find-GitHubReposInMetadata
    }
    elseif ($functionChoice -eq 45){
        Repair-VTBaseline
    }
    elseif ($functionChoice -eq 46){
        New-MalwareDashboard
    }
    elseif ($functionChoice -eq 47){
        New-ApiMatrixDashboard
    }
    elseif ($functionChoice -eq 48){
        Get-WeeklyMetrics
    }
    elseif ($functionChoice -eq 49){
        Get-VTUsage
    }
    else {
      Write-Host "You did not choose a valid option"
    }

