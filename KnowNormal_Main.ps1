#Requirements
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
#Set-Secret -Name 'Cyber6Gil_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'Devo_Access_Token' -Secret 'API_Key_Here'


Import-Module -Name ".\AlertsModules\AgentsLessThan24-1.psm1"
Import-Module -Name ".\AlertsModules\Alerts_Main.psm1"
Import-Module -Name ".\AlertsModules\S1StatsAlertsThreats.psm1"
Import-Module -Name ".\AlertsModules\SyntaxConversion.psm1"
Import-Module -Name ".\asciiArt\resizeConsole.psm1"
Import-Module -Name ".\asciiArt\sashaPotato.psm1"
Import-Module -Name ".\baseline\BaseLineStrings_with_Intezer.psm1"
Import-Module -Name ".\baseline\compareAllProcessDiffs.psm1"
Import-Module -Name ".\baseline\compareSingleProcessDiffs.psm1"
Import-Module -Name ".\baseline\REDACTED_KEY.psm1"
Import-Module -Name ".\baseline\maliciousDifferential.psm1"
Import-Module -Name ".\baseline\OrganizeBaselines.psm1"
Import-Module -Name ".\baseline\StringsSearchLocalBaseline.psm1"
Import-Module -Name ".\baseline\REDACTED_KEY.psm1"
Import-Module -Name ".\baseline\UploadDiffsToVT.psm1"
Import-Module -Name ".\baseline\VTBaseline.psm1"
Import-Module -Name ".\certificateHunting\certGapHuntVT.psm1"
Import-Module -Name ".\certificateHunting\certGapHuntLocalBaseline.psm1"
Import-Module -Name ".\certificateHunting\revokedCertHunt.psm1"
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
Import-Module -Name ".\nsm\CheckDevoWAFNetworkAttacks.psm1"
Import-Module -Name ".\nsm\deduplicateIpsBySlash24.psm1"
Import-Module -Name ".\nsm\DevoGenericQuery.psm1"
Import-Module -Name ".\nsm\processBulkIps.psm1"
Import-Module -Name ".\nsm\S1PullIpsForProcess.psm1"
Import-Module -Name ".\purpleTeaming\REDACTED_KEY.psm1"
Import-Module -Name ".\purpleTeaming\GetDedupHashesToSha256.psm1"
Import-Module -Name ".\purpleTeaming\GetForensicLongTailAnalysis.psm1"
Import-Module -Name ".\purpleTeaming\GetRemoveMalwareBazaarEntries.psm1"
Import-Module -Name ".\purpleTeaming\GetSingleVTZippedSample.psm1"
Import-Module -Name ".\purpleTeaming\GetVTDetectionsFromList.psm1"
Import-Module -Name ".\purpleTeaming\GetVTZippedSamplesFromList.psm1"
Import-Module -Name ".\purpleTeaming\IndicatorsforRuleDevelopment.psm1"
Import-Module -Name ".\reports\createMalwareReport.psm1"
Import-Module -Name ".\reports\repairVTBaseline.psm1"

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
Write-Host ""
Write-Host "$([char]27)[4mPurple Teaming Analysis:$([char]27)[24m" -ForegroundColor Magenta
Write-Host "5) Analyze Indicators" -ForegroundColor Magenta
Write-Host "6) Forensic Artifacts Long Tail Analysis for Single Host" -ForegroundColor Magenta
Write-Host "7) Create Detections From ALL Malicious Static / Dynamic Analysis (Against Enterprise)" -ForegroundColor Magenta
Write-Host "8) Create Detections From SPECIFIED Malicious Static / Dynamic Analysis (Against Enterprise)" -ForegroundColor Magenta
Write-Host "9) Deduplicate Hashes" -ForegroundColor Magenta
Write-Host "10) Remove Malware Bazaar Entries" -ForegroundColor Magenta
Write-Host "11) Pull Samples from VT from a List" -ForegroundColor Magenta
Write-Host "12) Pull a Single SHA256 from VT" -ForegroundColor Magenta
Write-Host "13) Pull Detections from VT from a List" -ForegroundColor Magenta
Write-Host ""
Write-Host "$([char]27)[4mBaseline New Processes in the Environment:$([char]27)[24m" -ForegroundColor Yellow
Write-Host "14) Specific Processes Name" -ForegroundColor Yellow
Write-Host "15) New Drivers in the Env (Minus Benign and Excluded))" -ForegroundColor Yellow
Write-Host "16) New Unverified Processes" -ForegroundColor Yellow
Write-Host "17) New Unsigned Windows Processes" -ForegroundColor Yellow
Write-Host "18) New Unsigned Linux Processes" -ForegroundColor Yellow
Write-Host ""
Write-Host "$([char]27)[4mBuild Process Baseline:$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "19) Baseline Proc Strings with Intezer" -ForegroundColor DarkYellow
Write-Host "20) Baseline Procs with VirusTotal" -ForegroundColor DarkYellow
Write-Host "21) Upload Allowed Diffs to VT after Previous Two" -ForegroundColor DarkYellow
Write-Host "22) Separate Malicious Analysis (Cleanup, Shouldn't Normally Need)" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "$([char]27)[4mNetwork Security Monitoring Integration:$([char]27)[24m" -ForegroundColor DarkGreen
Write-Host "23) Pull Outbound C2 for a Process and Cross Reference Reputation" -ForegroundColor DarkGreen
Write-Host "24) Deduplicate Ips (in a csv) By /24" -ForegroundColor DarkGreen
Write-Host "25) Process Bulk Ips" -ForegroundColor DarkGreen
Write-Host "26) Top WAF perimeter Attackers" -ForegroundColor DarkGreen
Write-Host "27) Run Generic Devo Query" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "$([char]27)[4mCertificate Hunting:$([char]27)[24m" -ForegroundColor Green
Write-Host "28) Revoked Cert Hunt (Against Offline static-dynamic db)" -ForegroundColor Green
Write-Host "29) Processes with Special Characters in the Publisher Name" -ForegroundColor Green
Write-Host "30) New Windows Code Signing Publishers in the Environment" -ForegroundColor Green
Write-Host "31) Top Certificate Gaps Across VT Public" -ForegroundColor Green
Write-Host "32) Certificate Gap Hunt w/Local Baseline" -ForegroundColor Green
Write-Host ""
Write-Host "$([char]27)[4mStatic/Dynamic Module:$([char]27)[24m" -ForegroundColor Blue
Write-Host "33) Look for a string across local baseline" -ForegroundColor Blue
Write-Host "34) Look at Differentials for a Single Process" -ForegroundColor Blue
Write-Host "35) Look at Differentials for a Single Process but focus on one hash's differences" -ForegroundColor Blue
Write-Host "36) Look at Differentials for ALL Processes in Baseline" -ForegroundColor Blue
Write-Host "37) Malicious API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor Blue
Write-Host "38) Specified API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor Blue
Write-Host ""
Write-Host "$([char]27)[4mReport Creation:$([char]27)[24m" -ForegroundColor Gray
Write-Host "39) Repair VT Metadata Baseline" -ForegroundColor Gray
Write-Host "40) Iterate through APT Analyses and Create Updated Report" -ForegroundColor Gray
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
        Get-IndicatorsforRuleDevelopment
    }
    elseif ($functionChoice -eq 6){
        Get-ForensicLongTailAnalysis
    }
    elseif ($functionChoice -eq 7){
        Get-REDACTED_KEY
    }
    elseif ($functionChoice -eq 8){
        Get-TargetedMalwareAnalysis
    }
    elseif ($functionChoice -eq 9){
        Get-DedupHashesToSha256
    }
    elseif ($functionChoice -eq 10){
        Get-RemoveMalwareBazaarEntries
    }
    elseif ($functionChoice -eq 11){
        Get-VTZippedSamplesFromList
    }
    elseif ($functionChoice -eq 12){
        Get-SingleVTZippedSample
    }
    elseif ($functionChoice -eq 13){
        Get-VTDetectionsFromList
    }
    elseif ($functionChoice -eq 14){
        $procToQuery = Read-Host -Prompt "Enter process name (i.e. lsass.exe)"
        Get-SpecificProc -procName $procToQuery
    }
    elseif ($functionChoice -eq 15){
        Get-DriversMinusBenignExcluded
    }
    elseif ($functionChoice -eq 16){
        Get-UnverifiedProcs
    }
    elseif ($functionChoice -eq 17){
        Get-UnsignedProcs -os "windows"
    }
    elseif ($functionChoice -eq 18){
        Get-UnsignedProcs -os "linux"
    }
    elseif ($functionChoice -eq 19){
        Get-StringsBaseline
    }
    elseif ($functionChoice -eq 20){
        Get-VTBaseline
    }
    elseif ($functionChoice -eq 21){
        Get-UploadDiffsToVT
    }
    elseif ($functionChoice -eq 22){
        Move-OrganizeBaselines
    }
    elseif ($functionChoice -eq 23){
        Get-S1PullIpsForProcess
    }
    elseif ($functionChoice -eq 24){
        Get-DeduplicateIpsBySlash24
    }
    elseif ($functionChoice -eq 25){
        Get-ProcessBulkIps
    }
    elseif ($functionChoice -eq 26){
        Get-CheckWAFPerimeterAttacks
    }
    elseif ($functionChoice -eq 27){
        Get-DevoGenericQuery
    }
    elseif ($functionChoice -eq 28){
        Get-revokedCertHunt
    }
    elseif ($functionChoice -eq 29){
        Get-SpecialCharsProcs
    }
    elseif ($functionChoice -eq 30){
        Get-NewWinPublishers
    }
    elseif ($functionChoice -eq 31){
        Get-CertGapHuntVT
    } 
    elseif ($functionChoice -eq 32){
        Get-CertGapHuntLocalBaseline
    }
    elseif ($functionChoice -eq 33){
        Get-StringsSearchLocalBaseline
    }
    elseif ($functionChoice -eq 34){
        $procToDiff = Read-Host -Prompt "Enter process with extension (i.e. lsass.exe)"
        Get-CompareSingleProcessDiffs -ProcessName $procToDiff
    }
    elseif ($functionChoice -eq 35){
        $procToDiff = Read-Host -Prompt "Enter process with extension (i.e. lsass.exe)"
        $targetHash = Read-Host -Prompt "Enter SHA256 to focus results"
        Get-REDACTED_KEY -ProcessName $procToDiff -TargetHash $targetHash
    }
    elseif ($functionChoice -eq 36){
        Get-CompareAllProcessDiffs
    }
    elseif ($functionChoice -eq 37){
        Get-MaliciousDifferentialAnalysis
    }
    elseif ($functionChoice -eq 38){
        Get-TargetedMalwareAnalysis
    }
    elseif ($functionChoice -eq 39){
        Repair-VTBaseline
    }
    elseif ($functionChoice -eq 40){
        New-MalwareDashboard
    }
    else {
      Write-Host "You did not choose a valid option"
    }

