function Get-CheckAttribution{
    #This is if you don't have the private VT license
    param (
        [Parameter(Mandatory=$true)]
        $fileHash,
        $baselineWorkingWith
    )

    $attributionPattern = "equifax"

    #First check the Intezer strings for attribution
    $isMatch = $False
    $jsonFilePath = ".\output-baseline\IntezerStrings\$($fileHash).json"
    $isMatch = Select-String -Path $($jsonFilePath) -Pattern $attributionPattern -CaseSensitive:$false -Quiet
    if ($isMatch) {
        #Find the value to append
        $appendValue
        foreach ($unsProc in $unsignedWinProcsBaseline) {
            if ($fileHash -eq $($unsProc.value[2])){
                $appendValue = $unsProc
            }
        }

        #append the value metadata to the exclusions
        $filePath = "output\baselineVTExclusions.json"
        $baselineVTExclusions = Get-Content $filePath | ConvertFrom-Json
        $baselineVTExclusions += $appendValue
        $baselineVTExclusions | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding UTF8
        return $True
    } else {
        return $False
    }

}