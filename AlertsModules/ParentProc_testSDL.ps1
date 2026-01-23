#function Get-ParentProcs{

#    param (
#        [Parameter(Mandatory=$true)]
        $srcProcName = "lsass.exe"
        $timeToBaseline = "1"
        $os = "windows"
#    )


# Define variables
$apiToken = ''
$baseUrl = 'https://xdr.us1.sentinelone.net'
$query = "indicator.category = * | limit 1000"# | group count() by indicator.category"
#$query = "endpoint.os = '$os' and src.process.name = '$srcProcName' | columns src.process.parent.name | group srcProcParentCount = count (src.process.parent.name) by src.process.parent.name | sort -srcProcParentCount | limit 100" # Replace with your actual DeepViz query

$queryForGet = "%22indicator.category%20=%20*|limit%201000%22"
#$queryForGet = "%22endpoint.os%20=%20%27$os%27%20and%20src.process.name%20=%20%27$srcProcName%27%20|%20columns%20src.process.parent.name%20|%20group%20srcProcParentCount%20=%20count%20(src.process.parent.name)%20by%20src.process.parent.name%20|%20sort%20-srcProcParentCount%20|%20limit%20100%22"
#$siteId = 'your_site_id_here' # Replace with your actual Site ID (optional, depending on the scope of your query)
$pollingInterval = 3 # Interval in seconds to check the status of the query

# Define the endpoint URL for creating the Skylight query
$queryCreateUrl = "$baseUrl/api/powerQuery"
$queryCreateUrlforGet = "$baseUrl/api/powerQuery?query=$queryForGet&token=$apiToken"

# Time calculation
$currentTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = (Get-Date).AddHours(-$timeToBaseline).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "Bearer $apiToken"
    'Content-Type' = 'application/json'
}

# Define the payload for the Power query
$params = @{
    "query" = $query
    #'startTime' = "$($lastDayTime)"
    #'endTime' = "$($currentTime)"


} | ConvertTo-Json

# Step 1: Create the Power query
#$parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
#$parentProcResponse = Invoke-WebRequest -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
$parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrlforGet -Method Get

if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
    $queryId = $parentProcResponse.data.queryId
    Write-Output "Parent Process Query created successfully with Query ID: $queryId"
} else {
    Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
    break
}

# Step 2: Poll the query status until it's complete
$queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
$status = 'running'
while ($status -ne 'FINISHED') {
    try {
        $statusResponse = Invoke-RestMethod -Uri $queryStatusUrl -Method Get -Headers $headers
    }
    catch {
        Write-Host -ForegroundColor red "Could not get parent procs for the enterprise (surrounding the process from the alert). S1 API Issues."
        break
    }
    $status = $statusResponse.data.status
    $progress = $statusResponse.data.progress
    
    Write-Output "Current query progress: $progress"
    Start-Sleep -Seconds $pollingInterval
}

# Step 3: Once the status is finished, retrieve the results
if ($status -eq 'FINISHED') {
    Write-Output "Query completed successfully."
    #$statusResponse.data.data | ForEach-Object { $_.GetValue(0);$_.GetValue(1) } | Export-Csv -Path "parentProcs.csv"
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\parentProcs.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

#}