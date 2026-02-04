<#
.SYNOPSIS
    Retrieves VirusTotal API usage using a stored secret.

.DESCRIPTION
    Fetches the API Key from the PowerShell SecretStore and queries
    the VirusTotal v3 'users' endpoint for quota details.

.PARAMETER SecretName
    The name of the secret stored in the vault. Defaults to 'VT_API_Key_1'.

.EXAMPLE
    Get-VTUsage
#>
function Get-VTUsage {
    [CmdletBinding()]
    param (
        [string]$SecretName = 'VT_API_Key_2'
    )

    # 1. Retrieve the API Key from the SecretStore
    try {
        # -AsPlainText is required because Invoke-RestMethod needs a standard string for headers,
        # not a SecureString object.
        $ApiKey = Get-Secret -Name $SecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        Write-Error "Could not retrieve secret '$SecretName'. Please ensure the 'Microsoft.PowerShell.SecretManagement' module is installed and your vault is unlocked."
        return
    }

    # 2. VirusTotal API v3 Endpoint
    # We use the API Key itself as the User ID
    $Url = "https://www.virustotal.com/api/v3/users/$ApiKey"

    $Headers = @{
        "x-apikey" = $ApiKey
        "accept"   = "application/json"
    }

    # 3. Query the API
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers -ErrorAction Stop
        
        $QuotaData = $Response.data.attributes.quotas.api_requests_daily
        $MonthlyData = $Response.data.attributes.quotas.api_requests_monthly

        [PSCustomObject]@{
            'Daily Used'      = $QuotaData.used
            'Daily Allowed'   = $QuotaData.allowed
            'Daily Remaining' = ($QuotaData.allowed - $QuotaData.used)
            'Monthly Used'    = $MonthlyData.used
        }
    }
    catch {
        # Handle API errors (e.g., 401 Unauthorized if key is wrong)
        if ($_.Exception.Response) {
            Write-Error "VirusTotal API Error: $($_.Exception.Response.StatusCode.value__) - $($_.ErrorDetails.Message)"
        } else {
            Write-Error "Connection Error: $($_.Exception.Message)"
        }
    }
}