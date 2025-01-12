
<#
    Automate bulk IP address Abuse IP DB lookup from a text file and export the output to a CSV file.
    Either replace $TxtFilePath with the actual file path of the .txt file and $ApiKey with your Abuse IP DB V2 API key, or define them as variables prior to running the one-liner.

    It will create a CSV file with the following columns: ipAddress, countryCode, isp, domain, abuseConfidenceScore, totalReports, isWhitelisted, and isTor
#>

Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="$ApiKey";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Export-Csv -Path "output.csv" -NoTypeInformation