
<#
    Automate bulk IP address Abuse IP DB lookup from a text file and export the output to a CSV file.
    Replace the <FilePathofTxtFile.txt> with the actual file path of the .txt file, the <ApiKey> with your Abuse IP DB V2 API key, and run the PS script below on the console.

    It will create a CSV file with the following columns: ipAddress, countryCode, isp, domain, abuseConfidenceScore, totalReports, isWhitelisted, and isTor
#>

Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri 'https://api.abuseipdb.com/api/v2/check' -Method 'GET' -Headers @{'Key'="<ApiKey>";'Application'='application/json'} -Body @{'ipAddress'=$_; 'maxAgeInDays'='90'} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Export-Csv -Path 'output.csv' -NoTypeInformation