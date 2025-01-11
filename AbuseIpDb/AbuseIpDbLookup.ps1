
<#
    Automate bulk IP address Abuse IP DB lookup from a text file.
    Replace the <FilePathofTxtFile.txt> with the actual file path of the .txt file, the <ApiKey> with your Abuse IP DB V2 API key, and run the PS script below on the console.

    SAMPLE OUTPUT:
    ipAddress     countryCode isp                                       domain         abuseConfidenceScore totalReports isWhitelisted isTor
    ---------     ----------- ---                                       ------         -------------------- ------------ ------------- -----
    1.1.1.1       AU          APNIC and Cloudflare DNS Resolver project cloudflare.com                    0          178          True False
    8.8.8.8       US          Google LLC                                google.com                        0          137          True False
    98.199.20.100 US          Comcast Cable Communications, Inc.        comcast.net                       0            0               False
    192.168.1.1               Private IP Address LAN                                                      0           18         False False
#>

Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="<ApiKey>";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Format-Table -AutoSize