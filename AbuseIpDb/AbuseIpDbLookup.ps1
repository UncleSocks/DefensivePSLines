
<#
    Automate bulk IP address Abuse IP DB lookup from a text file.
    Either replace $TxtFilePath with the actual file path of the .txt file and $ApiKey with your Abuse IP DB V2 API key, or define them as variables prior to running the one-liner.

    SAMPLE OUTPUT:
    ipAddress     countryCode isp                                       domain         abuseConfidenceScore totalReports isWhitelisted isTor
    ---------     ----------- ---                                       ------         -------------------- ------------ ------------- -----
    1.1.1.1       AU          APNIC and Cloudflare DNS Resolver project cloudflare.com                    0          178          True False
    8.8.8.8       US          Google LLC                                google.com                        0          137          True False
    98.199.20.100 US          Comcast Cable Communications, Inc.        comcast.net                       0            0               False
    192.168.1.1               Private IP Address LAN                                                      0           18         False False

    Defining the variables (example):
    > $TxtFilePath="C:\Users\UncleSocks\LocationOfFile\address.txt"
    > $ApiKey="ThisIsARandomString1234567890"
#>

Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="$ApiKey";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Format-Table -AutoSize