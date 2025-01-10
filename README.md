# PowerShell One Liners for Cyber Defender

A collection of PowerShell one-liners for cyber defenders to automate tasks that typically require the ISE or running as a .ps1 script.

## Reverse DNS Lookup
Automate bulk IP address reverse DNS lookup from a text file. Replace the `<FilePathofTxtFile.txt>` with the actual .txt file path.
```
Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $domain=Resolve-DnsName -Name $_ -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost; [PSCustomObject]@{IPAddress=$_;Domain=$domain} } | Format-Table -AutoSize
```

## Abuse IP DB Lookup
Automate bulk IP address Abuse IP DB lookup from a text file. Replace the `<FilePathofTxtFile.txt>` with the actual .txt file path and the `<ApiKey>` with your Abuse IP DB v2 API key.
```
Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri 'https://api.abuseipdb.com/api/v2/check' -Method 'GET' -Headers @{'Key'="<ApiKey>";'Application'='application/json'} -Body @{'ipAddress'=$_; 'maxAgeInDays'='90'} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Format-Table -AutoSize
```

If you want to export the output to a CSV file, use the following one-liner, instead:
This will create a **output.csv** file on the currenct directory.
```
Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri 'https://api.abuseipdb.com/api/v2/check' -Method 'GET' -Headers @{'Key'="<ApiKey>";'Application'='application/json'} -Body @{'ipAddress'=$_; 'maxAgeInDays'='90'} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Export-Csv -Path 'output.csv' -NoTypeInformation
```

## VirusTotal Lookup
Automate bulk IP address VirusTotal lookup from a text file. Replace the `<FilePathofTxtFile.txt>` with the actual .txt file path.
```
Get-Content -Path .<FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$_" -Method GET -Headers @{"accept"="application/json";"x-apikey"="<ApiKey>"} -ErrorAction SilentlyContinue; [PSCustomObject]@{IpAddress=$_;AsOwner=$lookup.data.attributes.as_owner;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Format-Table -AutoSize
```
