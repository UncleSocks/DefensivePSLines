# PowerShell One Liners for Cyber Defender

A collection of PowerShell (PS) one-liners for cyber defenders to automate tasks that typically require the ISE or running a .ps1 script.

For each of the one-liners, you can either replace each variable directly or define them before running the PS command.

## Shortcut (LNK) Target
Recursively captures all LNK files from the base directory ($BaseDir) and displays each shortcut's target path. This will also display its directory and any arguments.

_Note: You can substitute the `$BaseDir` with `(Get-Location)` to recursively capture LNK files in your pwd._
```
$Sh=New-Object -ComObject WScript.Shell;Get-ChildItem -Recurse $BaseDir -Include *.lnk | ForEach-Object {[PSCustomObject]@{ Name=$_.Name;Dir=$_.Directory;Target=$Sh.CreateShortcut($_).TargetPath;Arguments=$Sh.CreateShortcut($_).Arguments }} | Format-Table -AutoSize
```

If you want to export the output to a CSV file, use the following one-liner instead:
This will create a **output.csv** file in the current directory.
```
$Sh=New-Object -ComObject WScript.Shell;Get-ChildItem -Recurse $ParentFilePath -Include *.lnk | ForEach-Object {[PSCustomObject]@{ Name=$_.Name;Dir=$_.Directory;Target=$Sh.CreateShortcut($_).TargetPath;Arguments=$Sh.CreateShortcut($_).Arguments }} | Export-Csv -Path "output.csv" -NoTypeInformation
```

## Reverse DNS Lookup
Automate bulk IP address reverse DNS lookup from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file or define it as a variable before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $domain=Resolve-DnsName -Name $_ -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost; [PSCustomObject]@{IpAddress=$_;Domain=$domain} } | Format-Table -AutoSize
```

## Windows Event External DNS Query
Captures external DNS queries from Windows Event ID 3008. Ensure that Microsoft Windows DNS Client Operational logging is enabled. Please also note that, depending on the max log file configured, it may take a while.
```
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object {$_.Id -eq '3008' -and $_.Message -ne (Hostname) -and $_.Message -notmatch "..localmachine"} | ForEach-Object {if ($_.Message -match "DNS query is completed for the name ([^,\s]+)") {$matches[1]}} | Sort-Object | Select-Object -Unique @{Name="DnsQuery";Expression={$_}}
```

## Hash IOC Search
Automate the search for hash IOCs in a local Windows host. Either directly replace the following variables or define them before running the one-liner:
- `$TxtFilePath` with the actual .txt file path
- `$Directory` with the directory to be scanned
- `$Extensions` with the list of extensions to include in the scan, use `*.*` to scan all extensions
- `$Algorithm` with the hash algorithm -- Get-FileHash currently supports MD5, SHA1, SHA256, SHA384, SHA512
```
$Output=@(); $FileCounter=0; $HashList=Get-Content -Path $TxtFilePath; Get-ChildItem -Path $Directory -Recurse -File -Force -Include $Extensions -ErrorAction SilentlyContinue | ForEach-Object {$FileHash=Get-FileHash -Path $_.FullName -Algorithm $Algorithm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash; Write-Progress -Activity "Searching for file hashes..." -Status "Files Processed: $FileCounter | Current Directory:$($_.Directory)" -PercentComplete (($FileCounter %100) * 1); $FileCounter++; if ($FileHash -in $HashList) {$Output+=[PSCustomObject]@{Hash=$FileHash;FilePath=$_.FullName}}}; $Output | Format-Table -AutoSize  
```

## Abuse IP DB Lookup
Automate bulk IP address Abuse IP DB lookup from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file and `$ApiKey` with your Abuse IP DB V2 API key, or define them as variables before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="$ApiKey";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,usageType,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Format-Table -AutoSize
```

If you want to export the output to a CSV file, use the following one-liner instead:
This will create a **output.csv** file in the current directory.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="$ApiKey";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,usageType,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Export-Csv -Path "output.csv" -NoTypeInformation
```

## VirusTotal Lookup
### IP Address
Automate bulk IP address lookups on VirusTotal from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file and `$ApiKey` with your VirusTotal V3 API key, or define them as variables before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"=$ApiKey} -ErrorAction SilentlyContinue; [PSCustomObject]@{IpAddress=$_;AsOwner=$lookup.data.attributes.as_owner;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout;Tags=$lookup.data.attributes.tags -join ';'}} | Format-Table -AutoSize
```

If you want to export the output to a CSV file, use the following one-liner instead:
This will create a **output.csv** file in the current directory.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"="$ApiKey"} -ErrorAction SilentlyContinue; [PSCustomObject]@{IpAddress=$_;AsOwner=$lookup.data.attributes.as_owner;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout;Tags=$lookup.data.attributes.tags -join ';'}} | Export-Csv -Path "output.csv" -NoTypeInformation
```
### Domain
Automate bulk domain VirusTotal lookup from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file and `$ApiKey` with your VirusTotal V3 API key, or define them as variables before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"="$ApiKey"} -ErrorAction SilentlyContinue; [PSCustomObject]@{Domain=$_;Registrar=$lookup.data.attributes.registrar;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Format-Table -AutoSize
```

If you want to export the output to a CSV file, use the following one-liner instead:
This will create a **output.csv** file in the current directory.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"="$ApiKey"} -ErrorAction SilentlyContinue; [PSCustomObject]@{Domain=$_;Registrar=$lookup.data.attributes.registrar;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Export-Csv -Path "output.csv" -NoTypeInformation
```
