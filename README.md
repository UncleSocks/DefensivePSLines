# Inline PowerShell Commands for Cyber Defense

A collection of PowerShell inline (one-liner) commands to help cyber defenders and security professionals in their investigations. Some commands may require you to define the variable(s) or directly substitute them before execution. Personally, I use these commands when investigating endpoints via an EDR and I need to quickly capture specific information.

You can also change the `Export-Csv` pipeline to `Format-Table -AutoSize` if you want to display the output in the console; the output path can always be changed according to your preference.


## Recursively Search for NPM Packages
```
Get-ChildItem -Path $Dir -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {$_.Parent.Name -like '*node_modules' -and $_.Name -notlike '*.bin'} | ForEach-Object {$npm=(Get-Content "$($_.FullName)\package.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json);[PSCustomObject]@{FullPath=$_.FullName;Package="$($npm.name)@$($npm.version)"}} | Export-Csv "output.csv" -NoTypeInformation
```
```
Get-ChildItem -Path $Dir -Recurse -ErrorAction SilentlyContinue -Force | Where-Object {$_.Name -eq $PackageName} | ForEach-Object {$npm=(Get-Content "$($_.FullName)\package.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json);[PSCustomObject]@{FullPath=$_.FullName;Package="$($npm.name)@$($npm.version)"}} | Export-Csv "output.csv" -NoTypeInformation
```


## Enumerate Run Registry Key [T1547.001]
**MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder):** Adversaries can reference a program in the "Run" registry key to achieve persistence. Once added to this key, the malicious program will be executed automatically when a user logs in. The "Run" key is present at the machine (HKLM) or at the user (HKU) level:

**HKLM:** This command will capture all "Run" properties and their values at the machine level.
```
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").PSObject.Properties | Where-Object Name -NotIn @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') | Select-Object Name, Value | Export-Csv "output.csv" -NoTypeInformation
```
**HKU:** This command iterates over the HKEY_USERS key to retrieve the "Run" properties and their corresponding values for each user. This also captures the SID to which the property belongs.
```
Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue -Force | ForEach-Object{$sid=$_.PSChildName;(Get-ItemProperty -Path ($_.PSPath+"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object Name -NotIn @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') | Select-Object @{n='SID';e={$sid}}, Name, Value} | Export-Csv "output.csv" -NoTypeInformation
```

## List Scheduled Tasks [T1053.005]
**MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task):** Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. They may also use Windows Task Scheduler to execute malware at startup or on a scheduled basis for persistence. This command captures all scheduled tasks using `Get-ScheduledTask` and displays the task name, status, task path, author, description, action with arguments, and last and next run times.
```
Get-ScheduledTask | ForEach-Object {$STInfo=Get-ScheduledTaskInfo -TaskName ($_.TaskPath+$_.TaskName);[PSCustomObject]@{Name=$_.TaskName;State=$_.State;TaskPath=$_.TaskPath;Author=$_.Author;Description=$_.Description;Actions=($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "|";LastRunTime=$STInfo.LastRunTime;NextRunTime=$STInfo.NextRunTime}} | Export-Csv "output.csv" -NoTypeInformation
```

## Image File Execution Option (IFEO) Debugger [T1546.012]
**MITRE ATT&CK T1546.012 (Event Triggered Execution: Image File Execution Options Injection):** Adversaries may abuse the IEFO Debugger value to point to a malicious executable instead of a legitimate debugger software. This command recursively captures the subkeys within IFEO and displays their Debugger values, if any, along with other properties.
```
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue -Force | ForEach-Object {[PSCustomObject]@{Name=$_.PSChildName;Debugger=(Get-ItemProperty $_.PSPath).Debugger;Properties=$_.Property -join "|"}} | Export-Csv "output.csv" -NoTypeInformation
```

## Shortcut (LNK) Target Path [T1547.009] [T1204.002]
**MITRE ATT&CK T1547.009 (Boot or Logon Autostart Execution: Shortcut Modification):** Adversaries may create or modify shortcuts in the startup folder ("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") to execute their tools and maintain persistence. This command captures all shortcut files (LNK) in the startup folder and displays their target path and arguments.
```
$Sh=New-Object -ComObject WScript.Shell;Get-ChildItem -Recurse "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Include *.lnk -ErrorAction SilentlyContinue -Force | ForEach-Object {[PSCustomObject]@{Name=$_.Name;Dir=$_.Directory;Target=$Sh.CreateShortcut($_).TargetPath;Arguments=$Sh.CreateShortcut($_).Arguments}} | Export-Csv "output.csv" -NoTypeInformation
```

**MITRE ATT&CK T1204.002 (User Execution: Malicious File):** Adversaries may masquerade their malware using legitimate-looking LNK files. This command can be used to output all LNK files and their actual target path and arguments.

_Note: You can substitute the `$BaseDir` with `(Get-Location)` to recursively capture LNK files in your pwd._
```
$Sh=New-Object -ComObject WScript.Shell;Get-ChildItem -Recurse $BaseDir -Include *.lnk | ForEach-Object {[PSCustomObject]@{Name=$_.Name;Dir=$_.Directory;Target=$Sh.CreateShortcut($_).TargetPath;Arguments=$Sh.CreateShortcut($_).Arguments}} | Export-Csv -Path "output.csv" -NoTypeInformation
```

## Microsoft Windows DNS Client Event ID 3008 External Queries [T1568.002]
**MITRE ATT&CK T1568.002 (Dynamic Resolution: Domain Generation Algorithms):** Adversaries may use Domain Generation Algorithms (DGA) to generate random and/or "gibberish" domains for the command & control (C2) communication. This command captures Windows Event ID 3008 and identifies external DNS queries performed by the hosts, which can help identify unusual domain names. 

_Note: Ensure that Microsoft Windows DNS Client Operational logging is enabled. Depending on the max log file configured, it may take sometime to complete._
```
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object {$_.Id -eq '3008' -and $_.Message -ne (Hostname) -and $_.Message -notmatch "..localmachine"} | ForEach-Object {if ($_.Message -match "DNS query is completed for the name ([^,\s]+)") {$matches[1]}} | Sort-Object | Select-Object -Unique @{Name="DnsQuery";Expression={$_}} | Export-Csv "output.csv" -NoTypeInformation
```

## Automating Bulk Inputs
## Reverse DNS Lookup
Automate bulk IP address reverse DNS lookup from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file or define it as a variable before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $domain=Resolve-DnsName -Name $_ -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost; [PSCustomObject]@{IpAddress=$_;Domain=$domain} } | Format-Table -AutoSize
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
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check" -Method "GET" -Headers @{"Key"="$ApiKey";"Application"="application/json"} -Body @{"ipAddress"=$_; "maxAgeInDays"="90"} -ErrorAction SilentlyContinue; $lookup.data } | Select-Object ipAddress,countryCode,usageType,isp,domain,abuseConfidenceScore,totalReports,isWhitelisted,isTor | Export-Csv -Path "output.csv" -NoTypeInformation
```

## VirusTotal Lookup
### IP Address
Automate bulk IP address lookups on VirusTotal from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file and `$ApiKey` with your VirusTotal V3 API key, or define them as variables before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"="$ApiKey"} -ErrorAction SilentlyContinue; [PSCustomObject]@{IpAddress=$_;AsOwner=$lookup.data.attributes.as_owner;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout;Tags=$lookup.data.attributes.tags -join ';'}} | Export-Csv -Path "output.csv" -NoTypeInformation
```
### Domain
Automate bulk domain VirusTotal lookup from a text file. Either directly replace `$TxtFilePath` with the actual file path of the .txt file and `$ApiKey` with your VirusTotal V3 API key, or define them as variables before running the one-liner.
```
Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"="$ApiKey"} -ErrorAction SilentlyContinue; [PSCustomObject]@{Domain=$_;Registrar=$lookup.data.attributes.registrar;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Export-Csv -Path "output.csv" -NoTypeInformation
```
