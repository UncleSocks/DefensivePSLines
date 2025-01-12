
<#
    Automate bulk IP address VirusTotal lookup from a text file.
    Either replace $TxtFilePath with the actual file path of the .txt file and $ApiKey with your virusTotal V3 API key, or define them as variables prior to running the one-liner.
    
    SAMPLE OUTPUT:
    IpAddress   AsOwner              Malicious Suspicious Undetected Harmless Timeout
    ---------   -------              --------- ---------- ---------- -------- -------
    8.8.8.8     GOOGLE                       0          0         31       63       0
    1.11.1.1    LG HelloVision Corp.         0          0         32       62       0
    4.2.2.2     LEVEL3                       0          0         32       62       0
    64.211.3.42 LVLT-3549                    0          0         94        0       0
    192.168.1.1                              0          0         32       62       0
    90.32.11.43 Orange                       0          0         94        0       0
#>

Get-Content -Path $TxtFilePath | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$_" -Method "GET" -Headers @{"accept"="application/json";"x-apikey"=$ApiKey} -ErrorAction SilentlyContinue; [PSCustomObject]@{IpAddress=$_;AsOwner=$lookup.data.attributes.as_owner;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Format-Table -AutoSize