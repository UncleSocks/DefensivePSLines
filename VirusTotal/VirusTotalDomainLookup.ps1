
<#
    Automate bulk domain VirusTotal lookup from a text file.
    Replace the <FilePathofTxtFile.txt> with the actual file path of the .txt file, the <ApiKey> with your virusTotal V3 API key, and run the PS script below on the console.

    SAMPLE OUTPUT:
    Domain       Registrar                    Malicious Suspicious Undetected Harmless Timeout
    ------       ---------                    --------- ---------- ---------- -------- -------
    google.com   MarkMonitor Inc.                     0          0         28       66       0
    facebook.com RegistrarSafe, LLC                   0          1         27       66       0
    rog.us       TLD Registrar Solutions Ltd.         0          0         35       59       0
#>

Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $lookup=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$_" -Method GET -Headers @{"accept"="application/json";"x-apikey"="<ApiKey>"} -ErrorAction SilentlyContinue; [PSCustomObject]@{Domain=$_;Registrar=$lookup.data.attributes.registrar;Malicious=$lookup.data.attributes.last_analysis_stats.malicious;Suspicious=$lookup.data.attributes.last_analysis_stats.suspicious;Undetected=$lookup.data.attributes.last_analysis_stats.undetected;Harmless=$lookup.data.attributes.last_analysis_stats.harmless;Timeout=$lookup.data.attributes.last_analysis_stats.timeout}} | Format-Table -AutoSize