
<#
    Capture and parse external DNS queries from Windows Event ID 3008, sorted in ascending order. This is a fragment from my Buck PS script.
    For this one-liner to work, ensure that Microsoft Windows DNS Client Operational logging is enabled. Please also note that it may take a while depending on the max log file configured.

    SAMPLE OUTPUT:
    DnsQuery
    --------
    github.com
    rog.asus.com
    www.google.com
    zoom.us
#>

Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object {$_.Id -eq '3008' -and $_.Message -ne (Hostname) -and $_.Message -notmatch "..localmachine"} | ForEach-Object {if ($_.Message -match "DNS query is completed for the name ([^,\s]+)") {$matches[1]}} | Sort-Object | Select-Object -Unique @{Name="DnsQuery";Expression={$_}}