
<#
    Automate bulk IP address reverse DNS lookup from a text file.
    Either replcee $TxtFilePath with the actual file path of the .txt file or define it as a variable prior to running the one-liner.

    SAMPLE OUTPUT:
    IpAddress     Domain
    ---------     ------
    1.1.1.1       one.one.one.one
    8.8.8.8       dns.google
#>

Get-Content -Path $TxtFilePath | ForEach-Object { $domain=Resolve-DnsName -Name $_ -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost; [PSCustomObject]@{IpAddress=$_;Domain=$domain} } | Format-Table -AutoSize