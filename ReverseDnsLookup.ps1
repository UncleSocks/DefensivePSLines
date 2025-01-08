
<#
    Automate reverse DNS lookup of multiple IP addresses from a text file.
    Replace the <FilePathofTxtFile.txt> with the actual file path of the .txt file and run the PS script below on the console.

    Sample output:
    8.8.8.8 : dns.google
    1.1.1.1 : one.one.one.one
#>

Get-Content -Path <FilePathofTxtFile.txt> | ForEach-Object { $domain=Resolve-DnsName -Name $_ -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost; Write-Output "$_ : $domain" }