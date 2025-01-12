
<#
    Automate hash IOC checks in a local Windows machine. Either directly replace the following variables or define them prior to running the one-liner:
    > $TxtFilePath=<FilePathOfHashIocs>
    > $Directory=<DirectoryToScan>
    > $Extensions=<ArrayOfExtensions> #To check all extensions enter @("*.*")
    > $Algorithm=<MD5,SHA1,SHA256,SHA384,SHA512>

    SAMPLE OUTPUT:
    Hash                                                             FilePath
    ----                                                             --------
    CC711971587726F7AB2DA909186BD5D1B2CC7E94CC17B7B34DA379D7147B202B C:\Program Files (x86)\Steam\steamapps\common\Tom Clancy's Rainbow Six Siege\RainbowSix.exe
    7EC9B28C8B5DCA771BD9C485BC27E656943EDD3E8A4954171719FD7CE2B582BC C:\Program Files (x86)\Steam\steamapps\common\Tom Clancy's Rainbow Six Siege\upc_r2_loader.dll
#>


$Output=@(); $FileCounter=0; $HashList=Get-Content -Path $TxtFilePath; Get-ChildItem -Path $Directory -Recurse -File -Force -Include $Extensions -ErrorAction SilentlyContinue | ForEach-Object {$FileHash=Get-FileHash -Path $_.FullName -Algorithm $Algorithm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash; Write-Progress -Activity "Searching for file hashes..." -Status "Files Processed: $FileCounter | Current Directory:$($_.Directory)" -PercentComplete (($FileCounter %100) * 1); $FileCounter++; if ($FileHash -in $HashList) {$Output+=[PSCustomObject]@{Hash=$FileHash;FilePath=$_.FullName}}}; $Output | Format-Table -AutoSize  