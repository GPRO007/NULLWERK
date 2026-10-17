$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$answer=[Windows.Forms.MessageBox]::Show('Uninstall NULLWERK for this Windows account? Game files and exported reports outside the app directory are not removed.','Uninstall NULLWERK','YesNo','Question')
if($answer -ne 'Yes'){exit 1602}
$target=[IO.Path]::GetFullPath($PSScriptRoot)
$expected=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\NULLWERK-Source'))
if($target -ne $expected){throw 'The uninstall location does not match the expected application directory.'}
$link=Join-Path ([Environment]::GetFolderPath('Programs')) 'NULLWERK (Python edition).lnk'
if(Test-Path -LiteralPath $link){Remove-Item -LiteralPath $link -Force}
$key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NULLWERK-Source'
if(Test-Path $key){Remove-Item $key -Recurse -Force}
Set-Location $env:TEMP
$manifestPath=Join-Path $target 'PACKAGE_MANIFEST.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
foreach($entry in $manifest.files){
 $file=[IO.Path]::GetFullPath((Join-Path $target $entry.path))
 if(!$file.StartsWith($target+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe uninstall manifest path.'}
 if(Test-Path -LiteralPath $file -PathType Leaf){Remove-Item -LiteralPath $file -Force}
}
Remove-Item -LiteralPath $manifestPath -Force
foreach($directory in (Get-ChildItem -LiteralPath $target -Directory -Recurse -Force|Sort-Object {$_.FullName.Length} -Descending)){
 if(!(Get-ChildItem -LiteralPath $directory.FullName -Force)){Remove-Item -LiteralPath $directory.FullName -Force}
}
if(!(Get-ChildItem -LiteralPath $target -Force)){Remove-Item -LiteralPath $target -Force}
[Windows.Forms.MessageBox]::Show('NULLWERK has been uninstalled. Local diagnostic logs, if any, are retained under LocalAppData\NULLWERK.','Uninstall complete')|Out-Null
