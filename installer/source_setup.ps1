$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem
$script:target=Join-Path $env:LOCALAPPDATA 'Programs\NULLWERK-Source'
$script:setup=$env:NULLWERK_SETUP_PATH
$script:silent=$env:NULLWERK_SETUP_SILENT -eq '1'
$script:exit=1602
function PythonPath {
 foreach($name in @('py.exe','python.exe')) {
  $cmd=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
  if(!$cmd){continue}
  $p=New-Object System.Diagnostics.Process
  $p.StartInfo=New-Object System.Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName=$cmd.Source
  $probeArgs='-X utf8 -c "import sys, tkinter; assert sys.version_info >= (3,11); print(sys.executable)"'
  if($name -eq 'py.exe'){$probeArgs='-3 '+$probeArgs}
  $p.StartInfo.Arguments=$probeArgs
  $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
  $p.StartInfo.StandardOutputEncoding=[Text.Encoding]::UTF8
  $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
  [void]$p.Start()
  if(!$p.WaitForExit(12000)){try{$p.Kill()}catch{};continue}
  if($p.ExitCode -eq 0){$v=$p.StandardOutput.ReadToEnd().Trim();if(Test-Path -LiteralPath $v -PathType Leaf){return $v}}
 }
 throw 'Python 3.11 or later with Tcl/Tk is required. Install it from python.org, then run this installer again.'
}
function ReadPayload {
 if($env:NULLWERK_PACKAGE_PATH){
  $data=[IO.File]::ReadAllBytes($env:NULLWERK_PACKAGE_PATH)
 }else{
  $fs=[IO.File]::OpenRead($script:setup)
  try {
  $fs.Seek(-16,[IO.SeekOrigin]::End)|Out-Null
  $br=New-Object IO.BinaryReader($fs)
  $magic=[Text.Encoding]::ASCII.GetString($br.ReadBytes(8))
  $size=$br.ReadInt64()
  if($magic -ne 'NWPKG001' -or $size -le 0 -or $size -gt $fs.Length-16){throw 'Invalid installer payload.'}
  $fs.Seek($fs.Length-16-$size,[IO.SeekOrigin]::Begin)|Out-Null
  $data=$br.ReadBytes([int]$size)
  }finally{$fs.Dispose()}
 }
 $sha=[Security.Cryptography.SHA256]::Create()
 $hash=([BitConverter]::ToString($sha.ComputeHash($data))).Replace('-','').ToLowerInvariant()
 $sha.Dispose()
 if($hash -ne '@PAYLOAD_HASH@'){throw 'Installer payload checksum failed.'}
 return ,$data
}
function InstallApp {
 $python=PythonPath
 $data=ReadPayload
 $parent=Split-Path $script:target
 [IO.Directory]::CreateDirectory($parent)|Out-Null
 $id=[Guid]::NewGuid().ToString('N')
 $stage=Join-Path $parent ('.nullwerk-stage-'+$id)
 $backup=Join-Path $parent ('.nullwerk-backup-'+$id)
 $zip=Join-Path ([IO.Path]::GetTempPath()) ('nullwerk-'+$id+'.zip')
 $swapped=$false;$hadOld=Test-Path -LiteralPath $script:target
 try {
  [IO.File]::WriteAllBytes($zip,$data)
  [IO.Compression.ZipFile]::ExtractToDirectory($zip,$stage)
  $manifest=Get-Content -LiteralPath (Join-Path $stage 'PACKAGE_MANIFEST.json') -Raw|ConvertFrom-Json
  foreach($entry in $manifest.files){
   $path=Join-Path $stage $entry.path
   $resolved=[IO.Path]::GetFullPath($path)
   if(!$resolved.StartsWith([IO.Path]::GetFullPath($stage)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe package path.'}
   $stream=[IO.File]::OpenRead($path)
   $hasher=[Security.Cryptography.SHA256]::Create()
   try{$actual=([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
   finally{$stream.Dispose();$hasher.Dispose()}
   if($actual -ne $entry.sha256){throw 'Application file checksum failed.'}
  }
  $pythonw=Join-Path (Split-Path $python) 'pythonw.exe'
  if(!(Test-Path -LiteralPath $pythonw)){$pythonw=$python}
  if($hadOld){
   $oldManifest=Join-Path $script:target 'PACKAGE_MANIFEST.json'
   if(!(Test-Path -LiteralPath $oldManifest)){throw 'The destination is not a managed NULLWERK installation. Rename that folder before installing.'}
   $owned=@{};$owned['PACKAGE_MANIFEST.json']=$true
   foreach($item in ((Get-Content -LiteralPath $oldManifest -Raw|ConvertFrom-Json).files)){$owned[$item.path.Replace('/','\')]=$true}
   foreach($item in (Get-ChildItem -LiteralPath $script:target -File -Recurse -Force)){
    $relative=$item.FullName.Substring($script:target.Length+1)
    if(!$owned.ContainsKey($relative)){
     $keep=Join-Path $stage $relative
     if(Test-Path -LiteralPath $keep){$keep=Join-Path $stage ('preserved\'+$relative)}
     [IO.Directory]::CreateDirectory((Split-Path $keep))|Out-Null
     Copy-Item -LiteralPath $item.FullName -Destination $keep
    }
   }
   [IO.Directory]::Move($script:target,$backup)
  }
  [IO.Directory]::Move($stage,$script:target);$swapped=$true
  $shell=New-Object -ComObject WScript.Shell
  $link=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Programs')) 'NULLWERK (Python edition).lnk'))
  $link.TargetPath=$pythonw;$link.Arguments='"'+(Join-Path $script:target 'app.py')+'"'
  $link.WorkingDirectory=$script:target;$link.IconLocation=(Join-Path $script:target 'assets\nullwerk.ico')+',0'
  $link.Description='NULLWERK - Authorized Steam-integration maintenance';$link.Save()
  $key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NULLWERK-Source'
  New-Item $key -Force|Out-Null
  $ps=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
  $uninstall='"'+$ps+'" -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $script:target 'Uninstall.ps1')+'"'
  $values=@{DisplayName='NULLWERK (Python edition)';DisplayVersion='4.2.0';Publisher='NULLWERK contributors';InstallLocation=$script:target;DisplayIcon=(Join-Path $script:target 'assets\nullwerk.ico');UninstallString=$uninstall}
  foreach($k in $values.Keys){New-ItemProperty $key -Name $k -Value $values[$k] -PropertyType String -Force|Out-Null}
  New-ItemProperty $key -Name NoModify -Value 1 -PropertyType DWord -Force|Out-Null
  New-ItemProperty $key -Name NoRepair -Value 1 -PropertyType DWord -Force|Out-Null
  if(Test-Path -LiteralPath $backup){Remove-Item -LiteralPath $backup -Recurse -Force}
 }catch {
  if($swapped -and (Test-Path -LiteralPath $script:target)){Remove-Item -LiteralPath $script:target -Recurse -Force}
  if(Test-Path -LiteralPath $backup){[IO.Directory]::Move($backup,$script:target)}
  throw
 }finally {
  if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force}
  if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
 }
}
if($script:silent){try{InstallApp;exit 0}catch{
 $message=$_.Exception.ToString()+[Environment]::NewLine+$_.ScriptStackTrace
 if($env:NULLWERK_SETUP_LOG){[IO.File]::WriteAllText($env:NULLWERK_SETUP_LOG,$message)}
 [Console]::Error.WriteLine($message);exit 1
}}
$form=New-Object Windows.Forms.Form
$form.Text='NULLWERK Setup';$form.ClientSize=New-Object Drawing.Size(560,365)
$form.StartPosition='CenterScreen';$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false
$form.BackColor=[Drawing.Color]::FromArgb(16,23,34);$form.ForeColor=[Drawing.Color]::FromArgb(231,238,245)
$form.Font=New-Object Drawing.Font('Segoe UI',10)
try{$form.Icon=[Drawing.Icon]::ExtractAssociatedIcon($script:setup)}catch{}
$title=New-Object Windows.Forms.Label
$title.Text='NULLWERK';$title.Font=New-Object Drawing.Font('Segoe UI',25,[Drawing.FontStyle]::Bold)
$title.SetBounds(28,24,500,48);$form.Controls.Add($title)
$subtitle=New-Object Windows.Forms.Label
$subtitle.Text='Authorized Steam-integration maintenance';$subtitle.SetBounds(30,78,490,25)
$subtitle.ForeColor=[Drawing.Color]::FromArgb(96,226,188);$form.Controls.Add($subtitle)
$info=New-Object Windows.Forms.Label
$info.Text="Installs for your Windows account. No administrator access required.`r`n`r`nRequires Python 3.11 or later with Tcl/Tk. This installer works offline.`r`n`r`nDestination:`r`n"+$script:target
$info.SetBounds(30,124,495,130);$form.Controls.Add($info)
$status=New-Object Windows.Forms.Label
$status.Text='Ready. Checksum first. Coffee second.';$status.SetBounds(30,268,490,30);$form.Controls.Add($status)
$button=New-Object Windows.Forms.Button
$button.Text='Install NULLWERK';$button.SetBounds(300,310,225,36)
$button.BackColor=[Drawing.Color]::FromArgb(96,226,188);$button.ForeColor=[Drawing.Color]::FromArgb(16,38,31)
$button.FlatStyle='Flat';$form.Controls.Add($button)
$cancel=New-Object Windows.Forms.Button
$cancel.Text='Cancel';$cancel.SetBounds(30,310,110,36);$cancel.FlatStyle='Flat';$form.Controls.Add($cancel)
$cancel.Add_Click({$form.Close()})
$button.Add_Click({
 $button.Enabled=$false;$cancel.Enabled=$false;$status.Text='Installing and verifying files...';$form.Refresh()
 try{InstallApp;$script:exit=0;[Windows.Forms.MessageBox]::Show('NULLWERK is installed. Open it from the Start menu.','Installation complete')|Out-Null;$form.Close()}
 catch{$status.Text='Installation stopped.';[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Installation failed')|Out-Null;$button.Enabled=$true;$cancel.Enabled=$true}
})
[void]$form.ShowDialog()
exit $script:exit
