$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
Set-Location $root
python -m pip install -r requirements-build.txt
if($LASTEXITCODE){throw 'Build dependencies could not be installed.'}
python -m unittest discover -s tests -v
if($LASTEXITCODE){throw 'Tests failed.'}
python tools/check_public_release.py
if($LASTEXITCODE){throw 'Public-release checks failed.'}
$env:PYTHONHASHSEED='0'
$env:SOURCE_DATE_EPOCH='1577836800'
python -m PyInstaller --noconfirm --clean --onedir --windowed --noupx --name NULLWERK --icon assets/nullwerk.ico --add-data 'assets;assets' --add-data 'profiles;profiles' --add-data 'LICENSE;.' --add-data 'NOTICE.txt;.' --add-data 'LEGAL.md;.' --add-data 'THIRD_PARTY_NOTICES.md;.' app.py
if($LASTEXITCODE){throw 'GUI build failed.'}
python -m PyInstaller --noconfirm --clean --onedir --console --noupx --name nullwerk-cli --add-data 'profiles;profiles' --add-data 'LICENSE;.' --add-data 'NOTICE.txt;.' --add-data 'LEGAL.md;.' --add-data 'THIRD_PARTY_NOTICES.md;.' workbench.py
if($LASTEXITCODE){throw 'CLI build failed.'}
$compiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
if(!(Test-Path -LiteralPath $compiler)){
 $iscc=Get-Command ISCC.exe -ErrorAction SilentlyContinue
 if($iscc){$compiler=$iscc.Source}
}
if(!(Test-Path -LiteralPath $compiler)){throw 'Install Inno Setup 6, then run this script again.'}
python tools/collect_runtime_notices.py --inno-root (Split-Path $compiler) dist/NULLWERK dist/nullwerk-cli
if($LASTEXITCODE){throw 'Required runtime license notices could not be collected.'}
& $compiler installer/nullwerk.iss
if($LASTEXITCODE){throw 'Installer build failed.'}
Get-ChildItem dist -Filter '*Setup.exe' | ForEach-Object {
 $hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
 ($hash+'  '+$_.Name)|Set-Content -LiteralPath ($_.FullName+'.sha256') -Encoding ascii
}
