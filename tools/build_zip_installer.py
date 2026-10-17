"""Build an offline source-install ZIP that does not require a native bootstrap."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile
from build_source_installer import ROOT,VERSION,payload_bytes


def build(destination):
    payload=payload_bytes();payload_hash=hashlib.sha256(payload).hexdigest()
    script=(ROOT/'installer/source_setup.ps1').read_text(encoding='utf-8').replace('@PAYLOAD_HASH@',payload_hash)
    launcher='''@echo off
setlocal
set "NULLWERK_PACKAGE_PATH=%~dp0Application.zip"
set "NULLWERK_SETUP_PATH="
"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Setup.ps1"
set "NULLWERK_RESULT=%ERRORLEVEL%"
if not "%NULLWERK_RESULT%"=="0" if not "%NULLWERK_RESULT%"=="1602" (
  echo Setup stopped. Read the error above, then press any key to close.
  pause >nul
)
exit /b %NULLWERK_RESULT%
'''
    readme='''NULLWERK offline source installer

1. Extract ALL files from this ZIP into one folder.
2. Double-click Install.cmd.
3. Choose Install NULLWERK in the setup window.

Requires Windows 10/11 and Python 3.11 or later with Tcl/Tk.
No administrator access or download is required. The setup verifies the
application package, installs for your account, creates a Start menu shortcut,
and adds an uninstall entry in Windows Settings.

This package uses Windows PowerShell directly; it does not run the native
x64 installer. It also supports a compatible 32-bit/ARM Python installation.
If organizational policy blocks setup, consult your administrator.

Checksum first. Coffee second.
'''
    files={'Install.cmd':launcher.replace('\n','\r\n').encode('ascii'),
           'Setup.ps1':script.encode('utf-8-sig'),'Application.zip':payload,
           'README.txt':readme.replace('\n','\r\n').encode('ascii')}
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16;z.writestr(info,data)
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(out.getvalue())
    return dict(filename=destination.name,sha256=hashlib.sha256(out.getvalue()).hexdigest(),
                payload_sha256=payload_hash,prerequisite='Python 3.11+ with Tcl/Tk',
                windows_runtime_tested=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('-o','--output',default=str(ROOT/('dist/NULLWERK-'+VERSION+'-Install.zip')))
    print(json.dumps(build(p.parse_args().output),indent=2))
