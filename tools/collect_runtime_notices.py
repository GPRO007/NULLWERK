"""Copy license notices from the actual runtime and build-tool installations."""
import argparse
from importlib.metadata import distribution
from pathlib import Path
import shutil
import sys


def first_file(candidates,label):
    for p in candidates:
        if p.is_file():return p
    raise RuntimeError('Required runtime license was not found: '+label)


def tcltk_license(base,component,python_license):
    candidates=[base/(component+'license.terms'),base/'DLLs'/(component+'license.terms')]
    candidates+=list((base/'tcl').glob(component+'*/license.terms'))
    for candidate in candidates:
        if candidate.is_file():return candidate
    # CPython's Windows build concatenates both notices into LICENSE.txt.
    # See CPython PCbuild/regen.targets, _LicenseSources and _RegenLicense.
    combined=' '.join(python_license.read_text(encoding='utf-8-sig').split())
    marker='This software is copyrighted by the Regents of the University of California'
    if combined.count(marker)>=2:return python_license
    raise RuntimeError('Required runtime license was not found: '+component)


def collect(destinations,inno_root):
    base=Path(sys.base_prefix)
    python_license=first_file([base/'LICENSE.txt',base/'LICENSE'],'Python')
    pyinstaller=distribution('PyInstaller')
    pyinstaller_licenses=[Path(pyinstaller.locate_file(p)) for p in pyinstaller.files or []
                         if str(p).casefold().endswith(('copying.txt','license.txt'))]
    licenses={
        'Python.txt':python_license,
        'Tcl.txt':tcltk_license(base,'tcl',python_license),
        'Tk.txt':tcltk_license(base,'tk',python_license),
        'PyInstaller.txt':first_file(pyinstaller_licenses,'PyInstaller'),
        'Inno-Setup.txt':first_file([Path(inno_root)/'license.txt',Path(inno_root)/'LICENSE.TXT'],'Inno Setup'),
    }
    for destination in destinations:
        folder=Path(destination)/'THIRD_PARTY_LICENSES';folder.mkdir(parents=True,exist_ok=True)
        for name,source in licenses.items():shutil.copyfile(source,folder/name)
    print('Collected Python, Tcl, Tk, PyInstaller and Inno Setup license notices.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inno-root',required=True,type=Path);p.add_argument('destinations',nargs='+',type=Path)
    args=p.parse_args();collect(args.destinations,args.inno_root)
