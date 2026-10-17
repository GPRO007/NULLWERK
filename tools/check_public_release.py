"""Check a source tree for accidental private artifacts and identifying paths."""
import argparse
import re
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
SKIP={'.git','__pycache__','.venv','venv','build','dist'}
FORBIDDEN={'.dmp','.exe','.dll','.pdb','.lnk','.pyc','.log','.zip','.7z'}
PATTERNS=[
    re.compile(rb'[/]workspace[/](?:scratch|uploads?)[/]',re.I),
    re.compile(rb'[A-Za-z]:[\\/]Users[\\/](?!Public|Default|runneradmin)[^\\/\s\"\']+[\\/]',re.I),
    re.compile(rb'libfile_[0-9a-f]{16,}',re.I),
    re.compile(rb'file_[0-9a-f]{16,}',re.I),
    re.compile(rb'\b(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{16,}'),
]


def check(root,deny_words=()):
    issues=[]
    for path in sorted(Path(root).rglob('*')):
        if not path.is_file() or any(p in SKIP for p in path.relative_to(root).parts):continue
        rel=path.relative_to(root).as_posix()
        if path.suffix.casefold()=='.json' and path.relative_to(root).parts[0]=='profiles':
            issues.append(rel+': product-specific profile data is not included in the public project')
        if path.suffix.casefold() in FORBIDDEN or path.name.startswith('.env'):
            issues.append(rel+': private/build artifact is not allowed in the public source tree')
        data=path.read_bytes()
        for pattern in PATTERNS:
            if pattern.search(data):issues.append(rel+': identifying path, internal reference, or credential-like value')
        for word in deny_words:
            if re.search(rb'(?i)\b'+re.escape(word.encode())+rb'\b',data):issues.append(rel+': explicitly denied personal term')
    return issues


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--deny-word',action='append',default=[])
    a=p.parse_args();issues=check(a.root,a.deny_word)
    if issues:
        print('\n'.join(issues));sys.exit(1)
    print('Public source scan passed: no prohibited artifacts or identifying path patterns found.')
