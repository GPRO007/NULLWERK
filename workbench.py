"""CLI and shared operations for NULLWERK."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import sys
from analysis_engine import analyze,VERSION
from profiles_engine import load_profiles,identify,apply_profile,digest
from pe_editor import PEError,save_copy
from privacy import public_report
from steam_support import inventory,is_steam_module

ROOT=Path(__file__).resolve().parent
PROFILE_DIR=(Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'NULLWERK'/'profiles'
             if getattr(sys,'frozen',False) else ROOT/'profiles')


def inspect(path):
    pe,report=analyze(path)
    profiles=load_profiles(PROFILE_DIR)
    profile,state=identify(pe.data,profiles)
    report['profile']=None if profile is None else {k:profile.get(k) for k in ('id','title','status','runtime_tested','description','limitations','validation')}
    report['profile_state']=state
    report['steam']=inventory(report)
    return pe,report,profile,state


def export_report(destination,report,include_paths=False):
    report=public_report(report,include_paths)
    destination=Path(destination)
    if destination.suffix.casefold()=='.csv':
        buf=io.StringIO(newline='');w=csv.writer(buf)
        w.writerow(['DLL','Type','Function','IAT_RVA','DLL_reference_candidates'])
        for e in report['imports']:
            for s in e['symbols'] or [dict(name='',iat_rva=0)]:
                cells=[e['name'],e['kind'],s['name'],hex(s['iat_rva']),len(e['candidate_references'])]
                w.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in cells])
        text=buf.getvalue()
    else:
        text=json.dumps(report,ensure_ascii=False,indent=2)
    with destination.open('x',encoding='utf-8',newline='') as out:
        out.write(text)


def transform(source,destination,profile_mode=False,restore=False,remove_names=None):
    pe,report,profile,state=inspect(source)
    if profile_mode or restore:
        if not profile:
            raise PEError('No profile is available for this exact version.')
        result=apply_profile(pe.data,profile,restore)
        operation='profile_restore' if restore else 'profile_patch'
    else:
        wanted={n.casefold() for n in remove_names or []}
        known={e['name'].casefold() for e in pe.imports}
        if not wanted or not wanted<=known:
            raise PEError('No DLL names were selected, or a name is absent.')
        if any(not is_steam_module(n) for n in wanted):
            raise PEError('Import-only editing is restricted to recognized Steam modules in this application.')
        keys=[e['key'] for e in pe.imports if e['name'].casefold() in wanted]
        result,_=pe.remove(keys);operation='import_edit_only'
    save_copy(source,destination,result)
    output=Path(destination)
    report['operation']=dict(mode=operation,output=str(output.resolve()),output_sha256=digest(result),
                             profile_id=profile['id'] if profile_mode or restore else None,
                             dll_names=remove_names or [],runtime_tested=False)
    return report


def main():
    parser=argparse.ArgumentParser(description='NULLWERK '+VERSION)
    sub=parser.add_subparsers(dest='command',required=True)
    a=sub.add_parser('analyze');a.add_argument('file',type=Path);a.add_argument('--report',type=Path);a.add_argument('--include-paths',action='store_true')
    for command in ['patch','restore','edit-imports']:
        p=sub.add_parser(command);p.add_argument('file',type=Path);p.add_argument('-o','--output',required=True,type=Path);p.add_argument('--report',type=Path);p.add_argument('--include-paths',action='store_true')
        if command=='edit-imports':
            p.add_argument('--remove',action='append',required=True)
            p.add_argument('--understand-import-only',action='store_true',required=True,help='Acknowledge that call sites remain unchanged and the output may crash.')
    args=parser.parse_args()
    try:
        if args.command=='analyze':
            _,report,_,_=inspect(args.file)
        else:
            report=transform(args.file,args.output,profile_mode=args.command=='patch',restore=args.command=='restore',remove_names=getattr(args,'remove',None))
        if args.report:
            export_report(args.report,report,include_paths=args.include_paths)
        print(f"{report['filename']} · {report['bits']} Bit · {len(report['imports'])} DLL imports")
        print('SHA-256: '+report['sha256'])
        print('Steam imports: '+str(len(report['steam']['static_imports'])))
        print('Profile: '+(report['profile']['title']+' / '+report['profile_state'] if report['profile'] else 'No matching profile'))
        if args.command=='analyze':
            for e in report['imports']:
                print(f"{e['name']}: {len(e['symbols'])} functions; {len(e['candidate_references'])} reference candidates")
        else:
            print('Saved: '+str(args.output))
            print('Runtime behavior has not been tested.')
        return 0
    except (OSError,PEError,ValueError) as error:
        print('Error: '+str(error),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
