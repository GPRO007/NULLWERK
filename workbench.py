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
from diagnostics import removal_preflight,compare_files,recover_original,scan_folder

ROOT=Path(__file__).resolve().parent
PROFILE_DIR=(Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'NULLWERK'/'profiles'
             if getattr(sys,'frozen',False) else ROOT/'profiles')


def inspect(path):
    pe,report=analyze(path)
    try:profiles=load_profiles(PROFILE_DIR)
    except (OSError,ValueError,TypeError,KeyError):
        profiles=[]
        report['profile_warning']='Local profiles could not be loaded. Analysis remains available; profile changes are disabled.'
    report['available_profiles']=[p['title'] for p in profiles]
    profile,state=identify(pe.data,profiles)
    report['profile']=None if profile is None else {k:profile.get(k) for k in ('id','title','status','runtime_tested','description','limitations','validation')}
    report['profile_state']=state
    report['steam']=inventory(report)
    report['import_edit_preflight']=removal_preflight(report,report['steam']['static_imports'])
    return pe,report,profile,state


def export_report(destination,report,include_paths=False):
    report=public_report(report,include_paths)
    destination=Path(destination)
    if destination.suffix.casefold()=='.csv':
        if 'imports' not in report:
            raise PEError('Folder audits and comparison reports use JSON format.')
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


def transform(source,destination,profile_mode=False,restore=False,remove_names=None,allow_unsafe=False,expected_sha256=None):
    pe,report,profile,state=inspect(source)
    if expected_sha256 and report['sha256']!=expected_sha256:
        raise PEError('The input file changed. Analyze it again before proceeding.')
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
        preflight=removal_preflight(report,wanted)
        if not allow_unsafe:
            raise PEError('Import-only export blocked: '+preflight['reasons'][0]['message']+' No output was written. Compare with the original or use an independently validated local profile. Expert CLI experiments require --allow-unsafe-import-edit.')
        result,_=pe.remove(keys);operation='import_edit_only'
    save_copy(source,destination,result)
    output=Path(destination)
    report['operation']=dict(mode=operation,output=str(output.resolve()),output_sha256=digest(result),
                             profile_id=profile['id'] if profile_mode or restore else None,
                             dll_names=remove_names or [],runtime_tested=False)
    if operation=='import_edit_only':
        report['operation']['status']='unsafe_experiment_not_a_working_standalone_build'
        report['operation']['preflight']=preflight
    return report


def main():
    parser=argparse.ArgumentParser(description='NULLWERK '+VERSION)
    sub=parser.add_subparsers(dest='command',required=True)
    a=sub.add_parser('analyze');a.add_argument('file',type=Path);a.add_argument('--report',type=Path);a.add_argument('--include-paths',action='store_true')
    scan=sub.add_parser('scan',help='Read-only folder dependency audit')
    scan.add_argument('folder',type=Path);scan.add_argument('--report',type=Path);scan.add_argument('--include-paths',action='store_true')
    for name in ('compare','recover'):
        c=sub.add_parser(name,help='Compare an original and edited copy' if name=='compare' else 'Recover an exact recognized import edit using its original')
        c.add_argument('original',type=Path);c.add_argument('modified',type=Path)
        c.add_argument('--report',type=Path);c.add_argument('--include-paths',action='store_true')
        if name=='recover':c.add_argument('-o','--output',required=True,type=Path)
    for command in ['patch','restore','edit-imports']:
        p=sub.add_parser(command);p.add_argument('file',type=Path);p.add_argument('-o','--output',required=True,type=Path);p.add_argument('--report',type=Path);p.add_argument('--include-paths',action='store_true')
        if command=='edit-imports':
            p.add_argument('--remove',action='append',required=True)
            p.add_argument('--understand-import-only',action='store_true',required=True,help='Acknowledge that call sites remain unchanged and the output may crash.')
            p.add_argument('--allow-unsafe-import-edit',action='store_true',help='Expert-only override: permits an unverified metadata experiment that can prevent startup.')
    args=parser.parse_args()
    try:
        if args.command in ('scan','compare','recover'):
            if args.command=='scan':report=scan_folder(args.folder)
            elif args.command=='compare':report=compare_files(args.original,args.modified)
            else:report=recover_original(args.original,args.modified,args.output)
            if args.report:export_report(args.report,report,include_paths=args.include_paths)
            if args.command=='scan':
                print(f"Folder audit: {report['files_analyzed']} PE files, {len(report['errors'])} unreadable inputs, truncated={report['scan_truncated']}")
                print(f"Same-directory links: {len(report['static_links'])}; x86/x64 mismatches: {len(report['architecture_mismatches'])}")
            else:print(report['explanation'])
            return 0
        if args.command=='analyze':
            _,report,_,_=inspect(args.file)
        else:
            report=transform(args.file,args.output,profile_mode=args.command=='patch',restore=args.command=='restore',remove_names=getattr(args,'remove',None),allow_unsafe=getattr(args,'allow_unsafe_import_edit',False))
        if args.report:
            export_report(args.report,report,include_paths=args.include_paths)
        print(f"{report['filename']} · {report['bits']} Bit · {len(report['imports'])} DLL imports")
        print('SHA-256: '+report['sha256'])
        print('Steam imports: '+str(len(report['steam']['static_imports'])))
        print('Profile: '+(report['profile']['title']+' / '+report['profile_state'] if report['profile'] else 'No matching profile'))
        if report['steam']['static_imports']:
            print('Import-only preflight: '+report['import_edit_preflight']['status'])
            for reason in report['import_edit_preflight']['reasons']:print('  '+reason['message'])
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
