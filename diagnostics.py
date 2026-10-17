"""General dependency diagnostics and conservative recovery from import edits."""
from collections import Counter
from pathlib import Path
import os
from analysis_engine import analyze,read_binary,VERSION
from pe_editor import PEFile,PEError,save_copy
from profiles_engine import digest
from steam_support import is_steam_module


def removal_preflight(report,names):
    wanted={n.casefold() for n in names}
    entries=[e for e in report['imports'] if e['name'].casefold() in wanted]
    reasons=[]
    def add(code,message):reasons.append(dict(code=code,message=message))
    if not wanted or wanted!={e['name'].casefold() for e in entries}:
        add('invalid_selection','Select DLL names that exist in this file.')
    if any(not is_steam_module(n) for n in wanted):
        add('outside_scope','The application editor is limited to recognized Steam modules.')
    symbols=sum(len(e['symbols']) for e in entries)
    references=sum(len(e['candidate_references']) for e in entries)
    if references:
        add('code_references',f'{references} possible references still target the selected import address slots. Removing descriptors does not replace those functions.')
    if symbols:
        add('imported_functions',f'{symbols} imported functions would no longer be resolved by the Windows loader.')
    if any(e['symbol_error'] for e in entries):
        add('incomplete_symbols','One or more thunk lists could not be decoded completely.')
    if any(e['kind']=='delay' for e in entries):
        add('delay_helpers','Delay-load helpers can retain descriptor addresses. Compacting the table alone is not a complete code change.')
    features=report.get('features',{})
    if features.get('bound_imports'):
        add('bound_imports','Bound-import state requires rebinding; descriptor editing alone is not sufficient verification.')
    if features.get('managed'):
        add('managed_code','Managed P/Invoke and runtime loading are outside static native import editing.')
    if not report.get('reference_scan',{}).get('machine_supported',False):
        add('unsupported_reference_scan','Reference scanning is limited to x86 and x64 byte patterns.')
    # No static scanner can prove absence of callbacks, pointer copies, dynamic
    # dispatch or protected/packed code. Do not call a zero-hit result "safe".
    if entries:
        add('runtime_unverified','A working standalone application cannot be established by editing import metadata. Rebuild optional integration from source or use an exact, independently validated local profile.')
    return dict(status='blocked' if reasons else 'unverified',can_create_verified_standalone=False,
                selected_modules=[e['name'] for e in entries],imported_functions=symbols,
                reference_candidates=references,reasons=reasons)


def _identity(e):return e['kind'],e['name'],e['record']


def compare_files(original,modified):
    source=read_binary(original);edited=read_binary(modified)
    before=PEFile(source);after=PEFile(edited)
    remaining=Counter(_identity(e) for e in after.imports);removed=[]
    for entry in before.imports:
        token=_identity(entry)
        if remaining[token]:remaining[token]-=1
        else:removed.append(entry)
    exact=False
    if removed and not any(remaining.values()):
        try:exact=before.remove([e['key'] for e in removed])[0]==edited
        except PEError:pass
    executable_spans=[]
    for i,(_,_,raw,size) in enumerate(before.sections):
        if before.u32(before.optional+before.optional_size+40*i+36)&0x20000000:
            executable_spans.append((raw,size))
    code_same=bool(executable_spans) and all(source[o:o+n]==edited[o:o+n] and o+n<=len(edited) for o,n in executable_spans)
    report=dict(tool_version=VERSION,kind='binary_comparison',original_file=str(Path(original).resolve()),
                modified_file=str(Path(modified).resolve()),original_sha256=digest(source),modified_sha256=digest(edited),
                identical=source==edited,same_length=len(source)==len(edited),
                changed_bytes=sum(a!=b for a,b in zip(source,edited))+abs(len(source)-len(edited)),
                executable_bytes_unchanged=code_same,
                removed_imports=[dict(name=e['name'],kind=e['kind']) for e in removed],
                recognized_import_only_edit=exact,recovery_available=exact,
                runtime_tested=False,
                explanation=('The copy is exactly reproducible by descriptor removal with unchanged application code. Imported function implementations were not replaced. A new byte-identical copy of the supplied original can be restored.' if exact else
                             'No changes detected.' if source==edited else
                             'The files differ beyond a recognized import-only edit. Automatic recovery is unavailable; do not guess missing bytes.'))
    return report


def recover_original(original,modified,destination,expected_original=None,expected_modified=None):
    # Read and verify the same snapshots that will be used for the saved copy.
    source=read_binary(original);edited=read_binary(modified)
    if expected_original and digest(source)!=expected_original:raise PEError('The original changed. Compare the files again.')
    if expected_modified and digest(edited)!=expected_modified:raise PEError('The edited file changed. Compare the files again.')
    before=PEFile(source);after=PEFile(edited)
    remaining=Counter(_identity(e) for e in after.imports);keys=[]
    for entry in before.imports:
        token=_identity(entry)
        if remaining[token]:remaining[token]-=1
        else:keys.append(entry['key'])
    if not keys or any(remaining.values()) or before.remove(keys)[0]!=edited:
        raise PEError('This is not an exact recognized import-only edit. No recovery file was written.')
    if Path(destination).resolve() in {Path(original).resolve(),Path(modified).resolve()}:
        raise PEError('Choose a new destination; neither input may be overwritten.')
    save_copy(modified,destination,source)
    return dict(tool_version=VERSION,kind='original_recovery',original_sha256=digest(source),
                modified_sha256=digest(edited),output=str(Path(destination).resolve()),output_sha256=digest(source),
                original_bytes_restored=True,runtime_tested=False,
                explanation='A verified new copy of the supplied original was saved. This restores its original dependencies; it does not remove Steam integration.')


def scan_folder(folder,max_files=128,max_depth=6):
    root=Path(folder).resolve()
    if not root.is_dir():raise PEError('Choose a directory for the folder audit.')
    if not 1<=max_files<=4096 or not 0<=max_depth<=12:raise PEError('Invalid folder audit limits.')
    files=[];errors=[];truncated=False;total=0;directories=0
    for parent,dirs,names in os.walk(root,followlinks=False):
        directories+=1
        if directories>1024:truncated=True;break
        parent=Path(parent);depth=len(parent.relative_to(root).parts)
        dirs[:]=sorted(d for d in dirs if not (parent/d).is_symlink() and d not in {'.git','__pycache__'})
        if depth>=max_depth:
            if dirs:truncated=True
            dirs[:]=[]
        for name in sorted(names):
            path=parent/name
            if path.suffix.casefold() not in {'.exe','.dll'} or path.is_symlink():continue
            if len(files)+len(errors)>=max_files:truncated=True;break
            try:
                size=path.stat().st_size
                if total+size>512*1024*1024:truncated=True;continue
                total+=size
                _,report=analyze(path)
                files.append(dict(id='file-'+str(len(files)+1),relative_path=path.relative_to(root).as_posix(),analysis=report))
            except (OSError,PEError) as error:
                # Keep diagnostics free of exception paths, including OSError.
                errors.append(dict(relative_path=path.relative_to(root).as_posix(),error=type(error).__name__))
        if len(files)+len(errors)>=max_files:truncated=True;break
    by_location={(str(Path(f['relative_path']).parent).casefold(),Path(f['relative_path']).name.casefold()):f for f in files}
    links=[];mismatches=[]
    for item in files:
        parent=str(Path(item['relative_path']).parent).casefold()
        for entry in item['analysis']['imports']:
            target=by_location.get((parent,entry['name'].casefold()))
            if target:
                links.append(dict(source=item['id'],target=target['id'],module=entry['name'],resolution='same_directory_candidate'))
                machines={item['analysis']['machine'],target['analysis']['machine']}
                if machines=={'0x14c','0x8664'}:
                    mismatches.append(dict(source=item['id'],target=target['id'],module=entry['name'],issue='x86_x64_mismatch'))
    return dict(tool_version=VERSION,kind='folder_audit',folder=str(root),files=files,errors=errors,
                static_links=links,architecture_mismatches=mismatches,scan_truncated=truncated,
                files_analyzed=len(files),input_bytes_examined=total,
                limits=dict(max_files=max_files,max_depth=max_depth,max_directories=1024,max_total_bytes=512*1024*1024),
                runtime_tested=False,
                limitations=['Read-only audit; no binary was executed or changed.',
                             'Only files under the selected directory are inspected; symlinks are skipped.',
                             'Links are same-directory candidates, not a simulation of the Windows DLL search order.',
                             'Missing here is not missing from Windows. Dynamic loading and feature compatibility remain unverified.'])
