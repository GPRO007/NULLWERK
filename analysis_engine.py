"""Bounded, read-only PE analysis. Input binaries are never loaded or executed."""
import hashlib
import re
import struct
from pathlib import Path
from pe_editor import PEFile, PEError

VERSION = '4.2.0'
MAX_FILE_BYTES = 256*1024*1024
MAX_REFERENCE_HITS = 20000
MAX_DLL_STRINGS = 2000


def read_binary(path):
    with Path(path).open('rb') as stream:
        data=stream.read(MAX_FILE_BYTES+1)
    if len(data)>MAX_FILE_BYTES:
        raise PEError('Input exceeds the 256 MiB analysis limit.')
    return data


def import_symbols(pe, entry):
    record=entry['record'];uses_va=entry.get('uses_va',False)
    if entry['kind']=='normal':
        names,timestamp,_,_,iat=struct.unpack('<IIIII',record)
        if not names and timestamp:
            return [],'Bound IAT without an import lookup table: original names cannot be recovered reliably.'
    else:
        _,_,_,iat,names,_,_,_=struct.unpack('<IIIIIIII',record)
        names=pe.address_rva(names,uses_va);iat=pe.address_rva(iat,uses_va)
    names=names or iat
    width=pe.bits//8;ordinal_bit=1<<(pe.bits-1);symbols=[]
    try:
        if not names or not iat:
            return [],'No readable import thunks were found.'
        for i in range(65536):
            value=int.from_bytes(pe.slice(pe.offset(names+i*width,width),width),'little')
            if not value:return symbols,None
            pe.offset(iat+i*width,width)
            if value&ordinal_bit:
                if value&~(ordinal_bit|65535):
                    raise PEError('Reserved ordinal-import bits are set.')
                name='#'+str(value&65535)
            else:
                name=pe.name(pe.address_rva(value,uses_va)+2)
            symbols.append(dict(name=name,iat_rva=iat+i*width,iat_va=pe.image_base+iat+i*width))
        return symbols,'The thunk list exceeds the analysis limit.'
    except PEError as error:
        return symbols,str(error)


def reference_scan(pe,symbols):
    # One pass through executable sections for all modules. Pattern matches are
    # evidence of possible references, never proof of reachability or absence.
    targets={s['iat_va']:s['name'] for s in symbols};hits=[]
    machine=pe.u16(pe.pe+4)
    if machine not in (0x14c,0x8664):return hits,False
    if not targets:return hits,True
    for index,(va,vs,ro,rs) in enumerate(pe.sections):
        sh=pe.optional+pe.optional_size+40*index
        if not pe.u32(sh+36)&0x20000000:continue
        code=pe.slice(ro,rs)
        for match in re.finditer(rb'\xff[\x15\x25]|[\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',code):
            i=match.start()
            if i+6>len(code):continue
            operand=code[i+2:i+6]
            target=int.from_bytes(operand,'little') if pe.bits==32 else pe.image_base+va+i+6+int.from_bytes(operand,'little',signed=True)
            if target not in targets:continue
            kind='call' if code[i:i+2]==b'\xff\x15' else 'jump' if code[i:i+2]==b'\xff\x25' else 'pointer_address' if code[i]==0x8d else 'pointer_load'
            hits.append(dict(offset=ro+i,rva=va+i,symbol=targets[target],iat_rva=target-pe.image_base,kind=kind,method='byte_pattern'))
            if len(hits)>=MAX_REFERENCE_HITS:return hits,False
    return hits,True


def candidate_references(pe,symbols):
    return reference_scan(pe,symbols)[0]


def dll_indicators(data):
    found=set();truncated=False
    patterns=[rb'(?i)[a-z0-9_+.-]{1,120}\.dll',rb'(?i)(?:[a-z0-9_+.-]\x00){1,120}\.\x00d\x00l\x00l\x00']
    for index,pattern in enumerate(patterns):
        for match in re.finditer(pattern,data):
            value=match.group().decode('ascii' if index==0 else 'utf-16le')
            found.add(value)
            if len(found)>=MAX_DLL_STRINGS:return sorted(found),True
    return sorted(found),truncated


def analyze(path):
    path=Path(path);data=read_binary(path);pe=PEFile(data);entries=[]
    for entry in pe.imports:
        symbols,error=import_symbols(pe,entry)
        name=entry['name'];plain='/' not in name and '\\' not in name and ':' not in name
        local=(path.parent/name).is_file() if plain else False
        entries.append(dict(key=list(entry['key']),name=name,kind=entry['kind'],symbols=symbols,
                            symbol_error=error,candidate_references=[],uses_va=entry.get('uses_va',False),
                            in_program_directory=local))
    hits,complete=reference_scan(pe,[s for e in entries for s in e['symbols']])
    by_iat={}
    for hit in hits:by_iat.setdefault(hit['iat_rva'],[]).append(hit)
    for entry in entries:
        entry['candidate_references']=[h for s in entry['symbols'] for h in by_iat.get(s['iat_rva'],[])]
    all_names,strings_truncated=dll_indicators(data)
    imported={e['name'].casefold() for e in entries}
    functions={s['name'] for e in entries for s in e['symbols']}
    dynamic_names={'LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW','GetProcAddress','LdrLoadDll','LdrGetProcedureAddress'}
    report=dict(tool_version=VERSION,file=str(path.resolve()),filename=path.name,size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),bits=pe.bits,machine=hex(pe.u16(pe.pe+4)),
                signed=bool(pe.directory(4)[0]),aslr=bool(pe.u16(pe.optional+70)&0x40),
                entry_rva=pe.u32(pe.optional+16),imports=entries,
                features=dict(tls=bool(pe.directory(9)[0]),bound_imports=bool(pe.directory(11)[0]),
                              delay_imports=bool(pe.directory(13)[0]),managed=bool(pe.directory(14)[0]),
                              dynamic_loader_functions=sorted(functions&dynamic_names)),
                reference_scan=dict(method='byte_pattern',machine_supported=pe.u16(pe.pe+4) in (0x14c,0x8664),
                                    completed_within_limits=complete,hit_limit=MAX_REFERENCE_HITS),
                dll_strings_truncated=strings_truncated,
                dll_strings_without_import=[s for s in all_names if s.casefold() not in imported],
                analysis_limitations=['Reference candidates are byte-pattern matches, not full disassembly.',
                    'Zero matches do not prove that an import is unused.',
                    'Reachability, packed code, managed P/Invoke and indirect calls are not resolved.',
                    'DLL strings and loader API imports are indicators, not proof of a runtime dependency.',
                    'Only the application directory is checked; absence there does not mean a DLL is missing.',
                    'Input executables are never executed. Runtime compatibility is not established.'])
    return pe,report
