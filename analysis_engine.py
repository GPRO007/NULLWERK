"""Read-only analysis of PE imports and candidate x86/x64 code references."""
import hashlib
import re
import struct
from pathlib import Path
from pe_editor import PEFile, PEError

VERSION = '4.1.0'


def import_symbols(pe, entry):
    record = entry['record']
    if entry['kind'] == 'normal':
        names, _, _, _, iat = struct.unpack('<IIIII', record)
    else:
        _, _, _, iat, names, _, _, _ = struct.unpack('<IIIIIIII', record)
    names = names or iat
    width = pe.bits//8
    ordinal_bit = 1 << (pe.bits-1)
    base = pe.u32(pe.optional+28) if pe.bits==32 else struct.unpack('<Q',pe.slice(pe.optional+24,8))[0]
    symbols = []
    try:
        if not names or not iat:
            return [], 'No readable import thunks were found.'
        for i in range(65536):
            value = int.from_bytes(pe.slice(pe.offset(names+i*width,width),width),'little')
            if not value:
                return symbols, None
            name = '#'+str(value & 65535) if value & ordinal_bit else pe.name(value+2)
            symbols.append(dict(name=name,iat_rva=iat+i*width,iat_va=base+iat+i*width))
        return symbols, 'The thunk list exceeds the analysis limit.'
    except PEError as error:
        return symbols, str(error)


def candidate_references(pe, symbols):
    # Byte signatures only. These do not establish instruction boundaries or
    # reachability and do not find all indirect or dynamically resolved calls.
    targets = {s['iat_va']:s['name'] for s in symbols}
    hits = []
    machine = pe.u16(pe.pe+4)
    if machine not in (0x14c,0x8664) or not targets:
        return hits
    base = pe.u32(pe.optional+28) if pe.bits==32 else int.from_bytes(pe.slice(pe.optional+24,8),'little')
    for index,(va,vs,ro,rs) in enumerate(pe.sections):
        sh = pe.optional+pe.optional_size+40*index
        if not pe.u32(sh+36) & 0x20000000:
            continue
        code = pe.slice(ro,rs)
        for match in re.finditer(rb'\xff[\x15\x25]|\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',code):
            i = match.start()
            if i+6>len(code):
                continue
            operand = code[i+2:i+6]
            target = int.from_bytes(operand,'little') if pe.bits==32 else base+va+i+6+int.from_bytes(operand,'little',signed=True)
            if target in targets:
                kind = 'call' if code[i:i+2]==b'\xff\x15' else 'jump' if code[i:i+2]==b'\xff\x25' else 'pointer_load'
                hits.append(dict(offset=ro+i,rva=va+i,symbol=targets[target],kind=kind,method='byte_pattern'))
                if len(hits)>=1000:
                    return hits
    return hits


def analyze(path):
    path=Path(path);data=path.read_bytes();pe=PEFile(data)
    entries=[]
    for entry in pe.imports:
        symbols,error=import_symbols(pe,entry)
        local_name=Path(entry['name'])
        local=(path.parent/local_name).is_file() if local_name.name==entry['name'] else False
        entries.append(dict(key=list(entry['key']),name=entry['name'],kind=entry['kind'],symbols=symbols,
                            symbol_error=error,candidate_references=candidate_references(pe,symbols),
                            in_program_directory=local))
    all_names=sorted({x.decode('ascii') for x in re.findall(rb'(?i)[a-z0-9_+.-]{1,120}\.dll',data)})
    imported={e['name'].casefold() for e in entries}
    report=dict(tool_version=VERSION,file=str(path.resolve()),filename=path.name,size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),bits=pe.bits,machine=hex(pe.u16(pe.pe+4)),
                signed=bool(pe.directory(4)[0]),aslr=bool(pe.u16(pe.optional+70)&0x40),
                entry_rva=pe.u32(pe.optional+16),imports=entries,
                dll_strings_without_import=[s for s in all_names if s.casefold() not in imported],
                analysis_limitations=['Reference candidates are byte-pattern matches, not full disassembly.',
                    'Reachability and complete coverage of indirect calls are not established.',
                    'DLL strings without imports do not prove dynamic loading.',
                    'System DLL search paths and runtime behavior are not verified.'])
    return pe,report
