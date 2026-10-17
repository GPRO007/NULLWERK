"""Read-only validation of a NULLWERK source-installer executable."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pe_editor import PEFile
from analysis_engine import import_symbols


def verify_image_layout(data):
    """Check Windows image-loader constraints, not just readable PE imports.

    Reference: Microsoft PE/COFF specification, Section Table / Section Data.
    https://learn.microsoft.com/windows/win32/debug/pe-format
    """
    def require(condition,message):
        if not condition:raise ValueError(message)
    def aligned(value,boundary):return (value+boundary-1)//boundary*boundary
    require(len(data)>=64 and data[:2]==b'MZ','Missing DOS header')
    pe=struct.unpack_from('<I',data,60)[0];opt=pe+24
    require(pe>=64 and pe+24<=len(data) and data[pe:pe+4]==b'PE\0\0','Invalid PE header')
    machine,count,_,_,_,optional_size,flags=struct.unpack_from('<HHIIIHH',data,pe+4)
    require(machine==0x8664 and flags&2 and 0<count<=96,'Expected an executable x64 image')
    require(optional_size==240 and opt+240+count*40<=len(data),'Invalid optional/section headers')
    require(struct.unpack_from('<H',data,opt)[0]==0x20b,'Expected PE32+')
    section_align,file_align=struct.unpack_from('<II',data,opt+32)
    require(section_align==4096 and file_align==512,'Unexpected image alignment')
    image_size,header_size=struct.unpack_from('<II',data,opt+56)
    require(header_size==aligned(opt+240+count*40,file_align),'Invalid SizeOfHeaders')
    require(header_size<=len(data),'Truncated headers')
    next_va=aligned(header_size,section_align);next_raw=header_size
    sections=[];code_size=0;initialized_size=0
    for i in range(count):
        offset=opt+240+i*40
        name=data[offset:offset+8].rstrip(b'\0').decode('ascii')
        size,va,raw_size,raw=struct.unpack_from('<IIII',data,offset+8)
        section_flags=struct.unpack_from('<I',data,offset+36)[0]
        require(va==next_va,f'{name}: section RVAs must be adjacent after alignment')
        require(size>0 and raw_size==aligned(size,file_align),f'{name}: invalid section size')
        require(raw==next_raw and raw%file_align==0,f'{name}: invalid raw section order/alignment')
        require(raw+raw_size<=len(data),f'{name}: truncated section data')
        require(not(section_flags&0x80000000 and section_flags&0x20000000),f'{name}: writable executable section')
        next_va=aligned(va+max(size,raw_size),section_align);next_raw=raw+raw_size
        if section_flags&0x20:code_size+=raw_size
        if section_flags&0x40:initialized_size+=raw_size
        sections.append((name,va,size,raw,section_flags))
    require(image_size==next_va,'SizeOfImage does not match the sections')
    require(struct.unpack_from('<III',data,opt+4)==(code_size,initialized_size,0),'Invalid code/data size totals')
    entry=struct.unpack_from('<I',data,opt+16)[0]
    require(any(va<=entry<va+size and flags&0x20000000 for _,va,size,_,flags in sections),'Entry point is not executable')
    require(struct.unpack_from('<I',data,opt+108)[0]==16,'Invalid directory count')
    for i in range(16):
        rva,size=struct.unpack_from('<II',data,opt+112+8*i)
        if not(rva or size):continue
        require(i!=4 and rva>0 and size>0,'Unexpected/invalid data directory')
        require(any(va<=rva and rva+size<=va+length for _,va,length,_,_ in sections),'Data directory extends outside its section')
    stored=struct.unpack_from('<I',data,opt+64)[0]
    cleared=bytearray(data);struct.pack_into('<I',cleared,opt+64,0);total=0
    for i in range(0,len(cleared),2):
        total+=cleared[i]+(cleared[i+1]<<8 if i+1<len(cleared) else 0)
        total=(total&65535)+(total>>16)
    total=(total&65535)+(total>>16)
    require(stored==(total+len(data))&0xffffffff,'PE checksum mismatch')
    return dict(section_layout_verified=True,image_size=image_size,
                sections=[dict(name=name,rva=va,virtual_size=size) for name,va,size,_,_ in sections])


def verify(path):
    data=Path(path).read_bytes();layout=verify_image_layout(data);pe=PEFile(data)
    assert pe.bits==64
    assert {e['name'] for e in pe.imports}=={'KERNEL32.dll','USER32.dll'}
    names=[s['name'] for e in pe.imports for s in import_symbols(pe,e)[0]]
    for name in ['CreateProcessW','GetModuleFileNameW','SetEnvironmentVariableW','WaitForSingleObject','ExitProcess','MessageBoxW']:
        assert name in names
    for e in pe.imports:
        assert struct.unpack_from('<I',e['record'],16)[0]%8==0,'IAT alignment'
    assert pe.directory(2)[0] and pe.directory(5)[0]
    assert b'requestedExecutionLevel level="asInvoker"' in data
    assert data[-16:-8]==b'NWPKG001'
    size=struct.unpack_from('<Q',data,len(data)-8)[0]
    payload=data[-16-size:-16];assert len(payload)==size
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        assert z.testzip() is None
        manifest=json.loads(z.read('PACKAGE_MANIFEST.json'))
        for entry in manifest['files']:
            assert not entry['path'].startswith(('/','\\')) and '..' not in Path(entry['path']).parts
            assert hashlib.sha256(z.read(entry['path'])).hexdigest()==entry['sha256']
        assert 'app.py' in z.namelist() and 'Uninstall.ps1' in z.namelist()
        assert not any(n.casefold().endswith(('.exe','.dll','.dmp','.pdb')) for n in z.namelist())
    # The setup script is auditable UTF-16LE in the native command line.
    prefix='powershell.exe -NoProfile -NonInteractive -STA -EncodedCommand '.encode('utf-16le')
    offset=data.index(prefix)+len(prefix);end=offset
    while data[end:end+2]!=b'\0\0':end+=2
    encoded=data[offset:end].decode('utf-16le')
    script=base64.b64decode(encoded,validate=True).decode('utf-16le')
    assert hashlib.sha256(payload).hexdigest() in script
    assert len(prefix)//2+len(encoded)<32000
    assert 'Python 3.11 or later with Tcl/Tk' in script
    assert 'Programs\\NULLWERK-Source' in script
    assert 'https://' not in script,'The offline setup must not download code.'
    assert not re.search(rb'[/]workspace[/](?:scratch|uploads?)[/]',data,re.I)
    assert not re.search(rb'[A-Za-z]:[\\/]Users[\\/][^\\/\s]+[\\/]',data,re.I)
    return dict(format='PE32+ Windows x64 GUI',imports=names,embedded_files=len(manifest['files']),
                payload_sha256=hashlib.sha256(payload).hexdigest(),sha256=hashlib.sha256(data).hexdigest(),
                structure_verified=True,**layout,windows_runtime_tested=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('installer',type=Path)
    a=p.parse_args();print(json.dumps(verify(a.installer),indent=2))
