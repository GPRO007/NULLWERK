"""Build an offline Windows x64 source installer with GNU binutils.

The small position-independent bootstrap launches the included, auditable
PowerShell setup through the system PowerShell executable and waits for it.
Python + Tcl/Tk is a prerequisite; the separate Windows build bundles Python.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='4.2.0'
APP_FILES=['app.py','analysis_engine.py','pe_editor.py','profiles_engine.py',
           'workbench.py','steam_support.py','privacy.py','diagnostics.py','LICENSE','LEGAL.md',
           'NOTICE.txt','THIRD_PARTY_NOTICES.md','README.md','profiles/README.md',
           'docs/LIMITATIONS.md','docs/RESEARCH.md','docs/PRIVACY.md','docs/PROFILES.md']


def align(n,to):return (n+to-1)//to*to


def payload_bytes():
    files={name:(ROOT/name).read_bytes() for name in APP_FILES}
    for folder in ['assets']:
        for p in sorted((ROOT/folder).rglob('*')):
            if p.is_file() and p.suffix in ['.png','.ico']:
                files[p.relative_to(ROOT).as_posix()]=p.read_bytes()
    # Git can check out PS1 as CRLF. Keep package hashes identical across
    # checkouts while retaining valid PowerShell text.
    files['Uninstall.ps1']=(ROOT/'installer/Uninstall.ps1').read_text(encoding='utf-8').encode('utf-8')
    manifest=dict(version=VERSION,files=[dict(path=n,sha256=hashlib.sha256(b).hexdigest()) for n,b in sorted(files.items())])
    files['PACKAGE_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16;z.writestr(info,data)
    return out.getvalue()


def wide(label,text):
    values=[str(x) for x in struct.unpack('<'+'H'*len(text+'\0'),(text+'\0').encode('utf-16le'))]
    return label+':\n'+ '\n'.join('    .short '+','.join(values[i:i+16]) for i in range(0,len(values),16))+'\n'


def icon_resources(ico,rva):
    reserved,kind,count=struct.unpack_from('<HHH',ico)
    if reserved or kind!=1 or count<1:raise ValueError('Invalid ICO')
    images={};group=bytearray(struct.pack('<HHH',0,1,count))
    for i in range(count):
        w,h,c,res,planes,bits,size,offset=struct.unpack_from('<BBBBHHII',ico,6+i*16)
        images[i+1]=ico[offset:offset+size]
        group.extend(struct.pack('<BBBBHHIH',w,h,c,res,planes,bits,size,i+1))
    manifest=('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="'+VERSION+'.0" processorArchitecture="amd64" name="NULLWERK.SourceSetup" type="win32"/><description>NULLWERK Source Installer</description><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>').encode('utf-8')
    tree={3:{i:{0x409:data} for i,data in images.items()},14:{1:{0x409:bytes(group)}},24:{1:{0x409:manifest}}}
    out=bytearray()
    def pad():out.extend(bytes(align(len(out),4)-len(out)))
    def directory(items):
        pad();pos=len(out);out.extend(bytes(16+8*len(items)))
        struct.pack_into('<IIHHHH',out,pos,0,0,0,0,0,len(items))
        for i,(key,child) in enumerate(sorted(items.items())):
            if isinstance(child,dict):childpos=directory(child)|0x80000000
            else:
                pad();childpos=len(out);out.extend(bytes(16));pad();dataoffset=len(out);out.extend(child)
                struct.pack_into('<IIII',out,childpos,rva+dataoffset,len(child),0,0)
            struct.pack_into('<II',out,pos+16+i*8,key,childpos)
        return pos
    assert directory(tree)==0
    return bytes(out)


def build(destination):
    for tool in ['as','ld','objcopy','nm']:
        if not shutil.which(tool):raise RuntimeError('GNU binutils required: '+tool)
    payload=payload_bytes();payload_hash=hashlib.sha256(payload).hexdigest()
    script=(ROOT/'installer/source_setup.ps1').read_text(encoding='utf-8').replace('@PAYLOAD_HASH@',payload_hash)
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    command='powershell.exe -NoProfile -NonInteractive -STA -EncodedCommand '+encoded
    if len(command)>=32000:raise RuntimeError('Installer command exceeds the Windows command-line limit')
    constants=wide('setup_environment','NULLWERK_SETUP_PATH')+wide('package_environment','NULLWERK_PACKAGE_PATH')+wide('powershell_suffix','\\WindowsPowerShell\\v1.0\\powershell.exe')
    constants+=wide('error_message','Setup could not start Windows PowerShell. This installer requires Windows 10/11 x64.')+wide('error_title','NULLWERK Setup')
    funcs=['GetModuleFileNameW','SetEnvironmentVariableW','GetSystemDirectoryW','CreateProcessW',
           'WaitForSingleObject','GetExitCodeProcess','CloseHandle','ExitProcess']
    imports='imports_start:\n    .long kernel_orig,0,0,kernel_name,kernel_iat\n    .long user_orig,0,0,user_name,user_iat\n    .zero 20\n'
    imports+='.balign 8\nkernel_orig:\n'+''.join('    .quad hint_'+n+'\n' for n in funcs)+'    .quad 0\n'
    imports+='user_orig:\n    .quad hint_MessageBoxW,0\n.balign 8\niat_start:\nkernel_iat:\n'
    imports+=''.join('api_'+n+': .quad hint_'+n+'\n' for n in funcs)+'    .quad 0\nuser_iat:\napi_MessageBoxW: .quad hint_MessageBoxW,0\niat_end:\n'
    imports+='kernel_name: .asciz "KERNEL32.dll"\nuser_name: .asciz "USER32.dll"\n'
    for n in funcs+['MessageBoxW']:imports+='.balign 2\nhint_'+n+': .short 0\n    .asciz "'+n+'"\n'
    asm=(ROOT/'installer/bootstrap.S.in').read_text().replace('@CONSTANTS@',constants).replace('@COMMAND@',wide('command_line',command)).replace('@IMPORTS@',imports)
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);(td/'setup.S').write_text(asm)
        # Windows image sections must be adjacent after page alignment. A fixed
        # import RVA leaves a gap when the encoded command changes in size.
        (td/'layout.ld').write_text('ENTRY(_start)\nSECTIONS { . = 0x1000; .text : { text_rva = .; *(.text) } . = ALIGN(0x1000); .rdata : { rdata_rva = .; *(.rdata) } . = ALIGN(0x1000); .data : { data_rva = .; *(.data) } . = ALIGN(0x1000); .idata : { idata_rva = .; *(.idata) } /DISCARD/ : { *(.note*) *(.eh_frame*) } }\n')
        subprocess.run(['as','--64','-o',str(td/'setup.o'),str(td/'setup.S')],check=True)
        subprocess.run(['ld','--build-id=none','-T',str(td/'layout.ld'),'-o',str(td/'layout.elf'),str(td/'setup.o')],check=True)
        symbols={}
        for line in subprocess.check_output(['nm','--defined-only',str(td/'layout.elf')],text=True).splitlines():
            parts=line.split()
            if len(parts)==3:symbols[parts[2]]=int(parts[0],16)
        sections=[]
        for name,flags in [('.text',0x60000020),('.rdata',0x40000040),('.data',0xc0000040),('.idata',0xc0000040)]:
            rva=symbols[name[1:]+'_rva']
            file=td/(name[1:]+'.bin')
            subprocess.run(['objcopy','-O','binary','--only-section='+name,str(td/'layout.elf'),str(file)],check=True)
            section_data=file.read_bytes()
            if not section_data:raise RuntimeError('Empty native installer section: '+name)
            sections.append((name,rva,section_data,flags))
    resource_rva=align(sections[-1][1]+len(sections[-1][2]),0x1000)
    resources=icon_resources((ROOT/'assets/nullwerk.ico').read_bytes(),resource_rva)
    sections.append(('.rsrc',resource_rva,resources,0x40000040))
    reloc_rva=align(resource_rva+len(resources),0x1000)
    sections.append(('.reloc',reloc_rva,struct.pack('<IIHH',0,12,0,0),0x42000040))
    pe=0x80;opt=pe+24;header_size=align(opt+240+40*len(sections),512)
    image=bytearray(header_size);image[:2]=b'MZ';struct.pack_into('<I',image,60,pe);image[pe:pe+4]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',image,pe+4,0x8664,len(sections),0,0,0,240,0x22)
    code_size=sum(align(len(data),512) for _,_,data,flags in sections if flags&0x20)
    initialized_size=sum(align(len(data),512) for _,_,data,flags in sections if flags&0x40)
    struct.pack_into('<HBBIIIIIQII',image,opt,0x20b,1,0,code_size,initialized_size,0,symbols['_start'],symbols['text_rva'],0x140000000,0x1000,512)
    struct.pack_into('<HHHHHH',image,opt+40,6,0,4,1,6,0)
    struct.pack_into('<IIIHH',image,opt+56,align(reloc_rva+12,4096),header_size,0,2,0x160)
    struct.pack_into('<QQQQII',image,opt+72,0x100000,0x1000,0x100000,0x1000,0,16)
    struct.pack_into('<II',image,opt+112+8,symbols['imports_start'],60)
    struct.pack_into('<II',image,opt+112+16,resource_rva,len(resources))
    struct.pack_into('<II',image,opt+112+40,reloc_rva,12)
    struct.pack_into('<II',image,opt+112+96,symbols['iat_start'],symbols['iat_end']-symbols['iat_start'])
    for i,(name,rva,data,flags) in enumerate(sections):
        raw=len(image);padded=align(len(data),512);o=opt+240+40*i
        image[o:o+8]=name.encode().ljust(8,b'\0')
        struct.pack_into('<IIIIIIHHI',image,o+8,len(data),rva,padded,raw,0,0,0,0,flags)
        image.extend(data);image.extend(bytes(padded-len(data)))
    image.extend(payload);image.extend(b'NWPKG001'+struct.pack('<Q',len(payload)))
    # PE checksum covers the full self-extracting image, including its overlay.
    total=0
    for i in range(0,len(image),2):
        total+=image[i]+(image[i+1]<<8 if i+1<len(image) else 0);total=(total&65535)+(total>>16)
    total=(total&65535)+(total>>16);struct.pack_into('<I',image,opt+64,(total+len(image))&0xffffffff)
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(image)
    return dict(filename=destination.name,sha256=hashlib.sha256(image).hexdigest(),payload_sha256=payload_hash,
                prerequisite='Python 3.11+ with Tcl/Tk',windows_runtime_tested=False,command_characters=len(command))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('-o','--output',default=str(ROOT/('dist/NULLWERK-'+VERSION+'-Source-Setup.exe')))
    args=p.parse_args();print(json.dumps(build(args.output),indent=2))
