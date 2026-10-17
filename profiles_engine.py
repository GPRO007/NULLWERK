"""Exact-hash, reversible patch profiles. No executable profile code."""
import hashlib
import json
from pathlib import Path
from pe_editor import PEFile, PEError


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_profiles(directory):
    profiles=[]
    for file in sorted(Path(directory).glob('*.json')):
        p=json.loads(file.read_text(encoding='utf-8'))
        for name in ('id','title','source_sha256','output_sha256','operations','size'):
            if name not in p:
                raise PEError('Invalid profile: '+file.name)
        for name in ('source_sha256','output_sha256'):
            if len(p[name])!=64 or any(c not in '0123456789abcdef' for c in p[name]):
                raise PEError('Invalid profile checksum: '+file.name)
        if p['size']<=0 or p['size']>2**32:
            raise PEError('Invalid profile file size.')
        last_end=0
        for operation in p['operations']:
            o=operation['offset'];old=bytes.fromhex(operation['old']);new=bytes.fromhex(operation['new'])
            if not isinstance(o,int) or o<last_end or not old or len(old)!=len(new) or o+len(old)>p['size']:
                raise PEError('Invalid or overlapping profile operations.')
            last_end=o+len(old)
        profiles.append(p)
    return profiles


def identify(data,profiles):
    sha=digest(data)
    for profile in profiles:
        if sha==profile['source_sha256']:
            return profile,'original'
        if sha==profile['output_sha256']:
            return profile,'patched'
    return None,'unknown'


def apply_profile(data,profile,restore=False):
    expected=profile['output_sha256'] if restore else profile['source_sha256']
    wanted=profile['source_sha256'] if restore else profile['output_sha256']
    if len(data)!=profile['size'] or digest(data)!=expected:
        raise PEError('This profile does not exactly match the file. No changes were made.')
    b=bytearray(data)
    for op in profile['operations']:
        old=bytes.fromhex(op['new'] if restore else op['old'])
        new=bytes.fromhex(op['old'] if restore else op['new']);o=op['offset']
        if b[o:o+len(old)]!=old:
            raise PEError('Profile byte verification failed.')
        b[o:o+len(new)]=new
    result=bytes(b)
    if digest(result)!=wanted:
        raise PEError('The output checksum does not match. Output was discarded.')
    PEFile(result)
    return result
