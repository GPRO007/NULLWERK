import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pe_editor import PEFile,PEError,save_copy
from profiles_engine import load_profiles,apply_profile,identify,digest
from analysis_engine import import_symbols,candidate_references
from workbench import export_report


def fixture(bits=32):
    b=bytearray(2048);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    opt=152;optsz=240 if bits==64 else 224;struct.pack_into('<HH',b,132,0x8664 if bits==64 else 0x14c,1);struct.pack_into('<H',b,148,optsz)
    struct.pack_into('<H',b,opt,0x20b if bits==64 else 0x10b)
    struct.pack_into('<I',b,opt+60,512);dd=opt+(112 if bits==64 else 96);struct.pack_into('<I',b,opt+(108 if bits==64 else 92),16)
    sec=opt+optsz;b[sec:sec+8]=b'.rdata\0\0';struct.pack_into('<IIII',b,sec+8,1536,0x1000,1536,512)
    struct.pack_into('<II',b,dd+8,0x1000,60);struct.pack_into('<II',b,dd+13*8,0x1080,96)
    for i,rva in enumerate([0x1100,0x1120]):struct.pack_into('<IIIII',b,512+20*i,0,0,0,rva,0)
    for i,rva in enumerate([0x1140,0x1160]):struct.pack_into('<IIIIIIII',b,640+32*i,1,rva,0,0,0,0,0,0)
    for r,name in [(0x1100,b'A.dll\0'),(0x1120,b'B.dll\0'),(0x1140,b'C.dll\0'),(0x1160,b'A.dll\0')]:b[512+r-0x1000:512+r-0x1000+len(name)]=name
    return bytes(b)


def synthetic_profile():
    source=fixture();output=bytearray(source);output[1900]=1
    return dict(id='synthetic-data-edit',title='Synthetic fixture',
                source_sha256=digest(source),output_sha256=digest(bytes(output)),
                size=len(source),status='experimental',runtime_tested=False,
                operations=[dict(offset=1900,old='00',new='01')])


class CoreTests(unittest.TestCase):
    def test_architectures_and_import_types(self):
        for bits in [32,64]:
            pe=PEFile(fixture(bits));self.assertEqual(pe.bits,bits)
            out,_=pe.remove([('normal',0),('delay',1)])
            self.assertEqual([(e['kind'],e['name']) for e in PEFile(out).imports],[('normal','B.dll'),('delay','C.dll')])
    def test_remove_all(self):
        pe=PEFile(fixture());out,_=pe.remove([e['key'] for e in pe.imports]);p=PEFile(out)
        self.assertEqual(p.imports,[]);self.assertEqual(p.directory(1),(0,0));self.assertEqual(p.directory(13),(0,0))
    def test_bad_input(self):
        for data in [b'',b'MZ',b'not PE',fixture()[:200]]:
            with self.assertRaises(PEError):PEFile(data)
    def test_missing_selection(self):
        for keys in [[],[('normal',999)]]:
            with self.assertRaises(PEError):PEFile(fixture()).remove(keys)
    def test_signature_and_bound_directory(self):
        data=bytearray(fixture());pe=PEFile(data)
        for index in [4,11]:struct.pack_into('<II',data,pe.directory_base+index*8,1800,32)
        out,_=PEFile(data).remove([('normal',0)]);p=PEFile(out)
        self.assertEqual(p.directory(4),(0,0));self.assertEqual(p.directory(11),(0,0))
        self.assertEqual(out[1800:1832],data[1800:1832])
    def test_file_protection(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'source.exe';dst=Path(td)/'out.exe';src.write_bytes(fixture());save_copy(src,dst,b'copy')
            with self.assertRaises(FileExistsError):save_copy(src,dst,b'new')
            with self.assertRaises(PEError):save_copy(src,src,b'new')
            self.assertEqual(src.read_bytes(),fixture());self.assertEqual(dst.read_bytes(),b'copy')
    def test_report_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            dst=Path(td)/'report.json';export_report(dst,{'ok':True})
            with self.assertRaises(FileExistsError):export_report(dst,{'ok':False})
            self.assertTrue(json.loads(dst.read_text())['ok'])
    def test_profiles_load(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'fixture.json').write_text(json.dumps(synthetic_profile()))
            profiles=load_profiles(td)
            self.assertEqual(len(profiles),1)
            self.assertEqual(profiles[0]['id'],'synthetic-data-edit')
    def test_profile_wrong_source(self):
        with self.assertRaises(PEError):apply_profile(fixture(64),synthetic_profile())
    def test_bad_profile(self):
        p=synthetic_profile();p['operations'][0]['offset']=-1
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'bad.json').write_text(json.dumps(p))
            with self.assertRaises(PEError):load_profiles(td)
    def test_synthetic_profile_roundtrip_and_identification(self):
        p=synthetic_profile();source=fixture();output=apply_profile(source,p)
        self.assertEqual(output[1900],1)
        self.assertEqual(identify(source,[p])[1],'original')
        self.assertEqual(identify(output,[p])[1],'patched')
        self.assertEqual(apply_profile(output,p,restore=True),source)


if __name__=='__main__':unittest.main()
