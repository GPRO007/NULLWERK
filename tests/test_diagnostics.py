"""Synthetic format cases only; no product identifiers, hashes or game bytes."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_core import fixture
from analysis_engine import analyze,import_symbols,dll_indicators
from diagnostics import removal_preflight,compare_files,recover_original,scan_folder
from pe_editor import PEFile,PEError
from privacy import public_report
from workbench import inspect,transform,export_report


def executable(bits=32,ordinal=False,missing_ilt=False):
    data=bytearray(fixture(bits));pe=PEFile(data);base=0x400000 if bits==32 else 0x140000000
    struct.pack_into('<I' if bits==32 else '<Q',data,pe.optional+(28 if bits==32 else 24),base)
    section=pe.optional+pe.optional_size
    struct.pack_into('<H',data,pe.pe+6,2)
    struct.pack_into('<IIII',data,section+8,0x300,0x1000,0x300,512)
    struct.pack_into('<I',data,section+36,0x40000040)
    data[section+40:section+48]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,section+48,0x300,0x1300,0x300,1280)
    struct.pack_into('<I',data,section+76,0x60000020)
    struct.pack_into('<I',data,pe.optional+16,0x1300)
    data[768:800]=b'steam_api.dll\0'.ljust(32,b'\0')
    struct.pack_into('<IIIII',data,512,0 if missing_ilt else 0x1180,0,0,0x1100,0x11c0)
    width=bits//8;value=((1<<(bits-1))|27) if ordinal else 0x1200
    for rva in (0x1180,0x11c0):
        data[512+rva-0x1000:512+rva-0x1000+width*2]=value.to_bytes(width,'little')+bytes(width)
    data[1024:1060]=(b'\0\0Optional_Init\0').ljust(36,b'\0')
    operand=(base+0x11c0).to_bytes(4,'little') if bits==32 else (0x11c0-0x1306).to_bytes(4,'little',signed=True)
    data[1280:1286]=b'\xff\x15'+operand
    return bytes(data)


class DiagnosticsTests(unittest.TestCase):
    def test_named_and_ordinal_iat_references_on_both_architectures(self):
        for bits in (32,64):
            for ordinal in (False,True):
                pe=PEFile(executable(bits,ordinal));symbols,error=import_symbols(pe,pe.imports[0])
                self.assertIsNone(error);self.assertEqual(symbols[0]['name'],'#27' if ordinal else 'Optional_Init')
                with tempfile.TemporaryDirectory() as td:
                    path=Path(td)/'input.exe';path.write_bytes(pe.data);_,report=analyze(path)
                self.assertEqual(report['imports'][0]['candidate_references'][0]['kind'],'call')
                self.assertTrue(report['reference_scan']['completed_within_limits'])
                self.assertIn('code_references',{r['code'] for r in removal_preflight(report,['steam_api.dll'])['reasons']})
    def test_unbound_first_thunk_fallback(self):
        pe=PEFile(executable(missing_ilt=True))
        self.assertEqual(import_symbols(pe,pe.imports[0])[0][0]['name'],'Optional_Init')
    def test_bound_iat_without_lookup_names_is_not_misdecoded(self):
        data=bytearray(executable(missing_ilt=True));struct.pack_into('<I',data,516,12345)
        pe=PEFile(data);symbols,error=import_symbols(pe,pe.imports[0])
        self.assertEqual(symbols,[]);self.assertIn('Bound IAT',error)
    def test_legacy_va_delay_import(self):
        data=bytearray(executable());base=0x400000
        struct.pack_into('<IIIIIIII',data,640,0,base+0x1140,0,base+0x1240,base+0x1220,0,0,0)
        for rva in (0x1220,0x1240):struct.pack_into('<II',data,512+rva-0x1000,base+0x1260,0)
        offset=512+0x1260-0x1000;data[offset:offset+32]=b'\0\0Optional_Delay\0'.ljust(32,b'\0')
        pe=PEFile(data);entry=[e for e in pe.imports if e['kind']=='delay'][0]
        self.assertTrue(entry['uses_va']);self.assertEqual(import_symbols(pe,entry)[0][0]['name'],'Optional_Delay')
    def test_invalid_ordinal_reserved_bits_reported(self):
        data=bytearray(executable(ordinal=True));struct.pack_into('<I',data,896,0x8100001b)
        pe=PEFile(data);self.assertIn('Reserved ordinal',import_symbols(pe,pe.imports[0])[1])
    def test_rva_based_delay_symbols_and_helper_preflight(self):
        for bits in (32,64):
            data=bytearray(executable(bits));pe=PEFile(data);width=bits//8
            struct.pack_into('<IIIIIIII',data,640,1,0x1140,0,0x1240,0x1220,0,0,0)
            data[832:864]=b'steam_api64.dll\0'.ljust(32,b'\0')
            for rva in (0x1220,0x1240):
                o=512+rva-0x1000;data[o:o+width*2]=(0x1260).to_bytes(width,'little')+bytes(width)
            data[1120:1152]=b'\0\0Optional_Delay\0'.ljust(32,b'\0')
            with tempfile.TemporaryDirectory() as td:
                path=Path(td)/'input.exe';path.write_bytes(data);report=analyze(path)[1]
            delay=[e for e in report['imports'] if e['kind']=='delay'][0]
            self.assertEqual(delay['symbols'][0]['name'],'Optional_Delay')
            self.assertIn('delay_helpers',{r['code'] for r in removal_preflight(report,['steam_api64.dll'])['reasons']})
    def test_ambiguous_overlapping_sections_are_rejected(self):
        data=bytearray(executable());pe=PEFile(data);section=pe.optional+pe.optional_size
        struct.pack_into('<I',data,section+52,0x1000)
        with self.assertRaisesRegex(PEError,'overlapping'):PEFile(data)
    def test_ascii_and_utf16_indicators(self):
        values,truncated=dll_indicators(b'plugin.dll\0\0'+ 'steam_api64.dll'.encode('utf-16le'))
        self.assertIn('steam_api64.dll',values);self.assertIn('plugin.dll',values);self.assertFalse(truncated)
    def test_unsafe_export_requires_a_second_explicit_expert_override(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'source.exe';output=Path(td)/'output.exe';source.write_bytes(executable())
            with self.assertRaisesRegex(PEError,'blocked'):
                transform(source,output,remove_names=['steam_api.dll'])
            self.assertFalse(output.exists())
            report=transform(source,output,remove_names=['steam_api.dll'],allow_unsafe=True)
            self.assertEqual(report['operation']['status'],'unsafe_experiment_not_a_working_standalone_build')
            self.assertEqual(source.read_bytes(),executable())
    def test_zero_reference_count_does_not_claim_safe_removal(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'source.exe';data=bytearray(executable());data[1280:1286]=b'\x90'*6;path.write_bytes(data)
            report=inspect(path)[1];risk=report['import_edit_preflight']
            self.assertEqual(risk['reference_candidates'],0);self.assertFalse(risk['can_create_verified_standalone'])
            self.assertIn('imported_functions',{r['code'] for r in risk['reasons']})
    def test_exact_comparison_and_original_recovery(self):
        for bits in (32,64):
            with tempfile.TemporaryDirectory() as td:
                original=Path(td)/'source.exe';edited=Path(td)/'copy.exe';out=Path(td)/'restored.exe'
                original.write_bytes(executable(bits));pe=PEFile(original.read_bytes());edited.write_bytes(pe.remove([('normal',0)])[0])
                report=compare_files(original,edited)
                self.assertTrue(report['recovery_available']);self.assertTrue(report['executable_bytes_unchanged'])
                self.assertEqual(report['removed_imports'],[{'name':'steam_api.dll','kind':'normal'}])
                result=recover_original(original,edited,out,report['original_sha256'],report['modified_sha256'])
                self.assertTrue(result['original_bytes_restored']);self.assertEqual(out.read_bytes(),original.read_bytes())
                with self.assertRaises(FileExistsError):recover_original(original,edited,out)
                with self.assertRaises(PEError):recover_original(original,edited,original)
    def test_unrelated_code_changes_are_not_guessed_away(self):
        with tempfile.TemporaryDirectory() as td:
            original=Path(td)/'source.exe';edited=Path(td)/'copy.exe';out=Path(td)/'out.exe'
            original.write_bytes(executable());data=bytearray(PEFile(original.read_bytes()).remove([('normal',0)])[0]);data[1300]^=1;edited.write_bytes(data)
            self.assertFalse(compare_files(original,edited)['recovery_available'])
            with self.assertRaises(PEError):recover_original(original,edited,out)
            self.assertFalse(out.exists())
    def test_recovery_and_transform_reject_changed_input_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            original=Path(td)/'source.exe';edited=Path(td)/'copy.exe';out=Path(td)/'out.exe'
            original.write_bytes(executable());edited.write_bytes(PEFile(original.read_bytes()).remove([('normal',0)])[0]);report=compare_files(original,edited)
            data=bytearray(original.read_bytes());data[1900]^=1;original.write_bytes(data)
            with self.assertRaisesRegex(PEError,'changed'):recover_original(original,edited,out,report['original_sha256'],report['modified_sha256'])
            with self.assertRaisesRegex(PEError,'changed'):transform(original,out,remove_names=['steam_api.dll'],allow_unsafe=True,expected_sha256=report['original_sha256'])
            self.assertFalse(out.exists())
    def test_folder_links_architecture_mismatches_and_unreadable_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);data=bytearray(executable());data[768:800]=b'local.dll\0'.ljust(32,b'\0')
            (root/'application.exe').write_bytes(data);(root/'LOCAL.dll').write_bytes(executable(64));(root/'broken.dll').write_bytes(b'not a PE')
            report=scan_folder(root)
            self.assertEqual(report['files_analyzed'],2);self.assertEqual(len(report['errors']),1)
            self.assertEqual(len(report['architecture_mismatches']),1)
            self.assertFalse(report['runtime_tested']);self.assertFalse(report['scan_truncated'])
            self.assertTrue(scan_folder(root,max_files=1)['scan_truncated'])
            public=json.dumps(public_report(report));self.assertNotIn(str(root),public);self.assertNotIn('application.exe',public);self.assertNotIn('broken.dll',public)
    def test_nested_comparison_paths_are_redacted(self):
        report={'files':[{'analysis':{'file':'/private/source/a.exe','filename':'a.exe'},'relative_path':'nested/a.exe'}],
                'original_file':'/private/original.exe','modified_file':'/private/modified.exe'}
        text=json.dumps(public_report(report));self.assertNotIn('/private',text);self.assertNotIn('nested/a.exe',text)
        self.assertIn('/private',json.dumps(public_report(report,True)))
    def test_invalid_local_profile_does_not_disable_read_only_analysis(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'input.exe';source.write_bytes(executable());(root/'invalid.json').write_text('{}')
            with patch('workbench.PROFILE_DIR',root):result=inspect(source)
            self.assertIsNone(result[2]);self.assertIn('profile_warning',result[1])
    def test_oversized_input_stops_before_processing(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input.exe';path.write_bytes(executable())
            with patch('analysis_engine.MAX_FILE_BYTES',10):
                with self.assertRaisesRegex(PEError,'limit'):analyze(path)
    def test_json_only_diagnostic_export(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'report.csv'
            with self.assertRaisesRegex(PEError,'JSON'):export_report(path,{'kind':'folder_audit'})
            self.assertFalse(path.exists())


if __name__=='__main__':unittest.main()
