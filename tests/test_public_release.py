import copy
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from privacy import public_report
from steam_support import inventory,is_steam_module
from workbench import export_report,transform
from check_public_release import check
from test_core import fixture


class PublicReleaseTests(unittest.TestCase):
    def test_reports_redact_paths_without_mutating_source(self):
        report=dict(file='private directory/input.exe',filename='private_name.exe',
                    operation=dict(output='private directory/output.exe'),imports=[])
        original=copy.deepcopy(report);safe=public_report(report)
        self.assertEqual(report,original)
        self.assertEqual(safe['file'],'input.exe');self.assertEqual(safe['filename'],'input.exe')
        self.assertEqual(safe['operation']['output'],'output.exe')
        self.assertEqual(public_report(report,True)['file'],report['file'])
    def test_steam_inventory_is_not_a_universal_claim(self):
        report={'imports':[{'name':'steam_api64.dll','symbols':[{'name':'SteamAPI_Init'}],'candidate_references':[]}], 'dll_strings_without_import':['steamclient.dll']}
        result=inventory(report)
        self.assertEqual(result['static_imports'],['steam_api64.dll'])
        self.assertTrue(is_steam_module('STEAM_API.DLL'));self.assertFalse(is_steam_module('custom_engine.dll'))
        self.assertIn('not proof',result['limitation'])
    def test_csv_formula_cells_are_escaped(self):
        report={'imports':[dict(name='steam_api.dll',kind='normal',symbols=[dict(name='=1+1',iat_rva=0)],candidate_references=[])]}
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'report.csv';export_report(path,report)
            rows=list(csv.reader(io.StringIO(path.read_text())))
            self.assertEqual(rows[1][2],"'=1+1")
    def test_public_source_has_no_forbidden_artifacts(self):
        self.assertEqual(check(ROOT),[])
    def test_non_steam_import_edit_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'input.exe';src.write_bytes(fixture())
            with self.assertRaisesRegex(ValueError,'restricted'):
                transform(src,Path(td)/'output.exe',remove_names=['A.dll'])
    def test_public_distribution_contains_no_product_profiles(self):
        self.assertEqual(list((ROOT/'profiles').glob('*.json')),[])


if __name__=='__main__':unittest.main()
