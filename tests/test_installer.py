import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_source_installer import build
from build_zip_installer import build as build_zip
from verify_installer import verify,verify_image_layout


@unittest.skipUnless(sys.platform.startswith('linux') and all(shutil.which(n) for n in ('as','ld','nm','objcopy')),
                     'Native bootstrap build tests require Linux ELF-targeting GNU binutils; Windows runs the built installer separately')
class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.path=Path(cls.temp.name)/'Setup.exe'
        build(cls.path);cls.data=cls.path.read_bytes()

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_built_installer_passes_loader_and_payload_checks(self):
        result=verify(self.path)
        self.assertTrue(result['section_layout_verified'])
        self.assertFalse(result['windows_runtime_tested'])

    def test_fixed_import_section_gap_is_rejected(self):
        data=bytearray(self.data)
        pe=struct.unpack_from('<I',data,60)[0];table=pe+24+240
        # Recreate the 4.0.0 failure: an import section fixed at RVA 0x40000
        # despite the preceding data section ending much earlier.
        struct.pack_into('<I',data,table+3*40+12,0x40000)
        with self.assertRaisesRegex(ValueError,'adjacent'):
            verify_image_layout(data)

    def test_incorrect_initialized_data_total_is_rejected(self):
        data=bytearray(self.data);opt=struct.unpack_from('<I',data,60)[0]+24
        struct.pack_into('<I',data,opt+8,0)
        with self.assertRaisesRegex(ValueError,'size totals'):
            verify_image_layout(data)

    def test_truncated_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'truncated section'):
            verify_image_layout(self.data[:4096])

    def test_changed_overlay_is_rejected(self):
        data=bytearray(self.data);data[-32]^=1
        with self.assertRaisesRegex(ValueError,'checksum'):
            verify_image_layout(data)

    def test_zip_install_uses_identical_verified_application(self):
        path=Path(self.temp.name)/'Install.zip';result=build_zip(path)
        size=struct.unpack_from('<Q',self.data,len(self.data)-8)[0]
        embedded=self.data[-16-size:-16]
        with zipfile.ZipFile(path) as z:
            self.assertEqual(set(z.namelist()),{'Install.cmd','Setup.ps1','Application.zip','README.txt'})
            self.assertEqual(z.read('Application.zip'),embedded)
            self.assertIn(hashlib.sha256(embedded).hexdigest(),z.read('Setup.ps1').decode('utf-8-sig'))
            self.assertIn(b'NULLWERK_PACKAGE_PATH=%~dp0Application.zip',z.read('Install.cmd'))
            self.assertIn(b'"%~dp0Setup.ps1"',z.read('Install.cmd'))
            self.assertEqual(result['payload_sha256'],hashlib.sha256(embedded).hexdigest())
            with zipfile.ZipFile(io.BytesIO(embedded)) as app:
                self.assertTrue({'LEGAL.md','NOTICE.txt','THIRD_PARTY_NOTICES.md'}<=set(app.namelist()))
                self.assertFalse(any(n.startswith('profiles/') and n.endswith('.json') for n in app.namelist()))
                manifest=json.loads(app.read('PACKAGE_MANIFEST.json'))
                for entry in manifest['files']:
                    self.assertEqual(hashlib.sha256(app.read(entry['path'])).hexdigest(),entry['sha256'])


if __name__=='__main__':unittest.main()
