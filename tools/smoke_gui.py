"""Exercise real Tk widgets on a Windows build runner without running a game."""
import argparse
from pathlib import Path
import sys
import tempfile

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--app-root',type=Path,default=Path(__file__).resolve().parents[1]);args=p.parse_args()
sys.path.insert(0,str(args.app_root.resolve()))
import tkinter as tk
from app import Nullwerk
from workbench import inspect
root=tk.Tk();root.withdraw();ui=Nullwerk(root)
errors=[]
root.report_callback_exception=lambda *e: errors.append(e)
for view in ['analyze','profile','editor','activity']:
    ui.show_view(view);root.update_idletasks();root.update()
ui.humor.set(False);ui.humor.set(True);ui.sort_table('functions')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from test_core import fixture
from test_diagnostics import executable
from diagnostics import compare_files,recover_original,scan_folder
from pe_editor import PEFile
with tempfile.TemporaryDirectory() as folder:
    source=Path(folder)/'synthetic.exe';source.write_bytes(fixture())
    ui.analyzed(inspect(source));root.update_idletasks();root.update()
    assert ui.state['profile'] is None
    assert 'disabled' in ui.patch_button.state()
    assert 'No profiles are included' in ui.profile_text.get('1.0','end')
    original=Path(folder)/'original.exe';edited=Path(folder)/'edited.exe'
    original.write_bytes(executable(64));edited.write_bytes(PEFile(original.read_bytes()).remove([('normal',0)])[0])
    ui.analyzed(inspect(original));ui.tree.selection_set('0');ui.review_imports()
    root.update_idletasks();root.update()
    assert 'Imported functions: 1' in ui.diagnostic_text.get('1.0','end')
    comparison=compare_files(original,edited);ui.comparison=comparison
    ui.display_diagnostics(comparison);ui.enable_controls()
    assert 'disabled' not in ui.recover_button.state()
    assert 'Recovery available: True' in ui.diagnostic_text.get('1.0','end')
    recovered=Path(folder)/'recovered.exe'
    ui.display_diagnostics(recover_original(original,edited,recovered))
    assert recovered.read_bytes()==original.read_bytes()
    ui.display_diagnostics(scan_folder(folder));root.update_idletasks();root.update()
    assert 'PE files: 4' in ui.diagnostic_text.get('1.0','end')
root.update_idletasks();root.update()
assert not errors,errors
ui.close()
print('Tk GUI smoke test passed.')
