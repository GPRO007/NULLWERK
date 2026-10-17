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
with tempfile.TemporaryDirectory() as folder:
    source=Path(folder)/'synthetic.exe';source.write_bytes(fixture())
    ui.analyzed(inspect(source));root.update_idletasks();root.update()
    assert ui.state['profile'] is None
    assert 'disabled' in ui.patch_button.state()
    assert 'No profiles are included' in ui.profile_text.get('1.0','end')
root.update_idletasks();root.update()
assert not errors,errors
ui.close()
print('Tk GUI smoke test passed.')
