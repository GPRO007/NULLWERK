"""NULLWERK — a local, dependency-free Tk desktop for DLL analysis."""
import ctypes
from datetime import datetime
import os
from pathlib import Path
import queue
import sys
import threading
import traceback

from workbench import inspect, transform, export_report, PROFILE_DIR
from profiles_engine import load_profiles
from pe_editor import PEError
from steam_support import is_steam_module
from analysis_engine import VERSION
from diagnostics import removal_preflight,compare_files,recover_original,scan_folder

ROOT = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'NULLWERK' / 'logs'

def save_local_error(text):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        (LOG_DIR/'error.log').write_text(text, encoding='utf-8')
    except OSError:
        pass
C = dict(bg='#101722', side='#0b111b', panel='#172230', inset='#111c29',
         line='#293747', text='#e7eef5', muted='#8fa2b6', mint='#60e2bc',
         mint_bg='#1a3b36', amber='#f3bb75', amber_bg='#3c3023', red='#f29b96')
QUIPS = (
    'Dependency injection? More like dependency inspection.',
    'git commit -m "probably fine" is not a test suite.',
    'TODO: compile coffee.',
    'There are 10 kinds of people. You know the rest.',
    'NULL is just an opinion. Until you dereference it.',
    'One semicolon does not make a release.',
    '99 little bugs in the code. Fix one. 127 little bugs in the code.',
    'Works on my machine is not an export format.',
)


class Nullwerk:
    def __init__(self, root, initial=None):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        self.tk, self.ttk, self.dialog, self.message = tk, ttk, filedialog, messagebox
        self.root = root
        self.state = {}
        self.comparison = None
        self.diagnostic_report = None
        self.busy = False
        self.closed = False
        self.jobs = queue.Queue()
        self.logs = []
        self.current_view = 'analyze'
        self.sort_column, self.sort_reverse = 'dll', False
        self.quip_index = 0
        self.images = []
        root.title('NULLWERK · DLL Workbench')
        root.geometry('1240x850')
        root.minsize(1040, 740)
        root.configure(bg=C['bg'])
        if sys.platform == 'win32':
            try:
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('Nullwerk.Desktop.3')
                root.iconbitmap(str(ROOT/'assets/nullwerk.ico'))
            except (OSError, AttributeError, tk.TclError):
                pass
        try:
            image = tk.PhotoImage(file=str(ROOT/'assets/nullwerk_56.png'))
            self.images.append(image)
            root.iconphoto(True, image)
        except tk.TclError:
            pass
        self._style()
        self.humor = tk.BooleanVar(value=True)
        self.search = tk.StringVar()
        self.status = tk.StringVar(value='Ready. Open software you are authorized to inspect.')
        self.quote = tk.StringVar(value=QUIPS[0])
        self.profile_chip = tk.StringVar(value='WAITING FOR FILE')
        self.filename = tk.StringVar(value='Your next analysis starts here.')
        self.filepath = tk.StringVar(value='Choose an EXE or DLL. The input file is never executed.')
        self.hash = tk.StringVar(value='SHA-256 appears after analysis.')
        self.selected_summary = tk.StringVar(value='No DLL selected.')
        self.views, self.nav = {}, {}
        self._sidebar()
        self._main()
        self.search.trace_add('write', lambda *a: self.populate())
        self.humor.trace_add('write', lambda *a: self._humor_changed())
        root.bind('<Control-o>', lambda e: self.choose_file())
        root.bind('<Control-f>', lambda e: self.focus_search())
        root.bind('<Control-e>', lambda e: self.save_report())
        root.bind('<F5>', lambda e: self.reanalyze())
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.report_callback_exception = self._callback_error
        self.show_view('analyze')
        self.log('READY', f'NULLWERK {VERSION} started. Offline. Input executables are never run.')
        root.after(100, self.poll)
        root.after(16000, self.rotate_quip)
        if initial:
            root.after(250, lambda: self.analyze_path(Path(initial)))

    def _style(self):
        t = self.ttk.Style(self.root)
        if 'clam' in t.theme_names():
            t.theme_use('clam')
        t.configure('.', background=C['bg'], foreground=C['text'], font=('Segoe UI', 10))
        t.configure('TFrame', background=C['bg'])
        t.configure('TButton', background=C['panel'], foreground=C['text'], borderwidth=0,
                    padding=(14, 9), font=('Segoe UI', 10))
        t.map('TButton', background=[('active', '#25394b'), ('disabled', '#16202c')],
              foreground=[('disabled', '#5e7081')])
        t.configure('Accent.TButton', background=C['mint'], foreground='#10261f', font=('Segoe UI', 10, 'bold'))
        t.map('Accent.TButton', background=[('active', '#8af0d1'), ('disabled', '#24483f')],
              foreground=[('disabled', '#6f998e')])
        t.configure('TEntry', fieldbackground=C['inset'], foreground=C['text'],
                    bordercolor=C['line'], insertcolor=C['mint'], padding=8)
        t.map('TEntry', fieldbackground=[('readonly', C['inset'])])
        t.configure('Treeview', background=C['panel'], fieldbackground=C['panel'],
                    foreground=C['text'], rowheight=30, borderwidth=0, font=('Segoe UI', 10))
        t.map('Treeview', background=[('selected', '#285047')], foreground=[('selected', '#e9fff7')])
        t.configure('Treeview.Heading', background=C['inset'], foreground=C['muted'],
                    font=('Segoe UI', 9, 'bold'), padding=(8, 9), relief='flat')
        t.map('Treeview.Heading', background=[('active', '#243649')])
        t.configure('Vertical.TScrollbar', background='#33465a', troughcolor=C['inset'], borderwidth=0,
                    arrowcolor=C['muted'])
        t.configure('Horizontal.TScrollbar', background='#33465a', troughcolor=C['inset'], borderwidth=0,
                    arrowcolor=C['muted'])
        t.configure('Mint.Horizontal.TProgressbar', background=C['mint'], troughcolor=C['bg'],
                    borderwidth=0, thickness=3)
        t.configure('TPanedwindow', background=C['bg'])

    def label(self, parent, text='', variable=None, size=10, color=None, bold=False, bg=None, **kw):
        return self.tk.Label(parent, text=text, textvariable=variable, bg=bg or C['bg'],
                             fg=color or C['text'], font=('Segoe UI', size, 'bold' if bold else 'normal'),
                             anchor='w', justify='left', **kw)

    def panel(self, parent, **kw):
        return self.tk.Frame(parent, bg=C['panel'], highlightbackground=C['line'], highlightthickness=1, **kw)

    def _sidebar(self):
        tk = self.tk
        side = tk.Frame(self.root, bg=C['side'], width=214)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        brand = tk.Frame(side, bg=C['side'])
        brand.pack(fill='x', padx=22, pady=(25, 8))
        if self.images:
            tk.Label(brand, image=self.images[0], bg=C['side']).pack(anchor='w', pady=(0, 14))
        self.label(brand, 'NULLWERK', size=20, bold=True, bg=C['side']).pack(anchor='w')
        self.label(brand, 'B I N A R Y   W O R K S H O P', size=8, color=C['muted'], bg=C['side']).pack(anchor='w', pady=(4, 0))
        self.label(side, 'WORKSPACE', size=8, bold=True, color='#5c7187', bg=C['side']).pack(anchor='w', padx=24, pady=(35, 12))
        for key, number, title in [('analyze', '01', 'Steam analysis'), ('profile', '02', 'Patch profiles'),
                                   ('editor', '03', 'Diagnostics'), ('activity', '04', 'Activity')]:
            button = tk.Button(side, text=f'{number}   {title}', anchor='w', relief='flat', bd=0,
                               bg=C['side'], fg=C['muted'], activebackground=C['mint_bg'],
                               activeforeground=C['mint'], font=('Segoe UI', 11), padx=17, pady=13,
                               cursor='hand2', command=lambda k=key: self.show_view(k))
            button.pack(fill='x', padx=10, pady=3)
            self.nav[key] = button
        bottom = tk.Frame(side, bg=C['side'])
        bottom.pack(side='bottom', fill='x', padx=23, pady=24)
        tk.Checkbutton(bottom, text='Developer humor', variable=self.humor, bg=C['side'], fg=C['muted'],
                       selectcolor=C['inset'], activebackground=C['side'], activeforeground=C['mint'],
                       font=('Segoe UI', 9), bd=0, highlightthickness=0).pack(anchor='w', pady=(0, 17))
        self.label(bottom, 'LOCAL  /  OFFLINE', size=8, bold=True, color=C['mint'], bg=C['side']).pack(anchor='w')
        self.label(bottom, f'v{VERSION}  ·  Ctrl+O to open', size=8, color=C['muted'], bg=C['side']).pack(anchor='w', pady=(6, 0))

    def _main(self):
        tk, ttk = self.tk, self.ttk
        main = tk.Frame(self.root, bg=C['bg'])
        main.pack(side='left', fill='both', expand=True, padx=25, pady=22)
        header = tk.Frame(main, bg=C['bg'])
        header.pack(fill='x')
        left = tk.Frame(header, bg=C['bg'])
        left.pack(side='left', fill='x', expand=True)
        self.page_title = self.label(left, 'Steam dependencies, in focus.', size=22, bold=True)
        self.page_title.pack(anchor='w')
        self.page_subtitle = self.label(left, 'Inspect the binary. Apply explicit, version-bound changes.', color=C['muted'])
        self.page_subtitle.pack(anchor='w', pady=(4, 0))
        self.open_button = ttk.Button(header, text='Open file…', style='Accent.TButton', command=self.choose_file)
        self.open_button.pack(side='right', padx=(10, 0))
        self.export_button = ttk.Button(header, text='Export report', command=self.save_report, state='disabled')
        self.export_button.pack(side='right')
        filebox = self.panel(main)
        filebox.pack(fill='x', pady=(20, 14))
        info = tk.Frame(filebox, bg=C['panel'])
        info.pack(fill='x', padx=16, pady=(12, 8))
        self.label(info, variable=self.filename, size=12, bold=True, bg=C['panel']).pack(side='left', fill='x', expand=True)
        self.chip = self.label(info, variable=self.profile_chip, size=8, color=C['muted'], bold=True, bg=C['inset'], padx=10, pady=6)
        self.chip.pack(side='right', padx=(8, 0))
        self.path_label = self.label(filebox, variable=self.filepath, size=9, color=C['muted'], bg=C['panel'])
        self.path_label.pack(fill='x', padx=16, pady=(0, 8))
        hashrow = tk.Frame(filebox, bg=C['panel'])
        hashrow.pack(fill='x', padx=16, pady=(0, 12))
        self.hash_label = tk.Label(hashrow, textvariable=self.hash, font=('Consolas', 8), anchor='w',
                                  bg=C['panel'], fg='#7f99ad', cursor='hand2')
        self.hash_label.pack(side='left', fill='x', expand=True)
        self.hash_label.bind('<Button-1>', lambda e: self.copy_hash())
        self.copy_button = ttk.Button(hashrow, text='Copy hash', command=self.copy_hash, state='disabled')
        self.copy_button.pack(side='right')
        cards = tk.Frame(main, bg=C['bg'])
        cards.pack(fill='x', pady=(0, 14))
        self.metric = {}
        for i, (key, title) in enumerate([('dlls', 'STEAM IMPORTS'), ('symbols', 'FUNCTIONS'),
                                          ('refs', 'REFERENCE CANDIDATES'), ('bits', 'ARCHITECTURE')]):
            cards.columnconfigure(i, weight=1)
            card = self.panel(cards)
            card.grid(row=0, column=i, sticky='nsew', padx=(0 if i==0 else 5, 0 if i==3 else 5))
            value = tk.StringVar(value='—')
            self.metric[key] = value
            self.label(card, variable=value, size=23, bold=True, color=C['mint'] if i==0 else C['text'], bg=C['panel']).pack(anchor='w', padx=14, pady=(12, 3))
            self.label(card, title, size=8, bold=True, color=C['muted'], bg=C['panel']).pack(anchor='w', padx=14, pady=(0, 12))
        self.viewbox = tk.Frame(main, bg=C['bg'])
        self.viewbox.pack(fill='both', expand=True)
        self.viewbox.rowconfigure(0, weight=1)
        self.viewbox.columnconfigure(0, weight=1)
        for key in self.nav:
            view = tk.Frame(self.viewbox, bg=C['bg'])
            view.grid(row=0, column=0, sticky='nsew')
            self.views[key] = view
        self._analysis_view()
        self._profile_view()
        self._editor_view()
        self._activity_view()
        self.progress = ttk.Progressbar(main, mode='indeterminate', style='Mint.Horizontal.TProgressbar')
        self.progress.pack(fill='x', pady=(13, 7))
        self.label(main, variable=self.status, size=9, wraplength=940).pack(anchor='w')
        self.label(main, variable=self.quote, size=9, color=C['muted'], wraplength=940).pack(anchor='w', pady=(6, 0))
        main.bind('<Configure>', self._resize)

    def text_widget(self, parent, mono=False, **kw):
        text = self.tk.Text(parent, bg=C['inset'], fg=C['text'], insertbackground=C['mint'], relief='flat',
                            font=('Consolas', 9) if mono else ('Segoe UI', 10), wrap='word',
                            padx=13, pady=12, selectbackground='#31574d', highlightthickness=0, **kw)
        return text

    def set_text(self, widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def _analysis_view(self):
        tk, ttk = self.tk, self.ttk
        view = self.views['analyze']
        bar = tk.Frame(view, bg=C['bg'])
        bar.pack(fill='x', pady=(0, 10))
        self.search_entry = ttk.Entry(bar, textvariable=self.search)
        self.search_entry.pack(side='left', fill='x', expand=True)
        self.label(bar, 'Find a DLL or function · Ctrl+F', size=9, color=C['muted']).pack(side='left', padx=12)
        pane = ttk.Panedwindow(view, orient='horizontal')
        pane.pack(fill='both', expand=True)
        tablebox = self.panel(pane)
        detailbox = self.panel(pane)
        pane.add(tablebox, weight=3)
        pane.add(detailbox, weight=2)
        self.label(tablebox, 'IMPORT TABLE', size=8, bold=True, color=C['muted'], bg=C['panel']).pack(anchor='w', padx=12, pady=(10, 7))
        tableframe = tk.Frame(tablebox, bg=C['panel'])
        tableframe.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(tableframe, columns=('dll', 'type', 'functions', 'refs'), show='headings', selectmode='extended')
        for col, title, width in [('dll', 'DLL', 210), ('type', 'Type', 72), ('functions', 'Funcs', 55), ('refs', 'Ref.*', 55)]:
            self.tree.heading(col, text=title, command=lambda c=col: self.sort_table(c))
            self.tree.column(col, width=width, minwidth=45, anchor='w', stretch=col=='dll')
        vs = ttk.Scrollbar(tableframe, orient='vertical', command=self.tree.yview)
        hs = ttk.Scrollbar(tablebox, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vs.pack(side='right', fill='y')
        hs.pack(fill='x')
        self.tree.tag_configure('steam', foreground=C['mint'])
        self.tree.bind('<<TreeviewSelect>>', self.show_selection)
        self.label(detailbox, 'DETAILS / FUNCTIONS', size=8, bold=True, color=C['muted'], bg=C['panel']).pack(anchor='w', padx=12, pady=(10, 7))
        self.detail = self.text_widget(detailbox, mono=True, width=30, height=8)
        scroll = ttk.Scrollbar(detailbox, orient='vertical', command=self.detail.yview)
        self.detail.configure(yscrollcommand=scroll.set)
        self.detail.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.set_text(self.detail, 'NO FILE, NO DRAMA.\n\nOpen an EXE or DLL to inspect imported functions and reference candidates.\n\n* References are byte patterns, not full disassembly.')
        self.label(view, 'Multi-select: Ctrl / Shift · * Candidates only; coverage is not guaranteed.', size=8, color=C['muted']).pack(anchor='w', pady=(8, 0))

    def _profile_view(self):
        view = self.views['profile']
        self.profile_text = self.text_widget(view, height=12)
        scroll = self.ttk.Scrollbar(view, orient='vertical', command=self.profile_text.yview)
        body = self.tk.Frame(view, bg=C['bg'])
        body.pack(side='bottom', fill='x', pady=(12, 0))
        self.patch_button = self.ttk.Button(body, text='Apply profile to a copy', style='Accent.TButton', state='disabled', command=lambda: self.change_file('patch'))
        self.patch_button.pack(side='left')
        self.restore_button = self.ttk.Button(body, text='Restore original', state='disabled', command=lambda: self.change_file('restore'))
        self.restore_button.pack(side='left', padx=8)
        self.profile_text.configure(yscrollcommand=scroll.set)
        self.profile_text.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.set_text(self.profile_text, 'CHECKSUMS BEFORE GUT FEELINGS.\n\nNo profiles are included in this release. Local profiles require the necessary authorization and an exact file version.\n\nAnalysis, folder audits and comparison remain available. A new copy is saved only after verification. The original is never overwritten. See LEGAL.md for the scope.')

    def _editor_view(self):
        outer = self.views['editor']
        canvas = self.tk.Canvas(outer, bg=C['bg'], highlightthickness=0, bd=0)
        scroll = self.ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        view = self.tk.Frame(canvas, bg=C['bg'])
        window = canvas.create_window((0, 0), window=view, anchor='nw')
        view.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(window, width=e.width))
        notice = self.tk.Frame(view, bg=C['amber_bg'], padx=18, pady=15)
        notice.pack(fill='x', pady=(0, 15))
        self.label(notice, 'Removing imports does not replace their functions.', size=12, bold=True, color=C['amber'], bg=C['amber_bg']).pack(anchor='w')
        self.editor_note = self.label(notice, 'Import-only copies can exit silently because the program still calls functions that the loader no longer resolves. The desktop does not export these unverified edits.', color='#e7caa7', bg=C['amber_bg'], wraplength=820)
        self.editor_note.pack(anchor='w', pady=(8, 0))
        self.label(view, 'Review dependencies, audit an application folder, or compare an edited copy with its original. Recovery saves the original bytes and restores the original dependencies.', size=11, wraplength=820).pack(anchor='w', pady=(2, 16))
        self.selection_label = self.label(view, variable=self.selected_summary, color=C['mint'], wraplength=820)
        self.selection_label.pack(anchor='w', pady=(0, 15))
        row=self.tk.Frame(view,bg=C['bg']);row.pack(fill='x',pady=(0,10))
        self.edit_button=self.ttk.Button(row,text='Explain selected imports',state='disabled',command=self.review_imports)
        self.edit_button.pack(side='left',padx=(0,8))
        self.scan_button=self.ttk.Button(row,text='Audit folder…',command=self.audit_folder)
        self.scan_button.pack(side='left')
        row=self.tk.Frame(view,bg=C['bg']);row.pack(fill='x',pady=(0,10))
        self.compare_button=self.ttk.Button(row,text='Compare with original…',state='disabled',command=self.compare_original)
        self.compare_button.pack(side='left',padx=(0,8))
        self.recover_button=self.ttk.Button(row,text='Save restored original…',state='disabled',command=self.recover_copy)
        self.recover_button.pack(side='left')
        self.diagnostic_text=self.text_widget(view,mono=True,height=13)
        self.diagnostic_text.pack(fill='both',expand=True,pady=(4,10))
        self.diagnostic_export_button=self.ttk.Button(view,text='Export diagnostics (JSON)…',state='disabled',command=self.save_diagnostics)
        self.diagnostic_export_button.pack(anchor='w')
        self.set_text(self.diagnostic_text,'Choose a file or audit a folder. No binary will be executed.\n\nZero reference matches do not prove that a DLL is unused.')

    def _activity_view(self):
        view = self.views['activity']
        bar = self.tk.Frame(view, bg=C['bg'])
        bar.pack(fill='x', pady=(0, 10))
        self.label(bar, 'What actually happened.', size=12, bold=True).pack(side='left')
        self.ttk.Button(bar, text='Save log', command=self.save_log).pack(side='right')
        self.activity = self.text_widget(view, mono=True, height=10)
        scroll = self.ttk.Scrollbar(view, orient='vertical', command=self.activity.yview)
        self.activity.configure(yscrollcommand=scroll.set)
        self.activity.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.set_text(self.activity, '')

    def _resize(self, event):
        width = max(400, event.width-36)
        self.path_label.configure(wraplength=width)
        self.editor_note.configure(wraplength=width-40)
        self.selection_label.configure(wraplength=width-10)

    def show_view(self, key):
        self.current_view = key
        self.views[key].tkraise()
        titles = dict(analyze=('Steam dependencies, in focus.', 'Steam imports, functions and reference candidates.'),
                      profile=('Exact profile. Explicit checks.', 'Version-bound changes and byte-exact restoration.'),
                      editor=('Understand before changing bytes.', 'Dependency checks, original comparison and verified recovery.'),
                      activity=('Debugging without a crystal ball.', 'Analysis, changes and verification in the activity log.'))
        title, subtitle = titles[key]
        self.page_title.configure(text=title)
        self.page_subtitle.configure(text=subtitle)
        for k, button in self.nav.items():
            button.configure(bg=C['mint_bg'] if k==key else C['side'], fg=C['mint'] if k==key else C['muted'])

    def log(self, level, text):
        line = f'{datetime.now():%H:%M:%S}  {level:<7} {text}'
        self.logs.append(line)
        self.set_text(self.activity, '\n'.join(self.logs))
        self.activity.see('end')

    def _humor_changed(self):
        self.quote.set(QUIPS[self.quip_index] if self.humor.get() else 'Local and offline. Input executables are never run.')
        if not self.humor.get() and not self.state:
            self.set_text(self.detail, 'Open an EXE or DLL for analysis.\n\nReference candidates are byte patterns, not full disassembly.')

    def rotate_quip(self):
        if self.closed:
            return
        self.quip_index = (self.quip_index+1) % len(QUIPS)
        self._humor_changed()
        self.root.after(16000, self.rotate_quip)

    def enable_controls(self):
        has = bool(self.state)
        self.open_button.configure(state='disabled' if self.busy else 'normal')
        for button in (self.export_button, self.copy_button):
            button.configure(state='normal' if has and not self.busy else 'disabled')
        self.patch_button.configure(state='normal' if has and self.state.get('profile') and self.state.get('pstate')=='original' and not self.busy else 'disabled')
        self.restore_button.configure(state='normal' if has and self.state.get('profile') and self.state.get('pstate')=='patched' and not self.busy else 'disabled')
        self.edit_button.configure(state='normal' if has and self.tree.selection() and not self.busy else 'disabled')
        self.compare_button.configure(state='normal' if has and not self.busy else 'disabled')
        self.recover_button.configure(state='normal' if self.comparison and self.comparison.get('recovery_available') and not self.busy else 'disabled')
        self.scan_button.configure(state='normal' if not self.busy else 'disabled')
        self.diagnostic_export_button.configure(state='normal' if self.diagnostic_report and not self.busy else 'disabled')

    def background(self, fn, done):
        if self.busy:
            return
        self.busy = True
        self.enable_controls()
        self.progress.start(12)
        def execute():
            try:
                self.jobs.put((done, fn(), None))
            except Exception as error:
                self.jobs.put((done, None, error))
        # Finish file writes even if the window is closed during a short task.
        threading.Thread(target=execute, daemon=False).start()

    def poll(self):
        if self.closed:
            return
        try:
            done, value, error = self.jobs.get_nowait()
            self.busy = False
            self.progress.stop()
            if error:
                self.status.set('Operation stopped: '+str(error))
                self.log('ERROR', type(error).__name__+'; operation stopped.')
                self.message.showerror('Operation not completed', str(error), parent=self.root)
            else:
                done(value)
            self.enable_controls()
        except queue.Empty:
            pass
        finally:
            if not self.closed:
                self.root.after(100, self.poll)

    def choose_file(self):
        if self.busy:
            return
        path = self.dialog.askopenfilename(parent=self.root, title='Select a file for NULLWERK',
                                           filetypes=[('Windows PE files', '*.exe *.dll'), ('All files', '*.*')])
        if path:
            self.analyze_path(Path(path))

    def analyze_path(self, path):
        if self.busy:
            return
        self.status.set('Analyzing file…')
        self.log('READ', 'Input file selected.')
        self.background(lambda: inspect(path), self.analyzed)

    def reanalyze(self):
        if self.state and not self.busy:
            self.analyze_path(self.state['path'])

    def analyzed(self, value):
        pe, report, profile, pstate = value
        self.state = dict(pe=pe, report=report, profile=profile, pstate=pstate, path=Path(report['file']))
        self.tree.selection_remove(*self.tree.selection())
        self.filename.set(report['filename'])
        self.filepath.set(report['file'])
        self.hash.set(report['sha256'])
        self.metric['dlls'].set(str(len(report['steam']['static_imports'])))
        self.metric['symbols'].set(str(sum(len(e['symbols']) for e in report['imports'])))
        self.metric['refs'].set(str(sum(len(e['candidate_references']) for e in report['imports'])))
        self.metric['bits'].set(str(report['bits'])+' BIT')
        self.comparison=None
        self.display_diagnostics(report['import_edit_preflight'])
        self.search.set('')
        if profile:
            self.profile_chip.set('PROFILE MATCHED' if pstate=='original' else 'PROFILE OUTPUT MATCHED')
            self.chip.configure(fg=C['mint'], bg=C['mint_bg'])
            validation = 'Experimental profile. This release does not establish complete runtime compatibility.'
            content = (profile['title']+'\n\nSTATUS  EXPERIMENTAL\nFILE  '+('Original' if pstate=='original' else 'Patched copy')+'\n\n'
                       +profile['description']+'\n\nTEST STATUS\n'+validation+'\n\nLIMITATIONS\n'
                       +'\n'.join('• '+s for s in profile.get('limitations', []))+'\n\nSTATIC CHECKS\n'
                       +'\n'.join('• '+s for s in profile.get('validation', [])))
        else:
            self.profile_chip.set('NO MATCHING PROFILE')
            self.chip.configure(fg=C['amber'], bg=C['amber_bg'])
            titles = report.get('available_profiles',[])
            content = ('No profile matches this exact file.\n\nAnalysis is available. Function changes require a matching version-bound profile.\n\nAVAILABLE PROFILES\n'
                       +('\n'.join('• '+t for t in titles) if titles else 'No profiles are included. Use only local profiles you are authorized to use.'))
        self.set_text(self.profile_text, content)
        if report.get('profile_warning'):
            self.set_text(self.profile_text,content+'\n\n'+report['profile_warning'])
        self.populate()
        self.show_view('analyze')
        self.status.set('Analysis complete. '+('Exact profile matched.' if profile else 'No matching profile; analysis is available.'))
        self.log('ANALYZE', f"{report['bits']} Bit, {len(report['imports'])} DLLs, profile state: {pstate}.")
        self.log('SCOPE', 'References are byte patterns. System search paths and runtime behavior are not verified.')

    def focus_search(self):
        self.show_view('analyze')
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, 'end')

    def sort_table(self, column):
        self.sort_reverse = not self.sort_reverse if self.sort_column==column else False
        self.sort_column = column
        self.populate()

    def populate(self):
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        q = self.search.get().casefold()
        entries = list(enumerate(self.state.get('report', {}).get('imports', [])))
        def sort_key(item):
            e = item[1]
            return {'dll': e['name'].casefold(), 'type': e['kind'], 'functions': len(e['symbols']), 'refs': len(e['candidate_references'])}[self.sort_column]
        entries.sort(key=sort_key, reverse=self.sort_reverse)
        visible = []
        for i, e in entries:
            if q and q not in e['name'].casefold() and not any(q in s['name'].casefold() for s in e['symbols']):
                continue
            iid = str(i)
            self.tree.insert('', 'end', iid=iid, values=(e['name'], 'Normal' if e['kind']=='normal' else 'Delay', len(e['symbols']), len(e['candidate_references'])), tags=('steam',) if is_steam_module(e['name']) else ())
            if iid in selected:
                visible.append(iid)
        if visible:
            self.tree.selection_set(visible)
        self.show_selection()

    def show_selection(self, event=None):
        entries = [self.state['report']['imports'][int(i)] for i in self.tree.selection()] if self.state else []
        self.selected_summary.set('Selected: '+', '.join(e['name'] for e in entries) if entries else 'No DLL selected.')
        chunks = []
        for e in entries:
            chunks += [e['name'], 'TYPE  '+e['kind'], 'APPLICATION DIRECTORY  '+('File present' if e['in_program_directory'] else 'Not found here; system search paths not checked'), '', 'FUNCTIONS']
            chunks.extend('  '+s['name']+'\n  IAT-RVA '+hex(s['iat_rva']) for s in e['symbols'])
            if e['symbol_error']:
                chunks.append('Note: '+e['symbol_error'])
            chunks += ['', 'REFERENCE CANDIDATES *']
            chunks.extend('  '+hex(h['rva'])+'  '+h['kind']+'\n  '+h['symbol'] for h in e['candidate_references'])
            chunks += ['', '* Byte patterns; complete coverage is not guaranteed.', '']
            if is_steam_module(e['name']):
                check=removal_preflight(self.state['report'],[e['name']])
                chunks += ['IMPORT-ONLY EXPORT: BLOCKED']+[r['message'] for r in check['reasons']]+['']
        if chunks:
            self.set_text(self.detail, '\n'.join(chunks))
        else:
            self.set_text(self.detail, 'Select a DLL to view functions and reference candidates.\n\nMulti-select: Ctrl / Shift.\n\nA directory-only check does not establish whether a system DLL is missing.')
        self.enable_controls()

    def display_diagnostics(self, report):
        self.diagnostic_report=report
        kind=report.get('kind','import_preflight')
        if kind=='folder_audit':
            text=(f"FOLDER AUDIT\n\nPE files: {report['files_analyzed']}\nUnreadable inputs: {len(report['errors'])}\n"
                  f"Same-directory links: {len(report['static_links'])}\nArchitecture mismatches: {len(report['architecture_mismatches'])}\n"
                  f"Scan limit reached: {report['scan_truncated']}\n\n")
            for item in report['files']:
                steam=[e for e in item['analysis']['imports'] if is_steam_module(e['name'])]
                text+=f"{item['id']}  {item['relative_path']}\n  {item['analysis']['bits']} bit; {len(steam)} static Steam modules\n"
            text+='\n'+'\n'.join(report['limitations'])
        elif kind in ('binary_comparison','original_recovery'):
            text=report['explanation']
            if kind=='binary_comparison':
                text+=(f"\n\nChanged bytes: {report['changed_bytes']}\nExecutable bytes unchanged: {report['executable_bytes_unchanged']}"
                       f"\nRecognized import-only edit: {report['recognized_import_only_edit']}\nRecovery available: {report['recovery_available']}")
                text+='\n\nRemoved imports:\n'+'\n'.join(e['name']+' ('+e['kind']+')' for e in report['removed_imports'])
            text+='\n\nRuntime behavior has not been tested.'
        else:
            text=('IMPORT-ONLY PREFLIGHT\n\n'+('Selected modules: '+', '.join(report['selected_modules']) if report['selected_modules'] else 'No static Steam imports selected.')
                  +f"\nImported functions: {report['imported_functions']}\nReference candidates: {report['reference_candidates']}\n\n"
                  +'\n\n'.join(r['message'] for r in report['reasons']))
        self.set_text(self.diagnostic_text,text)

    def review_imports(self):
        if not self.state or self.busy:return
        names=[self.state['report']['imports'][int(i)]['name'] for i in self.tree.selection()]
        self.display_diagnostics(removal_preflight(self.state['report'],names))
        self.show_view('editor');self.enable_controls()

    def audit_folder(self):
        if self.busy:return
        folder=self.dialog.askdirectory(parent=self.root,title='Choose a folder for a read-only dependency audit')
        if not folder:return
        def done(report):
            self.display_diagnostics(report);self.show_view('editor')
            self.status.set(f"Folder audit complete: {report['files_analyzed']} PE files. Runtime loading is unverified.")
            self.log('AUDIT','Read-only folder audit completed; no input binary was executed.')
        self.background(lambda:scan_folder(folder),done)

    def compare_original(self):
        if not self.state or self.busy:return
        original=self.dialog.askopenfilename(parent=self.root,title='Select the unmodified original for comparison',
                                             filetypes=[('Windows PE files','*.exe *.dll'),('All files','*.*')])
        if not original:return
        modified=self.state['path']
        def done(report):
            self.comparison=report
            self.display_diagnostics(report);self.show_view('editor')
            self.status.set('Comparison complete. '+('Original recovery is available.' if report['recovery_available'] else 'No automatic recovery available.'))
            self.log('COMPARE','Compared two local snapshots without executing either file.')
        self.background(lambda:compare_files(original,modified),done)

    def recover_copy(self):
        if not self.comparison or not self.comparison['recovery_available'] or self.busy:return
        comparison=dict(self.comparison)
        out=self.dialog.asksaveasfilename(parent=self.root,title='Save a verified copy of the supplied original',
                                          initialfile='restored-original.exe',defaultextension='.exe',
                                          filetypes=[('Windows PE files','*.exe *.dll')])
        if not out:return
        def done(report):
            self.display_diagnostics(report)
            self.status.set('Original bytes restored to a new copy.')
            self.log('RECOVER','Byte-identical copy of the supplied original saved; original dependencies restored.')
            self.message.showinfo('Original restored',report['explanation']+'\n\nThis does not establish runtime compatibility.',parent=self.root)
        self.background(lambda:recover_original(comparison['original_file'],comparison['modified_file'],out,
                        comparison['original_sha256'],comparison['modified_sha256']),done)

    def save_diagnostics(self):
        if not self.diagnostic_report or self.busy:return
        out=self.dialog.asksaveasfilename(parent=self.root,title='Save path-free diagnostics',initialfile='diagnostics.json',
                                          defaultextension='.json',filetypes=[('JSON diagnostics','*.json')])
        if out:
            try:export_report(out,self.diagnostic_report)
            except (OSError,PEError) as error:self.message.showerror('Report not saved',str(error),parent=self.root)
            else:self.status.set('Path-free diagnostics saved.')

    def copy_hash(self):
        if not self.state:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.state['report']['sha256'])
        self.status.set('SHA-256 copied to the clipboard.')

    def save_report(self):
        if not self.state or self.busy:
            return
        path = self.dialog.asksaveasfilename(parent=self.root, title='Save analysis report',
                                            initialfile=self.state['path'].stem+'_analysis.json', defaultextension='.json',
                                            filetypes=[('JSON analysis report', '*.json'), ('CSV function list', '*.csv')])
        if path:
            try:
                export_report(path, self.state['report'])
            except OSError as error:
                self.message.showerror('Report not saved', str(error), parent=self.root)
            else:
                self.status.set('Report saved: '+path)
                self.log('EXPORT', 'Path-free report saved.')

    def save_log(self):
        path = self.dialog.asksaveasfilename(parent=self.root, title='Save activity log',
                                            initialfile='nullwerk_activity.log', defaultextension='.log')
        if path:
            try:
                with Path(path).open('x', encoding='utf-8') as out:
                    out.write('\n'.join(self.logs)+'\n')
            except OSError as error:
                self.message.showerror('Log not saved', str(error), parent=self.root)
            else:
                self.status.set('Activity log saved: '+path)

    def change_file(self, mode):
        if not self.state or self.busy:
            return
        source = self.state['path']
        suffix = '_restored' if mode=='restore' else '_profile' if mode=='patch' else '_imports'
        out = self.dialog.asksaveasfilename(parent=self.root, title='Save a new copy',
                                           initialfile=source.stem+suffix+source.suffix, defaultextension=source.suffix,
                                           filetypes=[('Windows PE files', '*.exe *.dll')])
        if not out:
            return
        names = list(dict.fromkeys(self.state['report']['imports'][int(i)]['name'] for i in self.tree.selection()))
        original = self.state['pe'].data
        def work():
            if source.read_bytes()!=original:
                raise PEError('The input file changed. Analyze it again before proceeding.')
            return transform(source, out, profile_mode=mode=='patch', restore=mode=='restore', remove_names=names if mode=='edit' else None,expected_sha256=self.state['report']['sha256'])
        def saved(report):
            self.state['report'] = report
            self.status.set('Copy saved and statically verified: '+out)
            self.log('SAVED', f'{mode}: output copy saved.')
            self.log('HASH', report['operation']['output_sha256'])
            self.message.showinfo('Copy saved', 'The file was saved as a new copy and statically verified.\n\n'
                                  'Test startup, saving and loading in the complete game directory. '
                                  'Structural verification does not establish runtime compatibility.\n\nYou can now export the analysis report.', parent=self.root)
        self.status.set('Creating and verifying a copy…')
        self.log('START', f'{mode}: creating an output copy.')
        self.background(work, saved)

    def _callback_error(self, error_type, value, tb):
        details = ''.join(traceback.format_exception(error_type, value, tb))
        try:
            save_local_error(details)
        except OSError:
            pass
        self.busy = False
        self.progress.stop()
        self.enable_controls()
        self.log('ERROR', type(value).__name__+'; interface operation stopped.')
        self.message.showerror('Interface error', str(value)+'\n\nDetails: local NULLWERK error log (not uploaded)', parent=self.root)

    def close(self):
        self.closed = True
        self.root.destroy()


def main():
    import tkinter as tk
    root = tk.Tk()
    app = Nullwerk(root, sys.argv[1] if len(sys.argv)>1 else None)
    root.mainloop()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        text = traceback.format_exc()
        print(text, file=sys.stderr)
        try:
            save_local_error(text)
        except OSError:
            pass
        if sys.platform=='win32':
            ctypes.windll.user32.MessageBoxW(None, 'NULLWERK could not start.\n\nInstall Python with Tcl/Tk and extract all application files together.\n\nDetails were written to the local NULLWERK error log when possible.', 'NULLWERK - Startup error', 16)
        raise SystemExit(1)
