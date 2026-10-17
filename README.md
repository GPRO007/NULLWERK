<p align="center"><img src="assets/nullwerk_96.png" width="96" alt="NULLWERK icon"></p>
<h1 align="center">NULLWERK</h1>
<p align="center">Offline PE import analysis and authorized Steam-integration maintenance.</p>

NULLWERK inspects Windows EXE/DLL import tables and identifies references to Steam components. It supports explicit, local changes for software you are authorized to maintain. Files are analyzed without being executed; changes are saved as verified copies.

**Version 4.2 ships no product-specific patch profiles.** The default package provides analysis, folder audits, comparison and recovery. The optional profile engine works only with a locally supplied, exact-version profile; no automatic program patch is available out of the box.

## Rights and limitations

Use the tool only where you have the necessary permission or an applicable legal right. Purchasing or possessing a copy does not establish every right to modify, circumvent protection, or redistribute it. NULLWERK cannot grant ownership, replace a subscription, or change third-party license terms.

Read [legal scope](LEGAL.md), the [notice](NOTICE.txt), and [technical limitations](docs/LIMITATIONS.md). These notices do not guarantee that any use or publication is lawful and do not replace a qualified legal review. This project is independent and is not affiliated with or endorsed by Valve.

## Features

- Read-only analysis of PE32/PE32+ normal, ordinal and delay imports, including legacy VA descriptors; imported functions and reference candidates.
- Preflight diagnostics that explain why import-only edits can prevent startup. The desktop does not export these unverified edits.
- Read-only folder audits, same-directory dependency candidates and x86/x64 mismatch checks.
- Original/copy comparison and byte-identical recovery of exactly recognized import edits. Recovery restores the original dependencies.
- An optional exact-hash local profile engine with byte-for-byte restoration.
- JSON/CSV exports that omit local file paths and filenames by default.
- English desktop interface, application icon, activity log and optional developer humor.
- Offline operation, with no telemetry, account login or automatic uploads.

No product-specific patch data, third-party executables, replacement Steam binaries or built-in license-response emulation are distributed with this release. Removing imports does not prove that a program works independently of Steam.

## Install

Open the repository's **Releases** page for downloads.

| Package | Prerequisite |
|---|---|
| `NULLWERK-4.2.0-Windows-Setup.exe` | Windows 10/11 x64; Python is included |
| `NULLWERK-4.2.0-Source-Setup.exe` | Windows 10/11 x64 and Python 3.11+ with Tcl/Tk |
| `NULLWERK-4.2.0-Install.zip` | Windows 10/11 and compatible Python 3.11+ with Tcl/Tk; extract all files and open `Install.cmd` |

Installations are per-user. The source edition uses `%LOCALAPPDATA%/Programs/NULLWERK-Source`; the bundled edition uses `%LOCALAPPDATA%/Programs/NULLWERK`. Neither downloads Python on the destination PC. Packages include the project license and notices. Bundled runtime licenses are collected from the actual build installations.

Builds are unsigned unless a release explicitly says otherwise. Check the attached hashes and the release's validation record. A build or static check is not a runtime compatibility guarantee.

## Run from source

```console
python app.py
```

Keep `assets`, the source modules and the notice files together. Python with Tcl/Tk is required; the source application uses no third-party Python packages.

Shortcuts: **Ctrl+O** open, **Ctrl+F** search, **Ctrl+E** export report, **F5** analyze again.

## Command line

```console
python workbench.py analyze application.exe --report analysis.json
python workbench.py scan application-folder --report folder-audit.json
python workbench.py compare original.exe edited.exe --report comparison.json
python workbench.py recover original.exe edited.exe -o restored-original.exe
```

The desktop offers diagnostics and recovery. Recovery requires the matching original and refuses copies containing unrelated changes. It does not create a standalone edition. The expert-only CLI `edit-imports` command requires both `--understand-import-only` and `--allow-unsafe-import-edit`; its output is an unverified metadata experiment that can fail to start. It never replaces imported functions. Test authorized copies and keep backups. Reports still contain hashes and imported names; review them before sharing. `--include-paths` explicitly includes local paths in a CLI report.

For authorized local profile development, see [the data format](docs/PROFILES.md). The source/Python edition reads the local `profiles` directory. The bundled edition reads `%LOCALAPPDATA%/NULLWERK/profiles` and does not load legacy profiles from its installation directory. No JSON profiles are included in public builds or accepted in this repository.

## Development

```console
python -m unittest discover -s tests -v
python tools/check_public_release.py
```

See [Windows builds](docs/BUILDING.md), [privacy](docs/PRIVACY.md), [GitHub publishing](docs/GITHUB.md), and [contribution rules](CONTRIBUTING.md). Automated tests use synthetic PE data. See [research and format coverage](docs/RESEARCH.md) for primary references, tested cases and limits. No compatibility percentage for commercial software is claimed.

## License

Project source is offered under the [MIT License](LICENSE), to the extent contributors can grant the relevant rights. It does not license third-party software or waive mandatory statutory rights. Bundled components retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
