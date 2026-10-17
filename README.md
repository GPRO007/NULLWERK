<p align="center"><img src="assets/nullwerk_96.png" width="96" alt="NULLWERK icon"></p>
<h1 align="center">NULLWERK</h1>
<p align="center">Offline PE import analysis and authorized Steam-integration maintenance.</p>

NULLWERK inspects Windows EXE/DLL import tables and identifies references to Steam components. It supports explicit, local changes for software you are authorized to maintain. Files are analyzed without being executed; changes are saved as verified copies.

**Version 4.1 ships no product-specific patch profiles.** The default package provides analysis and a manual Steam import-table editor. The optional profile engine works only with a locally supplied, exact-version profile; no automatic program patch is available out of the box.

## Rights and limitations

Use the tool only where you have the necessary permission or an applicable legal right. Purchasing or possessing a copy does not establish every right to modify, circumvent protection, or redistribute it. NULLWERK cannot grant ownership, replace a subscription, or change third-party license terms.

Read [legal scope](LEGAL.md), the [notice](NOTICE.txt), and [technical limitations](docs/LIMITATIONS.md). These notices do not guarantee that any use or publication is lawful and do not replace a qualified legal review. This project is independent and is not affiliated with or endorsed by Valve.

## Features

- Read-only analysis of PE32/PE32+ imports, imported functions and reference candidates.
- A clearly marked Steam import-table editor, which leaves call sites unchanged and can produce an unusable output.
- An optional exact-hash local profile engine with byte-for-byte restoration.
- JSON/CSV exports that omit local file paths and filenames by default.
- English desktop interface, application icon, activity log and optional developer humor.
- Offline operation, with no telemetry, account login or automatic uploads.

No product-specific patch data, third-party executables, replacement Steam binaries or built-in license-response emulation are distributed with this release. Removing imports does not prove that a program works independently of Steam.

## Install

Open the repository's **Releases** page for downloads.

| Package | Prerequisite |
|---|---|
| `NULLWERK-4.1.0-Windows-Setup.exe` | Windows 10/11 x64; Python is included |
| `NULLWERK-4.1.0-Source-Setup.exe` | Windows 10/11 x64 and Python 3.11+ with Tcl/Tk |
| `NULLWERK-4.1.0-Install.zip` | Windows 10/11 and compatible Python 3.11+ with Tcl/Tk; extract all files and open `Install.cmd` |

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
python workbench.py edit-imports application.exe --remove steam_api.dll --understand-import-only -o application_copy.exe
```

The editor changes import metadata and does not replace imported functions. Test an authorized copy and keep a backup. Reports still contain hashes and imported names; review them before sharing. `--include-paths` explicitly includes local paths in a CLI report.

For authorized local profile development, see [the data format](docs/PROFILES.md). The source/Python edition reads the local `profiles` directory. The bundled edition reads `%LOCALAPPDATA%/NULLWERK/profiles` and does not load legacy profiles from its installation directory. No JSON profiles are included in public builds or accepted in this repository.

## Development

```console
python -m unittest discover -s tests -v
python tools/check_public_release.py
```

See [Windows builds](docs/BUILDING.md), [privacy](docs/PRIVACY.md), [GitHub publishing](docs/GITHUB.md), and [contribution rules](CONTRIBUTING.md). Automated tests use synthetic PE data.

## License

Project source is offered under the [MIT License](LICENSE), to the extent contributors can grant the relevant rights. It does not license third-party software or waive mandatory statutory rights. Bundled components retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
