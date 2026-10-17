# Builds

## Self-contained Windows installer

Requirements: Windows 10/11 x64, Python 3.11+ with Tcl/Tk, and Inno Setup 6.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build_windows.ps1
```

The script installs the pinned build dependency, runs tests, bundles the GUI and CLI using PyInstaller, and compiles the Inno Setup script. The resulting `dist/NULLWERK-4.1.0-Windows-Setup.exe` includes the Python runtime. Build dependencies need network access; the installed application works offline.

PyInstaller is not a cross-compiler. Build Windows applications on Windows. The repository's manual **Build Windows installer** GitHub workflow performs this process on a Windows runner and uploads the installer as a workflow artifact. It does not create a release or publish the repository.

The workflow checks for Inno Setup and installs it through the runner's Chocolatey package manager if needed. The resulting installer uses the current user's application directory and does not require elevation.

## Offline source installer

On Linux with Python and ELF-targeting GNU binutils (`as`, `ld`, `objcopy`, `nm`):

```console
python tools/build_source_installer.py
```

This builds a Windows x64 PE bootstrap with an embedded ZIP payload. The bootstrap starts the system Windows PowerShell executable with the auditable `installer/source_setup.ps1` content and waits for completion. It does not use a third-party installer stub or a remote script.

The builder derives every section RVA from the preceding section's size. Sections are adjacent after page alignment, and the optional header's code/data totals use file-aligned sizes. The verifier checks those Windows image-layout constraints, section bounds, entry-point permissions, directories, and the whole-file PE checksum before inspecting the package.

The destination PC must already have Python 3.11+ with Tcl/Tk. The installer checks that requirement, verifies its embedded package, installs per-user, creates a Start menu shortcut, and registers an uninstall command. Managed upgrades preserve files outside the previous package manifest. Uninstall removes package-owned files; extra files are retained.

For automated Windows smoke testing, set `NULLWERK_SETUP_SILENT=1` before running the source installer. This suppresses the interactive form but does not disable prerequisite or integrity checks.

## ZIP installer fallback

```console
python tools/build_zip_installer.py
```

This produces `dist/NULLWERK-4.1.0-Install.zip` using only the Python standard library. Extract all files and open `Install.cmd`. The launcher runs the included setup script using system Windows PowerShell, with the same application payload and SHA-256 checks as the EXE installer. It avoids loading a native x64 bootstrap, so it can also use a compatible 32-bit or ARM Python installation. It still requires Windows 10/11 and Python 3.11+ with Tcl/Tk.

For automated testing, set `NULLWERK_SETUP_SILENT=1` and `NULLWERK_PACKAGE_PATH` to the absolute extracted `Application.zip` path before starting `Setup.ps1` in a separate Windows PowerShell process.

## Validation scope

A PE parser, disassembly inspection, payload validation, and synthetic unit tests cannot substitute for a Windows installation test. Record whether the GUI, installer, uninstaller, and game runtime were actually executed. Do not promote static checks into runtime claims.

`tools/verify_installer.py` inspects a source installer without running it. It verifies PE imports, resources, the embedded archive, file hashes, the encoded setup script, and the absence of identifying build paths.
