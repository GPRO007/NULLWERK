# Changelog

## 4.2.0

- Added import-removal preflight and removed unverified import-only export from the desktop. Expert CLI experiments require an additional explicit override.
- Added original/copy comparison and byte-identical recovery for exactly recognized import-only edits. Unrelated changes are rejected.
- Added read-only folder audits, same-directory link candidates and x86/x64 mismatch detection.
- Added legacy VA delay-import analysis, bound-IAT diagnostics, wide DLL-string indicators and bounded one-pass reference scanning.
- Added nested report-path redaction, changed-input checks and analysis fallback when local profiles are malformed.
- Expanded synthetic format tests and Windows installer/GUI verification. No game-specific patch data or universal runtime-compatibility claim is included.

## 4.1.0 — generic distribution and rights notices

- Removed all bundled product-specific patch profiles and their documentation.
- Kept profile-engine tests using synthetic PE fixtures only.
- Clarified authorized maintenance, legal limits and third-party rights.
- Included project notices and collected runtime licenses in installer packages.
- The bundled edition reads locally supplied profiles from the user data directory, so legacy embedded profiles are not loaded.

## 4.0.2 — Windows setup compatibility

- Use .NET SHA-256 directly, so setup does not depend on the Get-FileHash module being available in a child Windows PowerShell process.
- Run ELF bootstrap build tests on Linux, and exercise the resulting installer separately on Windows.
- Capture detailed silent-install failures for CI diagnostics.

## 4.0.1 — installer format fix

- Fixed a non-adjacent PE section layout that could make Windows reject the source installer before setup opened.
- Corrected file-aligned code and initialized-data totals in the PE optional header.
- Added image-layout and checksum checks with regression tests for the rejected layout.
- Added an offline ZIP installer: extract all files and open `Install.cmd`.
- Both source installers use the same verified application payload and per-user setup.

Static verification passes; an actual Windows installation still needs runtime validation.

## 4.0.0 — public preview

- English interface, diagnostics, documentation, and installer text.
- Explicit focus on Steam dependency removal for supported exact game builds.
- Conservative Steam-module inventory and Steam-only manual import editing.
- Path-free report exports by default and CSV formula-cell escaping.
- Clean source archive without prior history, local test inputs, or identifying validation notes.
- MIT project license, contribution guidance, and public-source checks.
- Offline per-user source installer with integrity verification and uninstall support.
- Separate Windows build workflow for a bundled-runtime installer.

Historical previews did not establish universal Steam independence or full runtime compatibility.
