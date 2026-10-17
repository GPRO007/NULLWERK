# Research and format coverage

This revision is based on documented loader behavior and synthetic format cases, not a catalog of commercial-game patches. No game identifiers, game hashes, uploaded executables or proprietary patch bytes are included. The following primary sources were consulted on 2026-10-17.

| Primary source | Consequence for this tool |
| --- | --- |
| [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | Distinguish PE32/PE32+, lookup thunks, address slots, ordinal imports, bound state and delay descriptors. Report incomplete decoding rather than inventing names. |
| [Microsoft delay-load helper](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function?view=msvc-170) | A delay import is managed by runtime helper code; changing descriptor metadata does not establish a complete program modification. |
| [Microsoft runtime dynamic linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking) | LoadLibrary/GetProcAddress can resolve dependencies outside the static import table. DLL strings and loader-API imports remain indicators. |
| [Microsoft DLL search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) | A file absent from the inspected folder may still be resolved by Windows. Folder edges are candidates, not a loader simulation. |
| [Valve Steamworks API overview](https://partner.steamgames.com/doc/sdk/api) | Initialization and interface use belong to application behavior. Removing an import name does not provide those interfaces or the application's fallback logic. |
| [Valve Steamworks feature overview](https://partner.steamgames.com/doc/features) | Integration can involve achievements, cloud, input, networking and other features. A startup check alone cannot establish complete feature compatibility. |

## Reproducible checks

All repository fixtures are generated from synthetic data. Cases exercise both pointer widths, named and ordinal thunks, absent original lookup tables, unreadable bound IATs, RVA and legacy-VA delay imports, ambiguous section mappings, direct-IAT byte patterns, wide DLL strings and a zero-reference result that still must not be labeled safe.

Workflow tests also exercise default rejection of unsafe import export, the separate expert override, exact comparison/recovery, refusal of unrelated modifications, changed-input protection, no-overwrite behavior, folder links and x86/x64 mismatches, bounded scans, unreadable inputs, malformed local profiles and nested path redaction.

Windows checks exercise real Tk widgets, the source installers, the packaged CLI and the bundled installer/GUI/uninstaller. The release validation record states which of these have actually passed for the published build. A generated or statically parsed fixture is not a runnable game or a runtime compatibility benchmark.

## Supported purpose and remaining boundary

NULLWERK can explain dependency risks, inspect a bounded application folder and restore a known import edit from its matching original. It cannot generically infer the correct replacement behavior of arbitrary application-specific Steam calls, recover missing original bytes without a matching source, establish entitlement or prove broad commercial-game compatibility. For software whose source you control, make optional integration explicit in source and test startup, persistence and affected features. No universal remover or compatibility percentage is claimed.
