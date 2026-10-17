# Technical limits

NULLWERK 4.2 is a static dependency diagnostic and authorized maintenance tool. It is not a universal Steam remover and no percentage of working games is established.

## Import editing and startup

Removing a descriptor prevents the Windows loader from resolving that DLL's import address slots. Calls, pointer loads, callbacks and initialization logic can remain. A valid PE checksum and a shorter import list do not establish a working program. Delay-load helpers may retain pointers to descriptors; compacting those descriptors can also invalidate helper references. Bound imports and managed runtime loading add further state.

The desktop therefore offers preflight explanations instead of unverified import-only export. The low-level editor remains available through the expert CLI only when both acknowledgements are supplied. Its output is explicitly an unsafe metadata experiment, not a standalone application. Exact local profiles are optional, require the necessary rights, and establish only the checks actually performed by their author.

## Analysis coverage

PE32 and PE32+ normal imports, ordinal imports, original-thunk fallback and RVA/legacy-VA delay descriptors are decoded. A bound IAT without a readable lookup table is reported as unresolved. x86/x64 byte-pattern reference candidates are scanned once per file; this is not full disassembly and cannot establish reachability or prove unused imports. Other machine types can be inspected, but reference scanning is unavailable. Packed code, managed P/Invoke, copied pointers, dynamic module loading and external assets remain unresolved. ASCII and UTF-16 DLL strings are indicators and can produce false positives.

Each input is limited to 256 MiB. Reference hits and string indicators are bounded and truncation is reported. Folder audits inspect at most 128 PE files, six subdirectory levels, 1,024 directories and 512 MiB of input, without following symlinks. Same-directory candidates and x86/x64 mismatches are reported. The Windows loader's API sets, KnownDLLs, manifests, search paths and runtime state are not simulated. Absence from the application directory is not a missing-DLL verdict.

## Comparison and recovery

Recovery needs both the unmodified original and the edited copy. It is available only when the entire edited file exactly matches the known import-only transformation of that original. Additional or unrecognized changes are refused. Recovery saves a byte-identical new copy of the original, including its original dependencies. Neither input is overwritten. This does not remove Steam integration or prove startup, saving, loading, networking or other runtime behavior.

The application never executes inspected binaries. Project tests use synthetic fixtures; no product-specific patch bytes or third-party executables are distributed. See [research and test coverage](RESEARCH.md).
