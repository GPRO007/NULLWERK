# Technical scope

NULLWERK is a static import-analysis and authorized maintenance workbench. It is not a universal dependency remover or a proof that a modification is lawful.

- No product-specific patch profiles are shipped. Automatic byte operations need a locally supplied exact-hash profile.
- Import-only editing leaves API calls in place and may break startup, saving, networking or later behavior.
- Byte-pattern candidates do not prove reachability, correct calling conventions or safe edits.
- Dynamic loading, wrappers, other modules and packed code may escape static analysis.
- Removing Steam imports does not prove complete Steam independence or replace Steam-backed features.
- Other dependencies and application data remain necessary.
- The tool cannot change ownership, copyright, account entitlements or license terms.

Only verified copies are saved, and existing files are not overwritten. Backups and validation of an authorized modification remain necessary. See [legal scope](../LEGAL.md).
