# Optional local profiles

No product-specific profile is included in the public release. The engine is available for authorized local maintenance; the public repository does not accept proprietary-product patch data. Local JSON profiles are ignored by Git.

A profile is JSON data, not executable Python. It has an ID, title, complete source/output SHA-256 hashes, file size, status, validation scope and non-overlapping byte operations. The input must match its source hash and every old byte. The result must match its complete output hash and parse as PE. Restoration verifies the patched input, reverses the operations, and checks the original hash.

The automated test constructs a synthetic PE fixture and changes one byte of unused fixture data. No proprietary executable or patch offsets are used.

The source/Python edition reads `profiles` beside the modules. A frozen/bundled application reads `%LOCALAPPDATA%/NULLWERK/profiles`, so old embedded profiles are not automatically loaded during an upgrade.

Do not infer safety from successful process startup. Document the actual authorized use and affected behavior. A technically valid profile does not establish legal permission. See [legal scope](../LEGAL.md).
