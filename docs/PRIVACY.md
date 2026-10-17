# Privacy

NULLWERK performs analysis locally and has no telemetry, login, automatic upload, or connection to a Steam account.

Public source archives exclude game binaries, crash dumps, local reports, caches, logs, credentials, user-specific validation notes, and previous Git history. Project metadata uses the collective name “NULLWERK contributors”. The icon files contain no source-generation metadata or account identifiers.

Exported reports omit input/output paths and filenames by default. Explicit CLI `--include-paths` exports include them. Reports retain hashes, import names, function names, and analysis results. Hashes can identify a file even when its name is omitted.

The GUI displays the selected local path because it is needed to operate on the file. That display is not transmitted. A local error log can contain a traceback and local paths; it is stored in the user's local application-data directory and is not automatically attached to reports. Do not publish that log without review.

The public-source scanner catches common accidental artifacts and identifying path patterns. No automated scanner can prove anonymity. Publishing through a GitHub account can identify that account through repository ownership, commits, workflows, and platform metadata. Review account and commit-email settings separately before uploading; source sanitization does not hide platform-level identity.
