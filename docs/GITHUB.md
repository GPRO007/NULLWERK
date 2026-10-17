# Preparing a GitHub repository

Upload the complete contents of the clean source archive, including `.github`, `.gitignore`, and `.gitattributes`, to a repository you control. Do not upload previous project folders or private test inputs alongside it.

The supplied archive contains no Git history or configured remote. Choose your own repository visibility. GitHub repository ownership, commit authors, commit-email settings, and workflow metadata belong to the publishing account and are not hidden by sanitizing source files.

After uploading:

1. Check that **Tests and public-source checks** completes.
2. Run **Build Windows installer** manually from the Actions tab.
3. Download the installer workflow artifact.
4. Test installation, GUI startup, CLI startup, and uninstall on Windows.
5. Publish a release only after reviewing the validation scope and artifacts.

No workflow pushes commits, publishes a release, or uses a stored personal access token. Repository contents permissions are read-only. Public issues should contain only reviewed diagnostics.

Before changing visibility, review LEGAL.md and the actual release packages. A private repository and neutral author metadata do not provide legal immunity or erase earlier platform records. Use a GitHub no-reply author address for future commits if appropriate; do not reintroduce a personal author email.
