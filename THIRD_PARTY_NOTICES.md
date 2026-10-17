# Third-party notices

The source application uses Python's standard library. Its application artwork was generated for this project and does not include a game publisher's logo.

The self-contained Windows build uses [PyInstaller](https://pyinstaller.org/) and bundles [Python](https://www.python.org/), Tcl/Tk, and their runtime components. Their licenses remain applicable. PyInstaller's bootloader exception permits distribution of bundled applications under their own license. The Windows build copies the license texts of Python, Tcl, Tk, PyInstaller and Inno Setup from the actual build installations into `THIRD_PARTY_LICENSES` in both packaged application directories. A missing required notice stops the build. Preserve those files and this notice when redistributing the installer or either application directory.

CPython's Windows build may combine the Tcl and Tk notices with the other runtime notices in its `LICENSE.txt`. In that case, the complete combined file is preserved for both components; the collector checks that both copyright notices are present. This follows CPython's [license assembly](https://github.com/python/cpython/blob/3.14/PCbuild/regen.targets).

The conventional Windows installer is built with [Inno Setup](https://jrsoftware.org/isinfo.php). The source installer uses Windows PowerShell, Windows Forms, and Windows APIs already present on supported Windows installations. Those Windows components are not redistributed.

No Steam SDK binaries, game executables, or game assets are included.
