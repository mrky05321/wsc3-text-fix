# Third-party notices

The launcher bundles a Python runtime, psutil, and the PyInstaller bootloader/runtime hooks. Their license notices are embedded inside the executable under `THIRD_PARTY_LICENSES` and reproduced in this repository.

- Python: PSF License and the additional notices in `Python-LICENSE.txt`.
- psutil: BSD 3-Clause, `psutil-LICENSE.txt`.
- PyInstaller bootloader: GPL with the bootloader exception; runtime hooks: Apache License 2.0. Full text is in `PyInstaller-COPYING.txt`.
- Tk notices are included for the optional source GUI in `Tk-license.terms`. The standalone launcher does not import Tk.

The build script collects the installed Python, psutil, and PyInstaller licenses again so the embedded notices match the build environment. Repository copies document the original local build environment.

Game titles and other third-party names belong to their respective rights holders. No game executable, assets, memory dumps, or captured game text are distributed here. The source contains minimal instruction bytes and addresses needed to recognize and relay the supported drawing routine.

No open-source license has yet been selected for the project's own code. Third-party licenses remain applicable to their respective components.
