"""Build a standalone launcher and an archive containing only that executable."""
from pathlib import Path
import hashlib
import importlib.metadata as metadata
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parent
if sys.platform!='win32' or struct.calcsize('P')!=8:
    raise SystemExit('Build with 64-bit Python on Windows.')
version=(ROOT/'VERSION').read_text(encoding='utf-8').strip()
if not re.fullmatch(r'\d+\.\d+\.\d+',version):
    raise SystemExit('VERSION must contain a numeric x.y.z version.')
licenses=ROOT/'build'/'licenses'
licenses.mkdir(parents=True,exist_ok=True)
shutil.copy2(Path(sys.base_prefix)/'LICENSE.txt',licenses/'Python-LICENSE.txt')
for project,basename,target in [('psutil','LICENSE','psutil-LICENSE.txt'),
                                ('pyinstaller','COPYING.txt','PyInstaller-COPYING.txt')]:
    distribution=metadata.distribution(project)
    source=next(distribution.locate_file(f) for f in distribution.files if Path(f).name==basename)
    shutil.copy2(source,licenses/target)
shutil.copy2(ROOT/'THIRD_PARTY_NOTICES.md',licenses/'THIRD_PARTY_NOTICES.md')
subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--windowed','--onefile',
    '--name','WSC3Launcher','--distpath',str(ROOT/'release'),
    '--workpath',str(ROOT/'build'/'pyinstaller'),'--specpath',str(ROOT/'build'),
    '--add-data',str(licenses)+';THIRD_PARTY_LICENSES',str(ROOT/'src'/'launcher.py')],
    cwd=ROOT,check=True)
exe=ROOT/'release'/'WSC3Launcher.exe'
archive=ROOT/'release'/f'wsc3-text-fix-v{version}-win64.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as output:
    output.write(exe,'WSC3Launcher.exe')
info={'version':version,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
      'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
      'zip_contents':['WSC3Launcher.exe'],'hook_protocol_version':3,
      'game_runtime_verified_by_this_build':False}
(ROOT/'release'/'build_info.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
print(json.dumps(info,indent=2))
