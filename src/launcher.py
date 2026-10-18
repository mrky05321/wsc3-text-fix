"""Temporary startup-only launcher. No runtime hooks or thread suspension."""
from __future__ import annotations
import ctypes as C
import hashlib
from pathlib import Path
import subprocess
import sys

HOME=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[1]
GAME=HOME/'wsc3.exe'
GAME_SHA256='9a2a92e473e825b51a9d5bf657d84890e6d96ae3e586c8a5ce15c15514c3f4fc'


def validate_game():
    if not GAME.is_file():
        raise RuntimeError('WSC3Launcher.exeを元のwsc3.exeと同じフォルダに置いてください。')
    digest=hashlib.sha256()
    with GAME.open('rb') as source:
        for block in iter(lambda:source.read(4*1024*1024),b''):
            digest.update(block)
    if digest.hexdigest()!=GAME_SHA256:
        raise RuntimeError('対応するwsc3.exeのSHA-256と一致しません。ゲームは起動していません。')


def launch(arguments):
    validate_game()
    # No scan, memory access, patching, suspension, or exit-time detach.
    return subprocess.Popen([str(GAME),*arguments],cwd=str(HOME),close_fds=True)


def main(arguments=None):
    arguments=list(sys.argv[1:] if arguments is None else arguments)
    if arguments==['--check']:
        # File validation only: never start a process or show a dialog.
        try:
            validate_game()
            return 0
        except (OSError,RuntimeError):
            return 2
    try:
        launch(arguments)
        return 0
    except Exception as exc:
        box=C.windll.user32.MessageBoxW
        box.argtypes=[C.c_void_p,C.c_wchar_p,C.c_wchar_p,C.c_uint]
        box.restype=C.c_int
        box(None,str(exc),'WSC3 起動専用ランチャー（改行補正は一時停止）',0x10)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
