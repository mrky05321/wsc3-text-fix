"""Windowless game launcher with correction only (no text/metric capture)."""
from __future__ import annotations

import ctypes as C
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil
from safety_hold import require_runtime_approval

from process_patch import (attach_game, process_list, CodeNotReady, GAME_SHA256,
                           sha_file, create_mutex, close)

HOME = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]
GAME = HOME / 'wsc3.exe'
INSTALL_KEY = hashlib.sha256(str(HOME).casefold().encode('utf-8')).hexdigest()[:24]
STATE_DIR = Path(os.environ.get('LOCALAPPDATA') or (Path.home()/'AppData'/'Local')) / 'wsc3-text-fix' / INSTALL_KEY
STARTUP_TIMEOUT = 180


def notify(message):
    box = C.windll.user32.MessageBoxW
    box.argtypes = [C.c_void_p, C.c_wchar_p, C.c_wchar_p, C.c_uint]
    box.restype = C.c_int
    box(None, str(message), 'WSC3 自動改行補正ランチャー', 0x10)


def matching_games():
    found = []
    for item in process_list():
        try:
            if item['path'] and Path(item['path']).resolve() == GAME:
                found.append(item)
        except OSError:
            continue
    return found


def launch():
    require_runtime_approval()
    if not GAME.is_file():
        raise RuntimeError('WSC3Launcher.exeを元のwsc3.exeと同じフォルダに置いてください。')
    if sha_file(GAME) != GAME_SHA256:
        raise RuntimeError('対応するwsc3.exeのSHA-256と一致しません。ゲームは起動していません。')
    candidates = matching_games()
    if len(candidates) > 1:
        raise RuntimeError('同じフォルダのWSC3が複数起動しています。1つにしてから再実行してください。')
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    bootstrap = None
    if not candidates:
        bootstrap = subprocess.Popen([str(GAME), *sys.argv[1:]], cwd=str(HOME))
    absent_since = None
    while time.monotonic() - started < STARTUP_TIMEOUT:
        candidates = matching_games()
        if len(candidates) > 1:
            raise RuntimeError('起動中のWSC3が複数になったため、自動補正を中止しました。')
        if candidates:
            absent_since = None
            pid = candidates[0]['pid']
            try:
                return attach_game(pid, STATE_DIR, 1, capture=False)
            except CodeNotReady:
                pass
            except psutil.NoSuchProcess:
                pass  # Startup may replace its own process; identify the new PID.
            except (OSError, psutil.AccessDenied) as exc:
                if not psutil.pid_exists(pid):
                    continue
                raise RuntimeError('ゲームへ接続できません。旧補正ソフトを解除し、ゲームと同じ権限で起動してください。\n' + str(exc)) from exc
        elif bootstrap is not None and bootstrap.poll() is not None:
            # Allow the original startup process to hand off to the actual game.
            if absent_since is None:
                absent_since = time.monotonic()
            if time.monotonic() - absent_since > 10:
                raise RuntimeError('ゲームが終了したため、描画コードに接続できませんでした。ゲーム本体が正常起動できるか確認してください。')
        elif bootstrap is None:
            raise RuntimeError('接続待ちの間にゲームが終了しました。')
        time.sleep(0.2)
    raise RuntimeError('3分以内に対応する描画コードを確認できませんでした。補正は未適用です。')


def monitor(session):
    while session.process.alive:
        time.sleep(0.5)


def main():
    mutex = None
    session = None
    try:
        # Singleton belongs to this installation, independent of the hook mutex.
        C.set_last_error(0)
        mutex = create_mutex(None, False, 'Local\\WSC3Launcher_' + INSTALL_KEY)
        error = C.get_last_error()
        if not mutex:
            raise C.WinError(error)
        if error == 183:
            return  # An existing launcher already owns this game's lifecycle.
        session = launch()
        monitor(session)
    except Exception as exc:
        notify(str(exc) + '\n\n元のwsc3.exeファイルは変更していません。')
    finally:
        if session:
            try:
                session.detach()
                try:
                    session.journal.unlink(missing_ok=True)
                except OSError:
                    pass
            except Exception as exc:
                if session.process.alive:
                    notify('元の命令への復元を確認できませんでした。ゲームを終了してください。\nゲーム終了までランチャーは待機します。\n' + str(exc))
                    while session.process.alive:
                        time.sleep(0.5)
                session.process.close()
        if mutex:
            close(mutex)


if __name__ == '__main__':
    main()
