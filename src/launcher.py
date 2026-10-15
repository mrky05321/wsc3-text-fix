"""Windowless game launcher using the already deployed version 3 correction."""
from __future__ import annotations

import ctypes as C
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import psutil

from process_patch import (attach_game, process_list, CodeNotReady, GAME_SHA256,
                           sha_file, create_mutex, close)

HOME = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]
GAME = HOME / 'wsc3.exe'
LOG_DIR = HOME / 'wsc3_launcher_logs'
STARTUP_TIMEOUT = 180


def notify(message):
    box = C.windll.user32.MessageBoxW
    box.argtypes = [C.c_void_p, C.c_wchar_p, C.c_wchar_p, C.c_uint]
    box.restype = C.c_int
    box(None, str(message), 'WSC3 自動改行補正ランチャー', 0x10)


class Log:
    def __init__(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / (datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.jsonl')
        self.stream = self.path.open('a', encoding='utf-8')
        self.failed = False

    def write(self, event, **fields):
        try:
            self.stream.write(json.dumps({'event': event,
                'time': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                **fields}, ensure_ascii=False) + '\n')
            self.stream.flush()
        except OSError:
            # A disk failure must not interrupt restoration of the game code.
            self.failed = True

    def close(self):
        try:
            self.stream.close()
        except OSError:
            pass


def matching_games():
    found = []
    for item in process_list():
        try:
            if item['path'] and Path(item['path']).resolve() == GAME:
                found.append(item)
        except OSError:
            continue
    return found


def launch(log):
    if not GAME.is_file():
        raise RuntimeError('WSC3Launcher.exeを元のwsc3.exeと同じフォルダに置いてください。')
    if sha_file(GAME) != GAME_SHA256:
        raise RuntimeError('対応するwsc3.exeのSHA-256と一致しません。ゲームは起動していません。')
    candidates = matching_games()
    if len(candidates) > 1:
        raise RuntimeError('同じフォルダのWSC3が複数起動しています。1つにしてから再実行してください。')
    started = time.monotonic()
    bootstrap = None
    if not candidates:
        bootstrap = subprocess.Popen([str(GAME), *sys.argv[1:]], cwd=str(HOME))
        log.write('game_launched', pid=bootstrap.pid, game=str(GAME))
    else:
        log.write('existing_game_found', pid=candidates[0]['pid'])
    seen_pid = None
    absent_since = None
    while time.monotonic() - started < STARTUP_TIMEOUT:
        candidates = matching_games()
        if len(candidates) > 1:
            raise RuntimeError('起動中のWSC3が複数になったため、自動補正を中止しました。')
        if candidates:
            absent_since = None
            pid = candidates[0]['pid']
            if pid != seen_pid:
                log.write('waiting_for_render_code', pid=pid)
                seen_pid = pid
            try:
                session = attach_game(pid, LOG_DIR, 1)
                log.write('correction_attached', pid=pid, recovered=session.recovered,
                          protocol_version=3, policy='M == 2*height -> height+1')
                return session
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


def monitor(session, log):
    last_stats = None
    last_saved = 0.0
    while session.process.alive:
        stats = session.poll()
        if stats['exited']:
            break
        summary = {key: stats[key] for key in ('total', 'fixes', 'lost', 'mode')}
        now = time.monotonic()
        if summary != last_stats and (last_stats is None or now-last_saved >= 10):
            log.write('statistics', **summary)
            last_stats = summary
            last_saved = now
        time.sleep(0.25)
    log.write('game_exited', last_saved_statistics=last_stats)


def main():
    mutex = None
    session = None
    log = None
    try:
        # Singleton belongs to this installation, independent of the hook mutex.
        key = hashlib.sha256(str(HOME).casefold().encode('utf-8')).hexdigest()[:24]
        C.set_last_error(0)
        mutex = create_mutex(None, False, 'Local\\WSC3Launcher_' + key)
        error = C.get_last_error()
        if not mutex:
            raise C.WinError(error)
        if error == 183:
            return  # An existing launcher already owns this game's lifecycle.
        log = Log()
        log.write('launcher_started', game=str(GAME))
        session = launch(log)
        monitor(session, log)
    except Exception as exc:
        if log:
            log.write('error', message=str(exc))
        notify(str(exc) + '\n\n通常の補正操作は手動版WSC3Linewrap.exeでも行えます。')
    finally:
        if session:
            try:
                session.detach()
                if log:
                    log.write('session_closed')
            except Exception as exc:
                if log:
                    log.write('detach_failed', message=str(exc))
                if session.process.alive:
                    notify('元の命令への復元を確認できませんでした。ゲームを終了してください。\nゲーム終了までランチャーは待機します。\n' + str(exc))
                    while session.process.alive:
                        time.sleep(0.5)
                session.process.close()
        if log:
            log.write('launcher_exited', log_write_failed=log.failed)
            log.close()
        if mutex:
            close(mutex)


if __name__ == '__main__':
    main()
