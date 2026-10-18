"""Strict validation for the small local WSC3 hook-recovery journal.

Keep this module free of Windows dependencies so malformed files can be
tested without running or modifying a game process.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import re

MAX_JOURNAL_BYTES = 4096
MIN_USER_ADDRESS = 0x10000
MAX_HOOK_ADDRESS = 0x80000000


def load_recovery_journal(
    path: Path, *, pid: int, creation: float, site: int, vtable: int,
    original: bytes, version: int, data_size: int, code_capacity: int = 4096,
) -> dict:
    """Validate local metadata before any remote memory reads or writes."""
    try:
        with Path(path).open("rb") as source:
            raw = source.read(MAX_JOURNAL_BYTES + 1)
        if len(raw) > MAX_JOURNAL_BYTES:
            raise ValueError("Recovery journal exceeds the size limit")
        journal = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise RuntimeError("復元情報が読めないか破損しています。変更を中止します。") from exc

    if not isinstance(journal, dict):
        raise RuntimeError("復元情報の形式が不正です。")
    for field in ("version", "pid", "site", "vtable", "code", "data"):
        if type(journal.get(field)) is not int:
            raise RuntimeError(f"復元情報の {field} が不正です。")
    recorded_creation = journal.get("creation")
    if (type(recorded_creation) not in (int, float)
            or recorded_creation <= 0 or recorded_creation > 1e12
            or not math.isfinite(recorded_creation)):
        raise RuntimeError("復元情報の作成時刻が不正です。")
    if (journal["version"] != version or journal["pid"] != pid
            or abs(recorded_creation - creation) > 0.001
            or journal["site"] != site or journal["vtable"] != vtable
            or journal.get("original") != original.hex()
            or journal.get("state") not in ("prepared", "installed", "recovered")):
        raise RuntimeError("復元情報と現在のプロセスが一致しません。")

    code, data = journal["code"], journal["data"]
    if type(journal.get('capture')) is not bool:
        raise RuntimeError('復元情報の記録設定が不正です。')
    for address, size in ((code, code_capacity), (data, data_size)):
        if not (MIN_USER_ADDRESS <= address and address + size < MAX_HOOK_ADDRESS) or address % 4096:
            raise RuntimeError("復元情報のメモリアドレスが範囲外です。")
    if code < data + data_size and data < code + code_capacity:
        raise RuntimeError("復元情報の中継領域が重複しています。")
    digest = journal.get("hook_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("復元情報のコードハッシュが不正です。")
    return journal
