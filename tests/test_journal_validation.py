"""Recovery metadata validation tests; no Windows APIs or game required."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hook_code import DATA_SIZE, ORIGINAL, VERSION
from journal_validation import load_recovery_journal, MAX_JOURNAL_BYTES


class RecoveryJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "hook.json"
        self.pid = 1234
        self.creation = 1000.125
        self.site = 0x49B292
        self.vtable = 0x5A6264
        self.record = {
            "version": VERSION, "state": "installed",
            "pid": self.pid, "creation": self.creation,
            "site": self.site, "vtable": self.vtable,
            "code": 0x10000000, "data": 0x11000000,
            "original": ORIGINAL.hex(), "hook_sha256": "a" * 64,
        }

    def write(self, record=None):
        self.path.write_text(json.dumps(self.record if record is None else record), encoding="utf-8")

    def load(self):
        return load_recovery_journal(
            self.path, pid=self.pid, creation=self.creation,
            site=self.site, vtable=self.vtable,
            original=ORIGINAL, version=VERSION, data_size=DATA_SIZE,
        )

    def test_valid_journal_states(self):
        for state in ("prepared", "installed", "recovered"):
            with self.subTest(state=state):
                self.record["state"] = state
                self.write()
                self.assertEqual(self.load()["code"], 0x10000000)

    def test_missing_and_corrupt_journals(self):
        with self.assertRaises(RuntimeError):
            self.load()
        for payload in (b"not-json", b"{", b"\xff", b" " * (MAX_JOURNAL_BYTES + 1)):
            with self.subTest(length=len(payload)):
                self.path.write_bytes(payload)
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_wrong_process_or_hook_identity_is_rejected(self):
        variants = {
            "version": VERSION + 1,
            "state": "detached",
            "pid": self.pid + 1,
            "creation": self.creation + 1,
            "site": self.site + 5,
            "vtable": self.vtable + 4,
            "original": "909090",
            "hook_sha256": "invalid",
        }
        for key, value in variants.items():
            with self.subTest(key=key):
                record = {**self.record, key: value}
                self.write(record)
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_wrong_types_and_nonfinite_creation_are_rejected(self):
        variations = (
            {"pid": True}, {"pid": "1234"}, {"code": "0x10000000"},
            {"creation": None}, {"creation": "1000.125"}, {"creation": float("nan")},
            {"creation": float("inf")},
        )
        for change in variations:
            with self.subTest(change=change):
                self.write({**self.record, **change})
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_unsafe_addresses_rejected(self):
        changes = (
            {"code": 0}, {"data": -1},
            {"code": 0x7FFFFFF0},
            {"data": 0x7FFFFFF0},
            {"data": 0x10000010},
            {"code": 0x11000010},
        )
        for change in changes:
            with self.subTest(change=change):
                self.write({**self.record, **change})
                with self.assertRaises(RuntimeError):
                    self.load()


if __name__ == "__main__":
    unittest.main()
