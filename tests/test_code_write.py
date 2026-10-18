"""Windows-only fault-injection checks for remote code-write rollback.

Only a fake in-memory process is used: no real process is opened or patched.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

if sys.platform != "win32":
    raise unittest.SkipTest("Process Win32 API bindings require Windows")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import process_patch


class CodeWriteTests(unittest.TestCase):
    def setUp(self):
        self.before = b"\x8b\x8c\x24\x88\x00\x00\x00"
        self.replacement = b"\xe9\x01\x02\x03\x04\x90\x90"
        self.memory = self.before
        self.protection = process_patch.PAGE_RX
        self.protection_calls = []
        self.writes = []
        self.process = process_patch.Process.__new__(process_patch.Process)
        self.process.handle = 123
        self.process.read = self.read
        self.process.write = self.write
        self.process.protect = self.protect

    def read(self, address, length):
        self.assertEqual(address, 0x49B292)
        return self.memory[:length]

    def write(self, address, data):
        self.assertEqual(address, 0x49B292)
        self.writes.append(data)
        self.memory = bytes(data)

    def protect(self, address, length, new_protection):
        old = self.protection
        self.protection = new_protection
        self.protection_calls.append(new_protection)
        return old

    def assert_protection_restored(self):
        self.assertEqual(self.protection, process_patch.PAGE_RX)
        self.assertEqual(self.protection_calls[0], process_patch.PAGE_RWX)
        self.assertEqual(self.protection_calls[-1], process_patch.PAGE_RX)

    def test_successful_patch(self):
        with patch.object(process_patch, "flush_cache", return_value=1):
            self.process.code_write(0x49B292, self.replacement)
        self.assertEqual(self.memory, self.replacement)
        self.assertEqual(self.writes, [self.replacement])
        self.assert_protection_restored()

    def test_partial_write_error_rolls_back(self):
        def partially_write_then_raise(address, data):
            self.writes.append(data)
            if len(self.writes) == 1:
                self.memory = data[:3] + self.before[3:]
                raise OSError("simulated partial write")
            self.memory = bytes(data)

        self.process.write = partially_write_then_raise
        with patch.object(process_patch, "flush_cache", return_value=1):
            with self.assertRaisesRegex(process_patch.CodeWriteError, "partial"):
                self.process.code_write(0x49B292, self.replacement)
        self.assertEqual(self.memory, self.before)
        self.assertEqual(self.writes, [self.replacement, self.before])
        self.assert_protection_restored()

    def test_verification_mismatch_rolls_back(self):
        def wrong_write(address, data):
            self.writes.append(data)
            self.memory = b"X" * len(data) if len(self.writes) == 1 else bytes(data)

        self.process.write = wrong_write
        with patch.object(process_patch, "flush_cache", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "書込後照合"):
                self.process.code_write(0x49B292, self.replacement)
        self.assertEqual(self.memory, self.before)
        self.assert_protection_restored()

    def test_flush_failure_rolls_back(self):
        with patch.object(process_patch, "flush_cache", side_effect=[0, 1]) as flush:
            with self.assertRaises(process_patch.CodeWriteError):
                self.process.code_write(0x49B292, self.replacement)
        self.assertEqual(flush.call_count, 2)
        self.assertEqual(self.memory, self.before)
        self.assert_protection_restored()

    def test_protection_restore_failure_rolls_back_and_retries_original_protection(self):
        original_protect = self.process.protect
        failed = False
        def protect(address, length, protection):
            nonlocal failed
            if protection == process_patch.PAGE_RX and not failed:
                failed = True
                raise OSError('restore protection failed')
            return original_protect(address, length, protection)
        self.process.protect = protect
        with patch.object(process_patch, 'flush_cache', return_value=1):
            with self.assertRaises(process_patch.CodeWriteError) as result:
                self.process.code_write(0x49B292, self.replacement)
        self.assertTrue(result.exception.rolled_back)
        self.assertEqual(self.memory, self.before)
        self.assertEqual(self.protection, process_patch.PAGE_RX)

    def test_permanent_protection_failure_is_not_reported_as_safe(self):
        original_protect = self.process.protect
        def protect(address, length, protection):
            if protection == process_patch.PAGE_RX:
                raise OSError('restore protection failed')
            return original_protect(address, length, protection)
        self.process.protect = protect
        with patch.object(process_patch, 'flush_cache', return_value=1):
            with self.assertRaises(process_patch.CodeWriteError) as result:
                self.process.code_write(0x49B292, self.replacement)
        self.assertFalse(result.exception.rolled_back)
        self.assertEqual(self.memory, self.before)

    def test_initial_protect_failure_does_not_write(self):
        self.process.protect = unittest.mock.Mock(side_effect=OSError('protect failed'))
        with self.assertRaises(process_patch.CodeWriteError) as failure:
            self.process.code_write(0x49B292, self.replacement)
        self.assertTrue(failure.exception.rolled_back)
        self.assertEqual(self.memory, self.before)
        self.assertEqual(self.writes, [])

    def test_failed_rollback_reports_unverified_state(self):
        def always_fail(address, data):
            self.writes.append(data)
            self.memory = b"X" * len(data)
            raise OSError("write failed")

        self.process.write = always_fail
        with patch.object(process_patch, "flush_cache", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "ゲームを終了"):
                self.process.code_write(0x49B292, self.replacement)
        self.assertNotEqual(self.memory, self.before)
        self.assert_protection_restored()


if __name__ == "__main__":
    unittest.main()
