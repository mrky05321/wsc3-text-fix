"""Regression checks for the pure-Python x86 hook encoder (no game required)."""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hook_code import (  # noqa: E402
    CAPACITY, DATA_SIZE, HEADER_SIZE, MAGIC, ORIGINAL, RECORD_SIZE,
    REPLACEMENT, VERSION, build_hook, decode_record, make_header, make_jump,
)


class HeaderTests(unittest.TestCase):
    def test_header_fields_and_layout(self):
        site, code = 0x49B292, 0x10000000
        header = make_header(site, code, mode=1)
        self.assertEqual(len(header), HEADER_SIZE)
        self.assertEqual(header[:16], MAGIC)
        values = struct.unpack_from("<12I", header, 16)
        self.assertEqual(values[:4], (VERSION, 1, REPLACEMENT, CAPACITY))
        self.assertEqual(values[7:10], (RECORD_SIZE, site, code))
        self.assertEqual(DATA_SIZE, HEADER_SIZE + CAPACITY * RECORD_SIZE)

    def test_default_mode_is_observe(self):
        self.assertEqual(struct.unpack_from("<I", make_header(1, 2), 20)[0], 0)


class JumpTests(unittest.TestCase):
    def test_forward_and_backward_jump_targets(self):
        for site, destination in ((0x49B292, 0x20000000), (0x20000000, 0x49B292)):
            with self.subTest(site=site, destination=destination):
                raw = make_jump(site, destination)
                self.assertEqual(len(raw), len(ORIGINAL))
                self.assertEqual(raw[:1], b"\xe9")
                self.assertEqual(raw[5:], b"\x90\x90")
                displacement = struct.unpack_from("<i", raw, 1)[0]
                self.assertEqual(site + 5 + displacement, destination)

    def test_out_of_range_jump_is_rejected(self):
        with self.assertRaises(ValueError):
            make_jump(0x1000, 0x90001000)
        with self.assertRaises(ValueError):
            make_jump(0x90001000, 0x1000)


class HookTests(unittest.TestCase):
    def test_hook_replays_original_and_returns_after_patched_instruction(self):
        address, data, site, vtable = 0x10000000, 0x11000000, 0x49B292, 0x5A6264
        raw = build_hook(address, data, site, vtable)
        self.assertTrue(raw.startswith(ORIGINAL))
        self.assertEqual(raw[-5], 0xE9)
        displacement = struct.unpack_from("<i", raw, len(raw) - 4)[0]
        self.assertEqual(address + len(raw) + displacement, site + len(ORIGINAL))
        self.assertLess(len(raw), 4096)

    def test_generated_hook_is_deterministic(self):
        inputs = (0x10000000, 0x11000000, 0x49B292, 0x5A6264)
        self.assertEqual(build_hook(*inputs), build_hook(*inputs))


class RecordTests(unittest.TestCase):
    def make_record(self, sequence=7):
        raw = bytearray(RECORD_SIZE)
        struct.pack_into(
            "<16I", raw, 0,
            sequence, 0x401000, 24, 13, 640, 12, 2, 0x12345678,
            0x402000, 12, 42, 627, 12, 9, 24, sequence,
        )
        raw[64:67] = "あ".encode("cp932") + b"\0"
        struct.pack_into("<III", raw, 192, 640, 480, 3)
        return raw

    def test_valid_record_decodes_all_key_fields(self):
        decoded = decode_record(bytes(self.make_record()), 7)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sequence"], 7)
        self.assertEqual(decoded["original_M"], 24)
        self.assertEqual(decoded["effective_M"], 13)
        self.assertEqual(decoded["thread_id"], 42)
        self.assertEqual(decoded["text_prefix"], "あ")
        self.assertEqual(decoded["surface_width"], 640)
        self.assertEqual(decoded["surface_height"], 480)
        self.assertEqual(decoded["renderer_flags"], 3)

    def test_incomplete_or_overwritten_record_is_rejected(self):
        raw = self.make_record()
        self.assertIsNone(decode_record(bytes(raw[:-1]), 7))
        self.assertIsNone(decode_record(bytes(raw), 8))
        struct.pack_into("<I", raw, 60, 6)  # Commit sequence differs.
        self.assertIsNone(decode_record(bytes(raw), 7))

    def test_signed_widths_are_preserved(self):
        raw = self.make_record()
        struct.pack_into("<I", raw, 8, 0xFFFFFFFF)
        struct.pack_into("<I", raw, 12, 0x80000000)
        decoded = decode_record(bytes(raw), 7)
        self.assertEqual(decoded["original_M"], -1)
        self.assertEqual(decoded["effective_M"], -0x80000000)


if __name__ == "__main__":
    unittest.main()
