"""Regression checks for the pure-Python x86 hook encoder (no game required)."""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hook_code import (  # noqa: E402
    CAPACITY, DATA_SIZE, HEADER_SIZE, MAGIC, ORIGINAL, RECORD_SIZE,
    REPLACEMENT, VERSION, build_hook, make_header, make_jump,
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


if __name__ == "__main__":
    unittest.main()
