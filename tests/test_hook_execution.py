"""Execute the generated x86 bytes, independently of the game's process."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
    UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EIP)
from hook_code import build_hook, make_header, ORIGINAL, HEADER_SIZE, DATA_SIZE, decode_record

CODE, DATA, SITE, VTABLE = 0x10000000, 0x11000000, 0x49B292, 0x5A6264
RENDERER, STACK, ESP = 0x20000000, 0x30000000, 0x30001000


class HookExecutionTests(unittest.TestCase):
    def execute(self, height=12, width=24, mode=1, capture=False, lock=0,
                matching=True, buffer_matching=True, flags=0x602):
        cpu = Uc(UC_ARCH_X86, UC_MODE_32)
        for start, size in [(CODE, 0x1000), (DATA, 0x10000),
                            (SITE & ~4095, 4096), (RENDERER, 0x1000),
                            (STACK, 0x4000), (0, 4096)]:
            cpu.mem_map(start, size)
        # Only renderer's first page is mapped: text at +D44 could be
        # readable but the prefix straddles a guard/unmapped page instead.
        renderer = RENDERER + 0x240
        def put(address, value):
            cpu.mem_write(address, struct.pack('<I', value & 0xffffffff))
        cpu.mem_write(CODE, build_hook(CODE, DATA, SITE, VTABLE, capture=capture))
        cpu.mem_write(DATA, make_header(SITE, CODE, mode, capture=capture))
        put(DATA+56, lock)
        put(renderer, VTABLE if matching else VTABLE+4)
        put(renderer+0x53c, renderer+0xd44 if buffer_matching else renderer+0xd40)
        put(renderer+0x464, height)
        put(ESP+0x88, width)
        put(ESP+0x9b8, 640)
        put(ESP+0x9b0, 0)
        put(0x24, 42)  # FS:[24], test TEB ID
        regs = {UC_X86_REG_EAX:0x11223344, UC_X86_REG_EBX:0x55667788,
                UC_X86_REG_ECX:0xaabbccdd, UC_X86_REG_EDX:0x12345678,
                UC_X86_REG_ESI:0x87654321, UC_X86_REG_EDI:0x13579bdf,
                UC_X86_REG_EBP:renderer, UC_X86_REG_ESP:ESP}
        for reg, value in regs.items():
            cpu.reg_write(reg, value)
        cpu.reg_write(UC_X86_REG_EFLAGS, flags)
        before_stack = bytes(cpu.mem_read(ESP, 0x1000))
        cpu.emu_start(CODE, SITE+len(ORIGINAL), count=1000)
        self.assertEqual(cpu.reg_read(UC_X86_REG_EIP), SITE+len(ORIGINAL))
        expected = height+1 if matching and buffer_matching and mode==1 and 1<=height<=512 and width==2*height else width
        for reg, value in regs.items():
            self.assertEqual(cpu.reg_read(reg), expected & 0xffffffff if reg==UC_X86_REG_ECX else value)
        self.assertEqual(cpu.reg_read(UC_X86_REG_EFLAGS), flags)
        self.assertEqual(bytes(cpu.mem_read(ESP, 0x1000)), before_stack)
        header = bytes(cpu.mem_read(DATA, HEADER_SIZE))
        if capture and matching and buffer_matching and not lock:
            self.assertEqual(struct.unpack_from('<I', header, 56)[0], 0)
            record = decode_record(bytes(cpu.mem_read(DATA+HEADER_SIZE, 256)), 1)
            self.assertIsNotNone(record)
            self.assertEqual(record['original_M'], width)
            self.assertEqual(record['effective_M'], expected)
            self.assertEqual(record['text_prefix'], '')
        else:
            self.assertEqual(struct.unpack_from('<I', header, 32)[0], 0)
        return cpu

    def test_width_policy_all_heights_and_adjacent_widths(self):
        for capture in (False,True):
            for height in range(1, 513):
                for width in (2*height-1, 2*height, 2*height+1):
                    with self.subTest(height=height, width=width,capture=capture):
                        self.execute(height, width,capture=capture)

    def test_bounds_off_mode_mismatch_and_preserved_flags(self):
        for capture in (False, True):
            for height in (0, 513, -1, 0x7fffffff):
                self.execute(height, 24, capture=capture)
            for flags in (0x202, 0x246, 0x602, 0x693):
                self.execute(capture=capture, flags=flags)
                self.execute(mode=0, capture=capture, flags=flags)
            self.execute(matching=False, capture=capture)
            self.execute(buffer_matching=False,capture=capture)

    def test_busy_recorder_still_corrects_without_touching_slot(self):
        cpu = self.execute(capture=True, lock=1)
        self.assertEqual(bytes(cpu.mem_read(DATA+HEADER_SIZE, 256)), bytes(256))
        self.assertEqual(struct.unpack('<I', bytes(cpu.mem_read(DATA+56,4)))[0], 1)

    def test_telemetry_counter_and_commit(self):
        cpu = self.execute(capture=True)
        self.assertEqual(struct.unpack('<I', bytes(cpu.mem_read(DATA+32,4)))[0], 1)


if __name__ == '__main__':
    unittest.main()
