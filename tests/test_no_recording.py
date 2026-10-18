"""Execute the shipping hook with unreadable text and watch all memory accesses."""
import struct
import sys
import unittest
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EFLAGS

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from hook_code import build_hook, make_header, DATA_SIZE, CAPACITY, RECORD_SIZE, VERSION


class NoRecordingTests(unittest.TestCase):
    def exercise(self, mode=1, count=1):
        cpu=Uc(UC_ARCH_X86,UC_MODE_32)
        code,data,site,obj,stack=0x10000000,0x11000000,0x49b292,0x200002bc,0x30002000
        # this+D44 is exactly the following unmapped page. Any text read faults.
        for address,size in ((code,4096),(data,4096),(site&~4095,4096),
                             (0x20000000,4096),(0x30000000,0x4000)):
            cpu.mem_map(address,size)
        def put(address,value):
            cpu.mem_write(address,struct.pack('<I',value))
        put(obj,0x5a6264);put(obj+0x53c,obj+0xd44);put(obj+0x464,12)
        put(stack+0x88,24)
        cpu.mem_write(code,build_hook(code,data,site,0x5a6264))
        cpu.mem_write(data,make_header(site,code,mode))
        before_data=bytes(cpu.mem_read(data,4096))
        before_object=bytes(cpu.mem_read(0x20000000,4096))
        reads,writes=set(),set()
        cpu.hook_add(UC_HOOK_MEM_READ,lambda uc,access,address,size,value,ctx:reads.add((address,size)))
        cpu.hook_add(UC_HOOK_MEM_WRITE,lambda uc,access,address,size,value,ctx:writes.add((address,size)))
        for _ in range(count):
            cpu.reg_write(UC_X86_REG_EBP,obj)
            cpu.reg_write(UC_X86_REG_ESP,stack)
            cpu.reg_write(UC_X86_REG_EFLAGS,0x602)
            cpu.emu_start(code,site+7,count=200)
            self.assertEqual(cpu.reg_read(UC_X86_REG_ECX),13 if mode else 24)
        self.assertEqual(bytes(cpu.mem_read(data,4096)),before_data)
        self.assertEqual(bytes(cpu.mem_read(0x20000000,4096)),before_object)
        self.assertTrue(all(stack-36<=address and address+size<=stack for address,size in writes))
        nonstack={(address,size) for address,size in reads if not stack-36<=address<stack+0x100}
        expected={(obj,4),(obj+0x53c,4),(data+20,4)}
        if mode:
            expected.add((obj+0x464,4))
        self.assertEqual(nonstack,expected)

    def test_no_text_or_telemetry_access_on(self):
        self.exercise()

    def test_no_text_or_telemetry_access_off(self):
        self.exercise(mode=0)

    def test_repeated_calls_never_write_shared_data(self):
        self.exercise(count=1024)

    def test_no_ring_and_distinct_protocol(self):
        self.assertEqual((DATA_SIZE,CAPACITY,RECORD_SIZE,VERSION),(64,0,0,5))
