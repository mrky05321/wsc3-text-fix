"""Execute the unchanged v0.1.1 x86 hook against synthetic renderer memory."""
import struct
import sys
from pathlib import Path
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,
 UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,
 UC_X86_REG_EFLAGS,UC_X86_REG_EIP)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from hook_code import build_hook,make_header,ORIGINAL


class V011ExecutionTests(unittest.TestCase):
    def check(self,height,width,mode=1,renderer=True,buffer=True,flags=0x602):
        cpu=Uc(UC_ARCH_X86,UC_MODE_32)
        code,data,site,obj,stack=0x10000000,0x11000000,0x49b292,0x20000000,0x30002000
        for address,size in [(code,4096),(data,0x10000),(site&~4095,4096),
                             (obj,0x3000),(stack-0x2000,0x10000),(0,4096)]:
            cpu.mem_map(address,size)
        def put(address,value):
            cpu.mem_write(address,struct.pack('<I',value&0xffffffff))
        put(obj,0x5a6264 if renderer else 0x5a6268)
        put(obj+0x53c,obj+0xd44 if buffer else obj+0xe44)
        put(obj+0x464,height)
        put(stack+0x88,width)
        put(stack+0x9b8,328)
        initial={UC_X86_REG_EAX:0x81234567,UC_X86_REG_EBX:0x23456789,
                 UC_X86_REG_ECX:0xfedcba98,UC_X86_REG_EDX:0x10203040,
                 UC_X86_REG_ESI:0x44556677,UC_X86_REG_EDI:0x8899aabb,
                 UC_X86_REG_EBP:obj,UC_X86_REG_ESP:stack,UC_X86_REG_EFLAGS:flags}
        for reg,value in initial.items():
            cpu.reg_write(reg,value)
        before=bytes(cpu.mem_read(obj,0x3000))
        cpu.mem_write(code,build_hook(code,data,site,0x5a6264))
        cpu.mem_write(data,make_header(site,code,mode))
        cpu.emu_start(code,site+len(ORIGINAL),count=1000)
        expected=height+1 if mode and renderer and buffer and 1<=height<=512 and width==height*2 else width
        self.assertEqual(cpu.reg_read(UC_X86_REG_EIP),site+7)
        for reg,value in initial.items():
            self.assertEqual(cpu.reg_read(reg),(expected&0xffffffff) if reg==UC_X86_REG_ECX else value)
        self.assertEqual(bytes(cpu.mem_read(obj,0x3000)),before)
        self.assertEqual(bytes(cpu.mem_read(stack+0x88,4)),struct.pack('<I',width&0xffffffff))

    def test_all_heights_adjacent_widths_on_and_off(self):
        for mode in (0,1):
            for height in range(1,513):
                for width in (height*2-1,height*2,height*2+1):
                    self.check(height,width,mode)

    def test_bounds_renderer_buffer_and_cpu_flags(self):
        for height in (-1,0,513,0x7fffffff):
            self.check(height,24)
        self.check(12,24,renderer=False)
        self.check(12,24,buffer=False)
        for flags in (0x202,0x246,0x602,0x693):
            self.check(12,24,flags=flags)
