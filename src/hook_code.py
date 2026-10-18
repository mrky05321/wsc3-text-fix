"""Correction-only x86 trampoline: no text copies, records, or counters."""
from __future__ import annotations

import struct

MAGIC = b'WSC3WRAP20261015'
VERSION = 5
HEADER_SIZE = 64
CAPACITY = 0
RECORD_SIZE = 0
DATA_SIZE = HEADER_SIZE + CAPACITY * RECORD_SIZE
MODE_OFFSET = 20
ORIGINAL = bytes.fromhex('8b8c2488000000')
SITE_RVA = 0x9B292
VTABLE_RVA = 0x1A6264
REPLACEMENT = 13


class Assembler:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.refs = []

    def emit(self, value):
        self.code.extend(bytes.fromhex(value) if isinstance(value,str) else value)

    def u32(self, value):
        self.code.extend(struct.pack('<I', value & 0xFFFFFFFF))

    def label(self, name):
        self.labels[name] = len(self.code)

    def jne(self, label):
        self.emit('0f85')
        self.refs.append((len(self.code),label))
        self.u32(0)

    def jump(self, label):
        self.emit('e9')
        self.refs.append((len(self.code),label))
        self.u32(0)

    def finish(self):
        for offset,label in self.refs:
            struct.pack_into('<i',self.code,offset,self.labels[label]-(offset+4))
        return bytes(self.code)


def make_header(site, code_address, mode=0):
    raw = bytearray(HEADER_SIZE)
    raw[:16] = MAGIC
    struct.pack_into('<12I',raw,16,VERSION,mode,REPLACEMENT,CAPACITY,0,0,0,
                     RECORD_SIZE,site,code_address,0,0)
    return bytes(raw)


def build_hook(address, data, site, vtable):
    a = Assembler()
    a.emit(ORIGINAL)                         # original MOV, before changing ESP
    a.emit('9c60')                           # PUSHFD; PUSHAD, 36 bytes
    a.emit('817d00'); a.u32(vtable); a.jne('done')
    a.emit('8d85440d0000')                   # output buffer must be this+D44
    a.emit('39853c050000'); a.jne('done')

    a.emit('8b442418')                      # saved original ECX -> EAX
    a.emit('833d'); a.u32(data+MODE_OFFSET); a.emit('01'); a.jne('done')
    # Experimental shared-renderer policy: M == 2*font height -> height+1.
    # Accept positive heights up to 512, preserving all other metric values.
    a.emit('8b95640400008d4aff81f9ff010000')  # EDX=height; ECX=height-1
    a.emit('0f87'); a.refs.append((len(a.code),'done')); a.u32(0)
    a.emit('8d0c1239c8'); a.jne('done')     # compare original M with 2*height
    a.emit('8d420189442418')                # height+1 -> saved ECX only
    a.label('done')
    a.emit('619d')                           # POPAD; POPFD
    a.emit('e9')
    a.u32((site+len(ORIGINAL))-(address+len(a.code)+4))
    return a.finish()


def make_jump(site, destination):
    delta = destination-(site+5)
    if not -0x80000000 <= delta < 0x80000000:
        raise ValueError('Jump is outside signed 32-bit range')
    return b'\xE9'+struct.pack('<i',delta)+b'\x90\x90'
