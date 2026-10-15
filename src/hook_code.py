"""Small x86 observation/fix trampoline for one verified WSC3 instruction.

No calls or protected dispatcher instructions are inserted. A bounded ring
buffer receives snapshots at the point the width has just been loaded.
"""
from __future__ import annotations

import struct

MAGIC = b'WSC3WRAP20261015'
VERSION = 3
HEADER_SIZE = 64
CAPACITY = 128
RECORD_SIZE = 256
DATA_SIZE = HEADER_SIZE + CAPACITY * RECORD_SIZE
MODE_OFFSET = 20
COUNTER_OFFSET = 32
FIXES_OFFSET = 40
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

    a.emit('b801000000f00fc105'); a.u32(data+COUNTER_OFFSET)
    a.emit('8d7001')                         # ESI=sequence, counter+1
    a.emit('257f000000c1e00805'); a.u32(data+HEADER_SIZE)
    a.emit('89c7c7070000000089773c')          # EDI=record, clear commit; seq mirror
    a.emit('896f04')                         # renderer
    a.emit('8b44241889470889470c894738')       # original ECX; original/effective M
    a.emit('833d'); a.u32(data+MODE_OFFSET); a.emit('01'); a.jne('no_fix')
    # Experimental shared-renderer policy: M == 2*font height -> height+1.
    # Accept positive heights up to 512, preserving all other metric values.
    a.emit('8b95640400008d4aff81f9ff010000')  # EDX=height; ECX=height-1
    a.emit('0f87'); a.refs.append((len(a.code),'no_fix')); a.u32(0)
    a.emit('8d0c1239c8'); a.jne('no_fix')     # compare original M with 2*height
    a.emit('8d42018944241889470c')            # saved ECX and record = height+1
    a.emit('f0ff05'); a.u32(data+FIXES_OFFSET)
    a.label('no_fix')
    a.emit('8b8424dc0900002b8424d4090000894710')
    for source,dest in [(0x464,20),(0x468,24),(0x410,28),(0x53C,32)]:
        a.emit('8b85'); a.u32(source); a.emit(bytes([0x89,0x47,dest]))
    a.emit('8b4c24188b47102bc189472c')         # available=width-effective M
    a.emit('85c9')
    a.emit('0f8e'); a.refs.append((len(a.code),'invalid_quota')); a.u32(0)
    a.emit('99f7f9894724'); a.jump('quota_done')
    a.label('invalid_quota'); a.emit('c74724ffffffff')
    a.label('quota_done')
    a.emit('64a124000000894728')              # TEB32 thread ID, no API call
    a.emit('8b842494000000894730')            # original ESP+70: metrics height
    a.emit('8b8424a8000000894734')            # original ESP+84: average width
    a.emit('8db5440d00005783c740b920000000fcf3a55f')  # prefix128, DF saved
    for source,dest in [(0x418,192),(0x41C,196),(0x46C,200)]:
        a.emit('8b85'); a.u32(source); a.emit('8987'); a.u32(dest)
    a.emit('8b473c8907')                     # commit seq LAST
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


def decode_record(raw, expected_sequence):
    if len(raw)!=RECORD_SIZE:
        return None
    v = struct.unpack_from('<16I',raw)
    if v[0]!=expected_sequence or v[15]!=expected_sequence:
        return None
    signed = lambda value: value if value<0x80000000 else value-0x100000000
    return {'sequence':v[0],'renderer':hex(v[1]),'original_M':signed(v[2]),
            'effective_M':signed(v[3]),'rect_width':signed(v[4]),'font_height':v[5],
            'line_gap':v[6],'hdc':hex(v[7]),'text_address':hex(v[8]),
            'quota':signed(v[9]),'thread_id':v[10],'available_width':signed(v[11]),
            'metrics_height':signed(v[12]),'average_width':signed(v[13]),
            'original_metrics_max':signed(v[14]),
            'surface_width':signed(struct.unpack_from('<I',raw,192)[0]),
            'surface_height':signed(struct.unpack_from('<I',raw,196)[0]),
            'renderer_flags':struct.unpack_from('<I',raw,200)[0],
            'text_prefix':raw[64:192].split(b'\0',1)[0].decode('cp932',errors='replace')}
