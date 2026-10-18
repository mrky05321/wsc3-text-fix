"""Windows process backend. Only the verified game-code site is changed.

Threads are suspended while installing/removing the jump, then resumed exactly
once. Capturing and toggling mode never use a debugger or touch DRM code.
"""
from __future__ import annotations

import contextlib
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import struct
import time

import psutil

from hook_code import (MAGIC, VERSION, HEADER_SIZE, CAPACITY, RECORD_SIZE, DATA_SIZE,
                       MODE_OFFSET, COUNTER_OFFSET, ORIGINAL, SITE_RVA, VTABLE_RVA,
                       build_hook, make_header, make_jump, decode_record)
from journal_validation import load_recovery_journal
from safety_hold import require_runtime_approval

K = C.WinDLL('kernel32', use_last_error=True)
INVALID = C.c_void_p(-1).value
GAME_SHA256 = '9a2a92e473e825b51a9d5bf657d84890e6d96ae3e586c8a5ce15c15514c3f4fc'
SNAP_THREAD, SNAP_MODULE = 4, 0x18
PAGE_RW, PAGE_RX, PAGE_RWX = 4, 0x20, 0x40


def bind(name, result, args):
    f = getattr(K,name)
    f.restype, f.argtypes = result,args
    return f


open_process = bind('OpenProcess',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD])
close = bind('CloseHandle',W.BOOL,[W.HANDLE])
read_memory = bind('ReadProcessMemory',W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)])
write_memory = bind('WriteProcessMemory',W.BOOL,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)])
alloc_memory = bind('VirtualAllocEx',C.c_void_p,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD])
free_memory = bind('VirtualFreeEx',W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD])
protect_memory = bind('VirtualProtectEx',W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)])
flush_cache = bind('FlushInstructionCache',W.BOOL,[W.HANDLE,C.c_void_p,C.c_size_t])
snapshot = bind('CreateToolhelp32Snapshot',W.HANDLE,[W.DWORD,W.DWORD])
open_thread = bind('OpenThread',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD])
suspend_thread = bind('SuspendThread',W.DWORD,[W.HANDLE])
resume_thread = bind('ResumeThread',W.DWORD,[W.HANDLE])
wait_object = bind('WaitForSingleObject',W.DWORD,[W.HANDLE,W.DWORD])
is_wow64 = bind('IsWow64Process',W.BOOL,[W.HANDLE,C.POINTER(W.BOOL)])
create_mutex = bind('CreateMutexW',W.HANDLE,[C.c_void_p,W.BOOL,W.LPCWSTR])
context_function = bind('Wow64GetThreadContext' if C.sizeof(C.c_void_p)==8 else 'GetThreadContext',W.BOOL,[W.HANDLE,C.c_void_p])
thread_owner = bind('GetProcessIdOfThread',W.DWORD,[W.HANDLE])
query_memory = bind('VirtualQueryEx',C.c_size_t,[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t])


class MemoryInfo(C.Structure):
    _fields_=[('base',C.c_void_p),('allocation',C.c_void_p),('allocation_protect',W.DWORD),
              ('size',C.c_size_t),('state',W.DWORD),('protect',W.DWORD),('type',W.DWORD)]


class ThreadEntry(C.Structure):
    _fields_=[(n,W.DWORD) for n in ['size','usage','id','owner']]+[('base_priority',W.LONG),('delta_priority',W.LONG),('flags',W.DWORD)]


class ModuleEntry(C.Structure):
    _fields_=[(n,W.DWORD) for n in ['size','module_id','pid','global_usage','process_usage']]+[
        ('base',C.c_void_p),('image_size',W.DWORD),('module',W.HMODULE),
        ('name',W.WCHAR*256),('path',W.WCHAR*260)]


thread_first = bind('Thread32First',W.BOOL,[W.HANDLE,C.POINTER(ThreadEntry)])
thread_next = bind('Thread32Next',W.BOOL,[W.HANDLE,C.POINTER(ThreadEntry)])
module_first = bind('Module32FirstW',W.BOOL,[W.HANDLE,C.POINTER(ModuleEntry)])
module_next = bind('Module32NextW',W.BOOL,[W.HANDLE,C.POINTER(ModuleEntry)])


def check(ok, operation):
    if not ok:
        raise OSError(C.get_last_error(), f'{operation}: {C.FormatError(C.get_last_error()).strip()}')


def sha_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(4*1024*1024),b''):
            h.update(block)
    return h.hexdigest()


def process_list():
    found=[]
    for p in psutil.process_iter(['pid','name','exe']):
        try:
            if (p.info['name'] or '').lower()=='wsc3.exe':
                found.append({'pid':p.pid,'path':p.info['exe'] or ''})
        except (psutil.NoSuchProcess,psutil.AccessDenied):
            continue
    return found


def thread_ids(pid):
    h=snapshot(SNAP_THREAD,0)
    if h==INVALID:
        check(False,'Thread snapshot')
    result=[]
    try:
        e=ThreadEntry(); e.size=C.sizeof(e)
        ok=thread_first(h,C.byref(e))
        while ok:
            if e.owner==pid:
                result.append(e.id)
            ok=thread_next(h,C.byref(e))
        if C.get_last_error()!=18:  # ERROR_NO_MORE_FILES, not a failed snapshot
            check(False,'Thread enumeration')
    finally:
        close(h)
    return result


def module_base(pid, basename):
    for attempt in range(8):
        h=snapshot(SNAP_MODULE,pid)
        if h!=INVALID:
            break
        time.sleep(0.015)
    if h==INVALID:
        check(False,'Module snapshot')
    try:
        e=ModuleEntry(); e.size=C.sizeof(e)
        ok=module_first(h,C.byref(e))
        while ok:
            if e.name.lower()==basename.lower():
                return int(e.base),e.path
            ok=module_next(h,C.byref(e))
    finally:
        close(h)
    raise RuntimeError('対象のメインモジュールが見つかりません。')


class Process:
    def __init__(self,pid):
        self.pid=pid
        self.handle=open_process(0x400|0x8|0x10|0x20|0x100000,False,pid)
        check(self.handle,'OpenProcess')
        self.mutex=None
        try:
            self.creation=psutil.Process(pid).create_time()
            wow=W.BOOL()
            check(is_wow64(self.handle,C.byref(wow)),'IsWow64Process')
            if C.sizeof(C.c_void_p)==8 and not wow.value:
                raise RuntimeError('32bitプロセス専用です。対象がWSC3本体か確認してください。')
            C.set_last_error(0)
            self.mutex=create_mutex(None,False,f'Local\\WSC3Linewrap_{pid}_{int(self.creation*1000)}')
            error=C.get_last_error()
            check(self.mutex,'CreateMutexW')
            if error==183:
                raise RuntimeError('このプロセスには別の計測ソフトが接続中です。先に解除してください。')
        except Exception:
            self.close()
            raise

    @property
    def alive(self):
        return bool(self.handle) and wait_object(self.handle,0)==0x102

    def read(self,address,size):
        raw=C.create_string_buffer(size); count=C.c_size_t()
        check(read_memory(self.handle,address,raw,size,C.byref(count)),'ReadProcessMemory')
        if count.value!=size:
            raise RuntimeError('読み取りサイズが一致しません。')
        return raw.raw

    def write(self,address,raw):
        buf=C.create_string_buffer(raw,len(raw)); count=C.c_size_t()
        check(write_memory(self.handle,address,buf,len(raw),C.byref(count)),'WriteProcessMemory')
        if count.value!=len(raw):
            raise RuntimeError('書き込みサイズが一致しません。')

    def alloc(self,size):
        address=alloc_memory(self.handle,None,size,0x3000,PAGE_RW)
        check(address,'VirtualAllocEx')
        if address+size>=0x80000000:
            free_memory(self.handle,address,0,0x8000)
            raise RuntimeError('32bit中継に使える範囲へメモリを確保できませんでした。')
        return int(address)

    def free(self,address):
        check(free_memory(self.handle,address,0,0x8000),'VirtualFreeEx')

    def validate_allocation(self,address,size,protection):
        info=MemoryInfo()
        result=query_memory(self.handle,address,C.byref(info),C.sizeof(info))
        check(result==C.sizeof(info),'VirtualQueryEx')
        if (info.base!=address or info.allocation!=address or info.size<size
                or info.state!=0x1000 or info.type!=0x20000 or info.protect!=protection):
            raise RuntimeError('復元先の専用メモリ領域が一致しません。ゲームを終了してください。')

    def protect(self,address,size,protection):
        old=W.DWORD()
        check(protect_memory(self.handle,address,size,protection,C.byref(old)),'VirtualProtectEx')
        return old.value

    def code_write(self,address,raw):
        # The caller freezes all target threads. Keep the exact previous bytes
        # so a failed/partial write can be rolled back before threads resume.
        before=self.read(address,len(raw))
        old=self.protect(address,len(raw),PAGE_RWX)
        try:
            self.write(address,raw)
            check(flush_cache(self.handle,address,len(raw)),'FlushInstructionCache')
            if self.read(address,len(raw))!=raw:
                raise RuntimeError('コードの書込後照合に失敗しました。')
            self.protect(address,len(raw),old)
        except Exception as failure:
            restored=False
            try:
                # A failed VirtualProtectEx leaves protection unchanged, so
                # the page is still RWX here. Keep the ORIGINAL protection
                # for cleanup; never adopt RWX as the original state.
                self.write(address,before)
                check(flush_cache(self.handle,address,len(before)),'Rollback FlushInstructionCache')
                if self.read(address,len(before))!=before:
                    raise RuntimeError('元のコードへの復元後照合に失敗しました。')
                restored=True
            except Exception:
                pass
            protection_restored=False
            for _ in range(2):
                try:
                    self.protect(address,len(raw),old)
                    protection_restored=True
                    break
                except Exception:
                    pass
            if restored and protection_restored:
                raise CodeWriteError(str(failure), rolled_back=True) from failure
            raise CodeWriteError(
                '元の命令またはページ保護への復元を確認できません。対象ゲームを終了してください。',
                rolled_back=False) from failure

    @contextlib.contextmanager
    def frozen(self, forbidden=()):
        handles={}
        try:
            for _ in range(4):
                for tid,h in list(handles.items()):
                    if wait_object(h,0)==0:
                        close(h)
                        del handles[tid]
                pending=set(thread_ids(self.pid))-set(handles)
                if not pending:
                    if not handles and self.alive:
                        raise RuntimeError('対象スレッドを確認できません。変更を中止します。')
                    break
                for tid in pending:
                    h=open_thread(0x2|0x8|0x40|0x100000,False,tid)
                    if not h and C.get_last_error()==87:
                        continue  # Thread exited before OpenThread.
                    check(h,f'OpenThread({tid})')
                    if thread_owner(h)!=self.pid:
                        close(h)
                        raise RuntimeError('スレッド所有者が変化しました。変更を中止します。')
                    previous=suspend_thread(h)
                    if previous==0xFFFFFFFF:
                        close(h); check(False,f'SuspendThread({tid})')
                    handles[tid]=h
            else:
                raise RuntimeError('スレッド一覧が変化したため変更を中止しました。')
            for tid,h in handles.items():
                if wait_object(h,0)==0:
                    continue  # Terminated threads need no context or resume.
                ctx=C.create_string_buffer(716)
                struct.pack_into('<I',ctx,0,0x10001)
                check(context_function(h,ctx),f'Thread context({tid})')
                ip=struct.unpack_from('<I',ctx,184)[0]
                if any(lo<=ip<hi for lo,hi in forbidden):
                    raise BusySite('対象命令を実行中です。少し待って再試行してください。')
            yield
        finally:
            failures=[]
            for tid,h in handles.items():
                try:
                    if wait_object(h,0)!=0:
                        # Retry only after a failed ResumeThread (which did not
                        # decrement the count); never double-resume success.
                        if resume_thread(h)==0xFFFFFFFF:
                            if wait_object(h,0)!=0 and resume_thread(h)==0xFFFFFFFF:
                                if self.alive and wait_object(h,0)!=0:
                                    failures.append(tid)
                finally:
                    close(h)
            if failures:
                raise RuntimeError(f'スレッド再開を確認できませんでした: {failures}')

    def close(self):
        if getattr(self,'mutex',None):
            close(self.mutex)
            self.mutex=None
        if self.handle:
            close(self.handle)
            self.handle=None


class BusySite(RuntimeError):
    pass


class CodeNotReady(RuntimeError):
    """Expected during startup; the watcher may retry without changing code."""
    pass


class CodeWriteError(RuntimeError):
    def __init__(self,message,*,rolled_back):
        super().__init__(message)
        self.rolled_back=rolled_back


class Session:
    def __init__(self,process,site,vtable,journal,capture=True):
        self.process=process
        self.site=site
        self.vtable=vtable
        self.journal=Path(journal)
        self.code=0; self.data=0; self.code_bytes=b''
        self.installed=False; self.last=0; self.lost=0
        self.recovered=False
        self.capture=capture

    def _save(self,state):
        payload={'version':VERSION,'state':state,'pid':self.process.pid,
                 'creation':self.process.creation,'site':self.site,'vtable':self.vtable,
                 'code':self.code,'data':self.data,'original':ORIGINAL.hex(),
                 'hook_sha256':hashlib.sha256(self.code_bytes).hexdigest(),
                 'capture':self.capture,
                 'updated':time.time()}
        self.journal.parent.mkdir(parents=True,exist_ok=True)
        tmp=self.journal.with_suffix('.tmp')
        try:
            with tmp.open('w',encoding='utf-8') as stream:
                stream.write(json.dumps(payload,indent=2))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp,self.journal)
        except Exception:
            # Preserve the last valid journal and remove any incomplete temp.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _validate_remote(self):
        raw=self.process.read(self.data,HEADER_SIZE)
        if raw[:16]!=MAGIC:
            raise RuntimeError('計測領域の識別子が一致しません。')
        version,mode,replacement,capacity=struct.unpack_from('<4I',raw,16)
        stride,site,code=struct.unpack_from('<3I',raw,44)
        capture=struct.unpack_from('<I',raw,60)[0]
        if (version,replacement,capacity,stride,site,code)!=(VERSION,13,CAPACITY,RECORD_SIZE,self.site,self.code) or mode not in (0,1) or capture!=int(self.capture):
            raise RuntimeError('計測領域の構成が一致しません。')
        if self.process.read(self.code,len(self.code_bytes))!=self.code_bytes:
            raise RuntimeError('中継コードが変更されています。操作を中止します。')
        if self.process.read(self.site,len(ORIGINAL))!=make_jump(self.site,self.code):
            raise RuntimeError('対象命令が別の内容へ変更されています。操作を中止します。')
        return raw

    def install(self,mode=0):
        if type(mode) is not int or mode not in (0,1):
            raise ValueError('mode')
        if self.process.read(self.site,len(ORIGINAL))!=ORIGINAL:
            self._recover()
            self.set_mode(mode)
            return
        self.data=self.process.alloc(DATA_SIZE)
        try:
            self.code=self.process.alloc(4096)
            self.code_bytes=build_hook(self.code,self.data,self.site,self.vtable,capture=self.capture)
            self.process.write(self.data,make_header(self.site,self.code,mode,capture=self.capture))
            self.process.write(self.code,self.code_bytes)
            self.process.protect(self.code,4096,PAGE_RX)
            check(flush_cache(self.process.handle,self.code,len(self.code_bytes)),'FlushInstructionCache')
            self._save('prepared')
            for attempt in range(30):
                try:
                    with self.process.frozen([(self.site+1,self.site+len(ORIGINAL))]):
                        if self.process.read(self.site,len(ORIGINAL))!=ORIGINAL:
                            raise RuntimeError('接続中に元の命令が変化しました。')
                        try:
                            # Conservatively retain allocations until rollback is verified.
                            self.installed=True
                            self.process.code_write(self.site,make_jump(self.site,self.code))
                        except CodeWriteError as exc:
                            if exc.rolled_back:
                                self.installed=False
                            raise
                    break
                except BusySite:
                    if attempt==29:
                        raise
                    time.sleep(0.01)
            try:
                self._save('installed')
            except OSError:
                pass  # The mandatory prepared journal already contains recovery data.
        except Exception:
            # Never free a destination still reachable by a live installed jump.
            if not self.installed:
                for address in (self.code,self.data):
                    if address:
                        self.process.free(address)
            raise

    def _recover(self):
        j=load_recovery_journal(
            self.journal, pid=self.process.pid, creation=self.process.creation,
            site=self.site, vtable=self.vtable, original=ORIGINAL,
            version=VERSION, data_size=DATA_SIZE,
        )
        if j['capture']!=self.capture:
            raise RuntimeError('復元情報の記録設定が一致しません。同じ版・設定で再接続するかゲームを終了してください。')
        self.code=j['code']; self.data=j['data']
        self.code_bytes=build_hook(self.code,self.data,self.site,self.vtable,capture=self.capture)
        if j.get('hook_sha256')!=hashlib.sha256(self.code_bytes).hexdigest():
            raise RuntimeError('復元情報の中継コードが一致しません。')
        self.process.validate_allocation(self.code,4096,PAGE_RX)
        self.process.validate_allocation(self.data,DATA_SIZE,PAGE_RW)
        self._validate_remote()
        self.installed=True; self.recovered=True
        # Previously exported records remain in the prior JSONL session.
        self.last=struct.unpack_from('<I',self.process.read(self.data,HEADER_SIZE),COUNTER_OFFSET)[0]
        try:
            self._save('recovered')
        except OSError:
            pass  # Keep using the validated existing recovery journal.

    def set_mode(self,mode):
        if type(mode) is not int or mode not in (0,1):
            raise ValueError('mode')
        self._validate_remote()
        self.process.write(self.data+MODE_OFFSET,struct.pack('<I',mode))
        if struct.unpack('<I',self.process.read(self.data+MODE_OFFSET,4))[0]!=mode:
            raise RuntimeError('モード変更の照合に失敗しました。')

    def poll(self):
        # Keep writers stopped for the whole snapshot: a commit re-read alone
        # cannot exclude an overwrite that begins during ReadProcessMemory.
        if not self.process.alive:
            return {'exited':True,'records':[]}
        with self.process.frozen():
            return self._poll_frozen()

    def _poll_frozen(self):
        if not self.process.alive:
            return {'exited':True,'records':[]}
        raw=self._validate_remote()
        mode=struct.unpack_from('<I',raw,MODE_OFFSET)[0]
        counter=struct.unpack_from('<I',raw,COUNTER_OFFSET)[0]
        fixes=struct.unpack_from('<I',raw,40)[0]
        if counter<self.last:
            raise RuntimeError('計測カウンターの巻戻りを検出しました。接続し直してください。')
        start=max(self.last+1,counter-CAPACITY+1)
        self.lost+=max(0,start-(self.last+1))
        rows=[]
        self.last=start-1
        for seq in range(start,counter+1):
            address=self.data+HEADER_SIZE+((seq-1)&(CAPACITY-1))*RECORD_SIZE
            record=decode_record(self.process.read(address,RECORD_SIZE),seq)
            if record is None or struct.unpack('<I',self.process.read(address,4))[0]!=seq:
                break  # incomplete writer: retry on the next poll
            rows.append(record)
            self.last=seq
        return {'mode':mode,'total':counter,'fixes':fixes,'lost':self.lost,'records':rows,'exited':False}

    def detach(self):
        if not self.installed:
            self.process.close(); return
        if not self.process.alive:
            self.installed=False
            try:
                self._save('process_exited')
            finally:
                self.process.close()
            return
        self._validate_remote()
        for attempt in range(50):
            try:
                with self.process.frozen([(self.site+1,self.site+len(ORIGINAL)),(self.code,self.code+len(self.code_bytes))]):
                    self._validate_remote()
                    self.process.code_write(self.site,ORIGINAL)
                    self.installed=False
                break
            except BusySite:
                if attempt==49:
                    raise
                time.sleep(0.01)
        self.process.free(self.code)
        self.process.free(self.data)
        self._save('detached')
        self.process.close()


def attach_game(pid,log_dir,mode=0,*,capture=True):
    require_runtime_approval()
    proc=psutil.Process(pid)
    path=proc.exe()
    if Path(path).name.lower()!='wsc3.exe' or sha_file(path)!=GAME_SHA256:
        raise RuntimeError('対応するWSC3本体のSHA-256と一致しません。変更は行いません。')
    base,module_path=module_base(pid,'wsc3.exe')
    if base!=0x400000 or Path(module_path).resolve()!=Path(path).resolve():
        raise RuntimeError('想定したWSC3のモジュール配置と一致しません。')
    process=Process(pid)
    session=Session(process,base+SITE_RVA,base+VTABLE_RVA,
                    Path(log_dir)/f'hook_{pid}_{int(process.creation*1000)}.json',capture=capture)
    try:
        if process.read(0x49B1F0,10)!=bytes.fromhex('81ec9809000053558be9') or process.read(0x49B28B,7)!=bytes.fromhex('8bbc24b8090000'):
            raise CodeNotReady('描画コードの展開待ちです。ゲームの起動を続けてください。')
        session.install(mode)
        return session
    except Exception:
        process.close()  # Remote hook, if retained, can be recovered using the journal.
        raise
