"""Windows API failures and recovery state transitions using fake memory."""
import contextlib
import ctypes
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

if sys.platform != 'win32':
    raise unittest.SkipTest('Win32 bindings require Windows')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import process_patch as p
from hook_code import ORIGINAL, make_jump, DATA_SIZE, VERSION

SITE, VTABLE = 0x49b292, 0x5a6264


class FakeProcess:
    pid, creation, handle, alive = 1234, 1000.125, 99, True
    def __init__(self):
        self.memory = {SITE: bytearray(ORIGINAL)}
        self.freed, self.writes, self.closed = [], [], False
        self.allocations = []
    def alloc(self, size):
        address = 0x10000000 + len(self.allocations)*0x100000
        self.allocations.append(address)
        self.memory[address] = bytearray(size)
        return address
    def read(self, address, size):
        for base, data in self.memory.items():
            offset = address-base
            if 0<=offset and offset+size<=len(data):
                return bytes(data[offset:offset+size])
        raise OSError('unmapped')
    def write(self, address, data):
        self.writes.append((address, bytes(data)))
        for base, raw in self.memory.items():
            offset = address-base
            if 0<=offset and offset+len(data)<=len(raw):
                raw[offset:offset+len(data)] = data
                return
        raise OSError('unmapped')
    code_write = write
    def protect(self, *args):
        return p.PAGE_RW
    def validate_allocation(self, address, size, protection):
        if address not in self.allocations or len(self.memory[address])<size:
            raise RuntimeError('allocation mismatch')
    def free(self, address):
        self.freed.append(address)
        del self.memory[address]
    def close(self):
        self.closed=True
    @contextlib.contextmanager
    def frozen(self, forbidden=()):
        yield


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'hook.json'
        self.proc = FakeProcess()
        self.session = p.Session(self.proc, SITE, VTABLE, self.path)
        self.cache = patch.object(p, 'flush_cache', return_value=1)
        self.cache.start()
        self.addCleanup(self.cache.stop)

    def install(self):
        self.session.install(1)
        return self.session

    def test_install_recover_toggle_and_detach(self):
        self.install()
        self.assertEqual(self.proc.read(SITE,7), make_jump(SITE,self.session.code))
        recovered = p.Session(self.proc,SITE,VTABLE,self.path)
        recovered.install(0)
        self.assertTrue(recovered.recovered)
        self.assertEqual(len(self.proc.allocations),2)
        recovered.detach()
        self.assertEqual(self.proc.read(SITE,7), ORIGINAL)
        self.assertCountEqual(self.proc.freed,self.proc.allocations)
        self.assertTrue(self.proc.closed)

    def test_prepared_journal_recovers_after_install_save_failure(self):
        original_save = self.session._save
        def save(state):
            if state=='installed':
                raise OSError('disk full')
            original_save(state)
        self.session._save=save
        self.install()
        self.assertEqual(json.loads(self.path.read_text())['state'],'prepared')
        recovered=p.Session(self.proc,SITE,VTABLE,self.path)
        recovered.install(1)
        recovered.detach()

    def test_prepared_save_failure_never_patches_site(self):
        self.session._save=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):
            self.install()
        self.assertEqual(self.proc.read(SITE,7),ORIGINAL)
        self.assertCountEqual(self.proc.freed,self.proc.allocations)

    def test_uncertain_write_retains_both_destinations_and_journal(self):
        def fail(address, data):
            self.proc.write(address, data[:3]+b'BAD!')
            raise p.CodeWriteError('unsafe',rolled_back=False)
        self.proc.code_write=fail
        with self.assertRaises(p.CodeWriteError):
            self.install()
        self.assertEqual(self.proc.freed,[])
        self.assertTrue(self.path.exists())
        self.assertTrue(self.session.installed)

    def test_verified_rollback_can_free_destinations(self):
        self.proc.code_write=Mock(side_effect=p.CodeWriteError('rolled back',rolled_back=True))
        with self.assertRaises(p.CodeWriteError):
            self.install()
        self.assertEqual(self.proc.read(SITE,7),ORIGINAL)
        self.assertCountEqual(self.proc.freed,self.proc.allocations)

    def test_failed_detach_never_frees_reachable_code(self):
        self.install()
        self.proc.code_write=Mock(side_effect=p.CodeWriteError('rolled back to jump',rolled_back=True))
        with self.assertRaises(p.CodeWriteError):
            self.session.detach()
        self.assertTrue(self.session.installed)
        self.assertEqual(self.proc.freed,[])

    def test_tampered_remote_code_or_site_is_not_written(self):
        self.install()
        for target in (self.session.code,SITE):
            before=bytes(self.proc.memory[target])
            self.proc.memory[target][0]^=1
            self.proc.writes.clear()
            with self.assertRaises(RuntimeError):
                self.session.detach()
            self.assertEqual(self.proc.writes,[])
            self.assertEqual(self.proc.freed,[])
            self.proc.memory[target][:]=before

    def test_bad_journal_rejected_before_arbitrary_remote_read(self):
        self.install()
        record=json.loads(self.path.read_text())
        for change in ({'pid':9999},{'creation':float('nan')},{'code':SITE},
                       {'version':VERSION-1}):
            self.path.write_text(json.dumps({**record,**change}))
            recovered=p.Session(self.proc,SITE,VTABLE,self.path)
            with patch.object(self.proc,'read',wraps=self.proc.read) as reads:
                with self.assertRaises(RuntimeError):
                    recovered.install(1)
                self.assertEqual(reads.call_args_list,[unittest.mock.call(SITE,7)])

    def test_atomic_save_failure_keeps_previous_journal_and_removes_temp(self):
        self.install()
        before=self.path.read_bytes()
        with patch.object(p.os,'replace',side_effect=OSError('replace failed')):
            with self.assertRaises(OSError):
                self.session._save('recovered')
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(list(self.path.parent.glob('*.tmp')),[])

    def test_exited_process_is_closed_even_when_journal_write_fails(self):
        self.install()
        self.proc.alive=False
        self.session._save=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):
            self.session.detach()
        self.assertTrue(self.proc.closed)
        self.assertEqual(self.proc.freed,[])

    def test_invalid_mode_rejected_before_allocations(self):
        for mode in (-1,2,True,'1'):
            with self.assertRaises(ValueError):
                self.session.install(mode)
        self.assertEqual(self.proc.allocations,[])


class FrozenTests(unittest.TestCase):
    def setUp(self):
        self.proc=p.Process.__new__(p.Process)
        self.proc.pid,self.proc.handle=1234,99
        self.mocks={}
        for name, value in {'thread_ids':[1,2], 'open_thread':111,
                            'thread_owner':1234, 'suspend_thread':0,
                            'resume_thread':1, 'wait_object':0x102,
                            'close':1, 'thread_exited':False}.items():
            patcher=patch.object(p,name,return_value=value)
            self.mocks[name]=patcher.start()
            self.addCleanup(patcher.stop)
        self.mocks['open_thread'].side_effect=lambda access,inherit,tid:100+tid
        def context(handle, raw):
            struct.pack_into('<I',raw,184,SITE)
            return 1
        patcher=patch.object(p,'context_function',side_effect=context)
        self.mocks['context']=patcher.start()
        self.addCleanup(patcher.stop)

    def test_success_resumes_each_thread_exactly_once(self):
        with self.proc.frozen([(SITE+1,SITE+7)]):
            pass
        self.assertEqual(self.mocks['suspend_thread'].call_count,2)
        self.assertEqual(self.mocks['resume_thread'].call_count,2)
        self.assertEqual(self.mocks['close'].call_count,2)

    def test_preexisting_suspend_count_is_not_drained(self):
        self.mocks['suspend_thread'].return_value=3
        self.mocks['resume_thread'].return_value=4
        with self.proc.frozen():
            pass
        self.assertEqual(self.mocks['resume_thread'].call_count,2)

    def test_new_threads_are_captured_before_context_checks(self):
        self.mocks['thread_ids'].side_effect=[[1],[1,2],[1,2]]
        with self.proc.frozen():
            pass
        self.assertEqual(self.mocks['suspend_thread'].call_count,2)
        self.assertEqual(self.mocks['context'].call_count,2)

    def test_continuously_changing_threads_abort_and_resume_acquired_handles(self):
        self.mocks['thread_ids'].side_effect=[[1],[1,2],[1,2,3],[1,2,3,4]]
        with self.assertRaisesRegex(RuntimeError,'変化'):
            with self.proc.frozen():
                self.fail('unstable thread list')
        self.assertEqual(self.mocks['resume_thread'].call_count,4)

    def test_exited_thread_needs_no_context_or_resume(self):
        self.mocks['thread_ids'].side_effect=[[1],[1]]
        # The handle is live in the resnapshot, then terminated at context.
        self.mocks['thread_exited'].side_effect=[False,True,True]
        with self.proc.frozen():
            pass
        self.mocks['context'].assert_not_called()
        self.mocks['resume_thread'].assert_not_called()

    def test_suspend_failure_closes_unsuspended_handle(self):
        self.mocks['suspend_thread'].return_value=0xffffffff
        with self.assertRaises(OSError):
            with self.proc.frozen():
                self.fail('suspend failed')
        self.mocks['resume_thread'].assert_not_called()
        self.mocks['close'].assert_called_once()

    def test_empty_snapshot_never_allows_writing_live_process(self):
        self.mocks['thread_ids'].return_value=[]
        with self.assertRaisesRegex(RuntimeError,'対象スレッド'):
            with self.proc.frozen():
                self.fail('no threads suspended')

    def test_context_or_body_exception_still_resumes_all(self):
        for context_fails in (False,True):
            self.mocks['resume_thread'].reset_mock()
            if context_fails:
                self.mocks['context'].side_effect=OSError('context failed')
            with self.assertRaises(OSError):
                with self.proc.frozen():
                    raise OSError('body failed')
            self.assertEqual(self.mocks['resume_thread'].call_count,2)

    def test_busy_ip_does_not_enter_body(self):
        with self.assertRaises(p.BusySite):
            with self.proc.frozen([(SITE,SITE+7)]):
                self.fail('unsafe write')
        self.assertEqual(self.mocks['resume_thread'].call_count,2)

    def test_owner_reuse_never_suspends_other_process(self):
        self.mocks['thread_owner'].return_value=999
        with self.assertRaises(RuntimeError):
            with self.proc.frozen():
                self.fail('wrong process')
        self.mocks['suspend_thread'].assert_not_called()
        self.assertEqual(self.mocks['close'].call_count,1)

    def test_open_failure_resumes_already_suspended_handles(self):
        self.mocks['open_thread'].side_effect=[101,0]
        with patch.object(p.C,'get_last_error',return_value=5):
            with self.assertRaises(OSError):
                with self.proc.frozen():
                    self.fail('access denied')
        self.mocks['resume_thread'].assert_called_once_with(101)

    def test_resume_failure_retries_only_failed_thread_and_closes_all(self):
        self.mocks['resume_thread'].side_effect=[0xffffffff,0xffffffff,1]
        with self.assertRaisesRegex(RuntimeError,'再開'):
            with self.proc.frozen():
                pass
        self.assertEqual(self.mocks['resume_thread'].call_count,3)
        self.assertEqual(self.mocks['close'].call_count,2)

    def test_resume_transient_failure_can_recover(self):
        self.mocks['resume_thread'].side_effect=[0xffffffff,1,1]
        with self.proc.frozen():
            pass
        self.assertEqual(self.mocks['resume_thread'].call_count,3)

    def test_thread_enumeration_error_is_not_empty_success(self):
        with patch.object(p,'snapshot',return_value=55), patch.object(p,'thread_first',return_value=0):
            with patch.object(p.C,'get_last_error',return_value=5):
                with self.assertRaises(OSError):
                    # Restore real helper overwritten in setUp.
                    real_thread_ids(1234)


real_thread_ids=p.thread_ids
