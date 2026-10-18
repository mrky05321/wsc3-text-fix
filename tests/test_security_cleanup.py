import ctypes
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock,PropertyMock,patch

if sys.platform!='win32':
    raise unittest.SkipTest('Windows APIs')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import launcher
import process_patch as p


class CleanupTests(unittest.TestCase):
    def test_failed_status_query_is_not_treated_as_exit(self):
        proc=p.Process.__new__(p.Process)
        proc.handle=99
        with patch.object(p,'wait_object',return_value=0xffffffff):
            with self.assertRaises(OSError):
                _=proc.alive

    def test_unknown_status_during_cleanup_still_closes_handles(self):
        proc=Mock()
        type(proc).alive=PropertyMock(side_effect=OSError('status unavailable'))
        session=Mock(process=proc)
        session.detach.side_effect=RuntimeError('detach failed')
        with patch.object(launcher,'launch',return_value=session), \
             patch.object(launcher,'monitor'), \
             patch.object(launcher,'notify') as notify, \
             patch.object(launcher,'create_mutex',return_value=77), \
             patch.object(launcher.C,'get_last_error',return_value=0), \
             patch.object(launcher,'close') as close:
            launcher.main()
        proc.close.assert_called_once()
        close.assert_called_once_with(77)
        notify.assert_called_once()
        session.journal.unlink.assert_not_called()

    def test_private_allocation_attributes_are_required(self):
        proc=p.Process.__new__(p.Process)
        proc.handle=99
        expected=0x10000000
        base={'base':expected,'allocation':expected,'size':4096,
              'state':0x1000,'protect':p.PAGE_RX,'type':0x20000}
        def query(changes):
            def fill(handle,address,raw,size):
                for key,value in {**base,**changes}.items():
                    setattr(raw._obj,key,value)
                return ctypes.sizeof(p.MemoryInfo)
            return fill
        with patch.object(p,'query_memory',side_effect=query({})):
            proc.validate_allocation(expected,4096,p.PAGE_RX)
        for changes in ({'type':0x1000000},{'allocation':expected-4096},
                        {'base':expected-4096},{'size':1},{'state':0x2000},
                        {'protect':p.PAGE_RWX},{'protect':p.PAGE_RX|0x100}):
            with self.subTest(changes=changes),patch.object(p,'query_memory',side_effect=query(changes)):
                with self.assertRaises(RuntimeError):
                    proc.validate_allocation(expected,4096,p.PAGE_RX)
