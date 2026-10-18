import sys
import unittest
from pathlib import Path
from unittest.mock import patch,Mock

if sys.platform!='win32':
    raise unittest.SkipTest('Windows launcher')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from startup_ready import WindowReadyGate
import launcher


class GateTests(unittest.TestCase):
    def test_no_window_never_attaches_even_after_long_wait(self):
        gate=WindowReadyGate()
        for t in (0,2,5,100):
            self.assertFalse(gate.update(123,None,t))

    def test_visible_responding_window_must_remain_stable(self):
        gate=WindowReadyGate()
        self.assertFalse(gate.update(123,99,0))
        self.assertFalse(gate.update(123,99,1.9))
        self.assertTrue(gate.update(123,99,2))

    def test_disappearance_pid_or_handle_change_resets_gate(self):
        for new_pid,new_hwnd in ((123,None),(124,99),(123,100)):
            gate=WindowReadyGate()
            gate.update(123,99,0)
            self.assertFalse(gate.update(new_pid,new_hwnd,1))
            self.assertFalse(gate.update(123,99,2))

    def test_launcher_waits_for_window_before_v011_attach_mode_one(self):
        with patch.object(launcher.GAME.__class__,'is_file',return_value=True), \
             patch.object(launcher,'sha_file',return_value=launcher.GAME_SHA256), \
             patch.object(launcher,'matching_games',return_value=[{'pid':123}]), \
             patch.object(launcher.STATE_DIR.__class__,'mkdir'), \
             patch.object(launcher,'ready_window',side_effect=[None,99,99,99]), \
             patch.object(launcher.time,'monotonic',side_effect=[0,0,0,1,1,2,2,3.1,3.1]), \
             patch.object(launcher.time,'sleep'), \
             patch.object(launcher,'attach_game',return_value='session') as attach:
            self.assertEqual(launcher.launch(),'session')
            attach.assert_called_once_with(123,launcher.STATE_DIR,1)
