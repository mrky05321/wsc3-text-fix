"""The incident hold must prevent any game start or process attachment."""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from safety_hold import require_runtime_approval


class SafetyHoldTests(unittest.TestCase):
    def test_runtime_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError,'使用停止'):
            require_runtime_approval()

    def test_packaging_is_blocked(self):
        result=subprocess.run([sys.executable,str(ROOT/'build.py')],
                              capture_output=True,encoding='utf-8',errors='replace',
                              env={**__import__('os').environ,'PYTHONIOENCODING':'utf-8'})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('使用停止',result.stderr)

    @unittest.skipUnless(sys.platform=='win32','Win32 bindings require Windows')
    def test_launcher_does_not_reach_game_discovery_or_spawn(self):
        import launcher
        with patch.object(launcher,'matching_games') as discover, patch.object(launcher.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError,'使用停止'):
                launcher.launch()
            discover.assert_not_called()
            spawn.assert_not_called()

    @unittest.skipUnless(sys.platform=='win32','Win32 bindings require Windows')
    def test_gui_attach_does_not_reach_process_access(self):
        import process_patch
        with patch.object(process_patch.psutil,'Process') as lookup, patch.object(process_patch,'Process') as remote:
            with self.assertRaisesRegex(RuntimeError,'使用停止'):
                process_patch.attach_game(123,'.')
            lookup.assert_not_called()
            remote.assert_not_called()
