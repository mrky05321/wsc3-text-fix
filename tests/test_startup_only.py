"""Startup-only checks without running the actual game."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import launcher


class StartupOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.game=self.home/'wsc3.exe'
        self.game.write_bytes(b'fixture')
        for name,value in [('HOME',self.home),('GAME',self.game),
                           ('GAME_SHA256',hashlib.sha256(b'fixture').hexdigest())]:
            change=patch.object(launcher,name,value)
            change.start(); self.addCleanup(change.stop)

    def test_spawn_preserves_arguments_and_working_directory(self):
        with patch.object(launcher.subprocess,'Popen') as spawn:
            launcher.launch(['argument with spaces','/test'])
        spawn.assert_called_once_with([str(self.game),'argument with spaces','/test'],cwd=str(self.home),close_fds=True)

    def test_missing_and_wrong_sha_do_not_start_anything(self):
        with patch.object(launcher.subprocess,'Popen') as spawn:
            self.game.write_bytes(b'wrong version')
            with self.assertRaisesRegex(RuntimeError,'SHA-256'):
                launcher.launch([])
            self.game.unlink()
            with self.assertRaisesRegex(RuntimeError,'同じフォルダ'):
                launcher.launch([])
            spawn.assert_not_called()

    def test_check_never_starts_game(self):
        with patch.object(launcher.subprocess,'Popen') as spawn:
            self.assertEqual(launcher.main(['--check']),0)
            self.game.write_bytes(b'wrong version')
            self.assertEqual(launcher.main(['--check']),2)
            self.game.unlink()
            self.assertEqual(launcher.main(['--check']),2)
            spawn.assert_not_called()

    def test_launcher_does_not_import_hook_backend(self):
        script='import sys; sys.path.insert(0,sys.argv[1]); import launcher; assert not any(n in sys.modules for n in ("process_patch","hook_code","psutil"))'
        subprocess.run([sys.executable,'-c',script,str(ROOT/'src')],check=True)

    def test_success_does_not_wait_for_game_or_create_state(self):
        with patch.object(launcher.subprocess,'Popen') as spawn:
            self.assertEqual(launcher.main([]),0)
            spawn.return_value.wait.assert_not_called()
            spawn.return_value.terminate.assert_not_called()
        self.assertEqual(sorted(p.name for p in self.home.iterdir()),['wsc3.exe'])

    def test_actual_launch_of_harmless_standin(self):
        # Invoke installed Python via a command script, as a harmless stand-in.
        # Keep the real launch argument/cwd path; only redirect Popen's image.
        real_spawn=subprocess.Popen
        def spawn(argv,**kwargs):
            return real_spawn([sys.executable,*argv[1:]],**kwargs)
        with patch.object(launcher.subprocess,'Popen',side_effect=spawn):
            code='from pathlib import Path; import os,sys; Path("child-result.txt").write_text(os.getcwd()+"\\n"+sys.argv[1],encoding="utf-8")'
            child=launcher.launch(['-c',code,'argument with spaces'])
            try:
                self.assertEqual(child.wait(timeout=15),0)
            finally:
                if child.poll() is None:
                    child.kill(); child.wait()
            self.assertEqual((self.home/'child-result.txt').read_text(encoding='utf-8'),str(self.home)+'\nargument with spaces')
