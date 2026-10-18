"""Launcher failure paths without starting a game or showing a message box."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

if sys.platform != 'win32':
    raise unittest.SkipTest('Win32 bindings require Windows')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import launcher as l
import process_patch as p


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.game=self.home/'wsc3.exe'
        self.game.write_bytes(b'fixture, not a game')
        self.mocks={}
        for name,value in {'GAME':self.game,'HOME':self.home,
                           'STATE_DIR':self.home/'state'}.items():
            patcher=patch.object(l,name,value)
            patcher.start(); self.addCleanup(patcher.stop)
        for name,value in {'sha_file':l.GAME_SHA256,'matching_games':[{'pid':123}],
                           'attach_game':Mock(),'notify':None}.items():
            patcher=patch.object(l,name,return_value=value)
            self.mocks[name]=patcher.start(); self.addCleanup(patcher.stop)
        for owner,name in ((l.subprocess,'Popen'),(l.time,'sleep')):
            patcher=patch.object(owner,name)
            self.mocks[name]=patcher.start(); self.addCleanup(patcher.stop)

    def test_existing_game_connects_without_spawning_and_without_telemetry(self):
        l.launch()
        self.mocks['Popen'].assert_not_called()
        self.mocks['attach_game'].assert_called_once_with(123,self.home/'state',1,capture=False)

    def test_missing_or_wrong_version_never_starts_game(self):
        self.mocks['sha_file'].return_value='wrong'
        with self.assertRaisesRegex(RuntimeError,'SHA-256'):
            l.launch()
        self.game.unlink()
        with self.assertRaisesRegex(RuntimeError,'同じフォルダ'):
            l.launch()
        self.mocks['Popen'].assert_not_called()
        self.mocks['attach_game'].assert_not_called()

    def test_multiple_games_are_rejected_before_attach(self):
        self.mocks['matching_games'].return_value=[{'pid':1},{'pid':2}]
        with self.assertRaisesRegex(RuntimeError,'複数'):
            l.launch()
        self.mocks['attach_game'].assert_not_called()

    def test_unexpanded_drawing_code_can_retry_then_connect(self):
        session=Mock()
        self.mocks['attach_game'].side_effect=[l.CodeNotReady('waiting'),session]
        self.assertIs(l.launch(),session)
        self.assertEqual(self.mocks['attach_game'].call_count,2)

    def test_access_denied_explains_privilege_without_elevation(self):
        self.mocks['attach_game'].side_effect=PermissionError('denied')
        with patch.object(l.psutil,'pid_exists',return_value=True):
            with self.assertRaisesRegex(RuntimeError,'同じ権限'):
                l.launch()
        self.mocks['Popen'].assert_not_called()

    def test_timeout_is_bounded(self):
        self.mocks['attach_game'].side_effect=l.CodeNotReady('waiting')
        with patch.object(l.time,'monotonic',side_effect=[0,0,181]):
            with self.assertRaisesRegex(RuntimeError,'3分'):
                l.launch()

    def test_bootstrap_handoff_waits_for_real_game(self):
        self.mocks['matching_games'].side_effect=[[],[],[{'pid':123}]]
        self.mocks['Popen'].return_value.poll.return_value=None
        l.launch()
        self.mocks['Popen'].assert_called_once()
        self.mocks['attach_game'].assert_called_once()

    def test_ended_bootstrap_stops_after_grace_period(self):
        self.mocks['matching_games'].return_value=[]
        self.mocks['Popen'].return_value.poll.return_value=0
        with patch.object(l.time,'monotonic',side_effect=[0,0,0,0,11,11]):
            with self.assertRaisesRegex(RuntimeError,'ゲームが終了'):
                l.launch()

    def test_duplicate_launcher_closes_only_own_mutex(self):
        with patch.object(l,'create_mutex',return_value=55), patch.object(l.C,'get_last_error',return_value=183), patch.object(l,'close') as close:
            l.main()
        close.assert_called_once_with(55)
        self.mocks['attach_game'].assert_not_called()
        self.mocks['notify'].assert_not_called()

    def test_clean_shutdown_removes_transient_journal(self):
        journal=self.home/'hook.json'
        journal.write_text('{}')
        session=Mock(journal=journal)
        with patch.object(l,'create_mutex',return_value=55), patch.object(l.C,'get_last_error',return_value=0), patch.object(l,'close'), patch.object(l,'launch',return_value=session), patch.object(l,'monitor'):
            l.main()
        session.detach.assert_called_once()
        self.assertFalse(journal.exists())


class AttachTests(unittest.TestCase):
    def test_wrong_game_sha_never_opens_process(self):
        with patch.object(p.psutil,'Process') as proc, patch.object(p,'sha_file',return_value='wrong'), patch.object(p,'Process') as remote:
            proc.return_value.exe.return_value='C:/games/wsc3.exe'
            with self.assertRaisesRegex(RuntimeError,'SHA-256'):
                p.attach_game(123,'.')
            remote.assert_not_called()

    def test_unexpanded_code_closes_handle_without_writing(self):
        with patch.object(p.psutil,'Process') as proc, patch.object(p,'sha_file',return_value=p.GAME_SHA256), patch.object(p,'module_base',return_value=(0x400000,'C:/games/wsc3.exe')), patch.object(p,'Process') as remote:
            proc.return_value.exe.return_value='C:/games/wsc3.exe'
            remote.return_value.read.return_value=b'not ready'
            remote.return_value.creation=1000.125
            with self.assertRaises(p.CodeNotReady):
                p.attach_game(123,'.')
            remote.return_value.close.assert_called_once()
            remote.return_value.write.assert_not_called()
