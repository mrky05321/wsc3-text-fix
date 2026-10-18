"""Opt-in v0.1.1 backend integration against an owned x86 process only."""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


@unittest.skipUnless(os.environ.get('WSC3_RUN_FIXTURE')=='1' and sys.platform=='win32',
                     'Set WSC3_RUN_FIXTURE=1 to run the owned-process x86 fixture')
class LiveFixtureTests(unittest.TestCase):
    def test_real_install_policy_off_recover_detach(self):
        import process_patch as patcher
        compiler=Path(os.environ['WINDIR'])/'Microsoft.NET/Framework/v4.0.30319/csc.exe'
        fixture=ROOT/'build/fixture_x86.exe'
        fixture.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run([str(compiler),'/nologo','/platform:x86','/target:exe',
                        '/out:'+str(fixture),str(ROOT/'tests/fixture_x86.cs')],check=True)
        child=subprocess.Popen([str(fixture)],
              stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
              text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        # Bound the experiment; only this exact owned child can be killed.
        watchdog=threading.Timer(45,child.kill)
        watchdog.daemon=True; watchdog.start()
        session=None
        def read():
            lines=queue.Queue()
            threading.Thread(target=lambda:lines.put(child.stdout.readline()),daemon=True).start()
            line=lines.get(timeout=15)
            if not line:
                raise RuntimeError('Fixture exited: '+child.stderr.read())
            return line.strip()
        def evaluate(height,width):
            child.stdin.write(f'{height},{width}\n');child.stdin.flush()
            return int(read())
        try:
            target=json.loads(read())
            self.assertEqual(target['pid'],child.pid)
            self.assertEqual(evaluate(12,24),24)
            with tempfile.TemporaryDirectory() as folder:
                journal=Path(folder)/'fixture.json'
                session=patcher.Session(patcher.Process(child.pid),target['site'],target['vtable'],journal)
                session.install(1)
                cases=[(12,24,13),(28,56,29),(38,76,39),(1,2,2),(512,1024,513),
                       (0,24,24),(513,1026,1026),(12,23,23),(12,25,25)]
                for h,w,expected in cases:
                    self.assertEqual(evaluate(h,w),expected,(h,w))
                session.set_mode(0)
                self.assertEqual(evaluate(12,24),24)
                # Simulate losing the controller without closing the child.
                session.process.close()
                original_journal=journal.read_bytes()
                corrupt=json.loads(original_journal)
                corrupt['creation']=float('nan')
                journal.write_text(json.dumps(corrupt),encoding='utf-8')
                rejected=patcher.Process(child.pid)
                try:
                    with self.assertRaises(RuntimeError):
                        patcher.Session(rejected,target['site'],target['vtable'],journal).install(1)
                finally:
                    rejected.close()
                # Corrupt metadata must leave the already installed hook alone.
                self.assertEqual(evaluate(12,24),24)  # mode OFF before disconnect
                journal.write_bytes(original_journal)
                session=patcher.Session(patcher.Process(child.pid),target['site'],target['vtable'],journal)
                session.install(1)
                self.assertTrue(session.recovered)
                self.assertEqual(evaluate(12,24),13)
                session.detach();session=None
                self.assertEqual(evaluate(12,24),24)
            child.stdin.write('quit\n');child.stdin.flush()
            self.assertEqual(child.wait(timeout=10),0)
        finally:
            watchdog.cancel()
            # No game is started or touched; the fixture is never left running.
            if child.poll() is None:
                child.kill();child.wait(timeout=5)
            if session:
                session.process.close()
            for stream in (child.stdin,child.stdout,child.stderr):
                stream.close()
