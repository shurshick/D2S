"""Real inotify CLI, including replacement before the wait is armed."""
import subprocess
import os
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class WakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory()
        cls.binary=Path(cls.build.name)/'d2s-dns-watch'
        subprocess.run(['cc','-std=c99','-O2','-Wall','-Wextra','-Werror',
                        str(ROOT/'resolver-local/dns-media-watch.c'),'-o',str(cls.binary)],check=True)
    @classmethod
    def tearDownClass(cls): cls.build.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'names'
        self.path.write_text('media-one.cdn.whatsapp.net\n')
    def tearDown(self): self.tmp.cleanup()
    def token(self):
        return subprocess.check_output([self.binary,'--media-token',self.path],text=True).strip()
    def replace(self):
        new=self.path.with_suffix('.new');new.write_text('media-two.cdn.whatsapp.net\n');new.replace(self.path)
    def test_atomic_replace_wakes_waiter(self):
        token=self.token();start=time.monotonic()
        p=subprocess.Popen([self.binary,'--wait-media',self.path,'5',token])
        try:
            time.sleep(.1);self.replace()
            self.assertEqual(p.wait(timeout=2),0)
            self.assertLess(time.monotonic()-start,2)
        finally:
            if p.poll() is None:p.kill();p.wait()
    def test_change_during_refresh_is_not_lost(self):
        token=self.token();self.replace()
        p=subprocess.run([self.binary,'--wait-media',self.path,'5',token],timeout=2)
        self.assertEqual(p.returncode,0)
    def test_unchanged_file_waits_until_periodic_deadline(self):
        start=time.monotonic()
        p=subprocess.run([self.binary,'--wait-media',self.path,'1',self.token()],timeout=3)
        self.assertEqual(p.returncode,124)
        self.assertGreaterEqual(time.monotonic()-start,.9)
    def test_missing_file_and_unrelated_changes(self):
        self.path.unlink();token=self.token();self.assertEqual(token,'missing')
        p=subprocess.Popen([self.binary,'--wait-media',self.path,'5',token])
        try:
            time.sleep(.05)
            (self.path.parent/'other').write_text('unrelated')
            time.sleep(.05);self.assertIsNone(p.poll())
            self.replace();self.assertEqual(p.wait(timeout=2),0)
        finally:
            if p.poll() is None:p.kill();p.wait()
    def test_scheduler_refreshes_on_event_and_stops_its_waiter(self):
        root=self.path.parent
        for name in ['state','log']:(root/name).mkdir()
        (root/'state/success').write_text(time.strftime('%Y-%m-%d')+'\n'+str(int(time.time()))+'\n')
        calls=root/'calls';helper=root/'helper'
        helper.write_text(f'#!/bin/sh\necho refresh >> "{calls}"\n');helper.chmod(0o755)
        env=dict(os.environ,D2S_DIR=str(root),D2S_INSTAGRAM_HELPER='/bin/true',
            D2S_INSTAGRAM_SCHED_STATE=str(root/'state/success'),D2S_INSTAGRAM_REFRESH_AT='0000',
            D2S_INSTAGRAM_SCHED_ATTEMPT=str(root/'state/attempt'),
            D2S_MEDIA_HELPER=str(helper),D2S_MEDIA_WATCH_BIN=str(self.binary),
            D2S_MEDIA_OBSERVED=str(self.path),D2S_SCHEDULER_INTERVAL='30')
        p=subprocess.Popen(['sh',str(ROOT/'files/d2s-meta-dns-scheduler-core.sh'),'run'],env=env)
        def await_calls(count):
            until=time.monotonic()+2
            while time.monotonic()<until:
                if calls.exists() and len(calls.read_text().splitlines())>=count:return
                time.sleep(.02)
            self.fail(f'no refresh {count} before deadline')
        try:
            await_calls(1);self.replace();await_calls(2)
            time.sleep(.1);self.assertEqual(len(calls.read_text().splitlines()),2)
            p.terminate();self.assertEqual(p.wait(timeout=2),0)
        finally:
            if p.poll() is None:p.terminate();p.wait(timeout=3)

if __name__=='__main__':unittest.main(verbosity=2)
