import os,subprocess,tempfile,unittest,sys,shutil
from pathlib import Path
work=Path(sys.argv[1]);sys.argv=sys.argv[:1]
class MediaTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for name in ['state','log','files','bin']: (self.root/name).mkdir()
        shutil.copyfile(work/'d2k-meta-dns-library.sh',self.root/'d2k-meta-dns-library.sh')
        (self.root/'files/meta-ranges.txt').write_text('57.144.0.0/14\n')
        (self.root/'state/whatsapp-ip-hosts.tsv').write_text('web.whatsapp.com 57.144.245.32\nwww.whatsapp.com 57.144.249.32\n')
        (self.root/'log/d2kd.log').write_text('QUIC client name=media-otp1-1.cdn.whatsapp.net\nname=media-evil.example.com\n')
        (self.root/'log/d2kc.log').write_text('')
        (self.root/'ndm').write_text('ip host unrelated.example 192.0.2.7\n')
        self.env=dict(os.environ,D2K_DIR=str(self.root),D2K_STUB_PATH=str(self.root/'bin'),FIXTURE=str(self.root),D2K_IP_PROBE_ATTEMPTS='1')
        ndmc='''#!/usr/bin/python3
import os,sys
from pathlib import Path
r=Path(os.environ['FIXTURE']); command=sys.argv[2]
if command=='show running-config': print((r/'ndm').read_text(),end='')
elif command=='system configuration save':
 with (r/'calls').open('a') as f: f.write('save\\n')
elif command.startswith('ip host '):
 with (r/'ndm').open('a') as f: f.write(command+'\\n')
 with (r/'calls').open('a') as f: f.write(command+'\\n')
elif command.startswith('no ip host '):
 target=command[3:]
 (r/'ndm').write_text(''.join(line for line in (r/'ndm').read_text().splitlines(keepends=True) if line.strip()!=target))
else: sys.exit(2)
'''
        probe='#!/bin/sh\n[ "${FAIL_CERT:-0}" != 1 ]\n'
        for name,text in [('ndmc',ndmc),('d2ktg',probe)]:
            p=self.root/'bin'/name;p.write_text(text);p.chmod(0o755)
    def tearDown(self): self.tmp.cleanup()
    def call(self,command='refresh',**env):
        return subprocess.run(['sh',str(work/'d2k-whatsapp-media.sh'),command],env=dict(self.env,**env),capture_output=True,text=True)
    def test_add_idempotence_and_exact_removal(self):
        before=(self.root/'ndm').read_text()
        p=self.call();self.assertEqual(p.returncode,0,p.stderr)
        after=(self.root/'ndm').read_text();self.assertEqual(after.count('media-otp1-1'),2);self.assertNotIn('media-evil',after)
        calls=(self.root/'calls').read_text()
        self.assertEqual(self.call().returncode,0)
        self.assertEqual((self.root/'calls').read_text(),calls)
        p=self.call('remove');self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual((self.root/'ndm').read_text(),before)
    def test_certificate_failure_writes_nothing(self):
        before=(self.root/'ndm').read_text()
        p=self.call(FAIL_CERT='1');self.assertNotEqual(p.returncode,0)
        self.assertEqual((self.root/'ndm').read_text(),before)
    def test_existing_user_pair_never_claimed_or_removed(self):
        baseline='ip host media-otp1-1.cdn.whatsapp.net 57.144.245.32\nip host unrelated.example 192.0.2.7\n'
        (self.root/'ndm').write_text(baseline)
        self.assertEqual(self.call().returncode,0)
        manifest=(self.root/'state/whatsapp-media-hosts.tsv').read_text()
        self.assertNotIn('57.144.245.32',manifest)
        self.assertEqual(self.call('remove').returncode,0)
        self.assertEqual((self.root/'ndm').read_text(),baseline)
    def test_pool_change_retires_only_verified_old_pairs(self):
        self.assertEqual(self.call().returncode,0)
        (self.root/'state/whatsapp-ip-hosts.tsv').write_text('web.whatsapp.com 57.144.250.32\n')
        p=self.call();self.assertEqual(p.returncode,0,p.stderr)
        ndm=(self.root/'ndm').read_text()
        self.assertIn('57.144.250.32',ndm);self.assertNotIn('57.144.245.32',ndm);self.assertNotIn('57.144.249.32',ndm)
    def test_failed_replacement_preserves_old_pairs(self):
        self.assertEqual(self.call().returncode,0)
        before=(self.root/'ndm').read_text()
        (self.root/'state/whatsapp-ip-hosts.tsv').write_text('web.whatsapp.com 57.144.250.32\n')
        self.assertNotEqual(self.call(FAIL_CERT='1').returncode,0)
        self.assertEqual((self.root/'ndm').read_text(),before)
unittest.main(verbosity=2)
