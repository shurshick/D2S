import json,os,subprocess,tempfile,unittest
from pathlib import Path
import sys

LIB=Path(sys.argv[1]).resolve()
sys.argv=sys.argv[:1]
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.env=dict(os.environ,PATH=str(self.root)+':'+os.environ['PATH'],FIXTURE=str(self.root))
        for name,content in {
            'ndmc':'#!/bin/sh\n[ "${FAIL_READ:-0}" != 1 ] || exit 1\ncat "$FIXTURE/config"\n',
            'ip':'#!/bin/sh\ncat "$FIXTURE/addresses"\n',
            'ipset':'''#!/usr/bin/python3
import os,json,sys,ipaddress
from pathlib import Path
p=Path(os.environ['FIXTURE'])/'sets.json'
s=json.loads(p.read_text()) if p.exists() else {}
a=sys.argv[1:]; op=a[0]; name=a[1]
if op=='create': s.setdefault(name,[])
elif op=='flush': s[name]=[]
elif op=='add':
 if os.environ.get('FAIL_ADD')=='1': sys.exit(1)
 value=str(ipaddress.ip_network(a[2],strict=False))
 if value not in s[name]: s[name].append(value)
elif op=='swap': s[name],s[a[2]]=s[a[2]],s[name]
elif op=='destroy': s.pop(name,None)
elif op=='save':
 if name not in s: sys.exit(1)
 print('create '+name+' hash:net family inet')
 for value in s[name]: print('add '+name+' '+value)
else: sys.exit(2)
p.write_text(json.dumps(s))
'''
        }.items():
            path=self.root/name;path.write_text(content);path.chmod(0o755)
        self.fixture('192.168.31.1',24)
    def tearDown(self): self.temp.cleanup()
    def fixture(self,home,prefix):
        (self.root/'config').write_text(f'interface Bridge0\n    security-level private\n    ip address {home} 255.255.255.0\n!\ninterface ISP\n    security-level public\n    ip address 192.168.1.136 255.255.255.0\n!\ninterface Guest\n    security-level protected\n    ip address 10.1.30.1 255.255.255.0\n!\n')
        (self.root/'addresses').write_text(f'1: lo inet 127.0.0.1/8 scope host\n2: custom_lan inet {home}/{prefix} scope global\n3: wan0 inet 192.168.1.136/24 scope global\n4: guest42 inet 10.1.30.1/24 scope global\n')
    def run_sh(self,body,**extra):
        return subprocess.run(['sh','-c','. "$1"; '+body,'sh',str(LIB)],env=dict(self.env,**extra),capture_output=True,text=True)
    def test_lan_and_guest_include_wan_exclude(self):
        r=self.run_sh('d2s_lan_entries');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(set(r.stdout.splitlines()),{'custom_lan 192.168.31.0/24','guest42 10.1.30.0/24'})
    def test_new_address_and_mask_no_edit(self):
        self.fixture('172.22.17.1',20)
        r=self.run_sh('d2s_lan_entries');self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('custom_lan 172.22.16.0/20',r.stdout)
        self.assertNotIn('192.168.31',r.stdout)
    def test_no_lan_fails_closed(self):
        (self.root/'config').write_text('interface ISP\n    security-level public\n    ip address 192.168.1.136 255.255.255.0\n!\n')
        self.assertNotEqual(self.run_sh('d2s_lan_networks').returncode,0)
        self.assertNotEqual(self.run_sh('d2s_lan_sync').returncode,0)
    def test_config_read_failure_fails_closed(self):
        self.assertNotEqual(self.run_sh('d2s_lan_networks',FAIL_READ='1').returncode,0)
    def test_empty_config_fails_closed(self):
        (self.root/'config').write_text('')
        self.assertNotEqual(self.run_sh('d2s_lan_sync').returncode,0)
    def test_mask_change_invalidates_and_refreshes_set(self):
        self.assertEqual(self.run_sh('d2s_lan_sync && d2s_lan_installed').returncode,0)
        self.fixture('172.22.17.1',20)
        self.assertNotEqual(self.run_sh('d2s_lan_installed').returncode,0)
        self.assertEqual(self.run_sh('d2s_lan_sync && d2s_lan_installed').returncode,0)
    def test_partial_update_preserves_old_set(self):
        self.assertEqual(self.run_sh('d2s_lan_sync').returncode,0)
        before=json.loads((self.root/'sets.json').read_text())['d2s_lan4']
        self.fixture('172.22.17.1',20)
        self.assertNotEqual(self.run_sh('d2s_lan_sync',FAIL_ADD='1').returncode,0)
        after=json.loads((self.root/'sets.json').read_text())
        self.assertEqual(after['d2s_lan4'],before)
        self.assertNotIn('d2s_lan4_new',after)

unittest.main(verbosity=2)
