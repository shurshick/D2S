"""Use real DNS backend functions; isolate hosts and reload command."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    tmp=Path(tmp)
    library=(root/'files/d2s-meta-dns-library.sh').read_text()
    library=library.replace('/etc/openwrt_release',str(tmp/'release'))
    library=library.replace('/etc/init.d/dnsmasq',str(tmp/'dnsmasq'))
    (tmp/'release').touch()
    (tmp/'dnsmasq').write_text('#!/bin/sh\nexit 0\n')
    (tmp/'dnsmasq').chmod(0o755)
    (tmp/'library').write_text(library)
    script=f'''set -eu
DIR='{tmp}'
D2S_DIR='{tmp}'
D2S_DNS_HOSTS_DIR='{tmp}/hosts'
. '{tmp}/library'
mkdir -p "$D2S_DNS_HOSTS_DIR"
echo '203.0.113.9 manual.example' > "$D2S_DNS_HOSTS_DIR/user"
dns_pin_add web.whatsapp.com 192.0.2.10
ndm_touched
record_exists web.whatsapp.com 192.0.2.10
dns_pin_remove web.whatsapp.com 192.0.2.11
record_exists web.whatsapp.com 192.0.2.10
dns_pin_remove web.whatsapp.com 192.0.2.10
ndm_touched
if record_exists web.whatsapp.com 192.0.2.10; then exit 1; fi
grep -qx '203.0.113.9 manual.example' "$D2S_DNS_HOSTS_DIR/user"
ndm_save_if_changed
echo 'web.whatsapp.com 192.0.2.20' > "$MANIFEST"
dns_restore_owned
ndm_touched
record_exists web.whatsapp.com 192.0.2.20
dns_pin_remove web.whatsapp.com 192.0.2.20
ndm_touched
if record_exists web.whatsapp.com 192.0.2.20; then exit 1; fi
'''
    p=subprocess.run(['/bin/sh'],input=script,text=True,capture_output=True)
    assert p.returncode==0,p.stdout+p.stderr
    print('OpenWrt DNS exact add/remove, readback and foreign hosts preserved: PASS')
