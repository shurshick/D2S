"""Real discovery script against renamed UCI/netifd fixtures, no networking."""
from pathlib import Path
import subprocess,tempfile,os
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as td:
    t=Path(td);(t/'release').touch();(t/'bin').mkdir()
    (t/'functions').write_text('''
config_load() { dataset=$1; }
config_foreach() {
 case "$dataset:$2" in
 firewall:forwarding) "$1" f1; "$1" f2;;
 firewall:zone) "$1" z1; "$1" z2; "$1" z3;;
 dhcp:dhcp) [ "${NO_DHCP_SECTIONS:-0}" != 1 ] || return 0; "$1" d1; "$1" d2;;
 esac
}
config_get() {
 value=${4:-}
 case "$dataset:$2:$3" in
 firewall:f1:src) value=trusted;; firewall:f2:src) value=visitors;;
 firewall:z1:name) value=trusted;; firewall:z1:input) value=ACCEPT;; firewall:z1:network) value=office;;
 firewall:z2:name) value=visitors;; firewall:z2:input) value=REJECT;; firewall:z2:network) value=guestnet;;
 firewall:z3:name) value=uplink;; firewall:z3:input) value=REJECT;; firewall:z3:network) value=provider;; firewall:z3:masq) value=1;;
 dhcp:d1:interface) value=office;; dhcp:d1:ignore) value=1;;
 dhcp:d2:interface) value=provider;; dhcp:d2:ignore) value=1;;
 esac
 eval "$1=\\\"\\$value\\\""
}
config_get_bool() { config_get "$@"; }
''')
    (t/'network').write_text('''network_get_device() {
case "$2" in office) device=br-office;;guestnet) device=br-visitors;;provider) device=eth-uplink;;*) return 1;;esac
eval "$1=\\\"\\$device\\\""
}
''')
    (t/'bin/ip').write_text("#!/bin/sh\nprintf '%s\\n' '2: br-office inet 10.44.7.1/24' '3: br-visitors inet 172.20.8.1/24' '4: eth-uplink inet 192.168.9.2/24'\n")
    (t/'bin/ip').chmod(0o755)
    script=(root/'files/d2s-lan.sh').read_text().replace('/etc/openwrt_release',str(t/'release')).replace('/lib/functions.sh',str(t/'functions')).replace('/lib/functions/network.sh',str(t/'network'))
    (t/'lan').write_text(script)
    for absent in ('0','1'):
        p=subprocess.run(['/bin/sh','-ec',f'. "{t}/lan"; d2s_lan_entries'],env={**os.environ,'PATH':str(t/'bin')+':/usr/bin:/bin','NO_DHCP_SECTIONS':absent},capture_output=True,text=True)
        assert p.returncode==0,p.stderr
        assert p.stdout.splitlines()==['br-office 10.44.7.0/24','br-visitors 172.20.8.0/24'],p.stdout
    print('OpenWrt renamed LANs with disabled/missing DHCP retained; private-address WAN excluded: PASS')
