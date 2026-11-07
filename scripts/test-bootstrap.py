"""Exercise actual public entry point without a router or network."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    bin = tmp / 'bin'
    bin.mkdir()
    for name in ('sh', 'mktemp', 'rm'):
        (bin / name).symlink_to('/usr/bin/' + name)
    (bin / 'id').write_text('#!/bin/sh\necho 0\n')
    (bin / 'id').chmod(0o755)
    (bin / 'wget').write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n case "$1" in -O) out=$2; shift 2;; *) shift;; esac\ndone\nprintf "echo installed-from-signed-channel\\n" > "$out"\n')
    (bin / 'wget').chmod(0o755)
    release = tmp / 'openwrt_release'
    release.write_text("DISTRIB_ID='OpenWrt'\n")
    script = (root / 'install.sh').read_text().replace('/etc/openwrt_release', str(release))
    script = script.replace('PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin', 'PATH=' + str(bin))
    script = script.replace('/opt/d2k', str(tmp / 'old')).replace('/opt/etc/init.d/S99d2k', str(tmp / 'old-init'))
    local = tmp / 'bootstrap.sh'
    local.write_text(script)
    result = subprocess.run(['/bin/sh', str(local)], env={**os.environ, 'PATH': str(bin)}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert 'installed-from-signed-channel' in result.stdout
    print('OpenWrt public bootstrap without Entware/curl: PASS')
    release.unlink()
    result = subprocess.run(['/bin/sh', str(local)], env={**os.environ, 'PATH': str(bin)}, capture_output=True, text=True)
    assert result.returncode != 0 and 'installed-from-signed-channel' not in result.stdout
    for name in ('ndmc', 'opkg'):
        (bin / name).write_text('#!/bin/sh\nexit 0\n')
        (bin / name).chmod(0o755)
    result = subprocess.run(['/bin/sh', str(local)], env={**os.environ, 'PATH': str(bin)}, capture_output=True, text=True)
    assert result.returncode == 0 and 'installed-from-signed-channel' in result.stdout
    (bin / 'id').write_text('#!/bin/sh\necho 1000\n')
    result = subprocess.run(['/bin/sh', str(local)], env={**os.environ, 'PATH': str(bin)}, capture_output=True, text=True)
    assert result.returncode != 0 and 'installed-from-signed-channel' not in result.stdout
    print('Keenetic bootstrap preserved; unknown system and non-root refused: PASS')
