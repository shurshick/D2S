"""Validate the installable release, including new helpers and RAM preflight."""
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1])
installer = (root / 'scripts/install.sh').read_text()
metadata = json.loads((out / 'latest.json').read_text())
stage_limit = int(re.search(r'^TMP_NEED_KB=(\d+)$', installer, re.M)[1]) * 1024
release_limit = int(re.search(r'^TMP_RELEASE_NEED_KB=(\d+)$', installer, re.M)[1]) * 1024
for arch, asset in metadata['assets'].items():
    archive = out / f'd2k-{arch}.tar.gz'
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == asset['sha256']
    with tarfile.open(archive) as tar:
        files = {m.name.removeprefix('./'): m for m in tar.getmembers() if m.isfile()}
        for bin in ('d2kd', 'd2kc', 'd2kfetch', 'd2kpanel', 'd2ktg', 'd2o-resolver', 'd2o-dns-watch'):
            assert files[f'builds/{bin}-linux-{arch}'].size > 0
        for path in ('scripts/install.sh', 'files/S99d2k', 'files/S96d2o-resolver', 'files/S97d2o-dns-watch',
                     'files/d2k-lan.sh', 'files/d2k-meta-dns-core.sh', 'files/d2k-meta-dns-library.sh',
                     'files/d2k-meta-dns-scheduler-core.sh', 'files/d2k-whatsapp-media.sh',
                     'internal/web/assets/panel.css', 'internal/web/assets/panel.js', 'internal/web/assets/index.html'):
            assert path in files, path
        tree = sum((m.size + 4095) // 4096 * 4096 for m in files.values())
        # The staged install is a subset of the release. Include directory overhead.
        stage = sum(m.size for name, m in files.items() if name.startswith(('builds/', 'files/', 'internal/web/assets/')))
        assert stage <= stage_limit, (arch, 'staging RAM preflight too small', stage)
        assert max(tree + stage_limit, tree + archive.stat().st_size) + 256 * 1024 <= release_limit, (arch, 'release RAM preflight too small', tree)
    print(f'{arch}: complete signed package, SHA256 and RAM preflight PASS')
