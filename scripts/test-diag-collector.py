"""Real, isolated collector lifecycle; no router or host service changes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]

def wait_for(predicate, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.05)
    raise AssertionError('collector condition timed out')

with tempfile.TemporaryDirectory(prefix='d2s-diag-') as temporary:
    folder = Path(temporary)
    state = folder / 'diagnostics'
    state.mkdir(mode=0o700)
    (state / 'telegram-enabled').touch(mode=0o600)
    stats = folder / 'tg.sock'
    binary = folder / 'collector'
    subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    f'-DD2S_DIAG_DIR="{state}"', '-Icore/include',
                    '-o', str(binary), 'core/d2sdiag.c', 'core/diagnostics.c'], cwd=ROOT, check=True)
    subprocess.run([str(binary), '--self-check'], check=True)
    child = subprocess.Popen([str(binary), str(stats)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    stop = threading.Event()
    replies = []
    server = None
    try:
        report = state / 'report.json'
        wait_for(lambda: json.loads(report.read_text())['telegram_diagnostics']['collection_failures'] > 0)
        assert child.poll() is None and not (state / 'telegram.json').exists()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(stats))
        server.listen(8)
        server.settimeout(0.1)

        def serve():
            while not stop.is_set():
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                with client:
                    body = {'active_connections': 2, 'max_connections': 64,
                            'connections_started': 7, 'buffer_bytes_current': 4096,
                            'active_route_sessions': [], 'route_cooldowns': []}
                    client.sendall(json.dumps(body).encode() + b'\n')
                    replies.append(1)
        worker = threading.Thread(target=serve)
        worker.start()
        live = state / 'telegram.json'
        wait_for(lambda: json.loads(live.read_text())['active_connections'] == 2)
        assert live.stat().st_mode & 0o777 == 0o600
        # Toggle only the optional history to obtain a new first sample now.
        (state / 'telegram-enabled').unlink()
        time.sleep(2.2)
        (state / 'telegram-enabled').touch(mode=0o600)
        snapshot = wait_for(lambda: (lambda r: r if r['telegram_diagnostics']['memory_history']['samples'] else None)(json.loads(report.read_text())))
        assert snapshot['telegram_diagnostics']['memory_history']['capacity'] == 1440
        assert child.poll() is None and replies
        status = Path(f'/proc/{child.pid}/status').read_text()
        rss = next(line.strip() for line in status.splitlines() if line.startswith('VmRSS:'))
        print('collector live snapshot, first history sample, permissions:', rss)
        # An unrelated/malformed producer cannot become valid diagnostic history.
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        peer.sendto(b'invalid', str(state / 'input.sock'))
        peer.close()
        assert child.poll() is None
        stop.set()
        worker.join(timeout=3)
        server.close()
        server = None
        stats.unlink()
        wait_for(lambda: not live.exists())
        assert child.poll() is None
    finally:
        stop.set()
        if server is not None:
            if 'worker' in locals():
                worker.join(timeout=3)
            server.close()
        child.terminate()
        _, errors = child.communicate(timeout=5)
        assert child.returncode == 0, errors.decode()
    assert not (state / 'input.sock').exists() and not (state / 'telegram.json').exists()
    print('collector absent/recovered/stopped proxy and clean shutdown PASS')
