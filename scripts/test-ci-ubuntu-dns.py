"""Isolated DNS recovery fixtures: no network and no system hosts edits."""
import importlib.util
from pathlib import Path
import tempfile
spec = importlib.util.spec_from_file_location('dns', Path(__file__).with_name('ci-ubuntu-dns.py'))
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)
host = dns.HOSTS[0]
def answer(name, data='8.8.8.8'):
    return {'Status': 0, 'Question': [{'name': name + '.', 'type': 1}],
            'Answer': [{'name': name + '.', 'type': 1, 'TTL': 60, 'data': data}]}
assert dns.addresses(answer(host), host) == ['8.8.8.8']
cname = answer(host)
cname['Answer'][0]['name'] = 'cdn.example.'
cname['Answer'].append({'name': host + '.', 'type': 5, 'data': 'cdn.example.'})
assert dns.addresses(cname, host) == ['8.8.8.8']
for payload in [{'Status': 2}, dict(answer(host), TC=True), answer('other.example'),
                answer(host, '127.0.0.1'), answer(host, '10.1.2.3'), answer(host, '::1'),
                answer(host, 'bad\ninjected'), dict(answer(host), Answer=[]),
                dict(answer(host), Answer=[{'name': 'unrelated.example', 'type': 1, 'TTL': 60, 'data': '8.8.8.8'}])]:
    try: dns.addresses(payload, host)
    except (ValueError, TypeError): pass
    else: raise AssertionError(payload)
with tempfile.TemporaryDirectory() as tmp:
    hosts = Path(tmp)/'hosts'
    original = '127.0.0.1 localhost\n'
    hosts.write_text(original)
    def never(_): raise AssertionError('No HTTPS when system DNS works')
    assert dns.repair(hosts, lambda _: True, never) == 0
    assert hosts.read_text() == original
    assert dns.repair(hosts, lambda name: name != host, answer) == 1
    assert hosts.read_text() == original + '\n8.8.8.8 ' + host + ' # D2S ephemeral CI DNS\n'
    hosts.write_text(original)
    def failed(name):
        if name != host: raise OSError('HTTPS unavailable')
        return answer(name)
    try: dns.repair(hosts, lambda _: False, failed)
    except OSError: pass
    else: raise AssertionError('HTTPS failure must fail closed')
    assert hosts.read_text() == original, 'No partial writes on fallback failure'
print('CI Ubuntu DNS: healthy resolver, HTTPS fallback, CNAME, malformed/unsafe data, atomic staging PASS')
