#!/usr/bin/env python3
"""Ephemeral GitHub runner only: repair failed Ubuntu DNS via verified HTTPS.
APT repository signatures and TLS checks stay enabled. Never shipped to routers.
Cloudflare JSON API: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
"""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

HOSTS = ('azure.archive.ubuntu.com', 'archive.ubuntu.com', 'security.ubuntu.com')

def addresses(payload, host):
    if not isinstance(payload, dict) or payload.get('Status') != 0 or payload.get('TC'):
        raise ValueError('DNS response failed or truncated')
    if not any(q.get('name', '').lower().rstrip('.') == host and q.get('type') == 1
               for q in payload.get('Question', []) if isinstance(q, dict)):
        raise ValueError('DNS question mismatch')
    answers = payload.get('Answer', [])
    if not isinstance(answers, list) or len(answers) > 64:
        raise ValueError('Invalid DNS answers')
    names = {host}
    for _ in range(16):
        before = len(names)
        for rr in answers:
            if isinstance(rr, dict) and rr.get('type') == 5 and rr.get('name', '').lower().rstrip('.') in names:
                names.add(str(rr.get('data', '')).lower().rstrip('.'))
        if len(names) == before:
            break
    result = set()
    for rr in answers:
        if not isinstance(rr, dict) or rr.get('type') != 1 or rr.get('name', '').lower().rstrip('.') not in names:
            continue
        ip = ipaddress.ip_address(rr.get('data', ''))
        if ip.version != 4 or not ip.is_global or not isinstance(rr.get('TTL'), int) or rr['TTL'] <= 0:
            raise ValueError('Non-public address or invalid TTL')
        result.add(str(ip))
    if not result or len(result) > 16:
        raise ValueError('Missing or excessive A records')
    return sorted(result)

def query(host):
    url = 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name': host, 'type': 'A'})
    request = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError('Oversized DNS response')
    return json.loads(data)

def resolves(host):
    try:
        return subprocess.run(['getent', 'ahostsv4', host], timeout=8,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except subprocess.TimeoutExpired:
        return False

def repair(path, resolver=resolves, fetch=query):
    pending = []
    for host in HOSTS:
        if not resolver(host):
            pending.extend(f'{ip} {host} # D2S ephemeral CI DNS\n' for ip in addresses(fetch(host), host))
            print('CI DNS: HTTPS fallback for ' + host, flush=True)
    if pending:
        with path.open('a', encoding='utf-8') as stream:
            stream.write('\n' + ''.join(pending))
    return len(pending)

if __name__ == '__main__':
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('Only run as root on an ephemeral GitHub Actions runner')
    repair(Path('/etc/hosts'))
