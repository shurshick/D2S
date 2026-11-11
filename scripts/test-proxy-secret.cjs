#!/usr/bin/env node
// Exercise the real installer block with a BusyBox-style od that lacks -N/-t.
// Private filesystem only; no router, firewall or /opt changes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const source = fs.readFileSync(path.join(__dirname, 'install.sh'), 'utf8');
const start = source.indexOf("if ! grep -q '^[[:space:]]*TG_PROXY_SECRET='");
const end = source.indexOf('# WhatsApp DNS pins', start);
assert(start >= 0 && end > start);
const block = source.slice(start, end);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'd2s-secret-test-'));
try {
  const bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'od'), '#!/bin/sh\necho "od: unsupported option" >&2\nexit 1\n', {mode: 0o755});
  const script = path.join(tmp, 'test.sh');
  fs.writeFileSync(script, 'set -eu\ndie() { echo "$*" >&2; exit 1; }\nsay() { echo "$*"; }\n' + block);
  const cfg = path.join(tmp, 'config');
  const run = () => spawnSync('/bin/sh', [script], {env: {...process.env, DIR: tmp, PATH: bin + ':' + process.env.PATH}, encoding:'utf8'});
  fs.writeFileSync(cfg, '# fresh installation\n', {mode: 0o600});
  let result = run();
  assert.equal(result.status, 0, 'must generate with incompatible od: ' + result.stderr);
  const content = fs.readFileSync(cfg, 'utf8');
  const secret = content.match(/^TG_PROXY_SECRET=([0-9a-f]{32})$/m)?.[1];
  assert(secret, '16 random bytes encoded as 32 lowercase hex characters');
  assert(!result.stdout.includes(secret) && !result.stderr.includes(secret));
  assert.equal(fs.statSync(cfg).mode & 0o777, 0o600);
  // Existing installations must not require entropy or regenerate credentials.
  fs.writeFileSync(path.join(bin, 'openssl'), '#!/bin/sh\nexit 1\n', {mode:0o755});
  result = run(); assert.equal(result.status, 0);
  assert.equal(fs.readFileSync(cfg, 'utf8'), content);
  for (const body of ['exit 1', 'exit 0', 'echo abc', 'echo 0123456789abcdef0123456789abcdeg', 'echo 0123456789abcdef0123456789abcdef; exit 1']) {
    fs.writeFileSync(cfg, '# fresh installation\n');
    fs.writeFileSync(path.join(bin, 'openssl'), '#!/bin/sh\n' + body + '\n', {mode:0o755});
    result = run(); assert.notEqual(result.status, 0, body);
    assert.equal(fs.readFileSync(cfg, 'utf8'), '# fresh installation\n', 'no partial secret on RNG failure');
  }
  console.log('MTProto installer secret: incompatible od, generation, preservation, permissions and RNG failure PASS');
} finally { fs.rmSync(tmp, {recursive:true, force:true}); }
