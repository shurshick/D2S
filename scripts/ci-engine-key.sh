#!/bin/sh
# Fingerprint only inputs to the long engine regression suite, not docs or UI assets.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
set -- core datapath detect runtime scripts/test-d2sfetch-cli.py scripts/test-diag-collector.py scripts/ci-engine-key.sh scripts/ci-ubuntu-dns.py .github/workflows/check.yml
for path in "$@"; do git cat-file -e "HEAD:$path"; done
git diff --quiet HEAD -- "$@" || { echo 'Engine inputs differ from HEAD' >&2; exit 1; }
git ls-tree -r HEAD -- "$@" | sha256sum | cut -d' ' -f1
