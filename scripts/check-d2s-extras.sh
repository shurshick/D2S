#!/bin/sh
# Isolated tests: fake NDM/IP tools, no router access and no DNS changes.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT INT TERM
python3 "$ROOT/tests/keenetic/test-lan.py" "$ROOT/files/d2s-lan.sh"
python3 "$ROOT/tests/keenetic/test-media.py" "$ROOT/files"
cc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I"$ROOT/telegram/include" -o "$TEMP/resolver" "$ROOT/resolver-local/local-resolver.c" \
  "$ROOT/telegram/src/identity.c" "$ROOT/telegram/src/net.c" -lssl -lcrypto
python3 "$ROOT/tests/keenetic/test-resolver-http.py" "$TEMP/resolver"
cc -O1 -g -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=address,undefined -fno-omit-frame-pointer \
  -o "$TEMP/dns-test" "$ROOT/resolver-local/test-dns-media-watch.c"
"$TEMP/dns-test"
