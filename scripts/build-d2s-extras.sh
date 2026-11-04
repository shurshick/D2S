#!/bin/sh
# Static C runtimes for the local-only resolver and LAN DNS observer.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/build-target.sh"
PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-$ARCH"}
OUT=${OUT:-"$ROOT/builds"}
LIBDIR=$PREFIX/lib
[ -d "$LIBDIR" ] || LIBDIR=$PREFIX/lib64
mkdir -p "$OUT"
# TARGET_FLAGS comes only from build-target.sh.
# shellcheck disable=SC2086
"$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -Os -std=c11 \
    -Wall -Wextra -Werror -pedantic -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,-S \
    -I"$ROOT/telegram/include" -I"$PREFIX/include" -L"$LIBDIR" \
    -o "$OUT/d2o-resolver-linux-$ARCH" "$ROOT/resolver-local/local-resolver.c" \
    "$ROOT/telegram/src/identity.c" "$ROOT/telegram/src/net.c" -lssl -lcrypto -ldl -pthread
# shellcheck disable=SC2086
"$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -Os -std=c11 \
    -Wall -Wextra -Werror -pedantic -Wl,-S \
    -o "$OUT/d2o-dns-watch-linux-$ARCH" "$ROOT/resolver-local/dns-media-watch.c"
