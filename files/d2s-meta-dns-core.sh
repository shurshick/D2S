#!/bin/sh
# Shared DNS lifecycle; the media helper uses the same backend directly.
set -eu
DIR=${D2S_DIR:-/opt/d2s}
. "$DIR/d2s-meta-dns-library.sh"
case "${1:-}" in
    refresh) refresh;;
    remove) remove_owned;;
    restore) dns_restore_owned;;
    *) echo "usage: $0 refresh|remove|restore" >&2; exit 2;;
esac
