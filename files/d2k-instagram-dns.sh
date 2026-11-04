#!/bin/sh
set -eu
DIR=${D2K_DIR:-/opt/d2k}
if [ -r "$DIR/config" ]; then . "$DIR/config"; fi
export D2K_RELAY_URL=${D2K_RELAY_URL:-http://127.0.0.1:9083/resolve}
export D2K_DNS_FAMILY=whatsapp
export D2K_INSTAGRAM_MANIFEST="$DIR/state/whatsapp-ip-hosts.tsv"
export D2K_INSTAGRAM_LOG="$DIR/log/whatsapp-dns.log"
export D2K_INSTAGRAM_SCHED_STATE="$DIR/state/whatsapp-dns-last-success"
exec "$DIR/d2k-meta-dns-core.sh" "$@"
