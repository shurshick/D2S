#!/bin/sh
set -eu
DIR=${D2S_DIR:-/opt/d2s}
export D2S_INSTAGRAM_HELPER="$DIR/d2s-instagram-dns.sh"
export D2S_INSTAGRAM_SCHED_STATE="$DIR/state/whatsapp-dns-last-success"
export D2S_INSTAGRAM_SCHED_ATTEMPT=/tmp/d2s-whatsapp-dns-last-attempt
export D2S_INSTAGRAM_SCHED_LOG="$DIR/log/whatsapp-dns-scheduler.log"
export D2S_INSTAGRAM_SCHED_OFFSET="$DIR/state/whatsapp-dns-offset"
export D2S_MEDIA_HELPER="$DIR/d2s-whatsapp-media.sh"
export D2S_SCHEDULER_INTERVAL=30
exec "$DIR/d2s-meta-dns-scheduler-core.sh" "${1:-run}"
