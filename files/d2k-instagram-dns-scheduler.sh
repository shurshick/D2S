#!/bin/sh
set -eu
DIR=${D2K_DIR:-/opt/d2k}
export D2K_INSTAGRAM_HELPER="$DIR/d2k-instagram-dns.sh"
export D2K_INSTAGRAM_SCHED_STATE="$DIR/state/whatsapp-dns-last-success"
export D2K_INSTAGRAM_SCHED_ATTEMPT=/tmp/d2k-whatsapp-dns-last-attempt
export D2K_INSTAGRAM_SCHED_LOG="$DIR/log/whatsapp-dns-scheduler.log"
export D2K_INSTAGRAM_SCHED_OFFSET="$DIR/state/whatsapp-dns-offset"
export D2K_MEDIA_HELPER="$DIR/d2k-whatsapp-media.sh"
export D2K_SCHEDULER_INTERVAL=30
exec "$DIR/d2k-meta-dns-scheduler-core.sh" "${1:-run}"
