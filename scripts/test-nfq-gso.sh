#!/bin/sh
# Run only in a new network namespace; never change the host firewall/offloads.
set -eu
if [ "${1:-}" != --isolated ]; then
    exec unshare -n sh "$0" --isolated "$@"
fi
shift
ip link set lo up
nft -f - <<'EOF'
table inet d2s_gso_test {
    chain output {
        type filter hook output priority 0; policy accept;
        udp dport 46132 queue num 61432
    }
}
EOF
exec "${1:-/tmp/d2s-test-nfq-gso}"
