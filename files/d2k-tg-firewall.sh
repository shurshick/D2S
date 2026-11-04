#!/bin/sh
# Transparent Telegram only on live Keenetic private/protected LAN interfaces.
set -eu
PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
. "${D2K_LAN_LIB:-/opt/d2k/d2k-lan.sh}"
CHAIN=D2O_TG_LAB
SET=d2o_tg_lab4
PORT=1443
TAG=d2o-tg-lab
CIDRS='149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 91.105.192.0/23 95.161.64.0/20 185.76.151.0/24'
ipt() { iptables -w "$@"; }
owned_jumps() {
    ipt -t nat -S PREROUTING | awk -v tag="$TAG" -v chain="$CHAIN" '
        $1=="-A" && $2=="PREROUTING" {
            own=0;dest=0
            for(i=3;i<NF;i++) {
                if($i=="--comment" && ($(i+1)==tag || $(i+1)=="\""tag"\"")) own=1
                if($i=="-j" && $(i+1)==chain) dest=1
            }
            if(own && dest) {sub(/^-A PREROUTING /,"");gsub(/"/,"");print}
        }'
}
remove_jumps() {
    owned_jumps | while IFS= read -r args; do
        # Owned rules contain validated interface names and fixed tokens only.
        # shellcheck disable=SC2086
        ipt -t nat -D PREROUTING $args || return 1
    done
}
ensure() {
    interfaces=$(d2k_lan_ifaces) || { remove_jumps; return 1; }
    [ -n "$interfaces" ] || { remove_jumps; return 1; }
    ipset create "$SET" hash:net -exist
    for range in $CIDRS; do ipset add "$SET" "$range" -exist; done
    ipt -t nat -N "$CHAIN" 2>/dev/null || ipt -t nat -n -L "$CHAIN" >/dev/null
    for port in 443 5222; do
        ipt -t nat -C "$CHAIN" -p tcp --dport "$port" -m set --match-set "$SET" dst -j REDIRECT --to-ports "$PORT" 2>/dev/null ||
            ipt -t nat -A "$CHAIN" -p tcp --dport "$port" -m set --match-set "$SET" dst -j REDIRECT --to-ports "$PORT"
    done
    for interface in $interfaces; do
        ipt -t nat -C PREROUTING -i "$interface" -m comment --comment "$TAG" -j "$CHAIN" 2>/dev/null ||
            ipt -t nat -I PREROUTING 1 -i "$interface" -m comment --comment "$TAG" -j "$CHAIN"
    done
    # Retire only our jumps for interfaces no longer classified as LAN.
    owned_jumps | while IFS= read -r args; do
        keep=0
        for interface in $interfaces; do
            [ "$args" != "-i $interface -m comment --comment $TAG -j $CHAIN" ] || keep=1
        done
        if [ "$keep" = 0 ]; then
            # shellcheck disable=SC2086
            ipt -t nat -D PREROUTING $args || return 1
        fi
    done
}
stop() {
    remove_jumps
    if ipt -t nat -n -L "$CHAIN" >/dev/null 2>&1; then
        ipt -t nat -F "$CHAIN"
        ipt -t nat -X "$CHAIN"
    fi
    ipset destroy "$SET" 2>/dev/null || true
}
case "${1:-}" in
    start|heal) ensure ;;
    stop) stop ;;
    *) echo 'usage: {start|heal|stop}' >&2; exit 2 ;;
esac
