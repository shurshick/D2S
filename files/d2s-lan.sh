#!/bin/sh
# Discover numbered IPv4 LAN segments from live Keenetic configuration.
# No address, subnet, DHCP pool or Linux interface is embedded here.
D2S_LAN_SET4=${D2S_LAN_SET4:-d2s_lan4}

d2s_lan_entries() (
    config=$(LD_LIBRARY_PATH='' ndmc -c 'show running-config' 2>/dev/null) || exit 1
    [ -n "$config" ] || exit 1
    addresses=$(printf '%s\n' "$config" | awk '
        function emit() {if (inside && (level=="private" || level=="protected") && address ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print address}
        /^interface / {emit();inside=1;level="";address="";next}
        inside && /^[^ \t]/ {emit();inside=0}
        inside && $1=="security-level" {level=$2}
        inside && $1=="ip" && $2=="address" {address=$3}
        END {emit()}') || exit 1
    [ -n "$addresses" ] || exit 1
    ip -4 -o addr show | awk -v addresses="$addresses" '
        BEGIN {n=split(addresses, a, /[ \t\n]+/);for(i=1;i<=n;i++) wanted[a[i]]=1}
        {
            dev=$2; sub(/@.*/,"",dev)
            if(dev !~ /^[A-Za-z0-9_.:-]+$/) next
            for(i=1;i<NF;i++) if($i=="inet") {
                split($(i+1), cidr, "/"); if(!(cidr[1] in wanted)) continue
                if(cidr[2] !~ /^[0-9]+$/ || cidr[2]<0 || cidr[2]>32) continue
                split(cidr[1],oct,"."); valid=1
                for(j=1;j<=4;j++) if(oct[j]<0 || oct[j]>255) valid=0
                if(!valid) continue
                value=((oct[1]*256+oct[2])*256+oct[3])*256+oct[4]
                block=2^(32-cidr[2]); base=int(value/block)*block
                printf "%s %.0f.%.0f.%.0f.%.0f/%s\n",dev,int(base/16777216),int(base/65536)%256,int(base/256)%256,base%256,cidr[2]
            }
        }' | sort -u
)

d2s_lan_networks() {
    entries=$(d2s_lan_entries) || return 1
    [ -n "$entries" ] || return 1
    printf '%s\n' "$entries" | awk '{print $2}' | sort -u
}

d2s_lan_ifaces() {
    entries=$(d2s_lan_entries) || return 1
    [ -n "$entries" ] || return 1
    printf '%s\n' "$entries" | awk '{print $1}' | sort -u
}

d2s_lan_sync() (
    desired=$(d2s_lan_networks) || { echo 'd2o: no numbered private/protected LAN found; rules refused' >&2; exit 1; }
    stage=${D2S_LAN_SET4}_new
    ipset create "$D2S_LAN_SET4" hash:net family inet -exist || exit 1
    ipset create "$stage" hash:net family inet -exist || exit 1
    trap 'ipset destroy "$stage" >/dev/null 2>&1 || true' EXIT
    ipset flush "$stage" || exit 1
    for network in $desired; do ipset add "$stage" "$network" -exist || exit 1; done
    ipset swap "$stage" "$D2S_LAN_SET4" || exit 1
)

d2s_lan_installed() (
    desired=$(d2s_lan_networks) || exit 1
    saved=$(ipset save "$D2S_LAN_SET4" 2>/dev/null) || exit 1
    actual=$(printf '%s\n' "$saved" | awk '$1=="add"{print $3}' | sort -u)
    [ "$actual" = "$desired" ]
)
