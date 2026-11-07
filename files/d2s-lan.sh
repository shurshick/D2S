#!/bin/sh
# Discover numbered IPv4 LAN segments from live platform configuration.
# No address, subnet, DHCP pool or Linux interface is embedded here.
D2S_LAN_SET4=${D2S_LAN_SET4:-d2s_lan4}

d2s_lan_entries() (
    if [ -f /etc/openwrt_release ]; then
        # OpenWrt shell libraries intentionally read unset optional variables.
        set +u
        . /lib/functions.sh
        . /lib/functions/network.sh
        devices= client_zones= trusted_networks=
        collect_forward_source() {
            local source_zone
            config_get source_zone "$1" src
            [ -n "$source_zone" ] || return 0
            client_zones="$client_zones $source_zone"
        }
        collect_trusted_zone() {
            local name input networks nat client
            config_get name "$1" name
            [ -n "$name" ] || return 0
            config_get input "$1" input REJECT
            config_get networks "$1" network
            config_get_bool nat "$1" masq 0
            client=0
            case " $client_zones " in *" $name "*) client=1;; esac
            # Forwarding sources are client networks. A terminal NAT zone is
            # normally the uplink, even if it uses private IPv4 addresses.
            if [ "$client" = 1 ] || { [ "$nat" = 0 ] && [ "$input" = ACCEPT ]; }; then
                trusted_networks="$trusted_networks $networks"
            fi
            return 0
        }
        collect_device() {
            local interface device
            interface=$1
            network_get_device device "$interface" || return 0
            case "$device" in ''|lo|*[!A-Za-z0-9_.:-]*) return 0;; esac
            devices="$devices $device"
        }
        collect_dhcp_lan() {
            local interface ignored
            config_get ignored "$1" ignore 0
            [ "$ignored" != 1 ] || return 0
            config_get interface "$1" interface "$1"
            collect_device "$interface"
        }
        if config_load firewall; then
            config_foreach collect_forward_source forwarding
            config_foreach collect_trusted_zone zone
        fi
        for interface in $trusted_networks; do collect_device "$interface"; done
        config_load dhcp
        config_foreach collect_dhcp_lan dhcp
        [ -n "$devices" ] || exit 1
        ip -4 -o addr show | awk -v devices="$devices" '
            BEGIN {n=split(devices,a," ");for(i=1;i<=n;i++) wanted[a[i]]=1}
            {dev=$2;sub(/@.*/,"",dev);if(!(dev in wanted))next;
             for(i=1;i<NF;i++)if($i=="inet") {
                split($(i+1),c,"/");split(c[1],o,".");
                if(c[2]!~/^[0-9]+$/ || c[2]>32)continue;
                v=((o[1]*256+o[2])*256+o[3])*256+o[4];b=2^(32-c[2]);v=int(v/b)*b;
                printf "%s %.0f.%.0f.%.0f.%.0f/%s\n",dev,int(v/16777216),int(v/65536)%256,int(v/256)%256,v%256,c[2]
             }}' | sort -u
        exit
    fi
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
