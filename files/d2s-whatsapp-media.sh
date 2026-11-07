#!/bin/sh
# Discover media names seen in the application's own TLS/QUIC traffic.
# Every alternative address is a previously validated Meta edge and must
# present a certificate for the exact observed media hostname.
set -eu
DIR=${D2S_DIR:-/opt/d2s}
export D2S_DNS_FAMILY=whatsapp
export D2S_INSTAGRAM_MANIFEST="$DIR/state/whatsapp-media-hosts.tsv"
export D2S_INSTAGRAM_LOG="$DIR/log/whatsapp-media-dns.log"
. "$DIR/d2s-meta-dns-library.sh"
ca_bundle=${D2S_IP_CA_BUNDLE:-/opt/etc/ssl/certs/ca-certificates.crt}
[ -r "$ca_bundle" ] || ca_bundle=/etc/ssl/certs/ca-certificates.crt
CHECK_STATE=$DIR/state/whatsapp-media-last-check
NAMES=$DIR/state/whatsapp-media-names.txt
POOL=$DIR/state/whatsapp-media-pool.txt
CACHE=$DIR/state/whatsapp-media-pair-cache.tsv

# Cache the exact certificate-checked pair, not the whole name list. A new
# hostname must not invalidate other hosts. Failed probes get one scheduler
# interval of rest; a failed host never discards successful work for siblings.
media_edge_verified() {
    _media_cached=$(awk -v h="$1" -v a="$2" -v t="$now" '
        $1==h && $2==a && $4~/^[0-9]+$/ && t>=$4 &&
        t-$4<($3=="ok"?21600:30) {print $3;exit}' "$CACHE" 2>/dev/null || true)
    case "$_media_cached" in ok) return 0;; fail) return 1;; esac
    _media_status=fail
    if edge_verified "$1" "$2"; then _media_status=ok; fi
    _media_tmp="$CACHE.new.$$"
    if [ -r "$CACHE" ]; then
        awk -v h="$1" -v a="$2" '$1!=h || $2!=a' "$CACHE" > "$_media_tmp"
    else
        : > "$_media_tmp"
    fi
    printf '%s %s %s %s\n' "$1" "$2" "$_media_status" "$now" >> "$_media_tmp"
    mv -f "$_media_tmp" "$CACHE"
    [ "$_media_status" = ok ]
}

media_names() {
    {
        [ ! -r /tmp/d2s/whatsapp-media-observed.txt ] || cat /tmp/d2s/whatsapp-media-observed.txt
        tail -n 2000 "$DIR/log/d2sd.log" "$DIR/log/d2sc.log" 2>/dev/null || true
        [ ! -r "$MANIFEST" ] || cat "$MANIFEST"
    } | grep -Eo 'media-[a-zA-Z0-9-]+\.cdn\.whatsapp\.net' | tr 'A-Z' 'a-z' | sort -u | head -n 32
}

names=$(media_names || true)
HOSTS=$(printf '%s\n' "$names" | tr '\n' ' ')
case "${1:-refresh}" in
    remove) remove_owned; rm -f "$CHECK_STATE" "$NAMES" "$POOL" "$CACHE"; exit 0 ;;
    refresh) ;;
    *) echo 'usage: refresh|remove' >&2; exit 2 ;;
esac
[ -n "$names" ] || exit 0
now=$(date +%s)
last=$(cat "$CHECK_STATE" 2>/dev/null || echo 0)
case "$last" in ''|*[!0-9]*) last=0;; esac
old_names=$(cat "$NAMES" 2>/dev/null || true)
candidates=$(awk 'NF==2 {print $2}' "$DIR/state/whatsapp-ip-hosts.tsv" 2>/dev/null | sort -u)
[ -n "$candidates" ] || { log 'нет проверенного пула адресов WhatsApp'; exit 1; }
old_pool=$(cat "$POOL" 2>/dev/null || true)
if [ "$old_names" = "$names" ] && [ "$old_pool" = "$candidates" ] && [ "$now" -ge "$last" ] && [ $((now-last)) -lt 21600 ]; then exit 0; fi
ndm_config || exit 1
if [ -r "$CACHE" ]; then
    # Retain only the current bounded name/pool context, not a lifetime log.
    awk -v hs="$HOSTS" -v ips="$candidates" 'BEGIN {
        nh=split(hs,h);na=split(ips,a);for(i=1;i<=nh;i++)hosts[h[i]]=1;
        for(i=1;i<=na;i++)pool[a[i]]=1
    } $1 in hosts && $2 in pool {print}' "$CACHE" > "$CACHE.new.$$"
    mv -f "$CACHE.new.$$" "$CACHE"
fi
failed=0
for host in $names; do
    verified=0
    fresh_ips=
    for ip in $candidates; do
        is_meta_ip "$ip" || continue
        if ! media_edge_verified "$host" "$ip"; then continue; fi
        verified=$((verified+1))
        fresh_ips="$fresh_ips $ip"
        if record_exists "$host" "$ip"; then
            :
        else
            rc=$?
            [ "$rc" = 1 ] || exit 1
            printf '%s %s\n' "$host" "$ip" >> "$MANIFEST"
            if dns_pin_add "$host" "$ip"; then
                ndm_touched
                log "добавлен проверенный медиадомен $host $ip"
            else
                ndm_touched
                ndm_save_if_changed || true
                exit 1
            fi
        fi
        [ "$verified" -lt 2 ] || break
    done
    if [ "$verified" -eq 0 ]; then
        log "для $host не найден адрес с подходящим сертификатом"
        failed=1
        continue
    fi
    # Retire only our stale pairs, after replacement has passed verification.
    if [ -f "$MANIFEST" ]; then
        while read -r old_host old_ip extra; do
            [ "$old_host" = "$host" ] || continue
            case " $fresh_ips " in *" $old_ip "*) continue;; esac
            valid_ipv4 "$old_ip" || continue
            if record_exists "$old_host" "$old_ip"; then
                dns_pin_remove "$old_host" "$old_ip" || exit 1
                ndm_touched
            else
                rc=$?
                [ "$rc" = 1 ] || exit 1
            fi
            awk -v h="$old_host" -v a="$old_ip" '!($1==h && $2==a)' "$MANIFEST" > "$MANIFEST.keep"
            mv "$MANIFEST.keep" "$MANIFEST"
        done < "$MANIFEST"
    fi
done
if [ -f "$MANIFEST" ]; then
    sort -u "$MANIFEST" > "$MANIFEST.new"
    mv "$MANIFEST.new" "$MANIFEST"
fi
ndm_save_if_changed || exit 1
[ "$failed" -eq 0 ] || exit 1
printf '%s\n' "$names" > "$NAMES"
printf '%s\n' "$candidates" > "$POOL"
printf '%s\n' "$now" > "$CHECK_STATE"
log 'медиадомены проверены; повторная проверка через шесть часов или при новом имени'
