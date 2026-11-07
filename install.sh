#!/bin/sh
# D2S bootstrap. All runtime files come from an Ed25519-signed release.
set -eu

# Refuse a parallel installation of the retired namespace.
if [ -d /opt/d2k ] || [ -e /opt/etc/init.d/S99d2k ]; then
    echo 'D2S: обнаружена прежняя установка. Сначала удалите её штатным деинсталлятором; автоматической миграции нет.' >&2
    exit 1
fi
PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'D2S: требуется root' >&2; exit 1; }
if [ ! -f /etc/openwrt_release ]; then
    command -v ndmc >/dev/null 2>&1 && command -v opkg >/dev/null 2>&1 || { echo 'D2S: требуется OpenWrt или Keenetic/Netcraze с Entware' >&2; exit 1; }
    opkg update
    opkg install curl ca-bundle iptables ipset kmod_ndms xtables-addons_legacy openssl-util
fi
task_dir=$(mktemp -d /tmp/d2s-bootstrap.XXXXXX)
trap 'rm -rf "$task_dir"' EXIT INT TERM
url=https://raw.githubusercontent.com/shurshick/D2S/main/scripts/install.sh
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' "$url" -o "$task_dir/install.sh"
else
    wget -q -T 60 -O "$task_dir/install.sh" "$url"
fi
export D2S_REPO=shurshick/D2S
sh "$task_dir/install.sh"
