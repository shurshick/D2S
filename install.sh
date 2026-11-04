#!/bin/sh
# D2S bootstrap. All runtime files come from an Ed25519-signed release.
set -eu
PATH=/opt/sbin:/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'D2S: требуется root в Entware' >&2; exit 1; }
command -v ndmc >/dev/null 2>&1 && command -v opkg >/dev/null 2>&1 || { echo 'D2S: требуется Keenetic/Netcraze с Entware' >&2; exit 1; }
opkg update
opkg install curl ca-bundle iptables ipset kmod_ndms xtables-addons_legacy openssl-util
task_dir=$(mktemp -d /tmp/d2s-bootstrap.XXXXXX)
trap 'rm -rf "$task_dir"' EXIT INT TERM
curl -fsSL --proto '=https' https://raw.githubusercontent.com/shurshick/D2S/main/scripts/install.sh -o "$task_dir/install.sh"
export D2K_REPO=shurshick/D2S
sh "$task_dir/install.sh"
