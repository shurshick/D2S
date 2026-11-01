#!/usr/bin/env bash
# Build and atomically hot-deploy the locally changed datapath to the lab router.
# Backups and logs stay in builds/dev-router on the PC; router staging files are
# removed on success and on every handled error.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROUTER=${D2K_ROUTER:-root@192.168.1.1}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
RUN_DIR="$ROOT/builds/dev-router/$STAMP"
BUILD_DIR="$RUN_DIR/build"
LOG="$RUN_DIR/deploy.log"
REMOTE_NEW="/opt/sbin/.d2kd-dev-$STAMP.new"
REMOTE_OLD="/opt/sbin/.d2kd-dev-$STAMP.restore"
NEW_BIN="$BUILD_DIR/d2kd-linux-arm64"
BACKUP="$RUN_DIR/d2kd-before"
DEPLOY_STARTED=0
SUCCESS=0

mkdir -p "$BUILD_DIR"
exec > >(tee -a "$LOG") 2>&1

say() { printf '%s\n' "$*"; }
fail() { say "ОШИБКА: $*" >&2; exit 1; }

case "$ROUTER" in
    root@* ) ;;
    * ) fail "D2K_ROUTER должен иметь вид root@адрес" ;;
esac
case "$ROUTER" in *[!a-zA-Z0-9@._:-]*) fail "недопустимое значение D2K_ROUTER" ;; esac

find_tool() {
    local win_name=$1 unix_name=$2
    if [[ -n "${!win_name:-}" ]]; then
        printf '%s' "${!win_name}"
    elif command -v "$unix_name.exe" >/dev/null 2>&1; then
        command -v "$unix_name.exe"
    elif [[ -x "/mnt/c/Windows/System32/OpenSSH/$unix_name.exe" ]]; then
        printf '%s' "/mnt/c/Windows/System32/OpenSSH/$unix_name.exe"
    else
        command -v "$unix_name" || return 1
    fi
}

SSH_BIN=$(find_tool D2K_SSH_BIN ssh) || fail "не найдена ssh"
SCP_BIN=$(find_tool D2K_SCP_BIN scp) || fail "не найдена scp"
ZIG_BIN=${D2K_ZIG:-$(command -v zig || true)}
[[ -n "$ZIG_BIN" ]] || fail "не найден Zig; задайте D2K_ZIG"
[[ -x "$ZIG_BIN" ]] || fail "Zig недоступен по пути: $ZIG_BIN"
command -v make >/dev/null 2>&1 || fail "не найден make"
command -v sha256sum >/dev/null 2>&1 || fail "не найдена sha256sum"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=2)
SCP_OPTS=(-O -o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=2)
if [[ -n "${D2K_SSH_PORT:-}" ]]; then
    SSH_OPTS+=(-p "$D2K_SSH_PORT")
    SCP_OPTS+=(-P "$D2K_SSH_PORT")
fi

ssh_do() { "$SSH_BIN" "${SSH_OPTS[@]}" "$ROUTER" "$1"; }
local_for_scp() {
    if [[ "$SCP_BIN" == *.exe ]]; then
        wslpath -w "$1"
    else
        printf '%s' "$1"
    fi
}
copy_to_router() {
    local src
    src=$(local_for_scp "$1")
    "$SCP_BIN" "${SCP_OPTS[@]}" "$src" "$ROUTER:$2"
}
copy_from_router() {
    local dst
    dst=$(local_for_scp "$2")
    "$SCP_BIN" "${SCP_OPTS[@]}" "$ROUTER:$1" "$dst"
}

REMOTE_SNAPSHOT=$(cat <<'REMOTE'
set -eu
test "$(uname -m)" = aarch64
test -x /opt/sbin/d2kd
test -x /opt/etc/init.d/S99d2k
dp=$(pidof d2kd 2>/dev/null | awk '{print $1}')
ct=$(pidof d2kc 2>/dev/null | awk '{print $1}')
rules=$(nft list table inet d2k 2>/dev/null | grep -c 'to 2000' || true)
flow_rules=$(nft list ruleset 2>/dev/null | grep -E -c 'flowtable|flow add' || true)
flow_uci=$(uci -q get 'firewall.@defaults[0].flow_offloading' 2>/dev/null || true)
dp_version=$(/opt/sbin/d2kd --version)
ct_version=$(/opt/sbin/d2kc --version)
dp_release=${dp_version#*release=}; dp_release=${dp_release%% *}
ct_release=${ct_version#*release=}; ct_release=${ct_release%% *}
dp_wire=${dp_version##*wire=}
ct_wire=${ct_version##*wire=}
status=$(/opt/etc/init.d/S99d2k status)
queue_pid=$(printf '%s\n' "$status" | awk '/очередь 2000:/ {print $NF; exit}')
printf 'D2KD_RELEASE=%s\nD2KC_RELEASE=%s\nD2KD_WIRE=%s\nD2KC_WIRE=%s\n' \
    "$dp_release" "$ct_release" "$dp_wire" "$ct_wire"
printf 'ARCH=%s\nD2KD_PID=%s\nD2KC_PID=%s\nQUEUE_RULES=%s\nFLOW_RULES=%s\nFLOW_UCI=%s\n' \
    "$(uname -m)" "$dp" "$ct" "$rules" "$flow_rules" "${flow_uci:-unset}"
test -n "$dp"
test -n "$ct"
test "$queue_pid" = "$dp"
test "$rules" -gt 0
test "$flow_rules" -eq 0
test "$dp_release" = "$ct_release"
test "$dp_wire" = "$ct_wire"
case "$flow_uci" in 1|on|true|yes) exit 1 ;; esac
REMOTE
)

read_field() {
    local data=$1 key=$2
    sed -n "s/^$key=//p" <<<"$data" | head -n 1
}

say "Сверяю релиз контроллера перед сборкой…"
CONTROLLER_VERSION=$(ssh_do '/opt/sbin/d2kc --version')
if [[ "$CONTROLLER_VERSION" =~ ^d2kc\ release=([A-Za-z0-9._-]+)\ wire=([0-9]+)$ ]]; then
    RELEASE_ID=${BASH_REMATCH[1]}
    EXPECTED_WIRE=${BASH_REMATCH[2]}
else
    fail "не удалось прочитать версию d2kc: $CONTROLLER_VERSION"
fi
say "Согласованный релиз: $RELEASE_ID, wire=$EXPECTED_WIRE"

cleanup_remote() {
    ssh_do "rm -f '$REMOTE_NEW' '$REMOTE_OLD'; test ! -e '$REMOTE_NEW' -a ! -e '$REMOTE_OLD'" \
        >/dev/null 2>&1
}

rollback() {
    local live_hash restore_hash
    say "Проверяю автоматический откат…"
    live_hash=$(ssh_do "sha256sum /opt/sbin/d2kd 2>/dev/null | awk '{print \$1}'" 2>/dev/null || true)
    if [[ "$live_hash" != "$OLD_HASH" ]]; then
        copy_to_router "$BACKUP" "$REMOTE_OLD" || return 1
        restore_hash=$(sha256sum "$BACKUP" | awk '{print $1}')
        ssh_do "set -eu; test \"\$(sha256sum '$REMOTE_OLD' | awk '{print \$1}')\" = '$restore_hash'; chmod 0755 '$REMOTE_OLD'; mv -f '$REMOTE_OLD' /opt/sbin/d2kd; /opt/etc/init.d/S99d2k engine-restart" || return 1
    fi
    live_hash=$(ssh_do "sha256sum /opt/sbin/d2kd 2>/dev/null | awk '{print \$1}'" 2>/dev/null || true)
    [[ "$live_hash" == "$OLD_HASH" ]] || return 1
    ssh_do '/opt/etc/init.d/S99d2k status' || return 1
    say "Откат проверен: на роутере исходный datapath."
}

on_exit() {
    local rc=$?
    trap - EXIT
    if [[ "$SUCCESS" -eq 0 && "$DEPLOY_STARTED" -eq 1 ]]; then
        if ! rollback; then
            say "ОТКАТ НЕ УДАЛСЯ. Резервная копия на ПК: $BACKUP" >&2
            rc=1
        fi
    fi
    if [[ "$DEPLOY_STARTED" -eq 1 ]]; then
        if ! cleanup_remote; then
            say "Не удалось подтвердить удаление временных файлов роутера." >&2
            rc=1
        fi
    fi
    exit "$rc"
}
trap on_exit EXIT

say "Сборка только datapath для aarch64-linux-musl…"
make -C "$ROOT/datapath" d2kd-linux-arm64 \
    ARCH=arm64 TARGET=aarch64-linux-musl TARGET_FLAGS= \
    BUILDDIR="$BUILD_DIR" ZIG="$ZIG_BIN" RELEASE_ID="$RELEASE_ID"
[[ -s "$NEW_BIN" ]] || fail "сборка не создала $NEW_BIN"
NEW_HASH=$(sha256sum "$NEW_BIN" | awk '{print $1}')
say "Новый datapath SHA-256: $NEW_HASH"

say "Читаю состояние роутера (службы, NFQUEUE rules, flow offloading)…"
PRE=$(ssh_do "$REMOTE_SNAPSHOT")
printf '%s\n' "$PRE"
PRE_DP=$(read_field "$PRE" D2KD_PID)
PRE_RULES=$(read_field "$PRE" QUEUE_RULES)
PRE_RELEASE=$(read_field "$PRE" D2KC_RELEASE)
PRE_WIRE=$(read_field "$PRE" D2KC_WIRE)
[[ "$PRE_RELEASE" == "$RELEASE_ID" && "$PRE_WIRE" == "$EXPECTED_WIRE" ]] || fail "релиз контроллера изменился во время сборки"

say "Сохраняю текущий бинарник и проверяю копию…"
copy_from_router /opt/sbin/d2kd "$BACKUP"
chmod 0600 "$BACKUP"
OLD_HASH=$(sha256sum "$BACKUP" | awk '{print $1}')
LIVE_HASH=$(ssh_do "sha256sum /opt/sbin/d2kd | awk '{print \$1}'")
[[ "$LIVE_HASH" == "$OLD_HASH" ]] || fail "бинарник роутера изменился при резервном копировании"
say "Исходный datapath SHA-256: $OLD_HASH"

say "Передаю новый бинарник во временный файл на роутере…"
DEPLOY_STARTED=1
copy_to_router "$NEW_BIN" "$REMOTE_NEW"
ssh_do "set -eu; test \"\$(sha256sum '$REMOTE_NEW' | awk '{print \$1}')\" = '$NEW_HASH'; chmod 0755 '$REMOTE_NEW'; test \"\$(uname -m)\" = aarch64"
STAGE_VERSION=$(ssh_do "$REMOTE_NEW --version")
[[ "$STAGE_VERSION" == "d2kd release=$RELEASE_ID wire=$EXPECTED_WIRE" ]] || fail "собранный datapath не совпадает с релизом контроллера"

say "Атомарно заменяю /opt/sbin/d2kd и перезапускаю только движок…"
ssh_do "mv -f '$REMOTE_NEW' /opt/sbin/d2kd"
ssh_do '/opt/etc/init.d/S99d2k engine-restart'

say "Проверяю datapath, контроллер, очередь и неизменность firewall-счётчика правил…"
POST=
POST_OK=0
for attempt in {1..30}; do
    if POST=$(ssh_do "$REMOTE_SNAPSHOT"); then
        POST_OK=1
        break
    fi
    sleep 1
done
if [[ "$POST_OK" -ne 1 ]]; then
    printf '%s\n' "$POST"
    fail "роутер не прошёл проверку после перезапуска"
fi
printf '%s\n' "$POST"
POST_DP=$(read_field "$POST" D2KD_PID)
POST_RULES=$(read_field "$POST" QUEUE_RULES)
POST_RELEASE=$(read_field "$POST" D2KD_RELEASE)
POST_WIRE=$(read_field "$POST" D2KD_WIRE)
POST_HASH=$(ssh_do "sha256sum /opt/sbin/d2kd | awk '{print \$1}'")
[[ "$POST_HASH" == "$NEW_HASH" ]] || fail "на роутере не запущен собранный бинарник"
[[ "$POST_RELEASE" == "$RELEASE_ID" && "$POST_WIRE" == "$EXPECTED_WIRE" ]] || fail "запущенный datapath не совместим с контроллером"
[[ -n "$POST_DP" && "$POST_DP" != "$PRE_DP" ]] || fail "datapath не получил новый процесс после рестарта"
[[ "$POST_RULES" == "$PRE_RULES" ]] || fail "изменилось количество NFQUEUE правил"
ssh_do '/opt/etc/init.d/S99d2k status'

say "Удаляю и проверяю временные файлы на роутере…"
cleanup_remote || fail "не удалось очистить временные файлы на роутере"
SUCCESS=1
say "ROUTER TEST PASS: datapath обновлён, d2kc жив, очередь привязана службой; NFQUEUE rules и flow offloading не изменены."
say "Резервная копия и журнал оставлены на ПК: $RUN_DIR"
