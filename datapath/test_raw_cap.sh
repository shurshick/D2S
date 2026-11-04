#!/bin/sh
# Изолированный тест предела MTU; интерфейсы существуют только в namespace.
set -eu
cd "$(dirname "$0")"
[ -x ./test_raw_cap ] || { echo "test_raw_cap не собран: make test-raw-cap-linux" >&2; exit 2; }
exec unshare -n sh -eu -c '
  ip link set lo up
  ip link add d2slow type dummy
  ip link set d2slow mtu 1280 up
  ip link add d2sout type dummy
  ip link set d2sout mtu 1500 up
  ./test_raw_cap d2sout d2slow
'
