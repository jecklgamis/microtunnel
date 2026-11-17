#!/usr/bin/env bash
# End-to-end test of `microtunnel init relay` / `init peer`, with real TUN devices in Docker:
#
#   1. `init relay` writes a complete config; the relay starts from it as-is
#   2. two machines run `init peer` with only what the relay told them (address, key, PSK)
#   3. the admin registers each public key with `peer add`, learns the assigned address
#   4. each peer applies its address by rerunning `init peer -force` (the key is kept)
#   5. the peers connect and ping each other through the relay
#
# Needs Docker and the image from `make image` (override with IMAGE=...).
set -euo pipefail

IMAGE=${IMAGE:-microtunnel-peer:latest}
NET=mt-init-net
P=mt-init
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/build/init-test"
BIN=/microtunnel/microtunnel
SOCK=/tmp/admin.sock   # container-local (a bind-mounted host dir on Docker Desktop for Mac cannot hold a chmod-able socket)

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
dk() { docker run --rm -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" "$@"; }
mt() { docker exec "$P-relay" "$BIN" "$@"; }

cleanup() {
  docker rm -f "$P-relay" "$P-p1" "$P-p2" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker run --rm -v "$ROOT/build:/b" --entrypoint rm "$IMAGE" -rf /b/init-test >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"
docker network create "$NET" >/dev/null

start() { # name workdir config
  docker run -d --name "$P-$1" --network "$NET" --cap-add=NET_ADMIN --device=/dev/net/tun \
    -v "$WORK:/data" -w "$2" --entrypoint "$BIN" "$IMAGE" -c "$3" >/dev/null
}
wait_for() { # description timeout command...
  local what=$1 secs=$2
  shift 2
  for _ in $(seq "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out waiting for: $what"
}
ping_ok() { docker exec "$P-$1" ping -c1 -W1 "$2"; }

step "init relay"
OUT=$(dk init relay -dir /data/relay -endpoint "$P-relay:5040" -admin-socket "$SOCK")
echo "$OUT" | sed -n 1,8p
HINT=$(echo "$OUT" | grep 'MICROTUNNEL_PSK=')
PSK=$(echo "$HINT" | sed -n 's/.*MICROTUNNEL_PSK=\([0-9a-f]*\) .*/\1/p')
RELAY_KEY=$(echo "$HINT" | sed -n 's/.*-relay-key \([0-9a-f]*\).*/\1/p')
[ ${#PSK} = 64 ] && [ ${#RELAY_KEY} = 64 ] || fail "could not read the peer hint from init relay"
grep -q "tunnel_address: 10.9.0.1/24" "$WORK/relay/relay.yaml" || fail "relay config has no tunnel_address"
start relay /data /data/relay/relay.yaml
wait_for "relay to start" 20 sh -c "docker logs $P-relay 2>&1 | grep -q 'Admin API listening'"
STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")

join_peer() { # name
  local name=$1 pub ip
  step "init peer $name (no address yet)"
  pub=$(MICROTUNNEL_PSK=$PSK dk_env init peer -dir "/data/$name" -name "$name" -relay "$P-relay:5040" -relay-key "$RELAY_KEY" |
    sed -n 's/^  public key:  \([0-9a-f]*\)$/\1/p')
  [ ${#pub} = 64 ] || fail "init peer printed no public key"
  grep -q '^#tunnel_address:' "$WORK/$name/$name.yaml" || fail "expected a pending tunnel_address line"

  step "admin: peer add $name"
  ip=$(mt peer add "$name" -socket "$SOCK" -public-key "$pub" | sed -n "s|^Added peer \"$name\": \([0-9.]*\)/32.*|\1|p")
  [ -n "$ip" ] || fail "peer add did not report an address"
  echo "assigned $ip"

  step "init peer $name -address $ip/24 -force (key must be unchanged)"
  again=$(MICROTUNNEL_PSK=$PSK dk_env init peer -dir "/data/$name" -name "$name" -relay "$P-relay:5040" \
    -relay-key "$RELAY_KEY" -address "$ip/24" -force | sed -n 's/^  public key:  \([0-9a-f]*\)$/\1/p')
  [ "$again" = "$pub" ] || fail "the public key changed on rerun"
  grep -q "^tunnel_address: $ip/24" "$WORK/$name/$name.yaml" || fail "address not applied"
  start "$name" "/data/$name" "/data/$name/$name.yaml"
  wait_for "$name to reach the relay" 40 ping_ok "$name" 10.9.0.1
  echo "$name ($ip) -> relay: OK"
  eval "IP_$name=$ip"
}
dk_env() { docker run --rm -e MICROTUNNEL_PSK -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" "$@"; }

join_peer p1
join_peer p2

step "p1 <-> p2 through the relay"
wait_for "p1 to reach p2" 20 ping_ok p1 "$IP_p2"
wait_for "p2 to reach p1" 20 ping_ok p2 "$IP_p1"
echo "p1 <-> p2: OK"

step "an untouched refusal: init must not overwrite, and must keep the key"
if dk init relay -dir /data/relay >/dev/null 2>&1; then fail "a second init relay overwrote an existing config"; fi
[ "$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")" = "$STARTED" ] || fail "relay restarted"
echo "refused: OK"

printf '\n=== init test passed ===\n'
