#!/usr/bin/env bash
# End-to-end test of dynamic peer management, with real TUN devices in Docker:
#
#   1. a relay starts with an EMPTY peers_dir
#   2. `microtunnel peer add alice -generate`  -> alice connects and pings the relay
#   3. `microtunnel peer add bob -public-key`  -> bob connects; alice <-> bob works through the relay
#   4. `microtunnel peer remove alice`         -> alice is cut off, bob is unaffected
#   5. the relay process never restarted (no restart, no signal, no downtime)
#
# Needs Docker and the image from `make image` (override with IMAGE=...).
set -euo pipefail

IMAGE=${IMAGE:-microtunnel-peer:latest}
NET=mt-dyn-net
P=mt-dyn
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/build/dyn-test"
BIN=/microtunnel/microtunnel

dk() { docker run --rm --user "$(id -u):$(id -g)" -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" "$@"; }
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
relay_log() { docker logs "$P-relay" 2>&1; }

cleanup() {
  docker rm -f "$P-relay" "$P-alice" "$P-bob" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker run --rm -v "$ROOT/build:/b" --entrypoint rm "$IMAGE" -rf /b/dyn-test >/dev/null 2>&1 || true
}
# Create build/ ourselves: if docker has to, it makes it root-owned on Linux and we could not write to it.
mkdir -p "$ROOT/build"
trap cleanup EXIT
cleanup
mkdir -p "$WORK/peers.d"
docker network create "$NET" >/dev/null

start_peer() { # name workdir config
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
relay_says() { relay_log | grep -q "$1"; }
ping_ok() { docker exec "$P-$1" ping -c1 -W1 "$2"; }
ping_dead() { ! docker exec "$P-$1" ping -c2 -W1 "$2"; }

step "relay starts with an empty peers_dir"
dk keygen relay -dir /data >/dev/null
cat >"$WORK/relay.yaml" <<YAML
interface: microtunnel0
port: 5040
private_key_file: /data/relay.key
pre_shared_key: dynamic-test-psk
tunnel_address: 10.9.0.1/24
peers_dir: /data/peers.d
keepalive_interval: 5
YAML
start_peer relay /data /data/relay.yaml
wait_for "relay to start watching peers_dir" 20 relay_says "Watching peers_dir"
STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")

step "peer add alice -generate (the CLI creates her key pair and config)"
dk peer add alice -c /data/relay.yaml -generate -key-dir /data/alice -endpoint "$P-relay:5040" | head -3
wait_for "relay to load alice" 15 relay_says "Peer added"
start_peer alice /data/alice /data/alice/alice.yaml
wait_for "alice to reach the relay (10.9.0.1)" 40 ping_ok alice 10.9.0.1
echo "alice -> relay: OK"

step "peer add bob -public-key (bob made his own key; the relay only learns the public half)"
BOB_PUB=$(dk keygen bob -dir /data/bob | sed -n 's/^public key: //p')
[ -n "$BOB_PUB" ] || fail "keygen printed no public key"
T0=$SECONDS
dk peer add bob -c /data/relay.yaml -public-key "$BOB_PUB" -endpoint "$P-relay:5040" |
  sed -n '/^Config for bob:/,$p' | tail -n +3 >"$WORK/bob/bob.yaml"
grep -q "tunnel_address: 10.9.0.3/24" "$WORK/bob/bob.yaml" || fail "bob did not get 10.9.0.3"
start_peer bob /data/bob /data/bob/bob.yaml
wait_for "bob to reach the relay" 40 ping_ok bob 10.9.0.1
CONNECT=$((SECONDS - T0))
echo "bob connected ${CONNECT}s after peer add"
[ "$CONNECT" -le 20 ] || fail "first connection took ${CONNECT}s (expected <= 20s)"
wait_for "alice to reach bob through the relay (10.9.0.3)" 20 ping_ok alice 10.9.0.3
wait_for "bob to reach alice through the relay (10.9.0.2)" 20 ping_ok bob 10.9.0.2
echo "alice <-> bob via relay: OK"

step "peer remove alice"
dk peer remove alice -c /data/relay.yaml
wait_for "relay to drop alice" 15 relay_says "Peer removed"
wait_for "alice to be cut off" 20 ping_dead alice 10.9.0.1
ping_dead bob 10.9.0.2 || fail "bob can still reach removed alice"
ping_ok bob 10.9.0.1 >/dev/null || fail "bob lost the relay when alice was removed"
echo "alice cut off; bob unaffected: OK"

step "the relay never restarted"
[ "$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")" = "$STARTED" ] || fail "relay container restarted"
[ "$(relay_log | grep -c 'worker(s)')" = 1 ] || fail "relay process started more than once"
echo "relay uptime continuous: OK"

step "relay log (peer lifecycle)"
relay_log | grep -E "Peer (added|removed)|Peers reloaded|Peer connected" || true

printf '\n=== Dynamic peers test passed ===\n'
