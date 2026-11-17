#!/usr/bin/env bash
# End-to-end test of the admin API and the enrollment service, with real TUN
# devices in Docker:
#
#   1. a relay with admin_socket + public_endpoint, and an empty peers_dir
#   2. `peer add carol -generate` through the ADMIN SOCKET (relay allocates the IP)
#   3. the enrollment service runs beside the relay; a join token is created and
#      dave runs `microtunnel join` (key generated on dave, enrolled over HTTP)
#   4. carol and dave ping each other through the relay
#   5. `peer list` shows live state; a spent token cannot be reused
#   6. `peer remove carol` through the socket cuts her off at once; the relay never restarted
#
# Needs Docker and the image from `make image` (override with IMAGE=...).
set -euo pipefail

IMAGE=${IMAGE:-microtunnel-peer:latest}
NET=mt-enr-net
P=mt-enr
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/build/enroll-test"
BIN=/microtunnel/microtunnel
SOCK=/tmp/admin.sock   # container-local: a bind-mounted host dir (Docker Desktop on Mac) cannot hold a chmod-able socket

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
relay_log() { docker logs "$P-relay" 2>&1; }
mt() { docker exec "$P-relay" "$BIN" "$@"; }                       # CLI inside the relay container
dk() { docker run --rm -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" "$@"; }

cleanup() {
  docker rm -f "$P-relay" "$P-carol" "$P-dave" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker run --rm -v "$ROOT/build:/b" --entrypoint rm "$IMAGE" -rf /b/enroll-test >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK/peers.d"
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
relay_says() { relay_log | grep -q "$1"; }
ping_ok() { docker exec "$P-$1" ping -c1 -W1 "$2"; }
ping_dead() { ! docker exec "$P-$1" ping -c2 -W1 "$2"; }

step "relay with an admin socket and an empty peers_dir"
dk keygen relay -dir /data >/dev/null
cat >"$WORK/relay.yaml" <<YAML
interface: microtunnel0
port: 5040
private_key_file: /data/relay.key
pre_shared_key: enroll-test-psk
tunnel_address: 10.9.0.1/24
peers_dir: /data/peers.d
admin_socket: $SOCK
public_endpoint: $P-relay:5040
keepalive_interval: 5
YAML
start relay /data /data/relay.yaml
wait_for "admin API" 20 relay_says "Admin API listening"
STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")
mt peer list -socket "$SOCK" | head -2

step "carol: peer add -generate through the admin socket"
mt peer add carol -socket "$SOCK" -generate -key-dir /data/carol | head -3
relay_says "Admin API: registered peer carol" || fail "relay did not log the registration"
start carol /data/carol /data/carol/carol.yaml
wait_for "carol to reach the relay" 40 ping_ok carol 10.9.0.1
echo "carol -> relay: OK"

step "enrollment service beside the relay, then a self-service join for dave"
docker exec -d "$P-relay" "$BIN" enroll serve -socket "$SOCK" -tokens /data/tokens -insecure-http -listen :8443
wait_for "enrollment service" 20 docker run --rm --network "$NET" --entrypoint curl "$IMAGE" -fsS "http://$P-relay:8443/healthz"
TOKEN_OUT=$(mt enroll token create -tokens /data/tokens -name dave -ttl 10m)
TOKEN=$(echo "$TOKEN_OUT" | grep -o 'mt1\.[0-9a-f]\{16\}\.[A-Za-z0-9_-]*' | head -1)
[ -n "$TOKEN" ] || fail "no token printed"
T0=$SECONDS
docker run --rm --network "$NET" -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" \
  join "http://$P-relay:8443" -token "$TOKEN" -dir /data/dave -allow-http
[ -f "$WORK/dave/dave.key" ] && [ -f "$WORK/dave/dave.yaml" ] || fail "join did not write dave's files"
grep -q "tunnel_address: 10.9.0.3/24" "$WORK/dave/dave.yaml" || fail "dave did not get 10.9.0.3"
start dave /data/dave /data/dave/dave.yaml
wait_for "dave to reach the relay" 40 ping_ok dave 10.9.0.1
echo "dave enrolled and connected $((SECONDS - T0))s after the token was used"

step "carol <-> dave through the relay"
wait_for "carol to reach dave (10.9.0.3)" 20 ping_ok carol 10.9.0.3
wait_for "dave to reach carol (10.9.0.2)" 20 ping_ok dave 10.9.0.2
echo "carol <-> dave: OK"

step "live state, and a spent token"
LIST=$(mt peer list -socket "$SOCK")
echo "$LIST"
[ "$(echo "$LIST" | grep -c connected)" = 2 ] || fail "peer list should show both peers connected"
if docker run --rm --network "$NET" -v "$WORK:/data" --entrypoint "$BIN" "$IMAGE" \
  join "http://$P-relay:8443" -token "$TOKEN" -dir /data/dave2 -allow-http >/dev/null 2>&1; then
  fail "a spent token was accepted twice"
fi
[ ! -e "$WORK/dave2/dave.key" ] || fail "a failed join left a key behind"
echo "spent token rejected: OK"

step "peer remove carol through the socket"
mt peer remove carol -socket "$SOCK"
wait_for "carol to be cut off" 15 ping_dead carol 10.9.0.1
ping_dead dave 10.9.0.2 || fail "dave can still reach removed carol"
ping_ok dave 10.9.0.1 >/dev/null || fail "dave lost the relay when carol was removed"
echo "carol cut off; dave unaffected: OK"

step "the relay never restarted"
[ "$(docker inspect -f '{{.State.StartedAt}}' "$P-relay")" = "$STARTED" ] || fail "relay container restarted"
[ "$(relay_log | grep -c 'worker(s)')" = 1 ] || fail "relay process started more than once"
echo "relay uptime continuous: OK"

printf '\n=== Admin API + enrollment test passed ===\n'
