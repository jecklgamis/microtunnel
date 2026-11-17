#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_ABS="${SCRIPT_DIR}/../config/peer-1.yaml"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# private_key_file from the YAML config (default: peer.key); no YAML/Python dependency needed.
KEY_CONTAINER=$(sed -n -E 's/^private_key_file:[[:space:]]*([^[:space:]#]+).*/\1/p' "${CONFIG_ABS}" | head -n 1)
KEY_CONTAINER="${KEY_CONTAINER:-peer.key}"
KEY_HOST="${CONFIG_DIR}/$(basename "$KEY_CONTAINER")"

# config/peer-1.yaml's checked-in endpoint is a generic placeholder (for .deb/.rpm packaging);
# render a temp copy pointing at the relay's container name on the shared microtunnel-net network.
CONFIG_RENDERED="$(mktemp)"
trap 'rm -f "${CONFIG_RENDERED}"' EXIT
sed -E 's/^( *endpoint: ).*/\1microtunnel-relay:5040/' "${CONFIG_ABS}" > "${CONFIG_RENDERED}"

docker network create microtunnel-net 2>/dev/null || true
docker rm -f microtunnel-peer-1 2>/dev/null || true
docker run \
  --name microtunnel-peer-1 \
  --network microtunnel-net \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "${KEY_HOST}:${KEY_CONTAINER}:ro" \
  -v "${CONFIG_RENDERED}:/microtunnel/peer.yaml:ro" \
  -p 5042:5040/udp \
  -p 15042:15040 \
  -p 15052:15050 \
  -p 9902:9901 \
  -e PEER_IP="10.9.0.2/24" \
  -e ENVOY_UPSTREAM_HOST="10.9.0.3" \
  -e ENVOY_UPSTREAM_PORT="80" \
  microtunnel-peer:latest
