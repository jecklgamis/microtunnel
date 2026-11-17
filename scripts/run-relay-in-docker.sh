#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_ABS="${SCRIPT_DIR}/../config/relay.yaml"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# private_key_file from the YAML config (default: peer.key); no YAML/Python dependency needed.
KEY_CONTAINER=$(sed -n -E 's/^private_key_file:[[:space:]]*([^[:space:]#]+).*/\1/p' "${CONFIG_ABS}" | head -n 1)
KEY_CONTAINER="${KEY_CONTAINER:-peer.key}"
KEY_HOST="${CONFIG_DIR}/$(basename "$KEY_CONTAINER")"

docker network create microtunnel-net 2>/dev/null || true
docker rm -f microtunnel-relay 2>/dev/null || true
docker run \
  --name microtunnel-relay \
  --network microtunnel-net \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "${KEY_HOST}:${KEY_CONTAINER}:ro" \
  -v "${CONFIG_ABS}:/microtunnel/peer.yaml:ro" \
  -p 5040:5040/udp \
  -p 9901:9901 \
  -e PEER_IP="10.9.0.1/24" \
  -e ENVOY_UPSTREAM_HOST="127.0.0.1" \
  -e ENVOY_UPSTREAM_PORT="9901" \
  microtunnel-peer:latest
