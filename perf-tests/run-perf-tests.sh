#!/usr/bin/env bash
# Runs the resonate load test(s) in this directory through the tunnel:
# resonate -> peer-1 Envoy (:15052) -> tunnel -> relay -> peer-2 nginx.
# Requires `resonate` on PATH and the dockerized relay + peers running.
#
# Usage: ./perf-tests/run-perf-tests.sh [-- extra resonate flags, e.g. --dry-run]
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "${1:-}" = "--" ] && shift

for s in "$DIR"/*.yaml; do
  echo "=== $(basename "$s") ==="
  resonate run "$s" "$@"
done
