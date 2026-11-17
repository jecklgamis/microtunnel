#!/usr/bin/env bash
# Run microtunnel natively on macOS: builds ./microtunnel for this Mac if needed,
# then starts it with sudo (creating a utun device requires root).
# Usage: ./scripts/run-macos.sh <config.yaml>
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
    echo "This script is for macOS. On Linux use scripts/run-peer-1.sh etc." >&2
    exit 1
fi
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <config.yaml>" >&2
    echo "See config/peer-macos.yaml for a template (needs interface: utun and tunnel_address)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
CONFIG="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

if [[ ! -x "${ROOT}/microtunnel" ]] || ! "${ROOT}/microtunnel" -version >/dev/null 2>&1; then
    (cd "${ROOT}" && make build)
fi
exec sudo "${ROOT}/microtunnel" -c "${CONFIG}"
