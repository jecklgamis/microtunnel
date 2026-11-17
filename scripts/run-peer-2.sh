#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SCRIPT_DIR}/../microtunnel" -c "${SCRIPT_DIR}/../config/peer-2.yaml"
