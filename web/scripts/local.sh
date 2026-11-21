#!/usr/bin/env bash
set -euo pipefail
web_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
local_node="$web_root/../../../.tools/web-node/node_modules/node/bin/node"
if [[ ! -x "$local_node" ]]; then local_node="$(command -v node)"; fi
exec "$local_node" "$web_root/scripts/run.mjs" "${1:-dev}"
