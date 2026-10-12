#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/prepare-android.py
cd .tools/strongswan-source/src/frontends/android
if [[ $# -eq 0 ]]; then set -- assembleDebug; fi
./gradlew "$@" --console=plain
