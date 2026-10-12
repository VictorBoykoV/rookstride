#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
sdk="${ROOKSTRIDE_SDK:-$PWD/.tools/sdk}"
bt="$sdk/build-tools/${ROOKSTRIDE_BUILD_TOOLS:-35.0.0}"
out="$PWD/.build/probe"
mkdir -p "$out/classes" "$out/dex"
"$JAVA_HOME/bin/javac" -source 8 -target 8 -classpath "$sdk/platforms/android-36/android.jar" -d "$out/classes" tests/probe/java/io/rookstride/probe/Main.java
"$bt/d8" --lib "$sdk/platforms/android-36/android.jar" --min-api 26 --output "$out/dex" "$out/classes/io/rookstride/probe/Main.class"
"$bt/aapt2" link -I "$sdk/platforms/android-36/android.jar" --manifest tests/probe/AndroidManifest.xml -o "$out/probe-unsigned.apk"
python3 - "$out" <<'PY'
import sys,zipfile
from pathlib import Path
p=Path(sys.argv[1])
with zipfile.ZipFile(p/'probe-unsigned.apk','a') as z:z.write(p/'dex/classes.dex','classes.dex')
PY
"$bt/zipalign" -f 4 "$out/probe-unsigned.apk" "$out/probe-aligned.apk"
"$bt/apksigner" sign --ks "$ROOKSTRIDE_KEYSTORE" --ks-key-alias rookstride --ks-pass env:ROOKSTRIDE_SIGNING_PASSWORD --out "$out/probe.apk" "$out/probe-aligned.apk"
