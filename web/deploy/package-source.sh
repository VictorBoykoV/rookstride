#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 3 || ! -d "$1" || ! "$2" =~ ^[0-9a-f]{40}$ || "$3" != /* || -e "$3" || -e "$3.sha256" ]]; then
  printf '%s\n' 'Use bash deploy/package-source.sh <verified web source directory> <commit> <new absolute archive path>.' >&2
  exit 1
fi
commit="$2"
archive="$3"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/rookstride-web-build.XXXXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

cd "$1"
npm ci --no-audit --no-fund
mkdir -m 700 "$workspace/build-data" "$workspace/release"
build_secret="$(node --input-type=module -e 'import { randomBytes } from "node:crypto"; process.stdout.write(randomBytes(48).toString("hex"));')"
env -i PATH="$PATH" \
  NODE_OPTIONS="--max-old-space-size=1536" \
  NEXT_TELEMETRY_DISABLED=1 PAYLOAD_TELEMETRY_DISABLED=1 \
  ROOKSTRIDE_HOSTED_SITE=1 ROOKSTRIDE_DATA_DIR="$workspace/build-data" \
  PAYLOAD_SECRET="$build_secret" \
  node node_modules/next/dist/bin/next build --webpack

standalone=.next/standalone
release="$workspace/release"
cp -R "$standalone/server.js" "$standalone/package.json" "$standalone/node_modules" "$standalone/.next" "$release/"
cp -R public "$release/"
node deploy/stage-android-apk.mjs "$release/public"
cp -R .next/static "$release/.next/"
mkdir "$release/deploy"
cp -R deploy/migrations deploy/cms-state.mjs deploy/serve.mjs deploy/rookstride-web.service "$release/deploy/"

if [[ -n "$(find "$release" \( -name .git -o -name .private -o -name .env -o -name 'cms.sqlite*' -o -name payload-secret -o -name gateway-worker.mjs \) -print -quit)" ]]; then
  printf '%s\n' 'Unexpected private runtime files in the release tree.' >&2
  exit 1
fi
node --input-type=module - "$commit" "$release/RELEASE.json" <<'NODE'
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const [, , commit, output] = process.argv;
const lock = createHash("sha256").update(readFileSync("package-lock.json")).digest("hex");
const manifest = { commit, lock, platform: process.platform, arch: process.arch, node: process.version };
writeFileSync(output, JSON.stringify(manifest, null, 2) + "\n");
NODE
tar -czf "$workspace/site.tar.gz" -C "$release" .
(set -o noclobber; cat "$workspace/site.tar.gz" > "$archive")
node --input-type=module - "$archive" <<'NODE'
import { createHash } from "node:crypto";
import { createReadStream, writeFileSync } from "node:fs";
import { basename } from "node:path";
const path = process.argv[2];
const hash = createHash("sha256");
for await (const chunk of createReadStream(path)) hash.update(chunk);
writeFileSync(`${path}.sha256`, `${hash.digest("hex")}  ${basename(path)}\n`, { flag: "wx" });
NODE
