#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 2 || "$2" != /* || -e "$2" || -e "$2.sha256" ]]; then
  printf '%s\n' 'Use bash deploy/package.sh <git revision> <new absolute archive path>.' >&2
  exit 1
fi
commit="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --verify --end-of-options "$1^{commit}")"
repo="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
archive="$2"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/rookstride-web-release.XXXXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

git -C "$repo" archive "$commit" projects/rookstride/web | tar -xf - -C "$workspace"
bash "$workspace/projects/rookstride/web/deploy/package-source.sh" \
  "$workspace/projects/rookstride/web" "$commit" "$archive"
