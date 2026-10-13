#!/usr/bin/env bash
set -Eeuo pipefail

: "${ENTRY_HOST:?Set ENTRY_HOST}"
: "${EXIT_HOST:?Set EXIT_HOST}"

SSH_USER="${SSH_USER:-root}"
REPORT_DIR="${REPORT_DIR:-audit-reports}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

load_password() {
  local value_name="$1" file_name="$2" file value
  [[ -n "${!value_name:-}" ]] && return
  file="${!file_name:-}"
  [[ -n "$file" && -r "$file" ]] || {
    echo "Set $value_name or $file_name to a readable root-only file." >&2
    exit 1
  }
  if [[ -n "$(find "$file" -prune -perm /077 -print 2>/dev/null)" ]]; then
    echo "$file_name must not be accessible by group or other users." >&2
    exit 1
  fi
  IFS= read -r value < "$file"
  [[ -n "$value" ]] || { echo "$file_name is empty." >&2; exit 1; }
  printf -v "$value_name" '%s' "$value"
  export "$value_name"
}

load_password ENTRY_SSH_PASSWORD ENTRY_SSH_PASSWORD_FILE
load_password EXIT_SSH_PASSWORD EXIT_SSH_PASSWORD_FILE

python3 - "$ENTRY_HOST" "$EXIT_HOST" "$SSH_USER" <<'PY'
import re
import sys

entry, exit, user = sys.argv[1:]
host_re = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
if not host_re.fullmatch(entry) or not host_re.fullmatch(exit) or entry == exit:
    raise SystemExit("Hosts must be distinct IPv4 addresses or DNS names")
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", user):
    raise SystemExit("Invalid SSH_USER")
PY

for command in ssh sshpass python3; do
  command -v "$command" >/dev/null || { echo "Missing local command: $command" >&2; exit 1; }
done

install -d -m 700 "$REPORT_DIR"
SSHPASS="$ENTRY_SSH_PASSWORD" sshpass -e ssh +  -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 +  "$SSH_USER@$ENTRY_HOST" 'bash -s -- entry' +  < "$REPO_ROOT/scripts/audit-vps.sh" > "$REPORT_DIR/entry.txt"
SSHPASS="$EXIT_SSH_PASSWORD" sshpass -e ssh +  -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 +  "$SSH_USER@$EXIT_HOST" 'bash -s -- exit' +  < "$REPO_ROOT/scripts/audit-vps.sh" > "$REPORT_DIR/exit.txt"
chmod 600 "$REPORT_DIR/entry.txt" "$REPORT_DIR/exit.txt"

echo "Redacted reports written to $REPORT_DIR/entry.txt and $REPORT_DIR/exit.txt."
echo "Treat them as private operational metadata and delete them after review."
