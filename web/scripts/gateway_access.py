#!/usr/bin/env python3
"""Inspect one installed standalone authority without dispatching SSH admin actions."""

from contextlib import closing
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time


METHODS = {
    "awg", "xray", "openvpn", "xhttp", "hysteria2", "outline",
    "shadowsocks", "trusttunnel", "naive",
}
ROLES = ("infrastructure", "user_manager", "viewer")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
SSH_CONFIG = "etc/ssh/sshd_config.d/80-rookstride-access.conf"
SUDO_CONFIG = "etc/sudoers.d/rookstride-access"
HELPER = "usr/local/sbin/rookstride-access"
CONFIG_MARKER = b"# Rookstride scoped administration v1\n"


def owned(path, uid, *, directory=False, private=False):
    metadata = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    mask = 0o077 if private else 0o022
    if not kind(metadata.st_mode) or metadata.st_uid != uid or metadata.st_mode & mask:
        raise ValueError("untrusted ownership")


def json_file(path, uid, maximum):
    owned(path.parent, uid, directory=True)
    owned(path, uid, private=True)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("oversized metadata")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("unexpected metadata")
    return value


def owned_instance(root, uid, address, method):
    if os.path.lexists(root / "etc/rookstride-pair/manifest.json"):
        raise ValueError("standalone protocol required")
    record = json_file(root / "var/lib/rookstride-web-gateway/protocol.json", uid, 4096)
    instance, job, bundle = (record.get(key, "") for key in ("instance", "job", "bundle"))
    if (record.get("method", "xray") != method or record.get("address") != address
            or not all(isinstance(item, str) for item in (instance, job, bundle))
            or not re.fullmatch(r"[0-9a-f]{32}", instance)
            or not re.fullmatch(r"[0-9a-f]{32}", job)
            or not re.fullmatch(r"[0-9a-f]{64}", bundle)):
        raise ValueError("changed protocol marker")
    state = root / "var/lib/rookstride-single"
    owned(state, uid, directory=True)
    owned(state / "jobs", uid, directory=True)
    installed = json_file(state / method / "state.json", uid, 262144)
    finished = json_file(state / "jobs" / job / "status.json", uid, 65536)
    if (installed.get("owner") != "rookstride-single-v1"
            or installed.get("server") != address or installed.get("protocol") != method
            or installed.get("instance") != instance or installed.get("pair")
            or installed.get("pair_dns") or installed.get("coexist_pair")
            or finished.get("state") != "complete" or finished.get("protocol") != method
            or finished.get("bundle") != bundle
            or finished.get("install_context", {}).get("instance") != instance):
        raise ValueError("changed protocol installation")
    return instance


def configured_marker(path, uid):
    owned(path.parent, uid, directory=True)
    owned(path, uid)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if stream.read(len(CONFIG_MARKER)) != CONFIG_MARKER:
            raise ValueError("unknown admin configuration")


def matching_counts(db, query, scope, *parameters):
    rows = db.execute(query, (*parameters, *scope))
    counts = dict(rows)
    if any(role not in ROLES or not 0 < count <= 4096 for role, count in counts.items()):
        raise ValueError("unsupported role inventory")
    return counts


SCOPE = """AND CASE json_extract(granted.value, '$.scope.kind')
    WHEN 'server' THEN json_extract(granted.value, '$.scope.id') = ?
    WHEN 'deployment' THEN json_extract(granted.value, '$.scope.id') = ?
    WHEN 'protocol' THEN json_extract(granted.value, '$.scope.id') = ?
    ELSE 0 END
    AND (json_type(granted.value, '$.scope.users') IS NULL
        OR json_extract(granted.value, '$.scope.users') IN ('own', 'all'))
    GROUP BY role"""

DEVICES = """SELECT json_extract(granted.value, '$.role') AS role, count(*)
FROM records AS device
JOIN records AS granted ON granted.kind='grant' AND granted.id=json_extract(device.value, '$.grant_id')
JOIN records AS credential ON credential.kind='credential' AND credential.id=json_extract(device.value, '$.account')
WHERE device.kind='device' AND json_extract(credential.value, '$.kind')='device'
    AND json_extract(credential.value, '$.device_id')=device.id
    AND json_type(device.value, '$.revoked')='false'
    AND json_type(granted.value, '$.revoked')='false'
    AND json_type(credential.value, '$.revoked')='false' """ + SCOPE

INVITATIONS = """SELECT json_extract(granted.value, '$.role') AS role, count(*)
FROM records AS granted
JOIN records AS credential ON credential.kind='credential' AND credential.id=json_extract(granted.value, '$.account')
WHERE granted.kind='invitation' AND json_extract(credential.value, '$.kind')='bootstrap'
    AND json_extract(credential.value, '$.invitation_id')=granted.id
    AND json_type(granted.value, '$.claimed_device')='null'
    AND json_type(granted.value, '$.revoked')='false'
    AND json_type(credential.value, '$.revoked')='false'
    AND json_type(granted.value, '$.expires')='integer' AND json_extract(granted.value, '$.expires') > ? """ + SCOPE


def authority_snapshot(root, db, uid, instance, method, now):
    row = db.execute("""SELECT json_extract(value, '$.server_id'),
        json_extract(value, '$.deployment_id'), json_extract(value, '$.revision'),
        json_type(value, '$.disabled') FROM records WHERE kind='meta' AND id='config'""").fetchone()
    if row is None:
        raise ValueError("unknown standalone authority")
    server, deployment, revision, disabled = row
    if (not all(isinstance(item, str) and ID.fullmatch(item) for item in (server, deployment))
            or type(revision) is not int or revision < 1 or disabled not in (None, "true", "false")):
        raise ValueError("unknown authority metadata")
    if db.execute("""SELECT 1 FROM records WHERE kind='peer'
        OR (kind='credential' AND json_extract(value, '$.kind')='peer')
        OR (kind='object' AND json_extract(value, '$.server_id') IS NOT ?)
        LIMIT 1""", (server,)).fetchone():
        raise ValueError("peer authority is outside standalone status")
    if disabled == "true":
        return {"state": "disabled"}
    configured_marker(root / SSH_CONFIG, uid)
    configured_marker(root / SUDO_CONFIG, uid)
    configured_helper = root / HELPER
    owned(configured_helper.parent, uid, directory=True)
    owned(configured_helper, uid)
    if not configured_helper.stat().st_mode & stat.S_IXUSR:
        raise ValueError("inactive admin configuration")
    object_id = "vpn-" + hashlib.sha256(f"{server}:{method}:{instance}".encode()).hexdigest()[:24]
    binding = db.execute("""SELECT json_extract(value, '$.kind'), json_extract(value, '$.id'),
        json_extract(value, '$.server_id'), json_extract(value, '$.deployment_id'),
        json_extract(value, '$.protocol'), json_extract(value, '$.instance')
        FROM records WHERE kind='object' AND id=?""", (object_id,)).fetchone()
    if binding is None:
        return {"state": "notRegistered"}
    if binding != ("protocol", object_id, server, deployment, method, instance):
        raise ValueError("changed authority object")
    scope = (server, deployment, object_id)
    devices = matching_counts(db, DEVICES, scope)
    invitations = matching_counts(db, INVITATIONS, scope, now)
    return {"state": "enabled", "roles": [
        {"role": role, "devices": devices.get(role, 0), "invitations": invitations.get(role, 0)}
        for role in ROLES
    ]}


def inspect(request, root=Path("/"), uid=0, now=None):
    if not isinstance(request, dict) or set(request) != {"address", "method"}:
        raise ValueError("invalid access request")
    address, method = request["address"], request["method"]
    if (not isinstance(address, str) or str(ipaddress.IPv4Address(address)) != address
            or not isinstance(method, str) or method not in METHODS):
        raise ValueError("invalid protocol target")
    instance = owned_instance(root, uid, address, method)
    directory = root / "var/lib/rookstride-access"
    if not any(os.path.lexists(item) for item in (directory, root / SSH_CONFIG, root / SUDO_CONFIG, root / HELPER)):
        return {"state": "notEnabled"}
    owned(directory, uid, directory=True, private=True)
    path = directory / "authority.sqlite"
    owned(path, uid, private=True)
    for suffix in ("-wal", "-shm"):
        companion = path.with_name(path.name + suffix)
        if os.path.lexists(companion):
            owned(companion, uid, private=True)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        result = authority_snapshot(root, db, uid, instance, method, int(time.time()) if now is None else now)
    if owned_instance(root, uid, address, method) != instance:
        raise ValueError("concurrent protocol replacement")
    return result


def main():
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise ValueError("owner session required")
        data = sys.stdin.buffer.read(513)
        if len(data) > 512:
            raise ValueError("oversized status request")
        result = inspect(json.loads(data))
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, sqlite3.Error):
        result = {"state": "unavailable"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
