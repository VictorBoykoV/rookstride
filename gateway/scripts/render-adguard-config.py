#!/usr/bin/env python3
"""Render a fixed, validated AdGuard Home template without shell interpolation."""
from pathlib import Path
import sys

template, dns, pool, password_hash, output = sys.argv[1:]
if not password_hash.startswith(("$2a$", "$2b$", "$2y$")):
    raise SystemExit("Expected bcrypt password hash")
text = Path(template).read_text(encoding="utf-8")
for key, value in (("__DNS_IP__", dns), ("__CLIENT_POOL__", pool), ("__ADMIN_HASH__", password_hash)):
    if text.count(key) < 1:
        raise SystemExit(f"Missing template token {key}")
    text = text.replace(key, value)
Path(output).write_text(text, encoding="utf-8")
