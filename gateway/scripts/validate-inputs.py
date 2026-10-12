#!/usr/bin/env python3
"""Fail before installing packages if endpoint or private ranges are unsafe."""
import ipaddress
import re
import sys

server, pool_text, sink_text, dns_text = sys.argv[1:]
try:
    address = ipaddress.ip_address(server)
except ValueError:
    if not (1 <= len(server) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
        for part in server.split(".")
    )):
        raise SystemExit("SERVER_ID must be a valid DNS hostname or public IPv4 address")
else:
    if address.version != 4 or not address.is_global:
        raise SystemExit("SERVER_ID must be a public IPv4 address")

try:
    pool = ipaddress.ip_network(pool_text, strict=True)
    sink = ipaddress.ip_network(sink_text, strict=True)
    dns = ipaddress.ip_address(dns_text)
except ValueError as exc:
    raise SystemExit(f"Invalid private IP input: {exc}") from exc
if pool.version != 4 or not pool.is_private or pool.prefixlen > 29:
    raise SystemExit("CLIENT_POOL must be a private IPv4 network with at least 8 addresses")
if sink.version != 6 or not sink.subnet_of(ipaddress.ip_network("fc00::/7")):
    raise SystemExit("IPV6_SINK_POOL must be a unique-local IPv6 network")
if dns.version != 4 or not dns.is_private or dns in pool:
    raise SystemExit("DNS_IP must be private IPv4 outside CLIENT_POOL")
