"""Bounded OpenVPN status-v3 reader; active-session estimates, never billing."""
import hashlib
import datetime
import os
import re
import stat
import time

LIMIT = 1024 * 1024
MAX_COUNTER = (1 << 63) - 1


def daemon_time(value):
    # Docker emits RFC3339Nano. Python before 3.11 accepts only three or six
    # fractional digits; normalize precision without changing the daemon ID.
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z', value) if isinstance(value, str) else None
    if not match:
        raise ValueError('Invalid OpenVPN daemon generation')
    fraction = (match[2] or '').ljust(6, '0')[:6]
    return datetime.datetime.fromisoformat(match[1] + '.' + fraction + '+00:00').timestamp()


def integer(value):
    if not re.fullmatch(r'[0-9]{1,20}', value or ''):
        raise ValueError('Invalid OpenVPN counter')
    number = int(value)
    if number > MAX_COUNTER:
        raise ValueError('OpenVPN counter exceeds the display limit')
    return number


def parse(state, text, daemon, now=None):
    """Read named columns, so extra/reordered upstream fields stay compatible."""
    now = time.time() if now is None else now
    lines = text.splitlines()
    if not lines or lines[-1] != 'END' or not daemon:
        raise ValueError('OpenVPN statistics are incomplete')
    columns = None
    stamp = None
    peers = []
    seen = set()
    users = {u['login']: u for u in state['users'] if u.get('enabled', True)}
    rows = {name: dict(upload=0, download=0, sessions=0, generations=[], vpn_addresses=[])
            for name in users}
    for line in lines:
        fields = line.split('\t')
        if fields[0] == 'TIME':
            if stamp is not None or len(fields) != 3:
                raise ValueError('Invalid OpenVPN statistics time')
            stamp = integer(fields[2])
        elif fields[:2] == ['HEADER', 'CLIENT_LIST']:
            if columns is not None or len(set(fields[2:])) != len(fields[2:]):
                raise ValueError('Invalid OpenVPN statistics header')
            columns = fields[2:]
        elif fields[0] == 'CLIENT_LIST':
            peers.append(fields[1:])
    required = {'Common Name', 'Bytes Received', 'Bytes Sent', 'Connected Since (time_t)', 'Client ID'}
    if columns is None or not required.issubset(columns) or stamp is None or not -10 <= now - stamp <= 45 or stamp < int(daemon_time(daemon)):
        raise ValueError('OpenVPN statistics are unavailable or stale')
    for fields in peers:
        if len(fields) != len(columns):
            raise ValueError('OpenVPN statistics changed while reading')
        peer = dict(zip(columns, fields))
        user = peer['Common Name']
        if user not in users:
            continue  # Never expose unknown/revoked logins or public endpoints.
        ident = peer['Client ID']
        if not re.fullmatch(r'[0-9]{1,20}', ident) or ident in seen:
            raise ValueError('Invalid OpenVPN session identity')
        seen.add(ident)
        since = integer(peer['Connected Since (time_t)'])
        if since > stamp + 10:
            raise ValueError('Invalid OpenVPN connection time')
        row = rows[user]
        row['upload'] += integer(peer['Bytes Received'])
        row['download'] += integer(peer['Bytes Sent'])
        if max(row['upload'], row['download']) > MAX_COUNTER:
            raise ValueError('OpenVPN totals exceed the display limit')
        row['sessions'] += 1
        row['generations'].append(ident + ':' + str(since))
    result = []
    for user, row in rows.items():
        generation = hashlib.sha256((state['instance'] + ':' + daemon + ':' + user + ':' +
                                     ','.join(sorted(row.pop('generations')))).encode()).hexdigest()
        result.append(dict(user=user, **row, recent=row['sessions'] > 0,
                           counter_scope='active connection sessions', generation=generation))
    return result


def read(state, container, runtime):
    directory = runtime.directory('openvpn') / 'runtime'
    if directory.is_symlink():
        raise ValueError('Unexpected OpenVPN statistics directory')
    path = directory / 'status.csv'  # status-version 3 uses tabs despite this name.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_size > LIMIT or before.st_mtime + .000001 < daemon_time(container['State']['StartedAt']):
            raise ValueError('Unexpected OpenVPN statistics file')
        data = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(data) > LIMIT or (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
        raise ValueError('OpenVPN statistics changed while reading')
    return parse(state, data.decode('utf-8'), container['State']['StartedAt'])
