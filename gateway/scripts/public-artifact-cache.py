"""Copy a pinned public archive from the shared cache without repairing it.

Exit 10 means absent; every existing unsafe/corrupt entry fails closed.
Only the recipe's fixed hash/size and its private temporary output are arguments.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


def copy_cached(digest, size, target, cache=Path('/var/cache/rookstride/artifacts'), uid=0, boundary=Path('/')):
    if not re.fullmatch('[0-9a-f]{64}', digest) or type(size) is not int or not 0 < size <= 32 * 1024 * 1024:
        raise ValueError('Public archive pin differs')
    current = boundary
    for part in cache.relative_to(boundary).parts:
        current /= part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != uid or observed.st_mode & 0o022:
            raise ValueError('Public archive directory needs review')
    try:
        fd = os.open(cache / digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size != size:
            raise ValueError('Public archive file needs review')
        raw = bytearray()
        while True:
            block = os.read(fd, min(65536, size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > size:
                raise ValueError('Public archive size differs')
        after = os.fstat(fd)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size):
            raise ValueError('Public archive checksum or size differs')
    finally:
        os.close(fd)
    # Caller owns an exclusive mktemp directory; refuse any existing output.
    output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(output, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return True


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4 or os.geteuid() != 0:
            raise ValueError('Pinned public archive arguments required')
        sys.exit(0 if copy_cached(sys.argv[1], int(sys.argv[2]), sys.argv[3]) else 10)
    except Exception:
        print('Existing public archive needs review; refusing download or overwrite.', file=sys.stderr)
        sys.exit(1)
