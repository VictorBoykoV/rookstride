"""Policy for newly created VPN account passwords; never SSH or protocol keys."""
import sys

MINIMUM=1
MAXIMUM=127
MESSAGE='Use a nonempty printable VPN password of at most 127 UTF-8 bytes'

def validate(value):
    if (not isinstance(value,str) or not MINIMUM<=len(value)<=MAXIMUM or
        any(0xD800<=ord(c)<=0xDFFF for c in value) or len(value.encode('utf-8'))>127 or
        any(ord(c)<32 or 127<=ord(c)<=159 or ord(c) in (0x2028,0x2029) or 0xD800<=ord(c)<=0xDFFF for c in value)):
        raise ValueError(MESSAGE)
    return value

if __name__=='__main__':
    try:validate(sys.stdin.buffer.read(513).decode('utf-8'))
    except (ValueError,UnicodeError):print(MESSAGE,file=sys.stderr);raise SystemExit(1)
