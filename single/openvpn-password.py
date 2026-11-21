#!/usr/bin/python3
"""OpenVPN via-file authentication. No shell, network, stdout or password logs."""
import json,sys
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/rookstride')
import access

def authenticate(path,accounts):
    try:
        raw=Path(path).read_bytes()
        if len(raw)>4096:return False
        rows=raw.decode('utf-8').splitlines()
        if len(rows)!=2:return False
        user=access.login(rows[0]);secret=access.password(rows[1])
        stored=json.loads(Path(accounts).read_text()).get(user,'')
        return access.verify(secret,stored)
    except (OSError,ValueError,UnicodeError,TypeError):return False

if __name__=='__main__':
    raise SystemExit(0 if len(sys.argv)==2 and authenticate(sys.argv[1],'/vpn/credentials.json') else 1)
