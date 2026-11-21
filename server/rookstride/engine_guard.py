"""Installed owner helper guard for a pending reviewed runtime rollback."""
import json,os
from pathlib import Path

def require_idle(root=Path('/var/lib/rookstride-engine-updates')):
    if root.is_symlink():raise ValueError('Unexpected runtime operation directory')
    for path in root.glob('*/journal.json'):
        if path.is_symlink() or path.parent.is_symlink() or path.stat().st_uid!=os.geteuid() or path.stat().st_size>2*1024*1024:raise ValueError('Runtime operation ownership cannot be verified')
        value=json.loads(path.read_text())
        if value.get('state') in ('applying','apply-failed','verified','rolling-back','rollback-failed'):
            raise ValueError('Finish or roll back the reviewed runtime update before changing VPN users or settings')
