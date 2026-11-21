"""Ubuntu single-server eligibility, separate from deployment acceptance.

Keep the gateway/scripts copy byte-identical. A future release can be assessed
without editing a version allowlist; successful probes do not certify its VPNs.
"""
import json
import platform
import re
from pathlib import Path

BASELINE=(22,4)
RELEASE_MATRIX=('22.04','24.04','26.04','26.10')
REQUIRED=('/usr/bin/python3','/usr/bin/apt-get','/usr/bin/dpkg','/usr/bin/systemctl')

def assess(root=Path('/')):
    root=Path(root)
    release=dict(line.split('=',1) for line in (root/'etc/os-release').read_text().splitlines() if '=' in line)
    identity=release.get('ID','').strip('"\'')
    version=release.get('VERSION_ID','').strip('"\'')
    match=re.fullmatch(r'(\d{2})\.(\d{2})(?:\.\d+)?',version)
    errors=[]
    if identity!='ubuntu' or not match or tuple(map(int,match.groups()))<BASELINE:
        errors.append('Use Ubuntu 22.04 or newer with apt and systemd')
    for command in REQUIRED:
        path=root/command.lstrip('/')
        if not path.is_file():errors.append('Required server component is missing: '+Path(command).name)
    if not (root/'run/systemd/system').is_dir():errors.append('A running systemd VPS is required')
    return {'eligible':not errors,'version':version,'errors':errors,
            'release_matrix':version in RELEASE_MATRIX,
            'assessment':'prerequisites only; deployment acceptance is recorded separately'}

def require(root=Path('/')):
    result=assess(root)
    if result['errors']:raise ValueError('; '.join(result['errors']))
    if platform.machine() not in ('x86_64','aarch64'):
        raise ValueError('This installer needs an x86_64 or aarch64 VPS')
    return result

if __name__=='__main__':
    try:print(json.dumps(require()))
    except (OSError,ValueError) as error:raise SystemExit(str(error))
