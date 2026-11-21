#!/usr/bin/env python3
"""Fetch hash-pinned worker toolchain and supplemental source; no server access."""
import argparse,hashlib,json,os,platform,shutil,tarfile,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.tools/native-engines'
PINS=json.loads((ROOT/'android/engines/routes/build-pins.json').read_text())

def download(record,path):
    def valid(p):return p.is_file() and not p.is_symlink() and p.stat().st_size==record['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==record['sha256']
    if valid(path):return
    path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.part')
    try:
        with urllib.request.urlopen(record['url'],timeout=120) as response,temporary.open('wb') as out:
            size=0
            while True:
                data=response.read(1024*1024)
                if not data:break
                size+=len(data)
                if size>record['bytes']:raise ValueError('Source download exceeds the pinned size')
                out.write(data)
        if not valid(temporary):raise ValueError('Worker source/toolchain checksum differs')
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--sources-only',action='store_true');args=parser.parse_args()
    for record in PINS['supplemental_sources']:download(record,CACHE/'route-sources'/record['path'])
    server=json.loads((ROOT/'single/routes-pins.json').read_text())['trusttunnel']['source']
    download(server,CACHE/'trusttunnel-server.tar.gz')
    if not args.sources_only:
        arch={'x86_64':'amd64','arm64':'arm64','aarch64':'arm64'}.get(platform.machine());host=platform.system().lower()+'-'+str(arch)
        if host not in PINS['host_sdks']:raise ValueError('Use a supported Linux/macOS build host')
        record=PINS['host_sdks'][host];archive=CACHE/('routes-'+PINS['go']+'-'+host+'.tar.gz');download(record,archive)
        sdk=CACHE/'go-sdk';stamp=sdk/'.rookstride-sdk'
        if sdk.is_symlink():raise ValueError('Unexpected toolchain link')
        if not stamp.is_file() or stamp.read_text()!=record['sha256']:
            with tempfile.TemporaryDirectory(prefix='routes-sdk-',dir=CACHE) as temporary:
                stage=Path(temporary)/'go';stage.mkdir()
                with tarfile.open(archive) as tar:
                    for member in tar.getmembers():
                        parts=Path(member.name).parts
                        if not parts or parts[0]!='go' or '..' in parts or Path(member.name).is_absolute() or member.issym() or member.islnk():raise ValueError('Unexpected Go archive member')
                        if not member.isfile():continue
                        out=stage/Path(*parts[1:]);out.parent.mkdir(parents=True,exist_ok=True)
                        with tar.extractfile(member) as source,out.open('wb') as target:shutil.copyfileobj(source,target)
                        out.chmod(member.mode&0o777)
                (stage/'.rookstride-sdk').write_text(record['sha256'])
                if sdk.exists():shutil.rmtree(sdk)
                os.replace(stage,sdk)
    print('Verified worker toolchain/source inputs')

if __name__=='__main__':main()
