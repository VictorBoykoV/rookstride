#!/usr/bin/env python3
"""Explicit, reviewed OS replacement. Never called by a VPN reset or fallback.

Initial adapter: one local system disk, GRUB, full x86_64/ARM64 Ubuntu VM.
Vendored upstream boot/network adapter is patched deterministically, never fetched
as floating root code. Inputs arrive on stdin; logs/status never include secrets.
"""
import base64,hashlib,json,os,re,secrets,shutil,subprocess,sys,time,urllib.request,tarfile
from pathlib import Path
BASE=Path('/var/lib/rookstride-reinstall')
VERSIONS={'22.04':'jammy','24.04':'noble','26.04':'resolute'}
CONFIRM='WIPE SERVER AND REINSTALL UBUNTU'

def call(args,timeout=30,check=True,**kw):
    result=subprocess.run(args,text=True,capture_output=True,timeout=timeout,**kw)
    if check and result.returncode:raise ValueError('A required server check failed: '+args[0])
    return result

def atomic(path,value):
    temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(value));temporary.chmod(0o600);temporary.replace(path)

def inspect():
    if os.geteuid()!=0:raise ValueError('OS reinstall requires root administrator access')
    distro=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if distro.get('ID','').strip('"')!='ubuntu':raise ValueError('This reinstall adapter currently starts from Ubuntu')
    virt=call(['systemd-detect-virt'],check=False).stdout.strip()
    if virt in ('lxc','openvz','docker','podman','systemd-nspawn','wsl','proot') or virt not in ('kvm','qemu','vmware','microsoft','apple','oracle','xen','amazon','google','vm-other'):raise ValueError('This server needs its hosting provider’s rebuild tools; a full supported virtual machine is required')
    arch=call(['uname','-m']).stdout.strip()
    if arch not in ('x86_64','aarch64'):raise ValueError('Use an x86_64 or ARM64 VPS')
    memory=int(re.search(r'MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text())[1])
    if memory<700000:raise ValueError('At least 700 MB of RAM is needed for this reinstall method')
    root=call(['findmnt','-n','-o','SOURCE','/']).stdout.strip()
    ancestors=json.loads(call(['lsblk','-J','-b','-s','-o','PATH,TYPE,SIZE,PTUUID',root]).stdout)['blockdevices']
    def walk(rows):
        for row in rows:
            yield row
            yield from walk(row.get('children',[]))
    rows=list(walk(ancestors));disks={r['path']:r for r in rows if r['type']=='disk'}
    if len(disks)!=1 or any(r['type'] not in ('lvm','part','disk') for r in rows):raise ValueError('The system disk layout needs a provider rebuild: encrypted, RAID or multiple-disk roots are not supported')
    disk=next(iter(disks.values()));all_disks=json.loads(call(['lsblk','-J','-d','-b','-o','PATH,TYPE,SIZE,RO']).stdout)['blockdevices']
    if len([r for r in all_disks if r['type']=='disk' and not r.get('ro')])!=1:raise ValueError('Extra disks are attached. Use provider rebuild tools to choose their scope safely')
    if int(disk['size'])<6*1024**3 or not disk.get('ptuuid'):raise ValueError('A uniquely identified system disk of at least 6 GB is required')
    if not shutil.which('grub-reboot') or not Path('/boot/grub/grub.cfg').is_file():raise ValueError('A supported GRUB bootloader is required for SSH reinstall')
    if shutil.disk_usage('/').free<3*1024**3:raise ValueError('At least 3 GB of free space is needed to prepare the installer')
    network=json.loads(call(['ip','-j','-4','route','show','default']).stdout)
    routes=[r for r in network if r.get('gateway') and r.get('dev') and not r['dev'].startswith(('tun','wg','awg','docker','veth'))]
    if not routes or len({r['dev'] for r in routes})!=1:raise ValueError('The server needs a single clear primary network route')
    secureboot=list(Path('/sys/firmware/efi/efivars').glob('SecureBoot-*'))
    if any(f.read_bytes()[4:5]==b'\x01' for f in secureboot):raise ValueError('Secure Boot needs a provider-supported reinstall method')
    connection=os.environ.get('SSH_CONNECTION','').split()
    ssh_port=int(connection[3]) if len(connection)==4 and connection[3].isdigit() else 0
    if not 0<ssh_port<65536:
        config=call(['sshd','-T']).stdout;ports={int(m) for m in re.findall(r'^port ([0-9]+)$',config,re.M)}
        if len(ports)!=1:raise ValueError('The active SSH listening port cannot be identified safely')
        ssh_port=ports.pop()
    return dict(ssh_port=ssh_port,machine=hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),disk=disk['path'],disk_id=disk['ptuuid'],disk_bytes=int(disk['size']),arch=arch,version=distro.get('VERSION_ID','').strip('"'),network=routes,virtualization=virt,boot='EFI' if Path('/sys/firmware/efi').exists() else 'BIOS')

def scope_digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
def secure_base():
    if BASE.is_symlink():raise ValueError('Reinstall storage is not a trusted directory')
    BASE.mkdir(mode=0o700,exist_ok=True)
    if BASE.stat().st_uid!=0:raise ValueError('Reinstall storage is not owned by root')
    BASE.chmod(0o700)
def engine_update_guard():
    # The detached reinstall adapter is self-contained after copying its folder.
    # Do not depend on a VPN helper that this same job will eventually erase.
    root=Path('/var/lib/rookstride-engine-updates')
    if root.is_symlink():raise ValueError('Unexpected runtime operation directory')
    for path in root.glob('*/journal.json'):
        if path.is_symlink() or path.parent.is_symlink() or path.stat().st_uid!=0 or path.stat().st_size>2*1024*1024:raise ValueError('Runtime operation ownership cannot be verified')
        if json.loads(path.read_text()).get('state') not in ('accepted','rolled-back','cancelled','abandoned'):
            raise ValueError('Finish, roll back or explicitly abandon the runtime update before wiping Ubuntu')

def plan(req):
    engine_update_guard()
    version=req.get('version')
    if version not in VERSIONS:raise ValueError('Choose Ubuntu 22.04, 24.04 or 26.04 LTS')
    current=inspect();secure_base();existing=BASE/'current.json'
    if existing.exists():
        job=json.loads(existing.read_text());status=json.loads((BASE/job['job']/'status.json').read_text())
        if status['state'] not in ('failed','cancelled'):raise ValueError('An OS reinstall is already recorded. Check its progress before starting another')
    coordinator=req.get('paired_operation')
    if coordinator is not None and (not isinstance(coordinator,str) or not re.fullmatch('[a-f0-9]{32}',coordinator)):raise ValueError('Invalid paired maintenance operation')
    token=secrets.token_hex(32);value=dict(token=token,job=secrets.token_hex(16),version=version,scope=current,expires=time.time()+(86400 if coordinator else 900))
    if coordinator:value['paired_operation']=coordinator
    planned=BASE/('planned-'+value['job']);planned.mkdir(mode=0o700)
    key=planned/'ssh_host_ecdsa_key';call(['ssh-keygen','-q','-t','ecdsa','-b','256','-N','','-f',str(key)])
    blob=base64.b64decode(key.with_suffix('.pub').read_text().split()[1]);value['fingerprint']='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    atomic(BASE/'plan.json',value)
    return dict(token=token,job=value['job'],version=version,fingerprint=value['fingerprint'],scope=current,confirmation=CONFIRM,message='The selected system disk is replaced. All applications, VPNs, users, files and server settings on it are erased. Snapshots and provider backups are separate. Root access and the network are provisioned again. Expect SSH to go offline during installation.')

def start(req):
    engine_update_guard()
    secure_base();value=json.loads((BASE/'plan.json').read_text())
    if req.get('token')!=value['token'] or req.get('confirmation')!=CONFIRM or time.time()>value['expires']:raise ValueError('Review the OS reinstall again and confirm its full scope')
    if scope_digest(inspect())!=scope_digest(value['scope']):raise ValueError('The server or disk changed. Review again')
    if not isinstance(req.get('password'),str) or not req['password'] or '\x00' in req['password'] or '\n' in req['password']:raise ValueError('Supply the administrator password to provision on the new OS')
    job=value['job'];folder=BASE/job
    if folder.exists():return read_status(job)
    folder.mkdir(mode=0o700);source=Path(__file__).resolve().parent
    shutil.copytree(source,folder/'adapter',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    planned=BASE/('planned-'+job)
    for name in ('ssh_host_ecdsa_key','ssh_host_ecdsa_key.pub'):shutil.copy2(planned/name,folder/name)
    shutil.rmtree(planned);fingerprint=value['fingerprint']
    (folder/'password').write_text(req['password']);(folder/'password').chmod(0o600)
    value.pop('token');value['fingerprint']=fingerprint;value['ssh_port']=value['scope']['ssh_port']
    if not 0<value['ssh_port']<65536:raise ValueError('Invalid SSH port')
    atomic(folder/'request.json',value);atomic(folder/'status.json',dict(job=job,state='preparing',stage=0,phase='Verifying the Ubuntu image and preparing the boot installer',fingerprint=fingerprint,version=value['version']))
    atomic(BASE/'current.json',dict(job=job));(BASE/'plan.json').unlink()
    try:call(['systemd-run','--unit=rookstride-os-reinstall-'+job,'--property=Type=exec','--property=UMask=0077','python3',str(folder/'adapter/run.py'),'worker',job])
    except Exception:
        (folder/'password').unlink(missing_ok=True)
        status=read_status(job);status.update(state='failed',phase='The background installer could not start; the OS has not been rebooted');atomic(folder/'status.json',status)
        raise
    return read_status(job)

def read_status(job):
    if not re.fullmatch('[a-f0-9]{32}',job):raise ValueError('Invalid reinstall identifier')
    return json.loads((BASE/job/'status.json').read_text())
def download(url,target,limit):
    temporary=target.with_name(target.name+'.download')
    try:
        with urllib.request.urlopen(url,timeout=45) as response,temporary.open('wb') as out:
            total=0
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>limit:raise ValueError('The Ubuntu download exceeds its allowed size')
                out.write(chunk)
        temporary.chmod(0o600);temporary.replace(target)
    finally:temporary.unlink(missing_ok=True)
def replace_once(text,old,new):
    if text.count(old)!=1:raise ValueError('Pinned reinstall source no longer matches its reviewed adapter')
    return text.replace(old,new)

def sha256(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        while chunk:=source.read(1024*1024):digest.update(chunk)
    return digest.hexdigest()

def prepare_boot(folder,value):
    pins=json.loads((folder/'adapter/boot-pins.json').read_text())['architectures'][value['scope']['arch']]
    cache=BASE/'images';cache.mkdir(mode=0o700,exist_ok=True);archive=cache/(pins['sha256']+'.tar.gz')
    if not archive.exists():download(pins['url'],archive,pins['bytes'])
    if archive.stat().st_size!=pins['bytes'] or sha256(archive)!=pins['sha256']:raise ValueError('The temporary boot bundle failed its pinned integrity check')
    boot=folder/'boot';boot.mkdir(mode=0o700)
    wanted={'vmlinuz-virt':32*1024**2,'initramfs-virt':64*1024**2,'modloop-virt':192*1024**2}
    with tarfile.open(archive,'r:gz') as bundle:
        found={}
        for member in bundle.getmembers():
            name=Path(member.name).name
            if name not in wanted:continue
            if name in found or not member.isfile() or not 0<member.size<wanted[name]:raise ValueError('Unexpected boot bundle layout')
            with bundle.extractfile(member) as source,(boot/name).open('wb') as out:shutil.copyfileobj(source,out)
            found[name]=True
        if set(found)!=set(wanted):raise ValueError('The pinned boot bundle is incomplete')
    apk=pins['dhcpcd'];download(apk['url'],boot/'dhcpcd.apk',apk['bytes'])
    if sha256(boot/'dhcpcd.apk')!=apk['sha256']:raise ValueError('The pinned installer network helper changed')
    return boot

def patched_vendor(folder,value,image_url,image_sha):
    vendor=folder/'adapter/vendor';pins=json.loads((folder/'adapter/upstream.json').read_text())
    for name,digest in pins['files'].items():
        if hashlib.sha256((vendor/name).read_bytes()).hexdigest()!=digest:raise ValueError('Reinstall source integrity check failed')
    ssh_port=int(value.get('ssh_port',22))
    if not 0<ssh_port<65536:raise ValueError('Invalid installer SSH port')
    revision=pins['revision'];script=(vendor/'reinstall.sh').read_text()
    script=script.replace('https://raw.githubusercontent.com/bin456789/reinstall/main','https://raw.githubusercontent.com/bin456789/reinstall/'+revision).replace('https://cnb.cool/bin456789/reinstall/-/git/raw/main','https://raw.githubusercontent.com/bin456789/reinstall/'+revision)
    script=script.replace('command curl --insecure','command curl').replace('http://dl-cdn.alpinelinux.org/','https://dl-cdn.alpinelinux.org/').replace('http://mirror.nju.edu.cn/','https://mirror.nju.edu.cn/')
    script=replace_once(script,'    alpine_ver_for_trans=$(get_latest_distro_releasever alpine)','    alpine_ver_for_trans=3.24')
    script=replace_once(script,'        is_virt && flavour=virt || flavour=lts','        flavour=virt # Full VMs only; pinned boot assets')
    script=script.replace('curl -Lo /reinstall-vmlinuz $nextos_vmlinuz','cp "$ROOK_BOOT/vmlinuz-virt" /reinstall-vmlinuz').replace('curl -Lo /reinstall-initrd $nextos_initrd','cp "$ROOK_BOOT/initramfs-virt" /reinstall-initrd')
    for helper in ('fix-eth-name.sh','fix-eth-name.service','get-xda.sh','ttys.sh','get-frpc-url.sh','frpc.service'):
        script=script.replace('curl -LO "$confhome/'+helper+'"','cp "$ROOK_ADAPTER/'+helper+'" .')
    script=script.replace('curl -L $confhome/ttys.sh | sh -s "console="','sh "$ROOK_ADAPTER/ttys.sh" "console="')
    first=script.index('download_and_extract_apk() {');last=script.index('\ninstall_grub_win() {',first)
    script=script[:first]+'''download_and_extract_apk() {
    [ "$2" = dhcpcd ] || error_and_exit "Unpinned boot package"
    install_pkg tar xz
    tar xzf "$ROOK_BOOT/dhcpcd.apk" -C "$3"
}
'''+script[last:]
    script=replace_once(script,'        done\nEOF\n\n    # 判断云镜像','''        done
        # Provision the identity before OpenRC can start any SSH listener.
        mkdir -p \\$sysroot/etc/ssh
        cp \\$sysroot/configs/rook/ssh_host_ecdsa_key* \\$sysroot/etc/ssh/
        chmod 600 \\$sysroot/etc/ssh/ssh_host_ecdsa_key
        printf 'HostKey /etc/ssh/ssh_host_ecdsa_key\\nPermitRootLogin yes\\nPasswordAuthentication yes\\n' >>\\$sysroot/etc/ssh/sshd_config
        printf '%s\\n' \"root:\\$(cat \\$sysroot/configs/password-linux-sha512)\" | chroot \\$sysroot /bin/busybox chpasswd -e
        # Already verified from the pinned versioned boot bundle.
        mv \\$sysroot/configs/rook/modloop-virt \\$sysroot/lib/modloop-virt
        sed -i '/wget -P.*KOPT_modloop/c\\                return 1 # Rookstride refuses network module fallback' \\$sysroot/etc/init.d/modloop
        grep -q 'Rookstride refuses network module fallback' \\$sysroot/etc/init.d/modloop || exit 1
EOF

    # 判断云镜像''')
    script=replace_once(script,"PasswordAuthentication yes\\n' >>\\$sysroot/etc/ssh/sshd_config","PasswordAuthentication yes\\nPort "+str(ssh_port)+"\\n' >>\\$sysroot/etc/ssh/sshd_config")
    script=replace_once(script,'        password=$2\n        shift 2','        password=$(cat "$2")\n        shift 2')
    script=replace_once(script,'    curl -Lo $initrd_dir/trans.sh $confhome/trans.sh','    cp "$ROOK_ADAPTER/trans.sh" "$initrd_dir/trans.sh"')
    script=replace_once(script,'    curl -Lo $initrd_dir/initrd-network.sh $confhome/initrd-network.sh','    cp "$ROOK_ADAPTER/initrd-network.sh" "$initrd_dir/initrd-network.sh"')
    script=replace_once(script,'\n    mkdir -p $initrd_dir/configs\n','\n    mkdir -p $initrd_dir/configs\n    cp -r "$ROOK_CONFIGS" "$initrd_dir/configs/rook"\n')
    # Upstream user-facing summary must not print the administrator password.
    script='\n'.join((line[:len(line)-len(line.lstrip())]+':') if 'echo ' in line and '$password' in line else line for line in script.splitlines())+'\n'
    (vendor/'rook-reinstall.sh').write_text(script)
    trans=(vendor/'trans.sh').read_text()
    # No-COW is a Btrfs swap requirement, not an ext4 requirement. Some chattr
    # implementations return 1 for ext4; retain the later real swapon check.
    trans=replace_once(trans,'        chattr +C $swapfile 2>/dev/null','        chattr +C $swapfile 2>/dev/null || true')
    # The new Canonical system image is owned by this reinstall. Keep archive
    # authentication on TLS as well as APT signatures; do not rewrite the old OS.
    apt_setup=r'''    for rook_source in "$os_dir/etc/apt/sources.list" "$os_dir"/etc/apt/sources.list.d/*.list "$os_dir"/etc/apt/sources.list.d/*.sources; do
        [ -f "$rook_source" ] || continue
        sed -i 's@http://archive\.ubuntu\.com/ubuntu@https://archive.ubuntu.com/ubuntu@g;s@http://security\.ubuntu\.com/ubuntu@https://security.ubuntu.com/ubuntu@g;s@http://ports\.ubuntu\.com/ubuntu-ports@https://ports.ubuntu.com/ubuntu-ports@g' "$rook_source"
    done
'''
    trans=replace_once(trans,'    current_hash=$(cat $os_dir/etc/apt/sources.list',apt_setup+'    current_hash=$(cat $os_dir/etc/apt/sources.list')
    trans=replace_once(trans,'        chroot $os_dir apt-get update','        chroot "$os_dir" apt-get -o Acquire::Retries=3 -o Acquire::Languages=none -o Acquire::https::No-Cache=true update')

    failure=json.dumps(dict(job=value['job'],state='failed',phase='The temporary Ubuntu installer stopped. Check its private log or your provider console before resuming.'),separators=(',',':'))
    trans=replace_once(trans,'error_and_exit() {\n    error "$@"',"error_and_exit() {\n    printf '%s\\n' '"+failure+"' >/etc/rookstride-reinstall-error.json || true\n    chmod 600 /etc/rookstride-reinstall-error.json || true\n    error \"$@\"")
    trans=replace_once(trans,'download() {\n    local url=$1','''
download() {
    case "$1" in
        "$confhome"/*)
            local rook_rel=${1#"$confhome"/}
            case "$rook_rel" in /*|*..*) error_and_exit "Invalid bundled helper path" ;; esac
            [ -f "/configs/rook/vendor/$rook_rel" ] || error_and_exit "Missing bundled helper"
            mkdir -p "$(dirname "$2")"
            cp "/configs/rook/vendor/$rook_rel" "$2"
            return
            ;;
    esac
    local url=$1''')
    trans=replace_once(trans,'wget $confhome/ttys.sh -O- | sh -s $prefix','sh /configs/rook/vendor/ttys.sh $prefix')

    trans=replace_once(trans,'    qcow_file=/installer/cloud_image.qcow2','    qcow_file=/installer/cloud_image.qcow2')
    trans=replace_once(trans,'        download "$img" "$qcow_file"\n    fi\n}', '        download "$img" "$qcow_file"\n    fi\n    echo "'+image_sha+'  $qcow_file" | sha256sum -c - || error_and_exit "Ubuntu image integrity failed"\n}')
    trans=replace_once(trans,'\n        setup_web_if_enough_ram\n','\n        : # Rookstride progress is private over SSH; no public log viewer\n')
    # Set the future host key before temporary SSH starts and on the final Ubuntu.
    trans=replace_once(trans,'apk add openssh-server\nif is_need_change_ssh_port;', 'apk add openssh-server\ncp /configs/rook/ssh_host_ecdsa_key* /etc/ssh/\nchmod 600 /etc/ssh/ssh_host_ecdsa_key\nprintf \'HostKey /etc/ssh/ssh_host_ecdsa_key\\n\' >>/etc/ssh/sshd_config\nif is_need_change_ssh_port;')
    hook='''
    # Rookstride: the future identity was pinned over the original SSH session.
    test -f /os/etc/os-release || error_and_exit 'Missing Ubuntu target'
    cp /configs/rook/ssh_host_ecdsa_key* /os/etc/ssh/
    chmod 600 /os/etc/ssh/ssh_host_ecdsa_key
    mkdir -p /os/etc/ssh/sshd_config.d
    printf 'HostKey /etc/ssh/ssh_host_ecdsa_key\\n' >/os/etc/ssh/sshd_config.d/00-rook-host-identity.conf
    mkdir -p /os/etc/cloud/cloud.cfg.d
    printf 'ssh_deletekeys: false\\nssh_genkeytypes: []\\n' >/os/etc/cloud/cloud.cfg.d/99-rook-reinstall.cfg
    cp /configs/rook/result.json /os/etc/rookstride-reinstall-result.json
    chmod 600 /os/etc/rookstride-reinstall-result.json
'''
    trans=replace_once(trans,"    info 'done'",hook+"\n    info 'done'")
    (vendor/'trans.sh').write_text(trans)
    configs=folder/'configs';configs.mkdir(mode=0o700)
    for name in ('ssh_host_ecdsa_key','ssh_host_ecdsa_key.pub'):shutil.copy2(folder/name,configs/name)
    atomic(configs/'result.json',dict(job=value['job'],version=value['version'],state='complete',message='Ubuntu reinstalled; no VPNs have been installed yet'))
    return vendor,configs

def worker(job):
    folder=BASE/job;value=json.loads((folder/'request.json').read_text());status=read_status(job)
    def update(stage,phase,state='preparing'):
        status.update(stage=stage,phase=phase,state=state,updated=time.time());atomic(folder/'status.json',status)
    try:
        # Trust the distribution's cloud-image signing keyring, not a key from a mirror.
        if not Path('/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg').is_file():
            call(['apt-get','-o','DPkg::Lock::Timeout=180','update'],timeout=300)
            call(['apt-get','-o','DPkg::Lock::Timeout=180','install','-y','ubuntu-cloudimage-keyring'],timeout=300)
        codename=VERSIONS[value['version']];arch='amd64' if value['scope']['arch']=='x86_64' else 'arm64'
        parent='https://cloud-images.ubuntu.com/releases/'+codename+'/'
        with urllib.request.urlopen(parent,timeout=45) as response:index=response.read(2*1024*1024).decode('utf-8')
        builds=re.findall(r'href="(release-[0-9]{8}/)"',index)
        if not builds:raise ValueError('No immutable Ubuntu image release is available')
        base=parent+max(builds)
        name='ubuntu-'+value['version']+'-server-cloudimg-'+arch+'.img'
        download(base+'SHA256SUMS',folder/'SHA256SUMS',4*1024*1024);download(base+'SHA256SUMS.gpg',folder/'SHA256SUMS.gpg',16384)
        call(['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(folder/'SHA256SUMS.gpg'),str(folder/'SHA256SUMS')])
        matches=re.findall(r'^([a-f0-9]{64}) [ *]'+re.escape(name)+r'$',(folder/'SHA256SUMS').read_text(),re.M)
        if len(matches)!=1:raise ValueError('No verified Ubuntu image matches this architecture and version')
        image_sha=matches[0];update(1,'Downloading and verifying the Ubuntu system image')
        cache=BASE/'images';cache.mkdir(mode=0o700,exist_ok=True);image=cache/(image_sha+'.img')
        if not image.exists():
            download(base+name,image.with_suffix('.part'),2*1024**3);image.with_suffix('.part').replace(image)
        with image.open('rb') as f:
            digestor=hashlib.sha256()
            while chunk:=f.read(1024*1024):digestor.update(chunk)
            digest=digestor.hexdigest()
        if digest!=image_sha:raise ValueError('The Ubuntu image checksum did not match')
        update(2,'Verifying the pinned temporary boot environment')
        boot=prepare_boot(folder,value)
        vendor,configs=patched_vendor(folder,value,base+name,image_sha)
        shutil.copy2(boot/'modloop-virt',configs/'modloop-virt')
        shutil.copytree(vendor,configs/'vendor')
        call(['bash','-n',str(vendor/'rook-reinstall.sh')])
        update(2,'Preparing the temporary boot environment')
        with (folder/'prepare.log').open('w') as log:
            result=subprocess.run(['bash',str(vendor/'rook-reinstall.sh'),'ubuntu',value['version'],'--username','root','--password',str(folder/'password'),'--ssh-port',str(value['ssh_port']),'--img',base+name],env=dict(os.environ,ROOK_ADAPTER=str(vendor),ROOK_CONFIGS=str(configs),ROOK_BOOT=str(boot)),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=2700)
        (folder/'password').unlink(missing_ok=True)
        if result.returncode:raise ValueError('The boot installer could not be prepared. The existing OS has not been rebooted; inspect the private preparation log')
        update(3,'Rebooting into the Ubuntu installer; SSH will be temporarily unavailable','rebooting')
        call(['systemd-run','--unit=rookstride-os-reboot-'+job,'--on-active=8s','systemctl','reboot'])
    except Exception as e:
        rollback=folder/'adapter/vendor/rook-reinstall.sh'
        if rollback.is_file():
            try:call(['bash',str(rollback),'reset'],timeout=120)
            except Exception:pass
        (folder/'password').unlink(missing_ok=True);update(status.get('stage',0),str(e) if isinstance(e,ValueError) else 'OS preparation failed; the existing OS was not deliberately rebooted','failed')

def dispatch(req):
    if req.get('action')=='plan':return plan(req)
    if req.get('action')=='start':return start(req)
    if req.get('action')=='status':return read_status(req.get('job',''))
    raise ValueError('Unknown OS reinstall action')
if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)==3 and sys.argv[1]=='worker':worker(sys.argv[2])
    else:
        try:print(json.dumps(dict(ok=True,result=dispatch(json.load(sys.stdin)))))
        except Exception as e:print(json.dumps(dict(ok=False,error=str(e) if isinstance(e,ValueError) else 'OS reinstall could not complete this action')));sys.exit(1)
