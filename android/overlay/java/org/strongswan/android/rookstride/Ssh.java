package org.strongswan.android.rookstride;

import com.jcraft.jsch.*;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/** All commands are fixed application commands; user values travel as JSON stdin. */
public final class Ssh implements AutoCloseable {
    // Authentication can succeed before a small VPS schedules its first channel.
    private static final int CHANNEL_OPEN_TIMEOUT_MS=30_000;
    private static final java.util.concurrent.ScheduledThreadPoolExecutor ARTIFACT_TIMEOUT=new java.util.concurrent.ScheduledThreadPoolExecutor(1,r->{Thread t=new Thread(r,"rookstride-public-transfer");t.setDaemon(true);return t;});
    static {ARTIFACT_TIMEOUT.setRemoveOnCancelPolicy(true);}
    private static java.util.concurrent.ScheduledFuture<?> artifactTimeout(Channel channel){return ARTIFACT_TIMEOUT.schedule(()->channel.disconnect(),180,java.util.concurrent.TimeUnit.SECONDS);}
    public static volatile com.jcraft.jsch.SocketFactory socketFactory;
    public interface RuntimeSource { JSONObject metadata() throws Exception; InputStream open(String architecture) throws Exception; }
    public static volatile RuntimeSource runtimeSource;
    public static volatile ArtifactBridge.Source artifactSource;
    // Set only by a PairSsh holding these two already-pinned live sessions.
    Ssh artifactPeer;
    public static final class HostTrust extends Exception {
        public final String fingerprint;
        public final boolean changed;
        public final Gateway node;
        public HostTrust(String fingerprint, boolean changed) {this(fingerprint,changed,null);}
        public HostTrust(String fingerprint, boolean changed,Gateway node) { super(changed?"Server SSH identity changed":"Verify this server's SSH identity"); this.fingerprint=fingerprint; this.changed=changed;this.node=node; }
    }
    public static String fingerprint(byte[] key) throws Exception {
        return "SHA256:"+Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(key));
    }
    public static final class SignInRejected extends IOException {
        public final String targetHost;
        public SignInRejected(Throwable cause){this(cause,null);}
        public SignInRejected(Throwable cause,Gateway node){super("The server rejected its administrator sign-in. Check the saved SSH username and password.",cause);targetHost=diagnosticHost(node);}
    }
    /** A connection negotiation failed before an authenticated command could run. */
    public static final class HandshakeFailure extends IOException {
        public HandshakeFailure(Throwable cause){super("SSH could not complete its secure connection. If another VPN is active, it must allow access to this server. Check Android’s VPN and lockdown settings.",cause);}
    }
    public static final class Unreachable extends IOException {
        public final String targetHost,relayHost;
        public final boolean relayAuthenticated;
        public Unreachable(Throwable cause){this(cause,null,false);}
        public Unreachable(Throwable cause,Gateway node,boolean relayReady){
            super(relayReady?"The relay server answered, but SSH to the destination through it failed. Check the connection between the servers and SSH forwarding.":"This phone could not establish SSH to the server. Check its address, SSH port and network access.",cause);
            targetHost=diagnosticHost(node);relayHost=diagnosticHost(node==null?null:node.sshRelay);relayAuthenticated=relayReady;
        }
    }
    private static String diagnosticHost(Gateway node){return node!=null&&InputRules.host(node.get("host"))?node.get("host"):"";}
    private static boolean unreachable(Throwable error){
        for(Throwable e=error;e!=null;e=e.getCause())if(e instanceof java.net.ConnectException||e instanceof java.net.NoRouteToHostException||e instanceof java.net.SocketTimeoutException||e instanceof java.net.UnknownHostException)return true;
        String m=error.getMessage();return m!=null&&(m.contains("timeout: socket is not established")||m.contains("Connection refused")||m.contains("Connection timed out")||m.contains("No route to host")||m.contains("connection is closed by foreign host")||m.contains("Connection reset"));
    }
    private final Session session;
    private final Ssh relay;
    public Ssh(Gateway node) throws Exception {
        JSch client=new JSch();
        final Throwable[] authenticationTransportFailure={null};
        // JSch logs then discards generic I/O exceptions inside user authentication,
        // replacing them with "Auth fail". Retain only the typed transport cause;
        // never log authentication messages, credentials or server text.
        client.setInstanceLogger(new Logger(){
            public boolean isEnabled(int level){return level>=Logger.WARN;}
            public void log(int level,String message){}
            public void log(int level,String message,Throwable cause){if(cause!=null&&unreachable(cause))authenticationTransportFailure[0]=cause;}
        });
        if (!node.privateKey.isEmpty()) client.addIdentity("rookstride",node.privateKey.getBytes(StandardCharsets.UTF_8),null,node.sshPassword.getBytes(StandardCharsets.UTF_8));
        final String expected=node.get("fingerprint");
        final String[] presented={null};
        client.setHostKeyRepository(new HostKeyRepository() {
            public int check(String host,byte[] key) {
                try { presented[0]=fingerprint(key); } catch(Exception e) { return CHANGED; }
                return expected.isEmpty()?NOT_INCLUDED:expected.equals(presented[0])?OK:CHANGED;
            }
            public void add(HostKey key,UserInfo info) { /* strict verification never auto-adds */ }
            public void remove(String h,String t) {}
            public void remove(String h,String t,byte[] k) {}
            public String getKnownHostsRepositoryID() { return "Rookstride encrypted vault"; }
            public HostKey[] getHostKey() { return new HostKey[0]; }
            public HostKey[] getHostKey(String h,String t) { return new HostKey[0]; }
        });
        if(node.sshRelay!=null && node.sshRelay.sshRelay!=null)throw new IOException("Only one SSH relay is supported");
        relay=node.sshRelay==null?null:new Ssh(node.sshRelay);
        int port=node.port();String address=node.get("host");
        if(relay!=null)try {port=relay.session.setPortForwardingL("127.0.0.1",0,address,port);address="127.0.0.1";}catch(Exception e){relay.close();throw e;}
        session=client.getSession(node.get("admin"),address,port);
        if(socketFactory!=null&&relay==null)session.setSocketFactory(socketFactory);
        if (node.privateKey.isEmpty()) session.setPassword(node.sshPassword);
        session.setConfig("StrictHostKeyChecking","yes");
        if(node.get("sshKeyType").equals("ecdsa-sha2-nistp256"))session.setConfig("server_host_key","ecdsa-sha2-nistp256");
        session.setConfig("PreferredAuthentications",node.privateKey.isEmpty()?"password":"publickey");
        session.setTimeout(20000); session.setServerAliveInterval(15000);
        try { session.connect(12000); }
        catch(JSchException e) {
            session.disconnect();
            if(relay!=null)relay.close();
            if (presented[0]!=null && !presented[0].equals(expected)) throw new HostTrust(presented[0],!expected.isEmpty(),node);
            if(unreachable(e))throw new Unreachable(e,node,relay!=null);
            if(authenticationTransportFailure[0]!=null)throw new Unreachable(authenticationTransportFailure[0],node,relay!=null);
            String detail=e.getMessage()==null?"":e.getMessage();
            if(detail.contains("Auth fail")||detail.contains("USERAUTH fail"))throw new SignInRejected(e,node);
            throw new HandshakeFailure(e);
        }
    }
    public String execute(String command,String input) throws Exception {
        ChannelExec channel=(ChannelExec)session.openChannel("exec");
        channel.setCommand(command);
        // Responses contain structured errors; never retain unbounded remote stderr.
        channel.setErrStream(new OutputStream() { public void write(int b) {} public void write(byte[] b,int off,int len) {} });
        InputStream output=channel.getInputStream(); OutputStream stdin=channel.getOutputStream();
        ByteArrayOutputStream result=new ByteArrayOutputStream();
        try {
            channel.connect(CHANNEL_OPEN_TIMEOUT_MS);
            if(input!=null) stdin.write(input.getBytes(StandardCharsets.UTF_8));
            stdin.close();
            byte[] buffer=new byte[8192]; long deadline=System.nanoTime()+120_000_000_000L;
            while(true) {
                while(output.available()>0) {
                    int count=output.read(buffer); if(count<0) break;
                    result.write(buffer,0,count);
                    if(result.size()>2*1024*1024) throw new IOException("Server response is too large");
                }
                if(channel.isClosed() && output.available()==0) break;
                if(System.nanoTime()>deadline) throw new java.net.SocketTimeoutException("Server command timed out");
                Thread.sleep(25);
            }
            String text=result.toString("UTF-8").trim();
            if(channel.getExitStatus()!=0 && !text.startsWith("{")) throw new IOException("The server could not run this command. Check root or passwordless sudo access and gateway enrollment.");
            return text;
        } finally { channel.disconnect(); }
    }
    private String rootPrefix() throws Exception { return execute("id -u",null).trim().equals("0")?"":"sudo -n "; }
    public JSONObject admin(JSONObject request) throws Exception {
        return response(execute(rootPrefix()+"/usr/local/sbin/rookstride-admin",request.toString()));
    }
    public JSONObject access(InputStream bundle,JSONObject request)throws Exception{return bundledAction(bundle,request,"server/access_install.py");}
    public JSONObject access(JSONObject request)throws Exception{return response(execute(rootPrefix()+"/usr/local/sbin/rookstride-access",request.toString()));}
    public JSONObject probe() throws Exception {
        String code="import json,pathlib; d=dict(x.split('=',1) for x in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in x); j=sorted(pathlib.Path('/var/lib/rookstride/jobs').glob('*/status.json'),key=lambda p:p.stat().st_mtime); print(json.dumps({'machine':__import__('hashlib').sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest(), 'pair_helper':pathlib.Path('/opt/rookstride-pair/server/pair.py').exists(), 'pair_bundle':json.loads(pathlib.Path('/etc/rookstride-pair/manifest.json').read_text()).get('bundle','') if pathlib.Path('/etc/rookstride-pair/manifest.json').exists() else '', 'os':d.get('ID','').strip(chr(34)), 'version':d.get('VERSION_ID','').strip(chr(34)), 'helper':pathlib.Path('/usr/local/sbin/rookstride-admin').exists(), 'gateway':pathlib.Path('/etc/single-vps-vpn/network.env').exists(), 'existing':pathlib.Path('/etc/ipsec.conf').exists(), 'job':json.loads(j[-1].read_text()) if j else None}))";
        return new JSONObject(execute(rootPrefix()+"python3 -c "+InputRules.quote(code),null));
    }
    public JSONObject deploy(InputStream bundle,JSONObject config) throws Exception {
        return bundledAction(bundle,config,"server/deploy.py start");
    }
    public JSONObject pairStart(InputStream bundle,JSONObject config) throws Exception {
        ensureRuntime(config);
        return bundledAction(bundle,config,"server/pair.py");
    }
    public JSONObject pair(JSONObject request) throws Exception {
        ensureRuntime(request);
        ensureArtifacts("pair",request,null);
        ArtifactBridge.beforeDispatch();
        return response(execute(rootPrefix()+"python3 /opt/rookstride-pair/server/pair.py",request.toString()));
    }
    public JSONObject entryMigration(InputStream bundle,JSONObject config)throws Exception{return bundledAction(bundle,config,"server/entry_migration.py");}
    public JSONObject recovery(InputStream bundle,JSONObject config)throws Exception{return bundledAction(bundle,config,"server/recovery.py");}
    public JSONObject lifecycle(InputStream bundle,JSONObject config)throws Exception{return bundledAction(bundle,config,"server/lifecycle.py");}
    public JSONObject maintenance(InputStream bundle,JSONObject config)throws Exception{return bundledAction(bundle,config,"server/maintenance.py");}
    public JSONObject engineUpdates(InputStream bundle,JSONObject config)throws Exception{
        if(config.optString("action").equals("prepare")&&config.optString("group").equals("routes"))ensureRuntime(new JSONObject().put("action","start").put("protocol","hysteria2"));
        return bundledAction(bundle,config,"server/engine_updates.py");
    }
    public JSONObject engineUpdates(JSONObject config)throws Exception{
        String operation=config.getString("operation");if(!InputRules.job(operation))throw new IOException("Invalid engine update identifier");
        String path="/var/lib/rookstride-engine-updates/"+operation+"/source/server/engine_updates.py";
        String runner="import pathlib,runpy,json,sys; p=pathlib.Path(sys.argv[1]); runpy.run_path(str(p),run_name='__main__') if p.is_file() else print(json.dumps({'ok':True,'result':{'state':'not-started','phase':'No runtime operation has started'}}))";
        return response(execute(rootPrefix()+"python3 -c "+InputRules.quote(runner)+" "+InputRules.quote(path),config.toString()));
    }
    public JSONObject reinstall(InputStream bundle,JSONObject config)throws Exception{return bundledAction(bundle,config,"reinstall/run.py");}
    public JSONObject reinstall(JSONObject config)throws Exception{return response(execute(rootPrefix()+"python3 /var/lib/rookstride-reinstall/"+checkedJob(config.getString("job"))+"/adapter/run.py",config.toString()));}
    private static String checkedJob(String job)throws IOException{if(!InputRules.job(job))throw new IOException("Invalid OS reinstall job");return job;}
    public JSONObject reset(InputStream bundle,JSONObject config) throws Exception {
        return bundledAction(bundle,config,"server/reset.py");
    }
    public JSONObject single(InputStream bundle,JSONObject request)throws Exception{ensureRuntime(request);return bundledAction(bundle,request,"single/run.py");}
    public JSONObject single(JSONObject request)throws Exception{
        ensureRuntime(request);
        ensureArtifacts("single",request,null);
        ArtifactBridge.beforeDispatch();
        // A pair owns its immutable helper directly and has no standalone
        // `current` link. Polling/user actions must use that enrolled helper.
        String runner="import pathlib,runpy; p='/opt/rookstride-pair/single/run.py' if pathlib.Path('/etc/rookstride-pair/manifest.json').is_file() else '/opt/rookstride-single/current/single/run.py'; runpy.run_path(p,run_name='__main__')";
        return response(execute(rootPrefix()+"python3 -c "+InputRules.quote(runner),request.toString()));
    }
    private void ensureRuntime(JSONObject request)throws Exception {
        String action=request.optString("action");if(!action.equals("start")&&!action.equals("bootstrap")&&!action.equals("add-user")&&!action.equals("remove-user"))return;
        String protocol=request.optString("protocol");
        if(request.has("role"))protocol=request.optString(request.optString("role").equals("exit")?"exit_protocol":"entry_protocol");
        if(!SingleProtocols.from(protocol).worker()&&!(request.optString("role").equals("entry")&&SingleProtocols.from(request.optString("exit_protocol")).worker()))return;
        RuntimeSource source=runtimeSource;if(source==null)throw new IOException("The verified server runtime is missing from this app build");
        String architecture=execute("uname -m",null).trim();if(!architecture.equals("x86_64")&&!architecture.equals("aarch64"))throw new IOException("Use an x86_64 or ARM64 server");
        JSONObject asset=source.metadata().getJSONObject("assets").getJSONObject(architecture);
        String hash=asset.getString("sha256");if(!hash.matches("[a-f0-9]{64}"))throw new IOException("Invalid runtime identity");
        String check="import pathlib,hashlib,json,sys; a=json.load(sys.stdin); p=pathlib.Path('/opt/rookstride-routes')/a['sha256']; print(json.dumps({'ready':all(not (p/n).is_symlink() and (p/n).is_file() and hashlib.sha256((p/n).read_bytes()).hexdigest()==a[k] for n,k in [('rook-routes','sha256'),('libcronet.so','library_sha256')]) and not p.is_symlink()}))";
        if(new JSONObject(execute(rootPrefix()+"python3 -c "+InputRules.quote(check),asset.toString())).optBoolean("ready"))return;
        String stage="/tmp/rookstride-"+UUID.randomUUID().toString().replace("-","");
        ChannelSftp channel=(ChannelSftp)session.openChannel("sftp");
        try(InputStream input=source.open(architecture)){channel.connect(CHANNEL_OPEN_TIMEOUT_MS);channel.mkdir(stage);channel.chmod(0700,stage);channel.put(input,stage+"/runtime.tar.gz");channel.chmod(0600,stage+"/runtime.tar.gz");}finally{channel.disconnect();}
        String install="import pathlib,hashlib,json,sys,tarfile,os,secrets,shutil\n"
          +"a=json.load(sys.stdin); stage=pathlib.Path(sys.argv[1]); data=(stage/'runtime.tar.gz').read_bytes()\n"
          +"assert len(data)==a['archive_bytes'] and hashlib.sha256(data).hexdigest()==a['archive_sha256']\n"
          +"root=pathlib.Path('/opt/rookstride-routes'); assert not root.is_symlink(); root.mkdir(mode=0o700,exist_ok=True); assert root.stat().st_uid==0; root.chmod(0o700)\n"
          +"target=root/a['sha256']; assert not target.exists() and not target.is_symlink(); temporary=root/('.upload-'+secrets.token_hex(16)); temporary.mkdir(mode=0o700)\n"
          +"try:\n"
          +" with tarfile.open(stage/'runtime.tar.gz') as archive:\n"
          +"  members=archive.getmembers(); assert len(members)==2 and {m.name for m in members}=={'rook-routes','libcronet.so'}\n"
          +"  for m in members:\n"
          +"   key='sha256' if m.name=='rook-routes' else 'library_sha256'; size='bytes' if m.name=='rook-routes' else 'library_bytes'; assert m.isfile() and m.size==a[size] and 0<m.size<96*1024*1024\n"
          +"   value=archive.extractfile(m).read(); assert hashlib.sha256(value).hexdigest()==a[key]; file=temporary/m.name; file.write_bytes(value); file.chmod(0o700)\n"
          +" os.rename(temporary,target)\n"
          +"finally:\n"
          +" if temporary.exists():shutil.rmtree(temporary)\n"
          +"print('ready')\n";
        try{execute(rootPrefix()+"python3 -c "+InputRules.quote(install)+" "+InputRules.quote(stage),asset.toString());}
        finally{if(InputRules.stage(stage))try{execute("rm -rf -- "+InputRules.quote(stage),null);}catch(Exception ignored){}}
    }
    private JSONObject bundledAction(InputStream bundle,JSONObject config,String action) throws Exception {
        String stage="/tmp/rookstride-"+UUID.randomUUID().toString().replace("-","");
        ChannelSftp sftp=(ChannelSftp)session.openChannel("sftp");
        try { sftp.connect(CHANNEL_OPEN_TIMEOUT_MS); sftp.mkdir(stage); sftp.chmod(0700,stage); sftp.put(bundle,stage+"/bundle.zip"); sftp.chmod(0600,stage+"/bundle.zip"); }
        finally { sftp.disconnect(); }
        String unpack="import sys,zipfile,pathlib; p=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(p/'bundle.zip'); assert all(not pathlib.PurePosixPath(n).is_absolute() and '..' not in pathlib.PurePosixPath(n).parts for n in z.namelist()); z.extractall(p/'package')";
        try {
            execute("python3 -c "+InputRules.quote(unpack)+" "+InputRules.quote(stage),null);
            String kind=action.equals("single/run.py")?"single":action.equals("server/pair.py")?"pair":action.equals("server/deploy.py start")?"deploy":"";
            ensureArtifacts(kind,config,stage+"/package");
            ArtifactBridge.beforeDispatch();
            return response(execute(rootPrefix()+"python3 "+stage+"/package/"+action,config.toString()));
        } finally {
            // Generated private stage only; cleanup failure must not overwrite the action result.
            if(InputRules.stage(stage))try{execute("rm -rf -- "+InputRules.quote(stage),null);}catch(Exception ignored){}
        }
    }
    private void ensureArtifacts(String kind,JSONObject request,String packageRoot)throws Exception{
        java.util.List<String> ids=ArtifactBridge.required(kind,request);if(ids.isEmpty())return;
        ArtifactBridge.Source source=artifactSource;if(source==null)throw new IOException("The verified public component catalog is missing from this app build.");
        try(ArtifactEndpoint target=new ArtifactEndpoint(source,packageRoot,false);ArtifactEndpoint peer=artifactPeer==null?null:artifactPeer.new ArtifactEndpoint(source,null,true)){
            ArtifactBridge.prepare(source,target,peer,ids);
        }
    }
    private final class ArtifactEndpoint implements ArtifactBridge.Endpoint {
        final ArtifactBridge.Source source;final boolean optionalPeer;String packageRoot,ownedStage;JSONObject observed;
        ArtifactEndpoint(ArtifactBridge.Source source,String root,boolean peer){this.source=source;packageRoot=root;optionalPeer=peer;}
        private Exception transport(Exception error){if(error instanceof JSchException||unreachable(error))return optionalPeer?new ArtifactBridge.PeerUnavailable(error):new ArtifactBridge.UnknownResult(error);return error;}
        public JSONObject identity()throws Exception{
            if(observed==null)try{observed=new JSONObject(execute("python3 -c "+InputRules.quote("import pathlib,platform,hashlib,json,os;print(json.dumps({'architecture':platform.machine(),'machine':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest(),'cache_readable':os.geteuid()==0}))"),null));}catch(Exception e){throw transport(e);}
            return new JSONObject(observed.toString());
        }
        private void packageReady()throws Exception{
            if(packageRoot!=null)return;ownedStage="/tmp/rookstride-"+UUID.randomUUID().toString().replace("-","");ChannelSftp sftp=(ChannelSftp)session.openChannel("sftp");java.util.concurrent.ScheduledFuture<?> timeout=artifactTimeout(sftp);
            try(InputStream bundle=source.openBundle()){sftp.connect(CHANNEL_OPEN_TIMEOUT_MS);sftp.mkdir(ownedStage);sftp.chmod(0700,ownedStage);sftp.put(bundle,ownedStage+"/bundle.zip");sftp.chmod(0600,ownedStage+"/bundle.zip");}finally{timeout.cancel(false);sftp.disconnect();}
            String unpack="import sys,zipfile,pathlib; p=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(p/'bundle.zip'); assert all(not pathlib.PurePosixPath(n).is_absolute() and '..' not in pathlib.PurePosixPath(n).parts for n in z.namelist()); z.extractall(p/'package')";
            execute("python3 -c "+InputRules.quote(unpack)+" "+InputRules.quote(ownedStage),null);packageRoot=ownedStage+"/package";
        }
        public JSONObject request(JSONObject request)throws Exception{String text;try{packageReady();text=execute(rootPrefix()+"python3 "+InputRules.quote(packageRoot+"/single/artifact_bridge.py"),request.toString());}catch(Exception e){throw transport(e);}return response(text);}
        public void upload(PublicArtifactCatalog.Asset asset,String nonce,File verified)throws Exception{
            ArtifactDownloader.verify(verified,asset);String stage=artifactStage(nonce,asset.id);ChannelSftp sftp=(ChannelSftp)session.openChannel("sftp");java.util.concurrent.ScheduledFuture<?> timeout=artifactTimeout(sftp);
            try(InputStream input=new FileInputStream(verified)){sftp.connect(CHANNEL_OPEN_TIMEOUT_MS);sftp.mkdir(stage);sftp.chmod(0700,stage);sftp.put(input,stage+"/"+asset.id,new SftpProgressMonitor(){long count;final long deadline=System.nanoTime()+180_000_000_000L;public void init(int op,String src,String dest,long size){}public boolean count(long n){count+=n;return !Thread.currentThread().isInterrupted()&&System.nanoTime()<=deadline&&count<=asset.bytes;}public void end(){}},ChannelSftp.OVERWRITE);sftp.chmod(0600,stage+"/"+asset.id);}finally{timeout.cancel(false);sftp.disconnect();}
        }
        public InputStream cached(PublicArtifactCatalog.Asset asset)throws Exception{
            ChannelSftp sftp=(ChannelSftp)session.openChannel("sftp");java.util.concurrent.ScheduledFuture<?> timeout=artifactTimeout(sftp);
            try{
                sftp.connect(CHANNEL_OPEN_TIMEOUT_MS);String path="/var/cache/rookstride/artifacts/"+asset.sha256;SftpATTRS attrs=sftp.lstat(path);
                if(!attrs.isReg()||attrs.isLink()||attrs.getUId()!=0||(attrs.getPermissions()&0022)!=0||attrs.getSize()!=asset.bytes)throw new IOException("The other server's public component has an unexpected file identity.");
                InputStream stream=sftp.get(path);return new FilterInputStream(stream){@Override public int read()throws IOException{try{return in.read();}catch(IOException e){throw new ArtifactBridge.PeerUnavailable(e);}}@Override public int read(byte[] b,int off,int len)throws IOException{try{return in.read(b,off,len);}catch(IOException e){throw new ArtifactBridge.PeerUnavailable(e);}}@Override public void close()throws IOException{try{super.close();}finally{timeout.cancel(false);sftp.disconnect();}}};
            }catch(SftpException e){timeout.cancel(false);sftp.disconnect();if(e.id==ChannelSftp.SSH_FX_NO_SUCH_FILE||e.id==ChannelSftp.SSH_FX_PERMISSION_DENIED||e.id==ChannelSftp.SSH_FX_CONNECTION_LOST||e.id==ChannelSftp.SSH_FX_NO_CONNECTION)throw new ArtifactBridge.PeerUnavailable(e);throw e;}catch(JSchException e){timeout.cancel(false);sftp.disconnect();throw new ArtifactBridge.PeerUnavailable(e);}catch(Exception e){timeout.cancel(false);sftp.disconnect();throw e;}
        }
        public void clean(String nonce,String id)throws Exception{String stage=artifactStage(nonce,id);execute("rm -rf -- "+InputRules.quote(stage),null);}
        public void close(){if(ownedStage!=null&&InputRules.stage(ownedStage))try{execute("rm -rf -- "+InputRules.quote(ownedStage),null);}catch(Exception ignored){}}
    }
    private static String artifactStage(String nonce,String id)throws IOException{if(!nonce.matches("[a-f0-9]{32}")||!(id.equals("adguard")||id.equals("xray")||id.equals("trusttunnel")))throw new IOException("Invalid public component upload identity.");return "/tmp/rookstride-artifact-"+nonce;}
    public JSONObject job(String id) throws Exception {
        if(!InputRules.job(id)) throw new IOException("Invalid installation identifier");
        return response(execute(rootPrefix()+"python3 /opt/rookstride/releases/0.1.0/server/deploy.py status "+id,null));
    }
    /** Structured server refusal is distinct from lost transport confirmation. */
    public static final class ServerActionException extends IOException {
        public final String code, safeDetail;
        public final boolean rejectedBeforeMutation;
        public ServerActionException(String message){
            super(message);
            rejectedBeforeMutation="This Double VPN uses another installer version. Review its update before changing users or services.".equals(message);
            code=rejectedBeforeMutation?"pair_helper_update_required":"server_action_failed";
            safeDetail=rejectedBeforeMutation?"This Double VPN needs a reviewed management update before it can create or change VPN users. No account was created by this request.":"The server could not confirm that this action finished. Check its current users before trying the change again.";
        }
    }
    public static JSONObject response(String text) throws Exception {
        JSONObject data=new JSONObject(text);
        if(!data.optBoolean("ok")) throw new ServerActionException(data.optString("error","Server action failed"));
        return data.getJSONObject("result");
    }
    @Override public void close() { session.disconnect();if(relay!=null)relay.close(); }
}
