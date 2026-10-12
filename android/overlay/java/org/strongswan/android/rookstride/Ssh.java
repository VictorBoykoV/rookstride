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
    public static final class HostTrust extends Exception {
        public final String fingerprint;
        public final boolean changed;
        public HostTrust(String fingerprint, boolean changed) { super(changed?"Server SSH identity changed":"Verify this server's SSH identity"); this.fingerprint=fingerprint; this.changed=changed; }
    }
    public static String fingerprint(byte[] key) throws Exception {
        return "SHA256:"+Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(key));
    }
    private final Session session;
    public Ssh(Gateway node) throws Exception {
        JSch client=new JSch();
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
        session=client.getSession(node.get("admin"),node.get("host"),node.port());
        if (node.privateKey.isEmpty()) session.setPassword(node.sshPassword);
        session.setConfig("StrictHostKeyChecking","yes");
        session.setConfig("PreferredAuthentications",node.privateKey.isEmpty()?"password":"publickey");
        session.setTimeout(20000); session.setServerAliveInterval(15000);
        try { session.connect(12000); }
        catch(JSchException e) {
            session.disconnect();
            if (presented[0]!=null && !presented[0].equals(expected)) throw new HostTrust(presented[0],!expected.isEmpty());
            throw new IOException("SSH connection failed. Check the administrator login, SSH port and network access.",e);
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
            channel.connect(10000);
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
                if(System.nanoTime()>deadline) throw new IOException("Server command timed out");
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
    public JSONObject probe() throws Exception {
        String code="import json,pathlib; d=dict(x.split('=',1) for x in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in x); j=sorted(pathlib.Path('/var/lib/rookstride/jobs').glob('*/status.json'),key=lambda p:p.stat().st_mtime); print(json.dumps({'os':d.get('ID','').strip(chr(34)), 'version':d.get('VERSION_ID','').strip(chr(34)), 'helper':pathlib.Path('/usr/local/sbin/rookstride-admin').exists(), 'gateway':pathlib.Path('/etc/single-vps-vpn/network.env').exists(), 'existing':pathlib.Path('/etc/ipsec.conf').exists(), 'job':json.loads(j[-1].read_text()) if j else None}))";
        return new JSONObject(execute(rootPrefix()+"python3 -c "+InputRules.quote(code),null));
    }
    public JSONObject deploy(InputStream bundle,JSONObject config) throws Exception {
        return bundledAction(bundle,config,"deploy.py start");
    }
    public JSONObject reset(InputStream bundle,JSONObject config) throws Exception {
        return bundledAction(bundle,config,"reset.py");
    }
    private JSONObject bundledAction(InputStream bundle,JSONObject config,String action) throws Exception {
        String stage="/tmp/rookstride-"+UUID.randomUUID().toString().replace("-","");
        ChannelSftp sftp=(ChannelSftp)session.openChannel("sftp");
        try { sftp.connect(10000); sftp.mkdir(stage); sftp.chmod(0700,stage); sftp.put(bundle,stage+"/bundle.zip"); sftp.chmod(0600,stage+"/bundle.zip"); }
        finally { sftp.disconnect(); }
        String unpack="import sys,zipfile,pathlib; p=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(p/'bundle.zip'); assert all(not pathlib.PurePosixPath(n).is_absolute() and '..' not in pathlib.PurePosixPath(n).parts for n in z.namelist()); z.extractall(p/'package')";
        execute("python3 -c "+InputRules.quote(unpack)+" "+InputRules.quote(stage),null);
        String result=execute(rootPrefix()+"python3 "+stage+"/package/server/"+action,config.toString());
        // Only our generated private staging directory is removed.
        if(InputRules.stage(stage)) execute("rm -rf -- "+InputRules.quote(stage),null);
        return response(result);
    }
    public JSONObject job(String id) throws Exception {
        if(!InputRules.job(id)) throw new IOException("Invalid installation identifier");
        return response(execute(rootPrefix()+"python3 /opt/rookstride/releases/0.1.0/server/deploy.py status "+id,null));
    }
    public static JSONObject response(String text) throws Exception {
        JSONObject data=new JSONObject(text);
        if(!data.optBoolean("ok")) throw new IOException(data.optString("error","Server action failed"));
        return data.getJSONObject("result");
    }
    @Override public void close() { session.disconnect(); }
}
