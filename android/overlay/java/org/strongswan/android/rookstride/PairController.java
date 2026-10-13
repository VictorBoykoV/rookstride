package org.strongswan.android.rookstride;

import org.json.JSONObject;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import java.util.TreeMap;
import java.util.Map;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipEntry;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/** Two trusted SSH sessions coordinate durable jobs; no private tunnel key leaves its node. */
public final class PairController {
    public interface Bundle { InputStream open() throws Exception; }
    public interface Progress { void update(String phase); }
    public static final class TrustNeeded extends Exception {
        public final Gateway node; public final Ssh.HostTrust issue;
        TrustNeeded(Gateway node,Ssh.HostTrust issue) { super(issue.getMessage());this.node=node;this.issue=issue; }
    }
    public static final class RebootNeeded extends Exception {
        public final Gateway node;
        RebootNeeded(Gateway node) {super(node.get("name")+" needs a reboot to load its matching kernel. Then resume this pair.");this.node=node;}
    }
    private static Ssh open(Gateway node) throws Exception {
        try { return new Ssh(node); } catch(Ssh.HostTrust e) { throw new TrustNeeded(node,e); }
    }
    public static String bundleDigest(Bundle bundle) throws Exception {
        TreeMap<String,byte[]> files=new TreeMap<>();
        try(ZipInputStream zip=new ZipInputStream(bundle.open())) {
            ZipEntry item;byte[] buffer=new byte[8192];int total=0;
            while((item=zip.getNextEntry())!=null) {
                String name=item.getName();
                if(item.isDirectory()||!(name.startsWith("server/")||name.startsWith("gateway/")||name.startsWith("twohop/")))continue;
                if(name.contains("../")||name.contains("/__pycache__/")||name.endsWith(".pyc"))throw new IOException("Invalid installer bundle path");
                ByteArrayOutputStream data=new ByteArrayOutputStream();int n;
                while((n=zip.read(buffer))!=-1){total+=n;if(total>8*1024*1024)throw new IOException("Installer bundle too large");data.write(buffer,0,n);}
                if(files.put(name,data.toByteArray())!=null)throw new IOException("Duplicate installer file");
            }
        }
        if(files.isEmpty())throw new IOException("Empty installer bundle");
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        for(String folder:new String[]{"server/","twohop/","gateway/"}) for(Map.Entry<String,byte[]> file:files.entrySet()) if(file.getKey().startsWith(folder)){digest.update(file.getKey().getBytes(StandardCharsets.UTF_8));digest.update(file.getValue());}
        StringBuilder hex=new StringBuilder();for(byte value:digest.digest())hex.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return hex.toString();
    }
    public static JSONObject request(Gateway entry,String role) throws Exception {
        if(!entry.isPair()) throw new IOException("This is not a two-server gateway");
        String pair=entry.get("pairId");
        if(!InputRules.job(pair)) throw new IOException("Invalid pair identifier");
        String server=entry.get("vpnServer").isEmpty()?entry.get("host"):entry.get("vpnServer");
        String endpoint=entry.get("exitEndpoint").isEmpty()?entry.exit.get("host"):entry.get("exitEndpoint");
        if(!InputRules.host(server)||!InputRules.host(endpoint)) throw new IOException("Invalid VPN or exit address");
        JSONObject req=new JSONObject();req.put("pair",pair);req.put("role",role);req.put("server",server);req.put("exit_host",endpoint);
        req.put("vpn_port",entry.data.optInt("vpnPort",500));req.put("tunnel_port",entry.data.optInt("tunnelPort",443));
        return req;
    }
    private static JSONObject step(Ssh ssh,Gateway node,JSONObject request,boolean enrolled,Bundle bundle,Progress progress,boolean resume) throws Exception {
        request.put("command","start");request.put("resume",resume);
        JSONObject started;
        if(enrolled) started=ssh.pair(request);
        else try(InputStream in=bundle.open()) {started=ssh.pairStart(in,request);}
        String job=started.getString("job");
        long deadline=System.nanoTime()+2_700_000_000_000L;
        String phase="";
        while(true) {
            JSONObject status=ssh.pair(new JSONObject().put("command","status").put("job",job));
            String state=status.getString("state");
            if(!phase.equals(status.optString("phase"))) {phase=status.optString("phase");progress.update(node.get("name")+" · "+phase);}
            if(state.equals("complete")) return status;
            if(state.equals("awaiting-reboot")) throw new RebootNeeded(node);
            if(state.equals("failed")||state.equals("paused")) throw new IOException(node.get("name")+": "+status.optString("phase")+" ("+status.optString("detail",status.optString("error","interrupted"))+")");
            if(System.nanoTime()>deadline) throw new IOException("The server job is still running. Reopen this pair to check and resume.");
            Thread.sleep(2000);
        }
    }
    public static JSONObject install(Gateway entry,Bundle bundle,Progress progress,boolean resume) throws Exception {
        if(!entry.isPair())throw new IOException("Add both servers first");
        String expectedBundle=bundleDigest(bundle);
        // Verify both SSH identities and machine IDs before mutating either node.
        try(Ssh first=open(entry); Ssh second=open(entry.exit)) {
            JSONObject a=first.probe(),b=second.probe();
            if(a.optString("machine").isEmpty()||a.optString("machine").equals(b.optString("machine"))) throw new IOException("Entry and exit must be distinct machines; aliases of the same VPS are refused.");
            for(JSONObject p:new JSONObject[]{a,b}) if(!p.optString("os").equals("ubuntu")||!p.optString("version").equals("24.04")) throw new IOException("Use Ubuntu 24.04 on both nodes");
            for(JSONObject p:new JSONObject[]{a,b}) if(p.optBoolean("pair_helper")&&!expectedBundle.equals(p.optString("pair_bundle"))) throw new IOException("This pair uses another installer version. An explicit pair upgrade is required; resume will not replace it.");
            JSONObject exit=request(entry,"exit");exit.put("action","bootstrap");
            step(second,entry.exit,exit,b.optBoolean("pair_helper"),bundle,progress,resume);
            JSONObject ingress=request(entry,"entry");ingress.put("action","bootstrap");ingress.put("login",entry.get("vpnLogin"));ingress.put("password",entry.vpnPassword);ingress.put("statistics",entry.data.optBoolean("pairStatistics",true));
            step(first,entry,ingress,a.optBoolean("pair_helper"),bundle,progress,resume);
            JSONObject exitMaterial=second.pair(new JSONObject().put("command","material").put("pair",entry.get("pairId")));
            JSONObject entryMaterial=first.pair(new JSONObject().put("command","material").put("pair",entry.get("pairId")));
            JSONObject exitConfig=request(entry,"exit");exitConfig.put("action","configure");exitConfig.put("peer_key",entryMaterial.getString("public_key"));
            step(second,entry.exit,exitConfig,true,bundle,progress,resume);
            JSONObject entryConfig=request(entry,"entry");entryConfig.put("action","configure");entryConfig.put("peer_key",exitMaterial.getString("public_key"));entryConfig.put("shared",exitMaterial.getJSONObject("shared"));
            step(first,entry,entryConfig,true,bundle,progress,resume);
            String expected=second.pair(new JSONObject().put("command","overview").put("pair",entry.get("pairId"))).getString("exit_ip");
            for(String action:new String[]{"verify","activate"}) {
                JSONObject req=request(entry,"entry");req.put("action",action);req.put("expected_exit_ip",expected);req.put("repeat",true);
                step(first,entry,req,true,bundle,progress,resume);
            }
            return new JSONObject().put("entry",first.admin(new JSONObject().put("action","status"))).put("exit",second.admin(new JSONObject().put("action","status"))).put("exit_ip",expected);
        }
    }
    public static String newId() {return UUID.randomUUID().toString().replace("-","");}
}
