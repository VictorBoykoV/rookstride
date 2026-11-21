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

/** Two pinned SSH sessions coordinate durable jobs. Native exit profiles travel
 * only through these encrypted sessions and remain out of progress and logs. */
public final class PairController {
    public interface Bundle { InputStream open() throws Exception; }
    public interface Progress { void update(String phase); default void stage(int index,String phase){update(phase);} }
    public static final class TrustNeeded extends Exception {
        public final Gateway node; public final Ssh.HostTrust issue;
        TrustNeeded(Gateway node,Ssh.HostTrust issue) { super(issue.getMessage());this.node=node;this.issue=issue; }
    }
    public static final class RebootNeeded extends Exception {
        public final Gateway node;
        RebootNeeded(Gateway node) {super(node.get("name")+" needs a reboot to load its matching kernel. Then resume this pair.");this.node=node;}
    }
    private static Ssh open(Gateway node) throws Exception {
        try { return new Ssh(node); } catch(Ssh.HostTrust e) { throw new TrustNeeded(e.node==null?node:e.node,e); }
    }
    public static String bundleDigest(Bundle bundle) throws Exception {
        TreeMap<String,byte[]> files=new TreeMap<>();
        try(ZipInputStream zip=new ZipInputStream(bundle.open())) {
            ZipEntry item;byte[] buffer=new byte[8192];int total=0;
            while((item=zip.getNextEntry())!=null) {
                String name=item.getName();
                if(item.isDirectory()||!(name.startsWith("server/")||name.startsWith("gateway/")||name.startsWith("twohop/")||name.startsWith("single/")))continue;
                if(name.contains("../")||name.contains("/__pycache__/")||name.endsWith(".pyc"))throw new IOException("Invalid installer bundle path");
                ByteArrayOutputStream data=new ByteArrayOutputStream();int n;
                while((n=zip.read(buffer))!=-1){total+=n;if(total>8*1024*1024)throw new IOException("Installer bundle too large");data.write(buffer,0,n);}
                if(files.put(name,data.toByteArray())!=null)throw new IOException("Duplicate installer file");
            }
        }
        if(files.isEmpty())throw new IOException("Empty installer bundle");
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        for(String folder:new String[]{"server/","twohop/","gateway/","single/"}) for(Map.Entry<String,byte[]> file:files.entrySet()) if(file.getKey().startsWith(folder)){digest.update(file.getKey().getBytes(StandardCharsets.UTF_8));digest.update(file.getValue());}
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
        req.put("vpn_port",entry.data.optInt("vpnPort",SingleProtocols.from(entry.get("pairEntryProtocol")).port));req.put("tunnel_port",entry.data.optInt("tunnelPort",entry.get("pairExitProtocol").equals("ikev2")?500:entry.get("pairExitProtocol").equals("openvpn")?1194:443));
        if(entry.get("pairEngine").equals("native-v2"))req.put("engine","native-v2");
        if(!entry.get("accessMode").isEmpty())req.put("access_mode",entry.get("accessMode"));
        if(!entry.get("pairEntryProtocol").isEmpty()){req.put("entry_protocol",entry.get("pairEntryProtocol"));req.put("exit_protocol",entry.get("pairExitProtocol"));}
        return req;
    }
    public static boolean modern(Gateway entry){return entry.get("pairEngine").equals("native-v2")||!entry.get("pairEntryProtocol").isEmpty()&&!entry.get("pairEntryProtocol").equals("ikev2")||!entry.get("pairExitProtocol").isEmpty()&&!entry.get("pairExitProtocol").equals("awg");}
    public static JSONObject bootstrapRequest(Gateway entry,String role)throws Exception{
        if(!role.equals("entry")&&!role.equals("exit"))throw new IOException("Invalid server role");
        JSONObject req=request(entry,role).put("action","bootstrap");
        if(role.equals("entry"))req.put("login",entry.get("vpnLogin")).put("password",entry.vpnPassword).put("statistics",entry.data.optBoolean("pairStatistics",true));
        return req;
    }
    static JSONObject step(Ssh ssh,Gateway node,JSONObject request,boolean enrolled,Bundle bundle,Progress progress,boolean resume) throws Exception {
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
        entry.configureRelay();
        String expectedBundle=bundleDigest(bundle);
        progress.stage(0,"Checking both pinned SSH identities");
        // Verify both SSH identities and machine IDs before mutating either node.
        try(PairSsh sessions=PairSsh.connect(entry,progress)) {
            Ssh first=sessions.entry,second=sessions.exit;
            JSONObject a=first.probe(),b=second.probe();
            if(a.optString("machine").isEmpty()||a.optString("machine").equals(b.optString("machine"))) throw new IOException("Entry and exit must be distinct machines; aliases of the same VPS are refused.");
            for(JSONObject p:new JSONObject[]{a,b})UbuntuCompatibility.require(p,modern(entry));
            for(JSONObject p:new JSONObject[]{a,b}) if(p.optBoolean("pair_helper")&&!expectedBundle.equals(p.optString("pair_bundle"))) throw new IOException("This pair uses another installer version. An explicit pair upgrade is required; resume will not replace it.");
            // Refuse occupied nodes before installing anything on their partner.
            for(String role:new String[]{"entry","exit"}){JSONObject preflight=request(entry,role);preflight.put("command","preflight");try(InputStream in=bundle.open()){(role.equals("entry")?first:second).pairStart(in,preflight);}}
            JSONObject exit=bootstrapRequest(entry,"exit");
            boolean nativePair=modern(entry); // The exit generates its own private bridge credentials.
            progress.stage(1,"Preparing the exit VPN and private DNS");
            step(second,entry.exit,exit,b.optBoolean("pair_helper"),bundle,progress,resume);
            progress.stage(2,"Checking ad blocking on the exit server");
            JSONObject filterHealth=nativePair?second.pair(new JSONObject().put("command","health").put("pair",entry.get("pairId"))):second.admin(new JSONObject().put("action","status"));
            JSONObject services=filterHealth.optJSONObject("services");
            if(services==null||!services.optBoolean("adguard")&&!services.optBoolean("adguardhome"))throw new IOException("The exit ad blocker is not ready. Check and resume.");
            JSONObject ingress=bootstrapRequest(entry,"entry");
            progress.stage(3,"Preparing the entry VPN");
            step(first,entry,ingress,a.optBoolean("pair_helper"),bundle,progress,resume);
            JSONObject exitMaterial=second.pair(new JSONObject().put("command","material").put("pair",entry.get("pairId")));
            JSONObject entryMaterial=nativePair?new JSONObject():first.pair(new JSONObject().put("command","material").put("pair",entry.get("pairId")));
            JSONObject exitConfig=request(entry,"exit");exitConfig.put("action","configure");if(!nativePair)exitConfig.put("peer_key",entryMaterial.getString("public_key"));
            progress.stage(4,"Joining the exit bridge");
            step(second,entry.exit,exitConfig,true,bundle,progress,resume);
            JSONObject entryConfig=request(entry,"entry");entryConfig.put("action","configure");if(nativePair)entryConfig.put("transport",exitMaterial);else{entryConfig.put("peer_key",exitMaterial.getString("public_key"));entryConfig.put("shared",exitMaterial.getJSONObject("shared"));}
            progress.stage(5,"Joining the entry bridge");
            step(first,entry,entryConfig,true,bundle,progress,resume);
            String expected=second.pair(new JSONObject().put("command","overview").put("pair",entry.get("pairId"))).getString("exit_ip");
            for(String action:new String[]{"verify","activate"}) {
                progress.stage(action.equals("verify")?6:7,action.equals("verify")?"Checking the complete server route":"Opening client forwarding");
                JSONObject req=request(entry,"entry");req.put("action",action);req.put("expected_exit_ip",expected);req.put("repeat",true);
                step(first,entry,req,true,bundle,progress,resume);
            }
            progress.stage(8,"Checking available connection monitoring");
            JSONObject monitoring=nativePair?first.pair(new JSONObject().put("command","health").put("pair",entry.get("pairId"))):first.admin(new JSONObject().put("action","status"));
            progress.update(monitoring.optBoolean("monitoring_available")?"Connection monitoring is ready":"This protocol does not provide per-user traffic counters yet");
            progress.stage(9,"Reading both gateway health reports");
            JSONObject entryStatus,exitStatus;if(nativePair){entryStatus=first.pair(new JSONObject().put("command","health").put("pair",entry.get("pairId")));exitStatus=second.pair(new JSONObject().put("command","health").put("pair",entry.get("pairId")));}else{entryStatus=first.admin(new JSONObject().put("action","status"));exitStatus=second.admin(new JSONObject().put("action","status"));}JSONObject completion=first.pair(new JSONObject().put("command","overview").put("pair",entry.get("pairId")));return new JSONObject().put("entry",entryStatus).put("exit",exitStatus).put("exit_ip",expected).put("completed_at",completion.optDouble("completed_at",0));
        }
    }
    public static String newId() {return UUID.randomUUID().toString().replace("-","");}
}
