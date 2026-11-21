package org.strongswan.android.rookstride;

import android.content.Context;
import org.json.*;
import org.strongswan.android.rookstride.engine.NativeProfiles;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** One catalog visibility commit; exact staged assets are cleaned after interrupted imports. */
public final class ConnectionBundleImport {
    private static final Object LOCK=new Object();
    private ConnectionBundleImport(){}

    public static final class Summary {
        public final String protocol,title,server,account,login,displayName;public final int port;
        Summary(String protocol,String server,String login,String label,int port){this.protocol=protocol;this.title=SingleProtocols.from(protocol).title;this.server=server;this.login=login;this.port=port;this.account=login.isEmpty()?(protocol.equals("awg")?"Device access":protocol.equals("openvpn")?"Certificate access":"Link access"):login;this.displayName=label.isEmpty()?title+" · "+(login.isEmpty()?server:login):label;}
    }
    public static final class Preview {
        public final List<Summary> connections;public final int toAdd,existing;
        private final String text;
        Preview(String text,List<Summary> connections,int existing){this.text=text;this.connections=Collections.unmodifiableList(connections);this.existing=existing;this.toAdd=connections.size()-existing;}
    }
    public static final class Result {
        public final ArrayList<Gateway> catalog;public final int added,existing;public final boolean cleanupPending;
        Result(ArrayList<Gateway> catalog,int added,int existing,boolean cleanupPending){this.catalog=catalog;this.added=added;this.existing=existing;this.cleanupPending=cleanupPending;}
    }
    static final class Asset {
        final String id,protocol,certificateAlias,certificateHash,operation;final boolean newCertificate;
        Asset(String id,String protocol,String alias,String hash,boolean fresh,String operation)throws Exception{
            if(!uuid(id)||!uuid(operation)||!SingleProtocols.from(protocol).id.equals(protocol)||alias==null||hash==null||(!alias.isEmpty()&&!alias.matches("local:[a-f0-9]{40}"))||(!hash.isEmpty()&&!hash.matches("[a-f0-9]{64}"))||alias.isEmpty()!=hash.isEmpty()||fresh&&(alias.isEmpty()||hash.isEmpty())||!protocol.equals("ikev2")&&(fresh||!alias.isEmpty()))throw new IOException("Invalid import recovery record");
            this.id=id;this.protocol=protocol;certificateAlias=alias;certificateHash=hash;newCertificate=fresh;this.operation=operation;
        }
        JSONObject json()throws Exception{return new JSONObject().put("id",id).put("protocol",protocol).put("certificate_alias",certificateAlias).put("certificate_hash",certificateHash).put("new_certificate",newCertificate);}
    }
    interface Store {
        ArrayList<Gateway> catalog()throws Exception;
        boolean matches(Gateway node,JSONObject profile)throws Exception;
        Asset describe(Gateway node,JSONObject profile)throws Exception;
        void stage(Gateway node,JSONObject profile,Asset asset)throws Exception;
        ArrayList<Gateway> append(List<Gateway> nodes)throws Exception;
        JSONObject journal()throws Exception;
        void journal(JSONObject value)throws Exception;
        void clearJournal()throws Exception;
        void cleanup(Asset asset,List<Gateway> references)throws Exception;
        default void finishCleanup(List<Asset> assets,List<Gateway> references)throws Exception{}
    }

    public static Preview preview(Context context,String text)throws Exception{synchronized(LOCK){return preview(new ConnectionBundleAndroidStore(context),text);}}
    public static Result apply(Context context,Preview preview)throws Exception{synchronized(LOCK){return apply(new ConnectionBundleAndroidStore(context),preview);}}
    public static void recover(Context context)throws Exception{synchronized(LOCK){recover(new ConnectionBundleAndroidStore(context));}}
    /** Fast, validated journal check; no catalog/SQL access or full-import lock. */
    public static boolean recoveryPending(Context context)throws Exception{return new ConnectionImportJournal(context).read()!=null;}
    /** Read-only and not held behind a potentially running import; use before SQL-profile sync. */
    public static Set<String> pendingIkeProfileIds(Context context)throws Exception{
        JSONObject journal=new ConnectionImportJournal(context).read();Set<String> ids=new HashSet<>();if(journal!=null)for(Asset asset:assets(journal))if(asset.protocol.equals("ikev2"))ids.add(asset.id);return ids;
    }
    public static JSONObject savedConnection(Context context,Gateway node)throws Exception{return new ConnectionBundleAndroidStore(context).savedConnection(node);}
    /** Non-secret native metadata for legacy single-file UI. This does not import anything. */
    public static Summary inspectMetadata(String protocol,String content)throws Exception{
        if(!SingleProtocols.from(protocol).id.equals(protocol)||protocol.equals("ikev2"))throw new IOException("Use the IKEv2 profile reader for this connection");NativeProfiles.validate(protocol,content);return summary(new JSONObject().put("format",protocol).put("name","rookstride-import").put("content",content));
    }

    /** Display metadata only. Saved transport/authentication bytes stay in their existing store. */
    private static boolean ordinaryNativeClient(Gateway node){
        String protocol=node.get("protocol");return node.data.optBoolean("clientOnly")&&!node.data.optBoolean("adminAccess")&&!node.isPair()&&!protocol.equals("ikev2")&&SingleProtocols.from(protocol).id.equals(protocol);
    }
    public static boolean needsNativeMetadata(Gateway node){
        return ordinaryNativeClient(node)&&node.data.optInt("nativeMetadataVersion")!=1&&(node.get("host").isEmpty()||!InputRules.port(node.data.optInt("vpnPort"))||PasswordSignIn.supported(node.get("protocol"))&&node.get("vpnLogin").isEmpty());
    }
    public static boolean populateNativeMetadata(Gateway node,String content)throws Exception{
        if(!ordinaryNativeClient(node))return false;
        Summary info=inspectMetadata(node.get("protocol"),content);boolean changed=false;
        // Parse and validate the complete profile before changing any catalog field.
        if(node.get("host").isEmpty()){node.set("host",info.server);changed=true;}
        if(!InputRules.port(node.data.optInt("vpnPort"))){node.data.put("vpnPort",info.port);changed=true;}
        if(node.get("vpnLogin").isEmpty()&&!info.login.isEmpty()){node.set("vpnLogin",info.login);changed=true;}
        if(node.data.optInt("nativeMetadataVersion")!=1){node.data.put("nativeMetadataVersion",1);changed=true;}return changed;
    }

    static Preview preview(Store store,String text)throws Exception{
        List<JSONObject> profiles=ConnectionBundle.parse(text);if(store.journal()!=null)throw new IOException("Finish recovering the previous connection import first");
        ArrayList<Gateway> current=store.catalog();List<Summary> summaries=new ArrayList<>();int existing=0;
        for(JSONObject profile:profiles){summaries.add(summary(profile));if(find(store,current,profile)!=null)existing++;}
        return new Preview(text,summaries,existing);
    }
    static Result apply(Store store,Preview preview)throws Exception{
        if(preview==null)throw new IOException("Review the connection collection first");
        List<JSONObject> profiles=ConnectionBundle.parse(preview.text);if(store.journal()!=null)throw new IOException("Finish recovering the previous connection import first");
        ArrayList<Gateway> current=store.catalog();List<Gateway> added=new ArrayList<>();List<JSONObject> payloads=new ArrayList<>();List<Asset> plans=new ArrayList<>();String operation=UUID.randomUUID().toString();int existing=0;
        for(JSONObject profile:profiles){if(find(store,current,profile)!=null){existing++;continue;}Gateway node=client(profile,operation);for(Gateway old:current)if(old.get("id").equals(node.get("id")))throw new IOException("Try importing the collection again");added.add(node);payloads.add(profile);}
        for(int i=0;i<added.size();i++){Gateway node=added.get(i);Asset asset=store.describe(node,payloads.get(i));if(!asset.id.equals(node.get("id"))||!asset.protocol.equals(node.get("protocol"))||!asset.operation.equals(operation))throw new IOException("The local import plan differs from its connections");plans.add(asset);}
        if(added.isEmpty())return new Result(current,0,existing,false);
        JSONArray entries=new JSONArray();for(Asset asset:plans)entries.put(asset.json());JSONObject journal=new JSONObject().put("schema",1).put("kind","rookstride-local-import").put("operation",operation).put("assets",entries);
        try{
            store.journal(journal);
            for(int i=0;i<added.size();i++)store.stage(added.get(i),payloads.get(i),plans.get(i));
            ArrayList<Gateway> committed=store.append(added);boolean pending=false;try{store.finishCleanup(plans,committed);store.clearJournal();}catch(Exception cleanup){pending=true;}
            return new Result(committed,added.size(),existing,pending);
        }catch(Exception failure){
            // A write can succeed before its reply fails. Read the durable catalog
            // before removing anything, and never replay the insertion blindly.
            try{recover(store);ArrayList<Gateway> observed=store.catalog();int found=0;for(Gateway node:observed)if(operation.equals(node.get("bundleImportId")))found++;if(found>0)return new Result(observed,found,existing,false);}
            catch(Exception uncertain){throw new IOException("Connection import needs recovery. Reopen the app before importing again.");}
            throw new IOException("The connections were not added. You can import the file again.");
        }
    }
    static void recover(Store store)throws Exception{
        JSONObject journal=store.journal();if(journal==null)return;List<Asset> plans=assets(journal);
        // If the catalog/key is unavailable, leave every asset and the journal.
        ArrayList<Gateway> references=store.catalog();for(Asset asset:plans)store.cleanup(asset,references);store.finishCleanup(plans,references);store.clearJournal();
    }
    private static Gateway find(Store store,List<Gateway> current,JSONObject profile)throws Exception{
        String hash=fingerprint(profile);for(Gateway node:current)if(node.data.optBoolean("clientOnly")&&hash.equals(node.get("importedConnectionHash"))&&profile.getString("format").equals(node.get("protocol"))&&store.matches(node,profile))return node;return null;
    }
    static Gateway client(JSONObject envelope,String operation)throws Exception{
        Summary info=summary(envelope);String format=envelope.getString("format"),content=envelope.getString("content");Gateway node=new Gateway();node.set("protocol",format);node.set("host",info.server);node.set("name",info.displayName);node.data.put("clientOnly",true).put("vpnPort",info.port);if(!info.login.isEmpty())node.set("vpnLogin",info.login);node.set("bundleImportId",operation);node.set("importedConnectionHash",fingerprint(envelope));
        if(format.equals("ikev2")){JSONObject p=new JSONObject(content),local=p.getJSONObject("local");node.set("profileUuid",node.get("id"));node.set("vpnLogin",local.getString("eap_id"));node.vpnPassword=local.getString("shared_secret");node.set("accessMode","password");node.data.put("rememberVpn",true).put("vpnPort",p.getJSONObject("remote").optInt("port",500));}
        else if(format.equals("openvpn")){JSONObject p=NativeProfiles.openVpnCredentials(content);if(p.has("login"))node.set("vpnLogin",p.getString("login"));}
        else if(SingleProtocols.from(format).worker())node.set("vpnLogin",new JSONObject(content).getString("login"));
        return node;
    }
    static Summary summary(JSONObject envelope)throws Exception{
        String format=envelope.getString("format"),content=envelope.getString("content"),host="",login="";int port;
        if(format.equals("ikev2")){JSONObject p=new JSONObject(content);host=p.getJSONObject("remote").getString("addr");port=p.getJSONObject("remote").optInt("port",500);login=p.getJSONObject("local").getString("eap_id");}
        else if(format.equals("awg")){org.amnezia.awg.config.Config p=org.amnezia.awg.config.Config.parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));if(p.getPeers().size()!=1||!p.getPeers().get(0).getEndpoint().isPresent())throw new IOException("Use a single-server AmneziaWG connection");host=p.getPeers().get(0).getEndpoint().get().getHost();port=p.getPeers().get(0).getEndpoint().get().getPort();}
        else if(format.equals("xray")||format.equals("xhttp")){Map<String,String> p=NativeProfiles.vless(content);host=p.get("host");port=Integer.parseInt(p.get("port"));}
        else if(format.equals("openvpn")){JSONObject p=NativeProfiles.openVpnCredentials(content);login=p.optString("login");java.util.regex.Matcher remote=java.util.regex.Pattern.compile("(?m)^\\s*remote\\s+([^\\s]+)\\s+([0-9]+)(?:\\s|$)").matcher(NativeProfiles.openVpnConfiguration(content));if(!remote.find())throw new IOException("This OpenVPN connection has no server");host=remote.group(1);port=Integer.parseInt(remote.group(2));}
        else{JSONObject p=NativeProfiles.workerProfile(format,content);host=p.getString("server");port=p.getInt("port");login=p.getString("login");}
        if(!InputRules.port(port))throw new IOException("This connection has an invalid VPN port");return new Summary(format,host,login,envelope.optString("display_name"),port);
    }
    static String fingerprint(JSONObject entry)throws Exception{MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(entry.getString("format").getBytes(StandardCharsets.US_ASCII));hash.update((byte)0);return hex(hash.digest(entry.getString("content").getBytes(StandardCharsets.UTF_8)));}
    static String hex(byte[] bytes){StringBuilder out=new StringBuilder();for(byte b:bytes){out.append(Character.forDigit((b>>>4)&15,16));out.append(Character.forDigit(b&15,16));}return out.toString();}
    private static boolean uuid(String value){try{return UUID.fromString(value).toString().equals(value);}catch(Exception invalid){return false;}}
    static List<Asset> assets(JSONObject journal)throws Exception{
        Set<String> allowed=new HashSet<>(Arrays.asList("schema","kind","operation","assets"));for(Iterator<String> it=journal.keys();it.hasNext();)if(!allowed.contains(it.next()))throw new IOException("Invalid import recovery record");
        if(journal.getInt("schema")!=1||!journal.getString("kind").equals("rookstride-local-import")||!uuid(journal.getString("operation")))throw new IOException("Invalid import recovery record");
        JSONArray entries=journal.getJSONArray("assets");if(entries.length()<1||entries.length()>ConnectionBundle.MAX_CONNECTIONS)throw new IOException("Invalid import recovery record");List<Asset> result=new ArrayList<>();Set<String> ids=new HashSet<>();
        for(int i=0;i<entries.length();i++){JSONObject p=entries.getJSONObject(i);Set<String> fields=new HashSet<>(Arrays.asList("id","protocol","certificate_alias","certificate_hash","new_certificate"));for(Iterator<String> it=p.keys();it.hasNext();)if(!fields.contains(it.next()))throw new IOException("Invalid import recovery record");Asset asset=new Asset(p.getString("id"),p.getString("protocol"),p.getString("certificate_alias"),p.getString("certificate_hash"),p.getBoolean("new_certificate"),journal.getString("operation"));if(!ids.add(asset.id))throw new IOException("Invalid import recovery record");result.add(asset);}
        return result;
    }
}
