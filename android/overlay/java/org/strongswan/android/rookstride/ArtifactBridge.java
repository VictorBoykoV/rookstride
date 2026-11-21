package org.strongswan.android.rookstride;

import org.json.*;
import java.io.*;
import java.util.*;

/** Pre-job public archive preparation. This class never starts/retries an installation. */
public final class ArtifactBridge {
    public interface Source {
        PublicArtifactCatalog catalog()throws Exception;
        InputStream openBundle()throws Exception;
        File cacheDirectory()throws Exception;
        ArtifactDownloader.Transport transport()throws Exception;
    }
    interface Endpoint extends AutoCloseable {
        JSONObject identity()throws Exception;
        JSONObject request(JSONObject request)throws Exception;
        void upload(PublicArtifactCatalog.Asset asset,String nonce,File verified)throws Exception;
        InputStream cached(PublicArtifactCatalog.Asset asset)throws Exception;
        void clean(String nonce,String id)throws Exception;
        void close();
    }
    static final class PeerUnavailable extends IOException {PeerUnavailable(Throwable e){super("The other server cannot supply this public component.",e);}}
    static final class UnknownResult extends IOException {UnknownResult(Throwable e){super("The public component cache reply was interrupted.",e);}}
    private ArtifactBridge(){}
    static void beforeDispatch()throws InterruptedIOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("Server action was interrupted before dispatch.");}
    static List<String> required(String kind,JSONObject request)throws Exception{
        List<String> result=new ArrayList<>();String action=request.optString("action");
        if(kind.equals("single")&&(action.equals("start")||action.equals("retry"))){
            JSONObject original=action.equals("retry")?request.getJSONObject("request"):request;
            result.add("adguard");if(!original.optBoolean("filter_only")&&xray(original.optString("protocol")))result.add("xray");
            if(!original.optBoolean("filter_only")&&original.optString("protocol").equals("trusttunnel"))result.add("trusttunnel");
        }else if(kind.equals("deploy")&&request.optString("mode").equals("install"))result.add("adguard");
        else if(kind.equals("pair")&&request.optString("command").equals("start")){
            String role=request.optString("role"),entry=request.optString("entry_protocol","ikev2"),exit=request.optString("exit_protocol","awg");
            boolean modern=request.optString("engine").equals("native-v2")||!entry.equals("ikev2")||!exit.equals("awg");
            if(modern&&(action.equals("bootstrap")||role.equals("entry")&&action.equals("configure"))){
                if(role.equals("exit")){result.add("adguard");if(xray(exit))result.add("xray");if(exit.equals("trusttunnel"))result.add("trusttunnel");}
                else if(role.equals("entry")){if(xray(entry)||xray(exit))result.add("xray");if(entry.equals("trusttunnel"))result.add("trusttunnel");}
            }else if(!modern&&role.equals("exit")&&action.equals("configure"))result.add("adguard");
        }
        return result;
    }
    private static boolean xray(String protocol){return protocol.equals("xray")||protocol.equals("xhttp");}
    static void prepare(Source source,Endpoint target,Endpoint peer,List<String> ids)throws Exception{
        if(ids.isEmpty())return;PublicArtifactCatalog catalog=source.catalog();JSONObject identity=checkedIdentity(target.identity());String architecture=identity.getString("architecture");
        LinkedHashSet<String> required=new LinkedHashSet<>(ids);if(required.size()!=ids.size())throw invalid();for(String id:required)catalog.asset(id,architecture);
        JSONObject request=base(catalog,identity,"prepare").put("ids",new JSONArray(ids)).put("reuse_installed",true);JSONObject prepared=target.request(request);binding(prepared,catalog,identity);
        Set<String> ready=list(prepared.getJSONArray("ready"),required),reused=list(prepared.getJSONArray("reused"),Collections.singleton("adguard")),pending=list(prepared.getJSONArray("phone_required"),required);Set<String> seen=new HashSet<>(ready);for(String id:reused)if(!required.contains(id)||!seen.add(id))throw invalid();for(String id:pending)if(!seen.add(id))throw invalid();if(!seen.equals(required))throw invalid();
        if(pending.isEmpty())return;ArtifactDownloader local=new ArtifactDownloader(catalog,source.cacheDirectory(),null);
        for(String id:pending){
            if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("Public component preparation was interrupted.");PublicArtifactCatalog.Asset asset=catalog.asset(id,architecture);File verified=local.cached(asset);
            if(verified==null&&peer!=null){
                try{
                    JSONObject observedPeer=peer.identity(),peerIdentity=checkedIdentity(observedPeer);
                    if(Boolean.TRUE.equals(observedPeer.opt("cache_readable"))&&peerIdentity.getString("architecture").equals(architecture)&&!peerIdentity.getString("machine").equals(identity.getString("machine"))){
                        JSONObject available=peer.request(base(catalog,peerIdentity,"prepare").put("ids",new JSONArray().put(id)).put("reuse_installed",false));binding(available,catalog,peerIdentity);if(available.getJSONArray("reused").length()!=0)throw invalid();
                        Set<String> peerReady=list(available.getJSONArray("ready"),Collections.singleton(id)),peerPending=list(available.getJSONArray("phone_required"),Collections.singleton(id));
                        if(peerReady.size()+peerPending.size()!=1)throw invalid();
                        if(peerReady.contains(id))verified=local.accept(asset,()->peer.cached(asset));
                    }
                }catch(PeerUnavailable unavailable){/* A readable same-architecture peer is optional. */}
            }
            if(verified==null)verified=new ArtifactDownloader(catalog,source.cacheDirectory(),source.transport()).acquire(asset);
            ArtifactDownloader.verify(verified,asset);String nonce=UUID.randomUUID().toString().replace("-","");target.upload(asset,nonce,verified);
            boolean acknowledged=false;
            JSONObject committed;
            try{committed=target.request(base(catalog,identity,"commit").put("id",id).put("nonce",nonce));}
            catch(UnknownResult unknown){
                // A lost commit reply can only be reconciled by a read-only cache check.
                JSONObject status;
                try{status=target.request(base(catalog,identity,"status").put("id",id));binding(status,catalog,identity);if(!strictReady(status,id))throw unknown;acknowledged=true;}catch(Exception refused){if(refused!=unknown)unknown.addSuppressed(refused);throw unknown;}
                committed=null;
            }
            if(committed!=null){binding(committed,catalog,identity);if(!strictReady(committed,id))throw invalid();acknowledged=true;}
            if(acknowledged)try{target.clean(nonce,id);}catch(Exception ignored){/* Retain only our public upload if cleanup is unavailable. */}
        }
    }
    static JSONObject checkedIdentity(JSONObject identity)throws Exception{
        String arch=identity.getString("architecture"),machine=identity.getString("machine");if(!(arch.equals("x86_64")||arch.equals("aarch64"))||!machine.matches("[a-f0-9]{64}"))throw invalid();return new JSONObject().put("architecture",arch).put("machine",machine);
    }
    static JSONObject base(PublicArtifactCatalog catalog,JSONObject identity,String action)throws Exception{return new JSONObject().put("schema",1).put("action",action).put("catalog_sha256",catalog.sha256).put("architecture",identity.getString("architecture")).put("machine",identity.getString("machine"));}
    static void binding(JSONObject result,PublicArtifactCatalog catalog,JSONObject identity)throws Exception{
        if(!(result.opt("schema") instanceof Number)||result.optDouble("schema")!=1||!catalog.sha256.equals(result.optString("catalog_sha256"))||!identity.getString("machine").equals(result.optString("machine"))||!identity.getString("architecture").equals(result.optString("architecture")))throw invalid();
    }
    private static boolean strictReady(JSONObject result,String id)throws Exception{if(!id.equals(result.optString("id"))||!(result.get("ready") instanceof Boolean))throw invalid();return result.getBoolean("ready");}
    private static Set<String> list(JSONArray values,Set<String> allowed)throws Exception{Set<String> result=new LinkedHashSet<>();for(int i=0;i<values.length();i++){Object value=values.get(i);if(!(value instanceof String)||!allowed.contains(value)||!result.add((String)value))throw invalid();}return result;}
    private static IOException invalid(){return new IOException("The server did not confirm this app's verified public component identity.");}
}
