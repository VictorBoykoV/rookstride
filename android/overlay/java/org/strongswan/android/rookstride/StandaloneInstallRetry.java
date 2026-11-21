package org.strongswan.android.rookstride;

import android.content.Context;
import org.json.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Exact standalone requests stay in a separate encrypted purpose, never Gateway.data. */
public final class StandaloneInstallRetry {
    private static final Object LOCK=new Object();
    private static final String PURPOSE="standalone-installs.enc",KIND="rookstride-standalone-install";
    private static final Set<String> CONTEXT=new HashSet<>(Arrays.asList("schema","owner","task","request_digest","config_digest","machine","source","instance","port"));
    private StandaloneInstallRetry(){}
    interface Store {ArrayList<Gateway> read()throws Exception;void write(ArrayList<Gateway> records)throws Exception;}
    private static Store store(Context context){final Vault vault=new Vault(context,PURPOSE);return new Store(){public ArrayList<Gateway> read()throws Exception{return vault.read();}public void write(ArrayList<Gateway> value)throws Exception{vault.write(value);}};}
    private interface Checked<T>{T run()throws Exception;}
    private static <T>T guarded(Checked<T> action)throws Exception{synchronized(LOCK){try{return action.run();}catch(Exception failure){throw new IOException("Installation details could not be saved or verified on this phone. The recorded setup was preserved.");}}}
    public static JSONObject startRequest(Context c,Gateway n,JSONObject request)throws Exception{return guarded(()->startRequest(store(c),n,request));}
    public static void rememberJob(Context c,Gateway n,JSONObject response)throws Exception{guarded(()->{rememberJob(store(c),n,response);return null;});}
    public static JSONObject retryRequest(Context c,Gateway n,JSONObject failure)throws Exception{return guarded(()->retryRequest(store(c),n,failure));}
    public static boolean has(Context c,Gateway n)throws Exception{return guarded(()->find(read(store(c)),n)!=null);}
    public static String recordedJob(Context c,Gateway n)throws Exception{return guarded(()->{Gateway r=find(read(store(c)),n);return r==null?"":r.get("job");});}
    public interface AcknowledgedSave {void save()throws Exception;}
    public static void abandonWithMarker(Context c,Gateway n,AcknowledgedSave marker)throws Exception{guarded(()->{abandonWithMarker(store(c),n,marker);return null;});}
    public static void forget(Context c,Gateway n)throws Exception{forgetOwner(c,n.get("id"));}
    static void forgetOwner(Context c,String owner)throws Exception{guarded(()->{forgetOwner(store(c),owner);return null;});}
    private static void need(boolean value)throws IOException{if(!value)throw new IOException("The saved installation retry does not match this server. Review its recorded setup.");}
    private static boolean uuid(String value){try{return UUID.fromString(value).toString().equals(value);}catch(Exception e){return false;}}
    private static boolean hex(String value,int length){return value!=null&&value.matches("[a-f0-9]{"+length+"}");}
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    private static Set<String> keys(JSONObject value){Set<String> result=new HashSet<>();for(Iterator<String> i=value.keys();i.hasNext();)result.add(i.next());return result;}
    private static int integer(JSONObject value,String name)throws Exception{Object n=value.get(name);need(n instanceof Integer||n instanceof Long);long x=((Number)n).longValue();need(x>=Integer.MIN_VALUE&&x<=Integer.MAX_VALUE);return(int)x;}
    private static void owner(Gateway node)throws Exception{need(uuid(node.get("id"))&&!node.isPair()&&!node.data.optBoolean("clientOnly")&&!node.data.optBoolean("adminAccess")&&node.get("coexistPair").isEmpty()&&!node.get("protocol").equals("ikev2")&&SingleProtocols.from(node.get("protocol")).id.equals(node.get("protocol"))&&InputRules.host(node.get("host"))&&InputRules.port(node.port())&&node.get("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}"));}
    private static void request(JSONObject value,String protocol)throws Exception{need(value!=null&&value.getString("action").equals("start")&&value.getString("protocol").equals(protocol)&&!value.has("install_context")&&!value.has("coexist_pair")&&!value.optBoolean("filter_only"));need(canonical(value).getBytes(StandardCharsets.UTF_8).length<=65536);}
    private static ArrayList<Gateway> read(Store store)throws Exception{
        ArrayList<Gateway> records=store.read();need(records.size()<=64);Set<String> ids=new HashSet<>();
        for(Gateway r:records){JSONObject v=r.data;Set<String> allowed=new HashSet<>(Arrays.asList("id","schema","kind","host","ssh_port","fingerprint","protocol","task","request","request_digest","job","context","claim","last_retry"));need(allowed.containsAll(keys(v))&&uuid(r.get("id"))&&ids.add(r.get("id"))&&integer(v,"schema")==1&&r.get("kind").equals(KIND)&&InputRules.host(r.get("host"))&&InputRules.port(integer(v,"ssh_port"))&&r.get("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}")&&hex(r.get("task"),32));request(v.getJSONObject("request"),r.get("protocol"));need(digest(v.getJSONObject("request")).equals(r.get("request_digest")));
            if(v.has("context")){context(v.getJSONObject("context"),r);need(InputRules.job(r.get("job")));}else need(r.get("job").isEmpty()&&!v.has("claim"));
            if(v.has("last_retry")){JSONObject ack=v.getJSONObject("last_retry");need(keys(ack).equals(new HashSet<>(Arrays.asList("job","retry_of","nonce")))&&ack.getString("job").equals(r.get("job"))&&InputRules.job(ack.getString("retry_of"))&&hex(ack.getString("nonce"),32));}
            if(v.has("claim")){JSONObject claim=v.getJSONObject("claim");need(keys(claim).equals(new HashSet<>(Arrays.asList("job","nonce","failed_receipt_sha256")))&&claim.getString("job").equals(r.get("job"))&&hex(claim.getString("nonce"),32)&&hex(claim.getString("failed_receipt_sha256"),64));}
        }return records;
    }
    private static Gateway find(ArrayList<Gateway> records,Gateway node)throws Exception{
        for(Gateway r:records)if(r.get("id").equals(node.get("id"))){owner(node);need(r.get("host").equalsIgnoreCase(node.get("host"))&&r.data.getInt("ssh_port")==node.port()&&r.get("fingerprint").equals(node.get("fingerprint"))&&r.get("protocol").equals(node.get("protocol")));if(r.data.has("context")&&!node.get("machine").isEmpty())need(node.get("machine").equals(r.data.getJSONObject("context").getString("machine")));return r;}return null;
    }
    private static JSONObject smallContext(Gateway r)throws Exception{return new JSONObject().put("schema",1).put("owner",r.get("id")).put("task",r.get("task"));}
    private static void context(JSONObject value,Gateway r)throws Exception{
        need(keys(value).equals(CONTEXT)&&integer(value,"schema")==1&&value.getString("owner").equals(r.get("id"))&&value.getString("task").equals(r.get("task"))&&value.getString("request_digest").equals(r.get("request_digest"))&&hex(value.getString("config_digest"),64)&&hex(value.getString("machine"),64)&&hex(value.getString("source"),64)&&hex(value.getString("instance"),32)&&InputRules.port(integer(value,"port")));
        if(r.data.getJSONObject("request").has("port"))need(integer(r.data.getJSONObject("request"),"port")==value.getInt("port"));
    }
    static JSONObject startRequest(Store store,Gateway node,JSONObject original)throws Exception{
        owner(node);ArrayList<Gateway> records=read(store);Gateway r=find(records,node);
        if(r==null){request(original,node.get("protocol"));need(node.get("job").isEmpty()&&records.size()<64);JSONObject v=new JSONObject().put("id",node.get("id")).put("schema",1).put("kind",KIND).put("host",node.get("host")).put("ssh_port",node.port()).put("fingerprint",node.get("fingerprint")).put("protocol",node.get("protocol")).put("task",UUID.randomUUID().toString().replace("-","")).put("request",copy(original)).put("request_digest",digest(original));r=new Gateway(v);records.add(r);store.write(records);}
        else if(original!=null&&original.length()>0){request(original,node.get("protocol"));need(r.get("request_digest").equals(digest(original)));}
        need(!r.data.has("claim"));return copy(r.data.getJSONObject("request")).put("install_context",smallContext(r));
    }
    static void rememberJob(Store store,Gateway node,JSONObject response)throws Exception{
        ArrayList<Gateway> records=read(store);Gateway r=find(records,node);need(r!=null);JSONObject next=response.getJSONObject("install_context");context(next,r);if(!node.get("machine").isEmpty())need(node.get("machine").equals(next.getString("machine")));String job=response.getString("job");need(InputRules.job(job)&&integer(response.getJSONObject("plan"),"port")==next.getInt("port")&&response.getString("bundle").equals(next.getString("source")));
        if(r.data.has("context"))need(canonical(r.data.getJSONObject("context")).equals(canonical(next)));
        if(r.get("job").equals(job)){
            need(!r.data.has("claim"));if(response.has("retry_of")||response.has("nonce")){JSONObject ack=r.data.getJSONObject("last_retry");need(response.getString("retry_of").equals(ack.getString("retry_of"))&&response.getString("nonce").equals(ack.getString("nonce")));}else need(!r.data.has("last_retry"));return;
        }
        if(!r.get("job").isEmpty()){need(r.data.has("claim"));JSONObject claim=r.data.getJSONObject("claim");need(response.getString("retry_of").equals(claim.getString("job"))&&response.getString("nonce").equals(claim.getString("nonce")));r.data.put("last_retry",new JSONObject().put("job",job).put("retry_of",claim.getString("job")).put("nonce",claim.getString("nonce")));}
        else need(!response.has("retry_of")&&!response.has("nonce")&&!r.data.has("claim"));
        r.set("job",job);r.data.put("context",copy(next));r.data.remove("claim");store.write(records);
    }
    static JSONObject retryRequest(Store store,Gateway node,JSONObject failure)throws Exception{
        ArrayList<Gateway> records=read(store);Gateway r=find(records,node);need(r!=null&&r.data.has("context")&&failure.getString("state").equals("failed")&&failure.getString("job").equals(r.get("job"))&&hex(failure.getString("failed_receipt_sha256"),64));
        JSONObject typed=failure.getJSONObject("retryable");Set<String> expected=new HashSet<>(CONTEXT);expected.add("reason");need(keys(typed).equals(expected)&&typed.getString("reason").equals("acquisition-unavailable"));JSONObject originalContext=copy(typed);originalContext.remove("reason");context(originalContext,r);need(canonical(originalContext).equals(canonical(r.data.getJSONObject("context"))));
        JSONObject claim=r.data.optJSONObject("claim");if(claim==null){claim=new JSONObject().put("job",r.get("job")).put("nonce",UUID.randomUUID().toString().replace("-","")).put("failed_receipt_sha256",failure.getString("failed_receipt_sha256"));r.data.put("claim",claim);store.write(records);}else need(claim.getString("job").equals(failure.getString("job"))&&claim.getString("failed_receipt_sha256").equals(failure.getString("failed_receipt_sha256")));
        return new JSONObject().put("action","retry").put("job",claim.getString("job")).put("nonce",claim.getString("nonce")).put("install_context",smallContext(r)).put("request",copy(r.data.getJSONObject("request"))).put("expected_config_digest",r.data.getJSONObject("context").getString("config_digest")).put("failed_receipt_sha256",claim.getString("failed_receipt_sha256"));
    }
    static void abandonWithMarker(Store store,Gateway node,AcknowledgedSave marker)throws Exception{
        need(uuid(node.get("id"))&&marker!=null);ArrayList<Gateway> records=read(store);find(records,node);
        // The caller must acknowledge the fresh catalog marker before this secret
        // is cleared. Any failure keeps the coordinator's attention record intact.
        marker.save();boolean removed=records.removeIf(r->r.get("id").equals(node.get("id")));if(removed)store.write(records);
    }
    static void forgetOwner(Store store,String id)throws Exception{need(uuid(id));ArrayList<Gateway> records=read(store);boolean removed=records.removeIf(r->r.get("id").equals(id));if(removed)store.write(records);}
    /** Cross-language canonical original request: sorted keys, no slash/non-ASCII escaping. */
    static String canonical(Object value)throws Exception{StringBuilder out=new StringBuilder();canonical(value,out,0);return out.toString();}
    private static void canonical(Object value,StringBuilder out,int depth)throws Exception{
        need(depth<=16);if(value==null||value==JSONObject.NULL){out.append("null");return;}if(value instanceof String){quote((String)value,out);return;}if(value instanceof Boolean){out.append(value);return;}if(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long){out.append(value);return;}
        if(value instanceof JSONObject){JSONObject object=(JSONObject)value;ArrayList<String> names=new ArrayList<>(keys(object));need(names.size()<=256);names.sort((a,b)->{int x=0,y=0;while(x<a.length()&&y<b.length()){int ac=a.codePointAt(x),bc=b.codePointAt(y);if(ac!=bc)return Integer.compare(ac,bc);x+=Character.charCount(ac);y+=Character.charCount(bc);}return Integer.compare(a.length()-x,b.length()-y);});out.append('{');boolean first=true;for(String key:names){if(!first)out.append(',');first=false;quote(key,out);out.append(':');canonical(object.get(key),out,depth+1);}out.append('}');return;}
        if(value instanceof JSONArray){JSONArray array=(JSONArray)value;need(array.length()<=256);out.append('[');for(int i=0;i<array.length();i++){if(i>0)out.append(',');canonical(array.get(i),out,depth+1);}out.append(']');return;}throw new IOException("Unsupported installation request value");
    }
    private static void quote(String text,StringBuilder out)throws Exception{
        out.append('"');for(int i=0;i<text.length();i++){char c=text.charAt(i);if(Character.isHighSurrogate(c)){need(i+1<text.length()&&Character.isLowSurrogate(text.charAt(i+1)));out.append(c).append(text.charAt(++i));continue;}need(!Character.isLowSurrogate(c));switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;default:if(c<32){out.append("\\u00").append(Character.forDigit(c>>4,16)).append(Character.forDigit(c&15,16));}else out.append(c);}}out.append('"');
    }
    static String digest(JSONObject value)throws Exception{byte[] hash=MessageDigest.getInstance("SHA-256").digest(canonical(value).getBytes(StandardCharsets.UTF_8));StringBuilder out=new StringBuilder();for(byte b:hash)out.append(Character.forDigit((b>>>4)&15,16)).append(Character.forDigit(b&15,16));return out.toString();}
}
