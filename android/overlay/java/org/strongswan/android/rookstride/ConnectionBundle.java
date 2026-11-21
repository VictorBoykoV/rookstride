package org.strongswan.android.rookstride;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.strongswan.android.rookstride.engine.NativeProfiles;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.*;

/** Bounded ordinary-client collection. Parsing has no catalog, key-store or server effects. */
public final class ConnectionBundle {
    public static final String EXTENSION=".rookbundle", MIME="application/json", KIND="rookstride-connections";
    public static final int MAX_CONNECTIONS=16, MAX_BYTES=4*1024*1024;
    private static final Set<String> FORMATS=new HashSet<>(Arrays.asList("ikev2","awg","openvpn","xray","xhttp","hysteria2","outline","shadowsocks","trusttunnel","naive"));
    private ConnectionBundle(){}

    public static String pack(List<JSONObject> profiles)throws Exception {
        try{return packValidated(profiles);}catch(BundleException safe){throw safe;}catch(Exception rejected){throw invalid("A selected VPN connection is invalid or incomplete");}
    }
    private static String packValidated(List<JSONObject> profiles)throws Exception {
        if(profiles==null||profiles.isEmpty()||profiles.size()>MAX_CONNECTIONS)throw invalid("Choose between 1 and 16 VPN connections");
        JSONArray entries=new JSONArray();Set<String> seen=new HashSet<>();long bytes=0;
        for(JSONObject profile:profiles){JSONObject entry=validateEntry(profile,seen);bytes+=entry.toString().getBytes(StandardCharsets.UTF_8).length+1;if(bytes>MAX_BYTES)throw invalid("The connection collection is too large");entries.put(entry);}
        String result=new JSONObject().put("schema",1).put("kind",KIND).put("connections",entries).toString();
        if(result.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw invalid("The connection collection is too large");
        return result;
    }

    public static List<JSONObject> parse(String text)throws Exception {
        try{return parseValidated(text);}catch(BundleException safe){throw safe;}catch(Exception rejected){throw invalid("Invalid connection collection. No connections were added.");}
    }
    private static List<JSONObject> parseValidated(String text)throws Exception {
        if(text==null||text.isEmpty()||text.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw invalid("The connection collection is empty or too large");
        StrictJson.check(text);JSONObject root=new JSONObject(text);only(root,"schema","kind","connections");
        if(integer(root,"schema")!=1||!KIND.equals(string(root,"kind")))throw invalid("Choose a supported Rookstride connection collection");
        Object raw=root.get("connections");if(!(raw instanceof JSONArray))throw invalid("Invalid connection collection");JSONArray entries=(JSONArray)raw;
        if(entries.length()<1||entries.length()>MAX_CONNECTIONS)throw invalid("A collection must contain between 1 and 16 connections");
        List<JSONObject> result=new ArrayList<>();Set<String> seen=new HashSet<>();
        for(int i=0;i<entries.length();i++){Object entry=entries.get(i);if(!(entry instanceof JSONObject))throw invalid("Invalid connection entry");result.add(validateEntry((JSONObject)entry,seen));}
        return result;
    }

    private static JSONObject validateEntry(JSONObject source,Set<String> seen)throws Exception {
        if(source==null)throw invalid("Invalid connection entry");only(source,"format","name","content","display_name");
        String format=string(source,"format"),name=string(source,"name"),content=string(source,"content");
        if(!FORMATS.contains(format))throw invalid("Unsupported VPN connection format");
        // Reconstruct an exact ordinary envelope; never carry Gateway/administrator metadata.
        JSONObject entry=new JSONObject().put("format",format).put("name",name).put("content",content);
        if(source.has("display_name")){String label=string(source,"display_name");if(label.codePointCount(0,label.length())>100||label.codePoints().allMatch(c->Character.isWhitespace(c)||Character.isSpaceChar(c))||label.codePoints().anyMatch(c->Character.isISOControl(c)||Character.getType(c)==Character.FORMAT||c==0x2028||c==0x2029||c>=0xD800&&c<=0xDFFF))throw invalid("Use a connection label of 1–100 visible characters");entry.put("display_name",label);}
        ConnectionExport.fromResponse(entry);
        if(format.equals("ikev2"))validateIke(content);
        else{
            if((format.equals("openvpn")&&content.trim().startsWith("{"))||SingleProtocols.from(format).worker())StrictJson.check(content);
            NativeProfiles.validate(format,content);
            if(format.equals("openvpn")&&!content.trim().startsWith("{")&&java.util.regex.Pattern.compile("(?m)^\\s*auth-user-pass(?:\\s|$)").matcher(content).find())throw invalid("Include the existing OpenVPN username and password before sharing this collection");
        }
        MessageDigest digest=MessageDigest.getInstance("SHA-256");digest.update(format.getBytes(StandardCharsets.US_ASCII));digest.update((byte)0);byte[] hash=digest.digest(content.getBytes(StandardCharsets.UTF_8));
        if(!seen.add(Base64.getEncoder().encodeToString(hash)))throw invalid("The same VPN connection was selected more than once");
        return entry;
    }

    private static void validateIke(String content)throws Exception {
        StrictJson.check(content);JSONObject p=new JSONObject(content);only(p,"uuid","name","type","remote","local","mtu","split-tunneling");
        if(!string(p,"type").equals("ikev2-eap"))throw invalid("This collection supports IKEv2 username/password connections");
        if(p.has("uuid")){String id=string(p,"uuid");if(!UUID.fromString(id).toString().equalsIgnoreCase(id))throw invalid("Invalid IKEv2 connection identifier");}
        if(p.has("name"))label(string(p,"name"),120);
        JSONObject remote=p.getJSONObject("remote"),local=p.getJSONObject("local");only(remote,"addr","port","id","cert","certreq");only(local,"eap_id","shared_secret");
        if(!InputRules.host(string(remote,"addr")))throw invalid("Invalid IKEv2 server address");
        if(remote.has("port")&&!InputRules.port(integer(remote,"port")))throw invalid("Invalid IKEv2 server port");
        if(remote.has("id"))label(string(remote,"id"),1024);
        if(remote.has("certreq")&&(!Boolean.FALSE.equals(remote.get("certreq"))))throw invalid("Import this advanced IKEv2 profile separately");
        if(remote.has("cert"))CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(string(remote,"cert"))));
        if(!InputRules.username(string(local,"eap_id"))||!InputRules.vpnPassword(string(local,"shared_secret")))throw invalid("Include the existing IKEv2 username and password before sharing this collection");
        if(p.has("mtu")&&integer(p,"mtu")!=1280)throw invalid("Import this advanced IKEv2 profile separately");
        if(p.has("split-tunneling")){JSONObject split=p.getJSONObject("split-tunneling");only(split,"block-ipv4","block-ipv6");for(String field:new String[]{"block-ipv4","block-ipv6"})if(!Boolean.TRUE.equals(split.get(field)))throw invalid("Import this advanced IKEv2 routing profile separately");}
    }

    private static void only(JSONObject value,String... fields)throws IOException {
        Set<String> allowed=new HashSet<>(Arrays.asList(fields));for(Iterator<String> keys=value.keys();keys.hasNext();)if(!allowed.contains(keys.next()))throw invalid("Unsupported connection collection option");
    }
    private static String string(JSONObject value,String key)throws Exception {Object raw=value.get(key);if(!(raw instanceof String)||((String)raw).isEmpty())throw invalid("Invalid connection collection value");return (String)raw;}
    private static int integer(JSONObject value,String key)throws Exception {Object raw=value.get(key);if(!(raw instanceof Integer)&&!(raw instanceof Long))throw invalid("Invalid connection collection number");long n=((Number)raw).longValue();if(n<Integer.MIN_VALUE||n>Integer.MAX_VALUE)throw invalid("Invalid connection collection number");return (int)n;}
    private static void label(String value,int limit)throws IOException {if(value.length()>limit||value.codePoints().anyMatch(c->Character.isISOControl(c)||c>=0xD800&&c<=0xDFFF))throw invalid("Invalid connection label");}
    private static final class BundleException extends IOException {BundleException(String message){super(message);}}
    private static IOException invalid(String message){return new BundleException(message);}

    /** Android's JSONTokener accepts duplicate members and non-JSON syntax.
     * Check the small bounded document's grammar before platform JSON decoding. */
    private static final class StrictJson {
        final String text;int pos;
        StrictJson(String text){this.text=text;}
        static void check(String text)throws Exception {StrictJson reader=new StrictJson(text);reader.value(0);reader.space();if(reader.pos!=text.length())throw invalid("Unexpected data after the connection collection");}
        void space(){while(pos<text.length()&&" \t\r\n".indexOf(text.charAt(pos))>=0)pos++;}
        boolean take(char c){space();if(pos<text.length()&&text.charAt(pos)==c){pos++;return true;}return false;}
        void need(char c)throws IOException {if(!take(c))throw invalid("Malformed connection collection JSON");}
        void value(int depth)throws Exception {
            if(depth>16)throw invalid("The connection collection is too deeply nested");space();if(pos>=text.length())throw invalid("Incomplete connection collection JSON");char c=text.charAt(pos);
            if(c=='{'){pos++;Set<String> keys=new HashSet<>();if(take('}'))return;do{space();int start=pos;quoted();String key=(String)new JSONTokener(text.substring(start,pos)).nextValue();if(!keys.add(key))throw invalid("Duplicate connection collection field");need(':');value(depth+1);}while(take(','));need('}');return;}
            if(c=='['){pos++;if(take(']'))return;do{value(depth+1);}while(take(','));need(']');return;}
            if(c=='"'){quoted();return;}
            for(String literal:new String[]{"true","false","null"})if(text.startsWith(literal,pos)){pos+=literal.length();return;}
            number();
        }
        void quoted()throws IOException {
            if(pos>=text.length()||text.charAt(pos++)!='"')throw invalid("A connection collection field must be quoted");
            while(pos<text.length()){char c=text.charAt(pos++);if(c=='"')return;if(c<32)throw invalid("Invalid control character in connection collection");if(c=='\\'){if(pos>=text.length())break;char e=text.charAt(pos++);if(e=='u'){for(int i=0;i<4;i++)if(pos>=text.length()||!hex(text.charAt(pos++)))throw invalid("Invalid connection collection escape");}else if("\"\\/bfnrt".indexOf(e)<0)throw invalid("Invalid connection collection escape");}}
            throw invalid("Unclosed connection collection string");
        }
        void number()throws IOException {
            int start=pos;if(pos<text.length()&&text.charAt(pos)=='-')pos++;
            if(pos>=text.length())throw invalid("Invalid connection collection number");
            if(text.charAt(pos)=='0')pos++;else{if(text.charAt(pos)<'1'||text.charAt(pos)>'9')throw invalid("Invalid connection collection JSON");while(pos<text.length()&&digit(text.charAt(pos)))pos++;}
            if(pos<text.length()&&text.charAt(pos)=='.'){pos++;int digits=pos;while(pos<text.length()&&digit(text.charAt(pos)))pos++;if(pos==digits)throw invalid("Invalid connection collection number");}
            if(pos<text.length()&&(text.charAt(pos)=='e'||text.charAt(pos)=='E')){pos++;if(pos<text.length()&&(text.charAt(pos)=='+'||text.charAt(pos)=='-'))pos++;int digits=pos;while(pos<text.length()&&digit(text.charAt(pos)))pos++;if(pos==digits)throw invalid("Invalid connection collection number");}
            if(pos==start)throw invalid("Invalid connection collection JSON");
        }
        boolean digit(char c){return c>='0'&&c<='9';}
        boolean hex(char c){return digit(c)||c>='a'&&c<='f'||c>='A'&&c<='F';}
    }
}
