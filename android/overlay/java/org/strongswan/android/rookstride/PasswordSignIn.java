package org.strongswan.android.rookstride;

import org.json.*;
import java.io.IOException;

/** Portable username/password definitions. Public roots are independent of a server rebuild. */
public final class PasswordSignIn {
    private PasswordSignIn(){}
    public static boolean supported(String protocol){return java.util.Arrays.asList("ikev2","openvpn","hysteria2","trusttunnel","naive").contains(protocol);}
    public static String tlsName(String host){return host.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")?host.replace('.','-')+".sslip.io":host.toLowerCase(java.util.Locale.ROOT);}
    public static JSONObject endpoint(String address,int defaultPort)throws Exception{
        if(address==null||!address.equals(address.trim()))throw new IOException("Enter the VPN IP address or domain");
        String host=address;int port=defaultPort;int colon=address.lastIndexOf(':');
        if(colon>=0){host=address.substring(0,colon);try{port=Integer.parseInt(address.substring(colon+1));}catch(NumberFormatException e){throw new IOException("Check the VPN address and port");}}
        if(!InputRules.host(host)||!InputRules.port(port)||host.contains(":"))throw new IOException("Enter an IPv4 address or domain, optionally followed by :port");
        return new JSONObject().put("host",host).put("port",port);
    }
    public static JSONObject definition(String protocol,String address,String login,String password,String roots)throws Exception{
        if(!supported(protocol)||!InputRules.username(login)||!InputRules.vpnPassword(password))throw new IOException("Check the VPN username and password (nonempty, up to 127 UTF-8 bytes)");
        JSONObject endpoint=endpoint(address,SingleProtocols.from(protocol).port);String host=endpoint.getString("host");int port=endpoint.getInt("port");
        if(protocol.equals("ikev2"))return new JSONObject().put("type","ikev2-eap").put("name","IKEv2 · "+host).put("remote",new JSONObject().put("addr",host).put("port",port).put("certreq",false)).put("local",new JSONObject().put("eap_id",login)).put("mtu",1280).put("split-tunneling",new JSONObject().put("block-ipv4",true).put("block-ipv6",true));
        if(roots==null||roots.isEmpty()||roots.length()>450000)throw new IOException("The phone’s trusted certificate store is unavailable");
        String name=tlsName(host);
        if(protocol.equals("openvpn")){
            String config="client\ndev tun\ntun-mtu 1280\nproto tcp-client\nremote "+host+" "+port+"\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nverify-x509-name "+name+" name\nauth-user-pass\nauth-nocache\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM\nredirect-gateway def1 ipv6\nblock-ipv6\nverb 3\n<ca>\n"+roots.trim()+"\n</ca>\n";
            return openVpn(config,login,password);
        }
        return new JSONObject().put("schema",1).put("protocol",protocol).put("access_mode","password").put("server",host).put("port",port).put("server_name",name).put("certificate",roots).put("login",login).put("password",password);
    }
    public static JSONObject openVpn(String config,String login,String password)throws Exception{
        if(!InputRules.username(login)||!InputRules.vpnPassword(password))throw new IOException("Enter the VPN username and password");
        return new JSONObject().put("schema",1).put("protocol","openvpn").put("access_mode","password").put("config",config).put("login",login).put("password",password);
    }
    public static String protocol(JSONObject profile){
        if(profile==null)return "";
        if(profile.optString("type").equals("ikev2-eap"))return "ikev2";
        return profile.optString("format",profile.optString("protocol"));
    }
    /** Only password-capable JSON payloads may be decoded here; INI and URI exports are opaque. */
    private static JSONObject passwordPayload(JSONObject profile)throws Exception{
        String protocol=protocol(profile);
        if(!supported(protocol))return null;
        if(profile.has("content")&&!protocol.equals("openvpn")){
            JSONObject payload=new JSONObject(profile.getString("content"));
            if(!protocol.equals(payload.optString("protocol")))throw new IOException("The connection format does not match its VPN protocol");
            return payload;
        }
        return profile;
    }
    public static boolean passwordBased(JSONObject profile)throws Exception{
        if(protocol(profile).equals("ikev2"))return true;
        JSONObject payload=passwordPayload(profile);
        return payload!=null&&payload.optString("access_mode").equals("password");
    }
    public static String login(JSONObject profile)throws Exception{
        if(protocol(profile).equals("ikev2")){
            JSONObject local=profile.optJSONObject("local");return local==null?"":local.optString("eap_id");
        }
        JSONObject payload=passwordPayload(profile);return payload==null?"":payload.optString("login");
    }
    /** A chosen/re-entered VPN secret is attached only to the account explicitly selected by the UI. */
    public static JSONObject withKnownPassword(JSONObject profile,String expectedLogin,String password)throws Exception{
        JSONObject result=new JSONObject(profile.toString());
        if(password==null||password.isEmpty())return result;
        if(!passwordBased(profile))return result;
        if(!InputRules.username(expectedLogin)||!expectedLogin.equals(login(profile)))throw new IOException("The connection belongs to a different VPN user. Reload that user's connection before sharing.");
        if(!InputRules.vpnPassword(password))throw new IOException("Enter the existing VPN password, up to 127 UTF-8 bytes");
        if(protocol(profile).equals("ikev2"))result.getJSONObject("local").put("shared_secret",password);
        else{
            JSONObject payload=passwordPayload(result);
            if(!payload.optString("access_mode").equals("password"))return result;
            payload.put("password",password);
            if(result.has("content")&&!protocol(profile).equals("openvpn"))result.put("content",payload.toString());
        }
        return result;
    }
    public static String share(JSONObject profile,String knownPassword)throws Exception{
        if(profile==null)return null;
        String protocol=protocol(profile);
        if(!supported(protocol))return null;
        if(protocol.equals("ikev2"))return IkeSignInDetails.from(withKnownPassword(profile,login(profile),knownPassword));
        JSONObject p=passwordPayload(profile);
        if(!p.optString("access_mode").equals("password"))return null;
        if(protocol.equals("openvpn")&&p.has("config")){
            java.util.regex.Matcher remote=java.util.regex.Pattern.compile("(?m)^remote\\s+([^\\s]+)\\s+([0-9]+)\\s*$").matcher(p.getString("config"));
            if(!remote.find())return null;p=new JSONObject(p.toString()).put("server",remote.group(1)).put("port",Integer.parseInt(remote.group(2)));
        }
        String secret=p.optString("password",knownPassword==null?"":knownPassword);
        if(secret==null||secret.isEmpty())return null;
        String host=p.getString("server");int port=p.getInt("port");
        return "VPN type: "+SingleProtocols.from(protocol).title+"\nServer: "+host+":"+port+"\nUsername: "+p.getString("login")+"\nPassword: "+secret+"\nUse username/password sign-in in Rookstride. No administrator access or client certificate is needed.";
    }
}
