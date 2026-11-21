package org.strongswan.android.rookstride.engine;

import org.json.*;
import java.net.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Only supported, self-contained connection formats enter a native engine. */
public final class NativeProfiles {
    public static void validate(String protocol,String text)throws Exception{
        if(text==null||text.isEmpty()||text.length()>512000||text.indexOf('\0')>=0)throw new IOException("Invalid VPN profile");
        switch(protocol){
            case "awg":org.amnezia.awg.config.Config.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));break;
            case "xray":case "xhttp":Map<String,String> v=vless(text);if(protocol.equals("xhttp")!=v.getOrDefault("type","tcp").equals("xhttp"))throw new IOException("VLESS connection method does not match this profile");break;
            case "hysteria2":case "outline":case "shadowsocks":case "trusttunnel":case "naive":workerProfile(protocol,text);break;
            case "openvpn":validateOpenVpn(text);break;
            default:throw new IOException("Unsupported VPN protocol");
        }
    }
    public static Map<String,String> vless(String text)throws Exception{
        URI uri=new URI(text.trim());if(!"vless".equals(uri.getScheme())||uri.getHost()==null||uri.getPort()<1||uri.getPort()>65535||uri.getUserInfo()==null)throw new IOException("Choose a VLESS connection link");
        String id=uri.getUserInfo();if(!UUID.fromString(id).toString().equalsIgnoreCase(id))throw new IOException("Invalid VLESS identifier");
        Map<String,String> q=new HashMap<>();if(uri.getRawQuery()!=null)for(String item:uri.getRawQuery().split("&")){String[] kv=item.split("=",2);String key=URLDecoder.decode(kv[0],"UTF-8");if(q.containsKey(key))throw new IOException("Duplicate VLESS option");q.put(key,kv.length==2?URLDecoder.decode(kv[1],"UTF-8"):"");}
        if(!"reality".equals(q.get("security"))||!Arrays.asList("tcp","xhttp").contains(q.getOrDefault("type","tcp")))throw new IOException("Choose a supported REALITY connection");
        if(!q.getOrDefault("pbk","").matches("[A-Za-z0-9_-]{43}")||q.getOrDefault("sni","").isEmpty()||!q.getOrDefault("sid","").matches("[a-fA-F0-9]{0,16}"))throw new IOException("Incomplete REALITY profile");
        String flow=q.getOrDefault("flow","");if(!flow.isEmpty()&&!flow.equals("xtls-rprx-vision")&&!flow.equals("xtls-rprx-vision-udp443"))throw new IOException("Unsupported VLESS flow");
        if(q.getOrDefault("type","tcp").equals("xhttp")&&(!flow.isEmpty()||!q.getOrDefault("path","").matches("/[a-f0-9]{48}")||!q.getOrDefault("mode","auto").equals("auto")))throw new IOException("Invalid XHTTP connection options");
        q.put("host",uri.getHost());q.put("port",String.valueOf(uri.getPort()));q.put("id",id);return q;
    }
    public static JSONObject xray(String link,int socksPort,String user,String password)throws Exception{
        Map<String,String> p=vless(link);
        JSONObject account=new JSONObject().put("id",p.get("id")).put("encryption","none").put("flow",p.getOrDefault("flow",""));
        JSONObject reality=new JSONObject().put("serverName",p.get("sni")).put("fingerprint",p.getOrDefault("fp","chrome")).put("publicKey",p.get("pbk")).put("shortId",p.getOrDefault("sid",""));
        JSONObject outbound=new JSONObject().put("tag","vpn").put("protocol","vless").put("settings",new JSONObject().put("vnext",new JSONArray().put(new JSONObject().put("address",p.get("host")).put("port",Integer.parseInt(p.get("port"))).put("users",new JSONArray().put(account)))))
            .put("streamSettings",new JSONObject().put("network","tcp").put("security","reality").put("realitySettings",reality));
        if(p.getOrDefault("type","tcp").equals("xhttp")){account.remove("flow");outbound.getJSONObject("streamSettings").put("network","xhttp").put("xhttpSettings",new JSONObject().put("path",p.get("path")).put("mode","auto"));}
        JSONObject socks=new JSONObject().put("listen","127.0.0.1").put("port",socksPort).put("protocol","socks").put("settings",new JSONObject().put("auth","password").put("accounts",new JSONArray().put(new JSONObject().put("user",user).put("pass",password))).put("udp",true));
        return new JSONObject().put("log",new JSONObject().put("loglevel","warning")).put("inbounds",new JSONArray().put(socks)).put("outbounds",new JSONArray().put(outbound));
    }
    public static JSONObject workerProfile(String protocol,String text)throws Exception{
        JSONObject p=new JSONObject(text);Set<String> allowed=new HashSet<>(Arrays.asList("schema","protocol","server","port","login","password","certificate","server_name","method","path","obfs","access_mode"));
        for(Iterator<String> it=p.keys();it.hasNext();)if(!allowed.contains(it.next()))throw new IOException("Unsupported connection option");
        if(p.getInt("schema")!=1||!protocol.equals(p.getString("protocol"))||!org.strongswan.android.rookstride.SingleProtocols.from(protocol).worker())throw new IOException("Unsupported connection format");
        boolean reusable=p.optString("access_mode").equals("password")&&org.strongswan.android.rookstride.PasswordSignIn.supported(protocol);
        if(p.has("access_mode")&&!reusable)throw new IOException("Unsupported sign-in mode");
        boolean privateIdentity=protocol.equals("trusttunnel")&&p.getString("server_name").matches("vpn-[a-f0-9]{32}\\.internal");
        String secret=p.getString("password");boolean validSecret=reusable?org.strongswan.android.rookstride.InputRules.vpnPassword(secret):secret.length()>=8&&secret.length()<=256;
        if(!org.strongswan.android.rookstride.InputRules.host(p.getString("server"))||p.getInt("port")<1||p.getInt("port")>65535||(!p.getString("server_name").equals(p.getString("server"))&&!privateIdentity&&!(reusable&&p.getString("server_name").equals(org.strongswan.android.rookstride.PasswordSignIn.tlsName(p.getString("server")))))||!p.getString("login").matches(reusable?"[A-Za-z0-9._@-]{1,64}":"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")||!validSecret)throw new IOException("Invalid connection identity");
        if(p.getString("certificate").length()>450000||java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(p.getString("certificate").getBytes(StandardCharsets.US_ASCII))).isEmpty())throw new IOException("Invalid trusted certificate store");
        if((protocol.equals("outline")||protocol.equals("shadowsocks"))&&(!p.getString("method").equals("chacha20-ietf-poly1305")||!p.getString("path").matches("/[a-f0-9]{48}")))throw new IOException("Invalid WebSocket profile");
        if(protocol.equals("hysteria2")&&(reusable?p.has("obfs"):!p.has("obfs")||p.getString("obfs").length()<16||p.getString("obfs").length()>128))throw new IOException("Invalid QUIC obfuscation key");return p;
    }
    public static JSONObject worker(String protocol,String text,int port,String user,String password,String protection,String endpoint)throws Exception{
        JSONObject p=workerProfile(protocol,text);JSONObject out=new JSONObject().put("tag","vpn").put("server",endpoint).put("server_port",p.getInt("port")).put("protect_path",protection);
        JSONObject tls=new JSONObject().put("enabled",true).put("server_name",p.getString("server_name")).put("certificate",new JSONArray().put(p.getString("certificate")));
        switch(protocol){
            case "hysteria2":out.put("type","hysteria2").put("password",p.optString("access_mode").equals("password")?p.getString("login")+":"+p.getString("password"):p.getString("password")).put("tls",tls);if(p.has("obfs"))out.put("obfs",new JSONObject().put("type","salamander").put("password",p.getString("obfs")));break;
            case "naive":out.put("type","naive").put("username",p.getString("login")).put("password",p.getString("password")).put("tls",tls).put("udp_over_tcp",true).put("quic",false);break;
            case "outline":case "shadowsocks":out.put("type","outline-wss").put("method",p.getString("method")).put("password",p.getString("password")).put("path",p.getString("path")).put("certificate",p.getString("certificate")).put("server_name",p.getString("server_name"));break;
            case "trusttunnel":out.put("type","trusttunnel-h2").put("username",p.getString("login")).put("password",p.getString("password")).put("certificate",p.getString("certificate")).put("server_name",p.getString("server_name"));break;
            default:throw new IOException("Unsupported worker protocol");
        }
        JSONObject socks=new JSONObject().put("type","socks").put("tag","phone").put("listen","127.0.0.1").put("listen_port",port).put("users",new JSONArray().put(new JSONObject().put("username",user).put("password",password)));
        JSONArray outbounds=new JSONArray().put(out);
        if(protocol.equals("naive")){out.remove("protect_path");out.put("detour","transport");outbounds.put(new JSONObject().put("type","endpoint-only").put("tag","transport").put("server",endpoint).put("server_port",p.getInt("port")).put("protect_path",protection));}
        JSONObject dns=new JSONObject().put("servers",new JSONArray().put(new JSONObject().put("type","tcp").put("tag","tunnel-dns").put("server","1.1.1.1").put("server_port",53).put("detour","vpn"))).put("strategy","ipv4_only");
        return new JSONObject().put("schema",1).put("box",new JSONObject().put("log",new JSONObject().put("disabled",true)).put("inbounds",new JSONArray().put(socks)).put("outbounds",outbounds).put("dns",dns).put("route",new JSONObject().put("default_domain_resolver","tunnel-dns").put("final","vpn")));
    }
    public static JSONObject openVpnCredentials(String text)throws Exception{
        if(!text.trim().startsWith("{"))return new JSONObject();
        JSONObject p=new JSONObject(text);Set<String> allowed=new HashSet<>(Arrays.asList("schema","protocol","access_mode","config","login","password"));for(Iterator<String> it=p.keys();it.hasNext();)if(!allowed.contains(it.next()))throw new IOException("Unsupported OpenVPN sign-in option");
        if(p.getInt("schema")!=1||!p.getString("protocol").equals("openvpn")||!p.getString("access_mode").equals("password")||!org.strongswan.android.rookstride.InputRules.username(p.getString("login"))||!org.strongswan.android.rookstride.InputRules.vpnPassword(p.getString("password")))throw new IOException("Invalid OpenVPN sign-in");return p;
    }
    public static String openVpnConfiguration(String text)throws Exception{JSONObject p=openVpnCredentials(text);return p.has("config")?p.getString("config"):text;}
    public static boolean openVpnNeedsPassword(String text)throws Exception{return openVpnConfiguration(text).contains("\nauth-user-pass")&&!text.trim().startsWith("{");}
    private static void validateOpenVpn(String text)throws Exception{
        text=openVpnConfiguration(text);
        Set<String> allowed=new HashSet<>(Arrays.asList("auth-user-pass","client","block-ipv6","dev","proto","remote","resolv-retry","nobind","persist-key","persist-tun","remote-cert-tls","verify-x509-name","auth","cipher","data-ciphers","data-ciphers-fallback","tls-version-min","verb","mute","tun-mtu","mssfix","redirect-gateway","auth-nocache","explicit-exit-notify","route","dhcp-option","key-direction","reneg-sec","connect-retry","connect-timeout","server-poll-timeout","pull"));
        Set<String> inline=new HashSet<>(Arrays.asList("ca","cert","key","tls-crypt","tls-auth","tls-crypt-v2"));String block="";boolean ca=false,cert=false,key=false,remote=false,password=false,name=false;
        for(String raw:text.split("\\r?\\n")){String line=raw.trim();if(line.isEmpty()||line.startsWith("#")||line.startsWith(";"))continue;
            if(!block.isEmpty()){if(line.equals("</"+block+">"))block="";continue;}
            if(line.startsWith("<")&&line.endsWith(">")){String b=line.substring(1,line.length()-1);if(!inline.contains(b))throw new IOException("Unsupported inline profile section");block=b;if(b.equals("ca"))ca=true;if(b.equals("cert"))cert=true;if(b.equals("key"))key=true;continue;}
            String directive=line.split("\\s+",2)[0];if(!allowed.contains(directive))throw new IOException("Unsupported OpenVPN option: "+directive);if(directive.equals("remote"))remote=true;if(directive.equals("verify-x509-name"))name=true;if(directive.equals("auth-user-pass")){if(!line.equals("auth-user-pass"))throw new IOException("External password files are not supported");password=true;}
        }
        if(!block.isEmpty()||!ca||(!password&&(!cert||!key))||(password&&!name)||!remote||!text.contains("remote-cert-tls server"))throw new IOException("Use an inline trusted-CA profile with verified server name and credentials or a client certificate");
    }
}
