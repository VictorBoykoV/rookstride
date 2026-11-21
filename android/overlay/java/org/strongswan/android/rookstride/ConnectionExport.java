package org.strongswan.android.rookstride;

import org.json.JSONObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** One portable client configuration, without administrator access. Never persisted by the UI. */
public final class ConnectionExport {
    public final String protocol,name,content;
    private ConnectionExport(String protocol,String name,String content)throws Exception{
        ProfileExportProvider.validateName(name);
        String extension=protocol.equals("awg")?".conf":protocol.equals("openvpn")?".ovpn":protocol.equals("xray")||protocol.equals("xhttp")?".txt":protocol.equals("ikev2")?".sswan":SingleProtocols.from(protocol).worker()?".rookvpn":"";
        if(extension.isEmpty()||!name.endsWith(extension))throw new IOException("Unexpected connection format");
        int size=content.getBytes(StandardCharsets.UTF_8).length;
        if(size==0||size>512000)throw new IOException("Connection profile is empty or too large");
        this.protocol=protocol;this.name=name;this.content=content;
    }
    public static ConnectionExport fromResponse(JSONObject profile)throws Exception{
        if(!profile.has("format")){
            if(!profile.optString("type").equals("ikev2-eap"))throw new IOException("Unexpected IKEv2 profile");
            String login=profile.getJSONObject("local").getString("eap_id");
            if(!InputRules.username(login))throw new IOException("Unexpected VPN login");
            return new ConnectionExport("ikev2","rookstride-"+login.replaceAll("[^A-Za-z0-9_-]","_")+".sswan",profile.toString(2));
        }
        return new ConnectionExport(profile.getString("format"),profile.getString("name"),profile.getString("content"));
    }
    public static ConnectionExport fromStored(String id,JSONObject stored)throws Exception{
        String protocol=stored.getString("protocol");
        if(!id.matches("[a-fA-F0-9-]{36}")||protocol.equals("ikev2"))throw new IOException("Unexpected saved VPN");
        String name="rookstride-"+id+(protocol.equals("openvpn")?".ovpn":SingleProtocols.from(protocol).worker()?".rookvpn":".txt");
        if(protocol.equals("awg")){
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8));
            StringBuilder suffix=new StringBuilder();for(int i=0;i<5;i++)suffix.append(String.format(java.util.Locale.ROOT,"%02x",digest[i]&255));
            name="rook-"+suffix+".conf";
        }
        return new ConnectionExport(protocol,name,protocol.equals("openvpn")?org.strongswan.android.rookstride.engine.NativeProfiles.openVpnConfiguration(stored.getString("content")):stored.getString("content"));
    }
    public JSONObject pending()throws Exception{return new JSONObject().put("format",protocol).put("name",name).put("content",content);}
    /** AmneziaWG derives its tunnel name from the filename and limits it to 15
     * characters. Fresh names avoid DocumentsUI's incompatible " (1)" suffix. */
    public String documentName(){return protocol.equals("awg")?freshAmneziaName():name;}
    public static String freshAmneziaName(){return "rook-"+java.util.UUID.randomUUID().toString().replace("-","").substring(0,10)+".conf";}
    public String mime(){return mimeForName(name);}
    public static String mimeForName(String name){
        if(name.endsWith(".sswan"))return "application/vnd.strongswan.profile";
        if(name.endsWith(".ovpn"))return "application/x-openvpn-profile";
        if(name.endsWith(".txt"))return "text/plain";
        if(name.endsWith(".rookvpn"))return "application/json";
        return "application/octet-stream";
    }
}
