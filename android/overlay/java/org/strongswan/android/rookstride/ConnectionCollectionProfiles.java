package org.strongswan.android.rookstride;

import org.json.JSONObject;
import java.io.IOException;

/** Turns an explicitly selected ordinary VPN account into a complete collection entry. */
public final class ConnectionCollectionProfiles {
    private ConnectionCollectionProfiles(){}
    public static final class PasswordRequired extends IOException {
        public PasswordRequired(){super("Include this VPN user's existing password");}
    }
    public static JSONObject complete(JSONObject response,String selectedLogin,String knownPassword,String displayName)throws Exception {
        boolean passwordBased=PasswordSignIn.passwordBased(response);
        String actual=PasswordSignIn.login(response);
        if(passwordBased&&!actual.equals(selectedLogin))throw new IOException("The connection belongs to a different VPN user. Select that user again.");
        // A fresh authenticated server response wins over a cached phone
        // password, which may have changed on another administrator's device.
        String attach=passwordBased&&PasswordSignIn.share(response,"")!=null?"":knownPassword;
        JSONObject prepared=PasswordSignIn.withKnownPassword(response,selectedLogin,attach);
        if(passwordBased&&PasswordSignIn.share(prepared,attach)==null)throw new PasswordRequired();
        ConnectionExport export=ConnectionExport.fromResponse(prepared);
        JSONObject entry=export.pending();
        if(export.protocol.equals("openvpn")&&passwordBased){
            String secret=prepared.optString("password",attach==null?"":attach);
            if(!InputRules.vpnPassword(secret))throw new PasswordRequired();
            entry.put("content",PasswordSignIn.openVpn(export.content,selectedLogin,secret).toString());
        }
        entry.put("display_name",label(displayName));
        // Validate the exact portable representation, including credentials,
        // before showing it as ready or issuing a share URI.
        ConnectionBundle.pack(java.util.Collections.singletonList(entry));
        return entry;
    }
    /** Keep protocol and the complete account visible; only shorten the server suffix. */
    public static String displayName(String protocol,String login,String serverName){
        SingleProtocols chosen=SingleProtocols.from(protocol);
        if(!chosen.id.equals(protocol)||!InputRules.username(login))throw new IllegalArgumentException("Choose a valid VPN protocol and user");
        String prefix=chosen.title+" · "+login;
        int available=100-prefix.codePointCount(0,prefix.length())-3;
        if(available<2||serverName==null||serverName.trim().isEmpty())return prefix;
        String server=label(serverName);
        if(server.codePointCount(0,server.length())>available)server=server.substring(0,server.offsetByCodePoints(0,available-1))+"…";
        return prefix+" · "+server;
    }
    public static String label(String value){
        StringBuilder visible=new StringBuilder();if(value!=null)value.codePoints().forEach(c->visible.appendCodePoint(Character.isISOControl(c)||Character.getType(c)==Character.FORMAT||c==0x2028||c==0x2029||c>=0xD800&&c<=0xDFFF?' ':c));
        String safe=visible.toString().trim();
        if(safe.isEmpty())safe="VPN connection";
        int length=safe.codePointCount(0,safe.length());
        return length<=100?safe:safe.substring(0,safe.offsetByCodePoints(0,99))+"…";
    }
}
