package org.strongswan.android.rookstride;

import org.json.*;
import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

/** Server-response fixtures, including the raw OpenVPN profile returned by runtime.profile(). */
public class ConnectionCollectionProfilesTest {
    private String roots()throws Exception{try(InputStream in=getClass().getResourceAsStream("/password-test-root.txt");ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[4096];for(int n;(n=in.read(b))!=-1;)out.write(b,0,n);return new String(out.toByteArray(),StandardCharsets.US_ASCII);}}
    private JSONObject response(String protocol,String user,String password)throws Exception{
        JSONObject definition=PasswordSignIn.definition(protocol,"vpn.example.net",user,password,protocol.equals("ikev2")?"":roots());
        if(protocol.equals("ikev2"))return definition;
        if(protocol.equals("openvpn"))return new JSONObject().put("format",protocol).put("name","rookstride-family.ovpn").put("content",definition.getString("config")).put("access_mode","password").put("server","vpn.example.net").put("port",443).put("login",user);
        definition.remove("password");return new JSONObject().put("format",protocol).put("name","rookstride-family.rookvpn").put("content",definition.toString());
    }
    @Test public void existingChosenPasswordIsIncludedForEveryPasswordMethodWithoutChangingResponse()throws Exception{
        for(String protocol:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"}){
            JSONObject response=response(protocol,"family","1");String original=response.toString();
            JSONObject entry=ConnectionCollectionProfiles.complete(response,"family","  chosen secret  ","Family · North");
            assertEquals(original,response.toString());assertEquals("Family · North",entry.getString("display_name"));
            JSONObject content=new JSONObject(entry.getString("content"));
            assertEquals("  chosen secret  ",protocol.equals("ikev2")?content.getJSONObject("local").getString("shared_secret"):content.getString("password"));
            assertEquals("family",protocol.equals("ikev2")?content.getJSONObject("local").getString("eap_id"):content.getString("login"));
            assertEquals(1,ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(entry))).size());
        }
    }
    @Test public void rawServerOpenVpnResponseBecomesACompletePasswordWrapper()throws Exception{
        JSONObject response=response("openvpn","mina","1").put("sshPassword","PRIVATE_ADMIN_SENTINEL");String config=response.getString("content");
        JSONObject entry=ConnectionCollectionProfiles.complete(response,"mina","existing password","Mina's VPN");
        JSONObject wrapper=new JSONObject(entry.getString("content"));assertEquals(config,wrapper.getString("config"));assertEquals("mina",wrapper.getString("login"));assertEquals("existing password",wrapper.getString("password"));assertFalse(entry.toString().contains("PRIVATE_ADMIN_SENTINEL"));assertEquals(4,entry.length());
    }
    @Test public void missingExistingSecretsRequireAnExplicitPromptInsteadOfCreatingIncompleteAccess()throws Exception{
        for(String protocol:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"})try{
            ConnectionCollectionProfiles.complete(response(protocol,"family","1"),"family","","Family");fail(protocol+" accepted a missing password");
        }catch(ConnectionCollectionProfiles.PasswordRequired expected){assertFalse(expected.getMessage().contains("secret"));}
    }
    @Test public void anotherUsersPasswordCanNeverBeAttachedByChoosingTheWrongLogin()throws Exception{
        for(String protocol:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"})try{
            ConnectionCollectionProfiles.complete(response(protocol,"mina","1"),"navid","PRIVATE_SECRET_SENTINEL","Navid");fail(protocol+" accepted a mismatched user");
        }catch(IOException expected){assertFalse(expected.getMessage().contains("PRIVATE_SECRET_SENTINEL"));}
    }
    @Test public void keyBasedAccessDoesNotAcquirePasswordOrAdministratorFields()throws Exception{
        String link="vless://b74ab96c-a1db-4f4a-b10c-a784c92c5c21@vpn.example.net:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=www.example.net&sid=abcd&flow=xtls-rprx-vision#Family";
        JSONObject response=new JSONObject().put("format","xray").put("name","rookstride-family.txt").put("content",link).put("adminAccess",true);
        JSONObject entry=ConnectionCollectionProfiles.complete(response,"family","UNRELATED_PASSWORD_SENTINEL","Family");assertEquals(link,entry.getString("content"));assertFalse(entry.toString().contains("UNRELATED_PASSWORD_SENTINEL"));assertFalse(entry.has("adminAccess"));
    }
    @Test public void freshServerPasswordWinsOverAnOlderCachedPhonePassword()throws Exception{
        JSONObject payload=PasswordSignIn.definition("hysteria2","vpn.example.net","family","fresh existing password",roots());
        JSONObject response=new JSONObject().put("format","hysteria2").put("name","rookstride-family.rookvpn").put("content",payload.toString());
        JSONObject entry=ConnectionCollectionProfiles.complete(response,"family","outdated phone password","Family");assertEquals("fresh existing password",new JSONObject(entry.getString("content")).getString("password"));
    }
    @Test public void displayLabelsAreBoundedInUnicodeCodepoints()throws Exception{
        String longLabel=String.join("",Collections.nCopies(130,"😀"));String actual=ConnectionCollectionProfiles.label(longLabel);assertEquals(100,actual.codePointCount(0,actual.length()));assertTrue(actual.endsWith("…"));assertEquals("Mina  North",ConnectionCollectionProfiles.label("Mina\n\tNorth"));assertEquals("Mina North",ConnectionCollectionProfiles.label("Mina\u202eNorth"));assertEquals("VPN connection",ConnectionCollectionProfiles.label("  "));
    }
}
