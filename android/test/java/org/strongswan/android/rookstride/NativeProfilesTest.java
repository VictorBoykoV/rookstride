package org.strongswan.android.rookstride;
import org.junit.Test;
import org.strongswan.android.rookstride.engine.NativeProfiles;
import org.json.JSONObject;
import static org.junit.Assert.*;

public class NativeProfilesTest {
 private String vless(){return "vless://b74ab96c-a1db-4f4a-b10c-a784c92c5c21@vpn.example.net:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=www.example.net&sid=abcd&flow=xtls-rprx-vision#test";}
 @Test public void generatedXrayConfigKeepsIdentityAndEnforcesLocalAuthentication()throws Exception{
  JSONObject config=NativeProfiles.xray(vless(),10807,"local-user","local-secret");JSONObject inbound=config.getJSONArray("inbounds").getJSONObject(0),outbound=config.getJSONArray("outbounds").getJSONObject(0);
  assertEquals("127.0.0.1",inbound.getString("listen"));assertEquals("password",inbound.getJSONObject("settings").getString("auth"));assertEquals(10807,inbound.getInt("port"));
  assertEquals("reality",outbound.getJSONObject("streamSettings").getString("security"));assertEquals("www.example.net",outbound.getJSONObject("streamSettings").getJSONObject("realitySettings").getString("serverName"));assertEquals(1,config.getJSONArray("outbounds").length());
 }
 @Test public void incompatibleAndAmbiguousLinksAreRejected()throws Exception{
  for(String link:new String[]{vless().replace("security=reality","security=none"),vless().replace("type=tcp","type=ws"),vless().replace("sid=abcd","sid=abcd&sid=efef"),vless().replace("vpn.example.net:443","vpn.example.net:0")}){
   try{NativeProfiles.validate("xray",link);fail("Unsupported link accepted");}catch(java.io.IOException expected){}
  }
 }
 @Test public void importedOpenVpnCannotReadExternalKeysOrExecuteHooks()throws Exception{
  String base="client\nblock-ipv6\ndev tun\nproto tcp-client\nremote vpn.example.net 1194\nremote-cert-tls server\n<ca>\nfixture\n</ca>\n<cert>\nfixture\n</cert>\n<key>\nfixture\n</key>\n";
  NativeProfiles.validate("openvpn",base);
  for(String extra:new String[]{"up /tmp/script","plugin /tmp/library","key /private/key","auth-user-pass /private/password","script-security 2"}){
   try{NativeProfiles.validate("openvpn",base+extra);fail("External behavior accepted");}catch(java.io.IOException expected){}
  }
 }
 @Test public void xhttpAndVisionProfilesCannotBeConfused()throws Exception{
  String link=vless().replace("type=tcp","type=xhttp").replace("flow=xtls-rprx-vision","flow=&path=%2F"+new String(new char[48]).replace('\0','a')+"&mode=auto");
  NativeProfiles.validate("xhttp",link);
  JSONObject outbound=NativeProfiles.xray(link,10807,"local-user","local-secret").getJSONArray("outbounds").getJSONObject(0);
  assertEquals("xhttp",outbound.getJSONObject("streamSettings").getString("network"));assertFalse(outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).has("flow"));
  try{NativeProfiles.validate("xray",link);fail("XHTTP accepted as TCP/Vision");}catch(java.io.IOException expected){}
  try{NativeProfiles.validate("xhttp",vless());fail("TCP/Vision accepted as XHTTP");}catch(java.io.IOException expected){}
 }
 @Test public void workerProfilesCannotDisableTlsOrSupplyArbitraryEngineOptions()throws Exception{
  for(String protocol:new String[]{"hysteria2","outline","shadowsocks","trusttunnel","naive"}){
   JSONObject data=new JSONObject().put("schema",1).put("protocol",protocol).put("server","vpn.example.net").put("port",443).put("server_name","vpn.example.net").put("login","phone").put("password","12345678").put("certificate","not-a-certificate").put("insecure",true);
   try{NativeProfiles.validate(protocol,data.toString());fail("Unverified TLS configuration accepted");}catch(Exception expected){assertNotNull(expected);}
  }
 }
}
