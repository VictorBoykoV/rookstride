package org.strongswan.android.rookstride;
import org.junit.Test;
import org.json.*;
import org.strongswan.android.rookstride.engine.NativeProfiles;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;
public class PasswordSignInTest {
 private String roots()throws Exception{return new String(getClass().getResourceAsStream("/password-test-root.txt").readAllBytes(),StandardCharsets.US_ASCII);}
 @Test public void allApplicableProtocolsAcceptOnlyVpnDetailsWithoutAdminAccess()throws Exception{
  for(String id:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"}){
   JSONObject p=PasswordSignIn.definition(id,"vpn.example.net","family.user","onlyletters",roots());
   assertFalse(p.has("sshPassword"));assertFalse(p.has("privateKey"));
   if(id.equals("ikev2")){assertFalse(p.getJSONObject("remote").has("cert"));assertEquals("family.user",p.getJSONObject("local").getString("eap_id"));}
   else{NativeProfiles.validate(id,p.toString());assertEquals("onlyletters",p.getString("password"));}
  }
 }
 @Test public void ipSetupUsesVerifiedStableTlsNameWithoutASecondUserQuestion()throws Exception{
  for(String id:new String[]{"openvpn","hysteria2","trusttunnel","naive"}){
   JSONObject p=PasswordSignIn.definition(id,"192.0.2.10:8443","family.user","12345678",roots());
   if(id.equals("openvpn")){assertTrue(p.getString("config").contains("remote 192.0.2.10 8443"));assertTrue(p.getString("config").contains("verify-x509-name 192-0-2-10.sslip.io name"));}
   else{assertEquals("192-0-2-10.sslip.io",p.getString("server_name"));assertEquals("192.0.2.10",p.getString("server"));}
  }
 }
 @Test public void chosenShortAndLongPasswordsSurviveTheCompleteClientValidation()throws Exception{
  for(String secret:new String[]{"1","Our family chooses a longer private passphrase 2026!"})
   for(String id:new String[]{"openvpn","hysteria2","trusttunnel","naive"}){
    JSONObject profile=PasswordSignIn.definition(id,"vpn.example.net","1",secret,roots());
    NativeProfiles.validate(id,profile.toString());
    assertEquals(secret,profile.getString("password"));
    if(!id.equals("openvpn")){
     JSONObject outbound=NativeProfiles.worker(id,profile.toString(),1080,"local","private","/private/socket","192.0.2.10").getJSONObject("box").getJSONArray("outbounds").getJSONObject(0);
     assertEquals(id.equals("hysteria2")?"1:"+secret:secret,outbound.getString("password"));
    }
   }
 }
 @Test public void hysteriaUsesUsernameInWireAuthAndDoesNotInventAnObfuscationSecret()throws Exception{
  String p=PasswordSignIn.definition("hysteria2","vpn.example.net","family.user","12345678",roots()).toString();JSONObject w=NativeProfiles.worker("hysteria2",p,1080,"local","private","/private/socket","192.0.2.10").getJSONObject("box").getJSONArray("outbounds").getJSONObject(0);
  assertEquals("family.user:12345678",w.getString("password"));assertFalse(w.has("obfs"));
 }
 @Test public void keysAreNeverPretendedToBePasswordSignIn()throws Exception{
  for(String id:new String[]{"awg","xray","xhttp","outline","shadowsocks"}){assertFalse(PasswordSignIn.supported(id));try{PasswordSignIn.definition(id,"vpn.example.net","user","12345678",roots());fail();}catch(java.io.IOException expected){}}
 }
 @Test public void openvpnWrapperNeverBecomesAnExportedPasswordFile()throws Exception{
  JSONObject p=PasswordSignIn.definition("openvpn","vpn.example.net:1195","family.user","12345678",roots());String wrapped=p.toString();assertEquals("family.user",NativeProfiles.openVpnCredentials(wrapped).getString("login"));assertTrue(NativeProfiles.openVpnNeedsPassword(p.getString("config")));assertFalse(NativeProfiles.openVpnNeedsPassword(wrapped));
  ConnectionExport out=ConnectionExport.fromStored("b74ab96c-a1db-4f4a-b10c-a784c92c5c21",new JSONObject().put("protocol","openvpn").put("content",wrapped));assertFalse(out.content.contains("12345678"));assertFalse(out.content.contains("<key>"));assertTrue(out.content.startsWith("client\n"));
 }
 @Test public void serverReinstallRetainsItsAutomaticallyChosenPort()throws Exception{
  Gateway a=new Gateway();a.set("host","vpn.example.net");a.set("protocol","naive");Gateway b=ServerProtocols.create(a,SingleProtocols.HYSTERIA2);java.util.List<Gateway> list=java.util.Arrays.asList(a,b);
  ServerProtocols.rememberConnection(list,b,new JSONObject().put("port",9443).put("manual_sign_in",true));ServerProtocols.recordRemoved(list,b);Gateway c=ServerProtocols.create(a,SingleProtocols.HYSTERIA2);assertEquals(9443,c.data.getInt("vpnPort"));assertFalse(c.data.getBoolean("vpnPortAuto"));assertEquals("password",b.get("accessMode"));
 }
 @Test public void sameClientDefinitionSurvivesANewLeafAndServerGeneration()throws Exception{
  String before=PasswordSignIn.definition("trusttunnel","vpn.example.net","family.user","12345678",roots()).toString();String after=PasswordSignIn.definition("trusttunnel","vpn.example.net","family.user","12345678",roots()).toString();assertEquals(before,after);assertFalse(before.contains("instance"));assertFalse(before.contains("obfs"));
 }
 @Test public void readableSharingContainsVpnAccessAndNoAdministratorCredential()throws Exception{
  JSONObject p=PasswordSignIn.definition("naive","vpn.example.net","family.user","onlyletters",roots());String text=PasswordSignIn.share(p,null);assertTrue(text.contains("Username: family.user"));assertTrue(text.contains("Password: onlyletters"));assertFalse(text.contains("root:"));
 }
 @Test public void nativeKeyExportsRemainOpaqueWhenChoosingTheShareSheet()throws Exception{
  for(String[] fixture:new String[][]{
   {"awg","rook-0123456789.conf","[Interface]\nPrivateKey = fixture\nAddress = 10.42.0.2/32\n\n[Peer]\nEndpoint = vpn.example.net:51820\n"},
   {"xray","rookstride-user.txt","vless://ba9cdf67-d5c2-45f7-a293-60447ff74258@vpn.example.net:443?security=reality&type=tcp"},
   {"xhttp","rookstride-user.txt","vless://ba9cdf67-d5c2-45f7-a293-60447ff74258@vpn.example.net:443?security=reality&type=xhttp"},
   {"outline","rookstride-user.rookvpn","{\"schema\":1,\"protocol\":\"outline\",\"password\":\"generated-key\"}"},
   {"shadowsocks","rookstride-user.rookvpn","{\"schema\":1,\"protocol\":\"shadowsocks\",\"password\":\"generated-key\"}"}}){
   JSONObject response=new JSONObject().put("format",fixture[0]).put("name",fixture[1]).put("content",fixture[2]);
   assertNull(PasswordSignIn.share(response,null));
   assertEquals("",PasswordSignIn.login(response));
   assertEquals(fixture[2],ConnectionExport.fromResponse(response).content);
  }
 }
 @Test public void delegatedIkeCreationIncludesChosenPasswordInBothTextAndFile()throws Exception{
  JSONObject server=new JSONObject().put("type","ikev2-eap").put("remote",new JSONObject().put("addr","vpn.example.net").put("port",4500)).put("local",new JSONObject().put("eap_id","family.user"));
  String before=server.toString(),secret="A chosen passphrase!";
  JSONObject prepared=PasswordSignIn.withKnownPassword(server,"family.user",secret);
  assertTrue(PasswordSignIn.share(prepared,null).contains("Password: "+secret));
  assertTrue(PasswordSignIn.share(server,secret).contains("Password: "+secret));
  JSONObject file=new JSONObject(ConnectionExport.fromResponse(prepared).content);
  assertEquals(secret,file.getJSONObject("local").getString("shared_secret"));
  assertEquals("vpn.example.net",file.getJSONObject("remote").getString("addr"));
  assertEquals(4500,file.getJSONObject("remote").getInt("port"));
  assertEquals(before,server.toString());
 }
 @Test public void knownPasswordsCannotBeAttachedToAnotherSelectedAccount()throws Exception{
  JSONObject server=new JSONObject().put("type","ikev2-eap").put("local",new JSONObject().put("eap_id","other-user"));
  try{PasswordSignIn.withKnownPassword(server,"this-phone","private-password");fail("Another account received this phone's password");}catch(java.io.IOException expected){}
  assertFalse(server.getJSONObject("local").has("shared_secret"));
 }
 @Test public void oldUnknownIkePasswordIsNotInvented()throws Exception{
  JSONObject server=new JSONObject().put("type","ikev2-eap").put("remote",new JSONObject().put("addr","vpn.example.net")).put("local",new JSONObject().put("eap_id","family.user"));
  JSONObject prepared=PasswordSignIn.withKnownPassword(server,"family.user","");
  assertNull(PasswordSignIn.share(prepared,null));
  assertFalse(new JSONObject(ConnectionExport.fromResponse(prepared).content).getJSONObject("local").has("shared_secret"));
 }
 @Test public void plainOpenVpnUsesAccountMetadataWhileTheFileRemainsNative()throws Exception{
  JSONObject response=new JSONObject().put("format","openvpn").put("name","rookstride-family.ovpn").put("content","client\nauth-user-pass\nremote vpn.example.net 1195\n")
   .put("access_mode","password").put("server","vpn.example.net").put("port",1195).put("login","family.user");
  JSONObject prepared=PasswordSignIn.withKnownPassword(response,"family.user","1");
  assertTrue(PasswordSignIn.share(prepared,null).contains("Username: family.user\nPassword: 1"));
  assertEquals(response.getString("content"),ConnectionExport.fromResponse(prepared).content);
  assertFalse(response.has("password"));
  response.remove("access_mode");assertNull(PasswordSignIn.share(response,"1"));
 }
 @Test public void wrappedPasswordWorkersSupportReadableSharingAndDoNotAlterServerResponse()throws Exception{
  for(String protocol:new String[]{"hysteria2","trusttunnel","naive"}){
   JSONObject definition=PasswordSignIn.definition(protocol,"vpn.example.net:9443","family.user","old-password",roots());
   JSONObject response=new JSONObject().put("format",protocol).put("name","rookstride-family.rookvpn").put("content",definition.toString());
   String before=response.toString();JSONObject prepared=PasswordSignIn.withKnownPassword(response,"family.user","chosen-password");
   assertEquals("family.user",PasswordSignIn.login(response));
   assertTrue(PasswordSignIn.share(prepared,null).contains("Password: chosen-password"));
   assertEquals("chosen-password",new JSONObject(ConnectionExport.fromResponse(prepared).content).getString("password"));
   assertEquals(before,response.toString());
  }
 }
}
