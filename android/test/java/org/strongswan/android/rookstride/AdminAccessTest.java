package org.strongswan.android.rookstride;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class AdminAccessTest {
 private JSONObject invitation()throws Exception{return new JSONObject().put("purpose",AdminAccess.PURPOSE).put("schema",1).put("invitation_id","inv-"+"a".repeat(32)).put("server_id","server-fixture").put("expires",System.currentTimeMillis()/1000+3600).put("role","user_manager").put("scope",new JSONObject().put("kind","protocol").put("id","vpn-exact").put("users","own")).put("endpoint",new JSONObject().put("host","vpn.example.test").put("port",22).put("fingerprint","SHA256:"+"a".repeat(43))).put("bootstrap",new JSONObject().put("account","rsb"+"a".repeat(20)).put("private_key","-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n"));}
 @Test public void administratorPurposeCannotImportVpnOrRecoveryFiles()throws Exception{
  JSONObject file=invitation();assertEquals(AdminAccess.PURPOSE,AdminAccess.parseInvitation(file.toString()).getString("purpose"));
  for(String purpose:new String[]{"rookstride.vpn","rookstride.owner.recovery",""}){file.put("purpose",purpose);try{AdminAccess.parseInvitation(file.toString());fail("Wrong file purpose accepted");}catch(java.io.IOException expected){}}
 }
 @Test public void unpinnedExpiredAndExecutableEndpointsAreRejected()throws Exception{
  for(String field:new String[]{"expired","pin","host","role"}){JSONObject file=invitation();if(field.equals("expired"))file.put("expires",1);else if(field.equals("pin"))file.getJSONObject("endpoint").put("fingerprint","");else if(field.equals("host"))file.getJSONObject("endpoint").put("host","x;reboot");else file.put("role","owner");try{AdminAccess.parseInvitation(file.toString());fail("Invalid invitation accepted");}catch(java.io.IOException expected){}}
 }
 @Test public void draftCreatesIndependentPersistableDeviceIdentityWithoutVpnCredentials()throws Exception{
  JSONObject invite=invitation();Gateway first=AdminAccessController.deviceDraft(invite),second=AdminAccessController.deviceDraft(invite);
  assertNotEquals(first.privateKey,second.privateKey);assertNotEquals(first.privateKey,invite.getJSONObject("bootstrap").getString("private_key"));assertTrue(first.remember());assertTrue(first.data.optBoolean("adminAccess"));assertEquals("",first.vpnPassword);assertEquals(first.privateKey,first.persisted().getString("privateKey"));
  // The same PKCS8 bytes must be accepted by the actual SSH implementation.
  new com.jcraft.jsch.JSch().addIdentity("device",first.privateKey.getBytes(StandardCharsets.US_ASCII),null,null);
 }
 @Test public void challengeProofBindsInvitationServerNonceAndDeviceKey()throws Exception{
  JSONObject key=AdminAccess.newDeviceKey(),challenge=new JSONObject().put("invitation_id","inv-fixture").put("server_id","server-fixture").put("nonce","nonce-fixture");
  String proof=AdminAccess.prove(challenge,key.getString("public_key"),key.getString("private_key"));assertTrue(Base64.getDecoder().decode(proof).length>=384);
  assertNotEquals(proof,AdminAccess.prove(new JSONObject(challenge.toString()).put("nonce","different"),key.getString("public_key"),key.getString("private_key")));
 }
 @Test public void allProtocolCreateRequestsOmitUnknownDeviceAndKeepOnlyRealPasswords()throws Exception{
  String secret=" 1 @ chosen secret ";
  for(SingleProtocols protocol:SingleProtocols.values()){
   JSONObject request=AdminAccessController.newUserParameters(protocol.id,"family-user",secret);
   assertEquals("family-user",request.getString("login"));assertEquals("family-user",request.getString("person"));assertFalse(request.has("device"));
   assertEquals(PasswordSignIn.supported(protocol.id),request.has("password"));
   if(request.has("password"))assertEquals(secret,request.getString("password"));
   assertEquals(PasswordSignIn.supported(protocol.id)?3:2,request.length());
  }
 }
 @Test public void nativeAndIkeEmptyMetadataEditsKeepExistingValues()throws Exception{
  for(SingleProtocols protocol:SingleProtocols.values()){
   JSONObject unchanged=AdminAccessController.editUserParameters(protocol.id,"family-user","  ",null,"");
   assertEquals(1,unchanged.length());assertEquals("family-user",unchanged.getString("login"));
   JSONObject edited=AdminAccessController.editUserParameters(protocol.id,"family-user","  Mina  ","  Tablet  ",null);
   assertEquals("Mina",edited.getString("person"));assertEquals("Tablet",edited.getString("device"));assertFalse(edited.has("password"));
  }
 }
 @Test public void passwordEditsPreserveWhitespaceAndWeakChosenSecrets()throws Exception{
  for(String protocol:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"})for(String secret:new String[]{"1"," exact secret "}){
   assertEquals(secret,AdminAccessController.newUserParameters(protocol,"1",secret).getString("password"));
   assertEquals(secret,AdminAccessController.editUserParameters(protocol,"1","","",secret).getString("password"));
  }
 }
 @Test public void metadataAndPasswordContractsFailBeforeTransport()throws Exception{
  for(String protocol:new String[]{"ikev2","awg"})for(String label:new String[]{"bad\nlabel","x".repeat(81)})try{AdminAccessController.editUserParameters(protocol,"family-user",label,null,null);fail("Invalid label accepted");}catch(java.io.IOException expected){}
  try{AdminAccessController.newUserParameters("ikev2","family-user","");fail("Empty manual password accepted");}catch(java.io.IOException expected){}
  try{AdminAccessController.newUserParameters("unknown","family-user","secret");fail("Unknown protocol accepted");}catch(java.io.IOException expected){}
  try{AdminAccessController.editUserParameters("awg","family-user",null,null,"fake password");fail("Key VPN accepted a password update");}catch(java.io.IOException expected){}
 }
 @Test public void installedAuthenticationModeControlsEveryProtocolRequest()throws Exception{
  for(SingleProtocols protocol:SingleProtocols.values())for(String mode:new String[]{"profile","password"}){
   JSONObject object=new JSONObject().put("protocol",protocol.id).put("access_mode",mode);
   boolean passwords=PasswordSignIn.supported(protocol.id)&&mode.equals("password");
   assertEquals(passwords,AdminAccessController.passwordUsers(object));
   JSONObject create=AdminAccessController.newUserParameters(object,"family-user"," chosen secret ");
   assertEquals(passwords,create.has("password"));assertFalse(create.has("device"));
   if(passwords){assertEquals(" chosen secret ",create.getString("password"));assertEquals("1",AdminAccessController.editUserParameters(object,"family.user","New name",null,"1").getString("password"));}
   else try{AdminAccessController.editUserParameters(object,"family-user",null,null,"1");fail("Profile-mode installation accepted a password edit");}catch(java.io.IOException expected){}
  }
 }
 @Test public void unknownLegacyModeNeverPromisesPasswordCreation()throws Exception{
  for(String protocol:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"})for(String mode:new String[]{"","unknown","unexpected"}){
   JSONObject object=new JSONObject().put("protocol",protocol);if(!mode.isEmpty())object.put("access_mode",mode);
   assertFalse(AdminAccessController.passwordUsers(object));
   try{AdminAccessController.newUserParameters(object,"family-user","ignored secret");fail("Unknown installation mode accepted");}catch(java.io.IOException expected){}
   JSONObject metadata=AdminAccessController.editUserParameters(object,"family.user","New name",null,"");assertFalse(metadata.has("password"));assertEquals("New name",metadata.getString("person"));
  }
  JSONObject awg=new JSONObject().put("protocol","awg");assertFalse(AdminAccessController.newUserParameters(awg,"family-user","").has("password"));
 }
 @Test public void profileModeRetainsNativeAccountNameLimits()throws Exception{
  for(String protocol:new String[]{"openvpn","hysteria2","trusttunnel","naive"}){
   JSONObject object=new JSONObject().put("protocol",protocol).put("access_mode","profile");
   try{AdminAccessController.newUserParameters(object,"family.user","");fail("Profile-native username format was broadened");}catch(java.io.IOException expected){}
   assertEquals("family-user",AdminAccessController.newUserParameters(object,"family-user","").getString("login"));
  }
 }
}
