package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.json.JSONArray;
import org.junit.Test;
import java.io.IOException;
import static org.junit.Assert.*;

/** Identity recovery is observation-based; these contracts do not contact SSH. */
public class AdminOwnerDiscoveryTest {
 private static final String PIN="SHA256:"+"a".repeat(43),MACHINE="b".repeat(64);
 private Gateway node()throws Exception{Gateway n=new Gateway();n.set("host","server.example.test");n.set("admin","root");n.set("fingerprint",PIN);n.set("machine",MACHINE);return n;}
 private JSONObject absent()throws Exception{return new JSONObject().put("schema",1).put("machine",MACHINE).put("state","absent").put("pair",JSONObject.NULL);}
 private JSONObject existing()throws Exception{return absent().put("state","existing").put("authority",new JSONObject().put("server_id","canonical-server").put("deployment_id","canonical-deployment").put("fingerprint",PIN).put("disabled",false));}
 private JSONObject paired(String role)throws Exception{return existing().put("pair",new JSONObject().put("deployment_id","canonical-deployment").put("role",role));}
 private void refused(Gateway n,JSONObject observation,String deployment)throws Exception{String before=n.data.toString();try{AdminAccessController.ownerEnableConfig(n,observation,deployment);fail("Unverified owner identity accepted");}catch(IOException expected){}assertEquals(before,n.data.toString());}

 @Test public void coldOwnerRecoversCanonicalIdsWithoutEnablingOrChangingLocalState()throws Exception{
  Gateway n=node();String before=n.data.toString();JSONObject config=AdminAccessController.ownerEnableConfig(n,existing(),"");
  assertEquals("canonical-server",config.getString("server_id"));assertEquals("canonical-deployment",config.getString("deployment_id"));assertEquals(PIN,config.getJSONObject("endpoint").getString("fingerprint"));assertEquals(3,config.length());assertEquals(before,n.data.toString());
 }
 @Test public void stalePhoneIdentityCannotOverrideTheAuthenticatedModule()throws Exception{
  Gateway n=node();n.set("adminServerId","wrong-old-server");n.set("adminDeploymentId","wrong-old-deployment");n.data.put("adminSnapshot",new JSONObject().put("role","owner"));
  JSONObject config=AdminAccessController.ownerEnableConfig(n,existing(),"");assertEquals("canonical-server",config.getString("server_id"));assertEquals("wrong-old-server",n.get("adminServerId"));
  AdminAccessController.rememberOwnerIdentity(n,config);assertEquals("canonical-server",n.get("adminServerId"));assertEquals("canonical-deployment",n.get("adminDeploymentId"));assertEquals(PIN,n.get("adminIdentityFingerprint"));assertFalse(n.data.has("adminSnapshot"));assertFalse(n.data.optBoolean("adminEnabled"));assertEquals("root",n.get("admin"));
 }
 @Test public void aConfirmedSameIdentityKeepsItsCurrentPermissionSnapshot()throws Exception{
  Gateway n=node();n.set("adminServerId","canonical-server");n.set("adminDeploymentId","canonical-deployment");n.data.put("adminSnapshot",new JSONObject().put("revision",42));
  AdminAccessController.rememberOwnerIdentity(n,AdminAccessController.ownerEnableConfig(n,existing(),""));assertEquals(42,n.data.getJSONObject("adminSnapshot").getInt("revision"));
 }
 @Test public void genuineAbsenceUsesFreshIdsInsteadOfStaleCache()throws Exception{
  Gateway n=node();n.set("adminServerId","old-server");n.set("adminDeploymentId","old-deployment");
  JSONObject a=AdminAccessController.ownerEnableConfig(n,absent(),""),b=AdminAccessController.ownerEnableConfig(n,absent(),"");assertNotEquals("old-server",a.getString("server_id"));assertNotEquals("old-deployment",a.getString("deployment_id"));assertNotEquals(a.getString("server_id"),b.getString("server_id"));assertEquals("old-server",n.get("adminServerId"));
 }
 @Test public void aPairMustMatchTheActualManifestDeploymentAndRole()throws Exception{
  Gateway entry=node();entry.exit=node();JSONObject config=AdminAccessController.ownerEnableConfig(entry,paired("entry"),"canonical-deployment");assertEquals("canonical-deployment",config.getString("deployment_id"));
  assertEquals("canonical-server",AdminAccessController.ownerEnableConfig(entry.exit,paired("exit"),"canonical-deployment").getString("server_id"));
  refused(entry,paired("entry"),"another-deployment");refused(entry,paired("exit"),"canonical-deployment");refused(entry,existing(),"canonical-deployment");refused(node(),paired("exit"),"");
 }
 @Test public void pairConfigurationCannotAdoptAnotherRetainedDeployment()throws Exception{
  Gateway entry=node();entry.exit=node();JSONObject observation=paired("entry");observation.getJSONObject("authority").put("deployment_id","old-deployment");refused(entry,observation,"canonical-deployment");
 }
 @Test public void wrongMachineOrStoredHostKeyStopsBeforeInstallation()throws Exception{
  refused(node(),existing().put("machine","c".repeat(64)),"");JSONObject wrong=existing();wrong.getJSONObject("authority").put("fingerprint","SHA256:"+"c".repeat(43));refused(node(),wrong,"");Gateway unpinned=node();unpinned.set("fingerprint","");refused(unpinned,existing(),"");
 }
 @Test public void unreadableOrMalformedStateIsNeverTreatedAsAbsent()throws Exception{
  refused(node(),new JSONObject().put("schema",1).put("error","unreadable"),"");refused(node(),absent().put("state","unknown"),"");refused(node(),absent().put("state","existing"),"");refused(node(),absent().put("authority",new JSONObject()),"");
  for(String key:new String[]{"server_id","deployment_id","fingerprint","disabled"}){JSONObject bad=existing();bad.getJSONObject("authority").remove(key);refused(node(),bad,"");}
  JSONObject typed=existing();typed.getJSONObject("authority").put("server_id",12);refused(node(),typed,"");
 }
 @Test public void discoveryDoesNotReactivateDisabledSharingOrAlterGrants()throws Exception{
  Gateway n=node();JSONObject observed=existing();observed.getJSONObject("authority").put("disabled",true);String before=observed.toString();JSONObject config=AdminAccessController.ownerEnableConfig(n,observed,"");assertEquals("canonical-server",config.getString("server_id"));assertEquals(before,observed.toString());assertFalse(n.data.optBoolean("adminEnabled"));
 }
 @Test public void delegatedDevicesCannotUseOwnerDiscovery()throws Exception{
  Gateway n=node();n.data.put("adminAccess",true);refused(n,existing(),"");
 }
 @Test public void persistingReviewedIdentityRejectsChangedPinsAndInvalidIds()throws Exception{
  Gateway n=node();JSONObject config=AdminAccessController.ownerEnableConfig(n,existing(),"");n.set("fingerprint","SHA256:"+"c".repeat(43));try{AdminAccessController.rememberOwnerIdentity(n,config);fail("Changed pin accepted");}catch(IOException expected){}assertEquals("",n.get("adminServerId"));
 }
 private JSONObject scope()throws Exception{return new JSONObject().put("kind","deployment").put("id","canonical-deployment").put("users","all");}
 private JSONObject endpoint()throws Exception{return new JSONObject().put("host","peer.example.test").put("port",22).put("fingerprint",PIN);}
 private JSONObject linkedAuthority()throws Exception{return paired("entry").put("peers",new JSONArray().put(new JSONObject().put("id","peer-server").put("server_id","peer-server").put("peer_id","peer-fixture").put("account","rsp"+"a".repeat(20)).put("scope",scope()).put("endpoint",endpoint())));}
 private JSONObject linkedPeer()throws Exception{JSONObject peer=paired("exit");peer.getJSONObject("authority").put("server_id","peer-server").put("endpoint",endpoint());return peer.put("incoming",new JSONArray().put(new JSONObject().put("authority_id","canonical-server").put("peer_id","peer-fixture").put("account","rsp"+"a".repeat(20)).put("scope",scope()).put("revoked",false)));}
 private void refusedLink(JSONObject a,JSONObject b)throws Exception{Gateway owner=node();owner.exit=node();String beforeA=a.toString(),beforeB=b.toString();try{AdminAccessController.pairLinkDisposition(owner,owner.exit,a,b,"canonical-deployment");fail("An unverified existing link was replaced");}catch(IOException expected){}assertEquals(beforeA,a.toString());assertEquals(beforeB,b.toString());}
 @Test public void exactRetainedLinkIsReusedWithoutNewCredentials()throws Exception{
  Gateway owner=node();owner.exit=node();JSONObject a=linkedAuthority(),b=linkedPeer();String beforeA=a.toString(),beforeB=b.toString();assertEquals("reuse",AdminAccessController.pairLinkDisposition(owner,owner.exit,a,b,"canonical-deployment"));assertEquals(beforeA,a.toString());assertEquals(beforeB,b.toString());
 }
 @Test public void genuinelyAbsentLinkCanBeCreatedButUncertainPreparationCannotBeReplayed()throws Exception{
  Gateway owner=node();owner.exit=node();JSONObject a=linkedAuthority().put("peers",new JSONArray()),b=linkedPeer().put("incoming",new JSONArray());assertEquals("create",AdminAccessController.pairLinkDisposition(owner,owner.exit,a,b,"canonical-deployment"));
  refusedLink(a,linkedPeer());JSONObject revoked=linkedPeer();revoked.getJSONArray("incoming").getJSONObject(0).put("revoked",true);assertEquals("create",AdminAccessController.pairLinkDisposition(owner,owner.exit,a,revoked,"canonical-deployment"));
 }
 @Test public void wrongLinkedEndpointOrScopeNeverCreatesAReplacement()throws Exception{
  for(String field:new String[]{"id","server_id","peer_id","account","scope","endpoint"}){JSONObject a=linkedAuthority(),link=a.getJSONArray("peers").getJSONObject(0);if(field.equals("scope"))link.getJSONObject(field).put("id","wrong-deployment");else if(field.equals("endpoint"))link.getJSONObject(field).put("fingerprint","SHA256:"+"c".repeat(43));else link.put(field,"wrong");refusedLink(a,linkedPeer());}
 }
 @Test public void counterpartCredentialMustBeCurrentAndBoundToThisAuthority()throws Exception{
  for(String field:new String[]{"authority_id","peer_id","account","scope","revoked"}){JSONObject b=linkedPeer(),credential=b.getJSONArray("incoming").getJSONObject(0);if(field.equals("scope"))credential.getJSONObject(field).put("users","own");else if(field.equals("revoked"))credential.put(field,true);else credential.put(field,"wrong");refusedLink(linkedAuthority(),b);}
  refusedLink(linkedAuthority(),linkedPeer().put("incoming",new JSONArray()));refusedLink(linkedAuthority().put("peers",new JSONArray().put(new JSONObject()).put(new JSONObject())),linkedPeer());
 }
}
