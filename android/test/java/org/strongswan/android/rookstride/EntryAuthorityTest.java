package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

/** Server-confirmed migration completion must not transfer cached owner authority. */
public class EntryAuthorityTest {
 private Gateway node(String suffix)throws Exception{Gateway n=new Gateway();n.set("host","192.0.2."+suffix);n.set("machine","machine-"+suffix);n.set("fingerprint","pin-"+suffix);n.set("admin","root");n.data.put("remember",true);n.set("vpnLogin","unchanged-user");n.vpnPassword="chosen VPN secret";n.sshPassword="owner sign-in";return n;}
 private void authority(Gateway n,String id)throws Exception{n.set("adminServerId",id);n.set("adminDeploymentId","deployment-"+id);n.set("adminIdentityFingerprint",n.get("fingerprint"));n.data.put("adminEnabled",true).put("adminSnapshot",new JSONObject().put("server_id",id)).put("deploymentInventory",new JSONObject().put("server",id));}
 private JSONObject operation()throws Exception{return new JSONObject().put("operation","same-reviewed-operation");}
 private Gateway copy(Gateway n)throws Exception{return new Gateway(new JSONObject(n.persisted().toString()));}
 private void endpoint(Gateway pair,Gateway selected){for(String key:new String[]{"host","fingerprint","machine"})pair.set(key,selected.get(key));}
 private void assertNoAuthority(Gateway n){assertFalse(n.data.has("adminServerId"));assertFalse(n.data.has("adminDeploymentId"));assertFalse(n.data.has("adminEnabled"));assertFalse(n.data.has("adminSnapshot"));assertFalse(n.data.has("adminIdentityFingerprint"));assertEquals("root",n.get("admin"));}

 @Test public void firstAcceptanceClearsOldAuthorityNotVpnOrSshAndIgnoresCandidateCache()throws Exception{
  Gateway pair=node("1"),candidate=node("2");authority(pair,"old");authority(candidate,"unverified-candidate");Gateway previous=copy(pair);JSONObject op=operation();
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);
  assertNoAuthority(pair);assertFalse(pair.data.has("deploymentInventory"));assertEquals("unchanged-user",pair.get("vpnLogin"));assertEquals("chosen VPN secret",pair.vpnPassword);assertEquals("owner sign-in",pair.sshPassword);
  assertEquals("accepted",op.getJSONObject("authorityReconciliation").getString("state"));assertEquals(candidate.get("machine"),op.getJSONObject("authorityReconciliation").getString("machine"));assertEquals("unverified-candidate",candidate.get("adminServerId"));
 }
 @Test public void firstAcceptanceRetiresCoincidentPinFromAnEarlierRoundTrip()throws Exception{
  Gateway pair=node("2"),candidate=node("1");authority(pair,"stale-server-one");pair.set("adminIdentityFingerprint",candidate.get("fingerprint"));
  EntryMigrationController.reconcileAuthority(pair,candidate,copy(pair),operation(),false);assertNoAuthority(pair);
 }
 @Test public void lostReplyAfterLegacyLocalEndpointChangeStillClearsOnce()throws Exception{
  Gateway previous=node("1"),pair=node("2"),candidate=node("2");authority(pair,"stale-old-owner");JSONObject op=operation();
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);assertNoAuthority(pair);
 }
 @Test public void durableExactReplayPreservesFreshCandidateAuthorityAndInventory()throws Exception{
  Gateway pair=node("1"),candidate=node("2"),previous=copy(pair);JSONObject op=operation();authority(pair,"old");
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);endpoint(pair,candidate);pair.data.put("lastEntryMigration",op);pair=copy(pair);op=pair.data.getJSONObject("lastEntryMigration");authority(pair,"fresh-candidate");String before=pair.persisted().toString();
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);assertEquals(before,pair.persisted().toString());
 }
 @Test public void rollbackRestoresPriorAuthorityAndReplayKeepsLaterRefresh()throws Exception{
  Gateway pair=node("1"),candidate=node("2");authority(pair,"original");Gateway previous=copy(pair);JSONObject op=operation();
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);endpoint(pair,candidate);authority(pair,"new-server");
  EntryMigrationController.reconcileAuthority(pair,previous,previous,op,true);endpoint(pair,previous);assertEquals("original",pair.get("adminServerId"));assertFalse(pair.data.has("deploymentInventory"));
  pair.data.put("lastEntryMigration",op);pair=copy(pair);op=pair.data.getJSONObject("lastEntryMigration");authority(pair,"original-refreshed");String before=pair.persisted().toString();
  EntryMigrationController.reconcileAuthority(pair,previous,previous,op,true);assertEquals(before,pair.persisted().toString());
 }
 @Test public void rollbackWithoutMovingKeepsCurrentOriginalAuthority()throws Exception{
  Gateway pair=node("1");authority(pair,"old-snapshot");Gateway previous=copy(pair);authority(pair,"fresh-original");
  EntryMigrationController.reconcileAuthority(pair,previous,previous,operation(),true);assertEquals("fresh-original",pair.get("adminServerId"));assertFalse(pair.data.has("deploymentInventory"));
 }
 @Test public void rollbackDoesNotRestoreKnownWrongPhysicalAuthority()throws Exception{
  Gateway previous=node("1"),pair=node("2");authority(previous,"stale-other-server");previous.set("adminIdentityFingerprint","unrelated-pin");authority(pair,"candidate");
  EntryMigrationController.reconcileAuthority(pair,previous,previous,operation(),true);assertNoAuthority(pair);
 }
 @Test public void markerFromAnotherOperationOrPhysicalNodeCannotSuppressRetirement()throws Exception{
  Gateway pair=node("1"),candidate=node("2"),previous=copy(pair);JSONObject op=operation();
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);endpoint(pair,candidate);authority(pair,"newer");op.put("operation","different-operation");
  EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);assertNoAuthority(pair);
  authority(pair,"newer-again");pair.set("machine","unexpected-physical-machine");EntryMigrationController.reconcileAuthority(pair,candidate,previous,op,false);assertNoAuthority(pair);
 }
 @Test public void missingSelectedIdentityRefusesBeforeChangingAnyCache()throws Exception{
  Gateway pair=node("1"),candidate=node("2");authority(pair,"old");candidate.set("machine","");String before=pair.persisted().toString();JSONObject op=operation();
  try{EntryMigrationController.reconcileAuthority(pair,candidate,copy(pair),op,false);fail();}catch(java.io.IOException expected){}
  assertEquals(before,pair.persisted().toString());assertFalse(op.has("authorityReconciliation"));
 }
}
