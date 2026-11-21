package org.strongswan.android.rookstride;

import org.json.*;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public class LifecycleSnapshotsTest {
 private Gateway node(String host)throws Exception{
  Gateway value=new Gateway();value.set("host",host);value.set("admin","root");value.set("fingerprint","SHA256:"+"a".repeat(43));value.set("machine","b".repeat(64));value.set("vpnServer",host);value.set("protocol","awg");value.set("adminServerId","physical-admin");value.set("adminDeploymentId","deployment-fixture");value.data.put("remember",true).put("port",2222).put("vpnPort",443).put("adminEnabled",true).put("adminSnapshot",new JSONObject().put("role","owner")).put("certificate","retained trust fixture");value.sshPassword="retained SSH secret";value.privateKey="retained SSH key";value.vpnPassword="retained VPN secret";return value;
 }
 private JSONObject receipt(String state)throws Exception{return new JSONObject().put("state",state).put("operation","a".repeat(32)).put("previous",new JSONObject().put("nested-history","fixture"));}
 @Test public void completedHistoryIsOmittedFromCopiesWithoutChangingCurrentReceipts()throws Exception{
  for(String state:new String[]{"accepted","rolled-back"}){
   Gateway value=node("entry.example.test");JSONObject entry=receipt(state),exit=receipt(state);value.data.put("lastEntryMigration",entry).put("lastLifecycleOperation",exit);String before=value.persisted().toString();
   JSONObject copy=LifecycleSnapshots.copy(value);assertFalse(copy.has("lastEntryMigration"));assertFalse(copy.has("lastLifecycleOperation"));assertSame(entry,value.data.getJSONObject("lastEntryMigration"));assertSame(exit,value.data.getJSONObject("lastLifecycleOperation"));assertEquals(before,value.persisted().toString());
  }
 }
 @Test public void rollbackKeepsExactIdentityAdministratorStateCredentialsAndPorts()throws Exception{
  Gateway value=node("entry.example.test");value.set("osPreviousFingerprint","previous SSH pin");value.set("osRestoredJob","c".repeat(32));value.set("osReinstallState","complete");value.data.put("osReinstall",new JSONObject().put("job","c".repeat(32))).put("lastEntryMigration",receipt("accepted"));JSONObject expected=value.persisted();expected.remove("lastEntryMigration");JSONObject copied=LifecycleSnapshots.copy(value);assertEquals(expected.toString(),copied.toString());Gateway rollback=new Gateway(copied);
  assertEquals(value.get("id"),rollback.get("id"));assertEquals(value.get("host"),rollback.get("host"));assertEquals(value.get("machine"),rollback.get("machine"));assertEquals(value.get("fingerprint"),rollback.get("fingerprint"));assertEquals(value.sshPassword,rollback.sshPassword);assertEquals(value.privateKey,rollback.privateKey);assertEquals(value.vpnPassword,rollback.vpnPassword);assertEquals(value.get("adminServerId"),rollback.get("adminServerId"));assertEquals(value.get("adminDeploymentId"),rollback.get("adminDeploymentId"));assertTrue(rollback.data.getBoolean("adminEnabled"));assertEquals(2222,rollback.port());assertEquals(443,rollback.data.getInt("vpnPort"));assertEquals("retained trust fixture",rollback.get("certificate"));
 }
 @Test public void unknownOrNonterminalHistoryIsNeverDiscarded()throws Exception{
  for(String state:new String[]{"preparing","awaiting-endpoint-switch","verified","accepting","rolled_back","ACCEPTED",""}){
   Gateway value=node("entry.example.test");value.data.put("lastEntryMigration",receipt(state)).put("lastLifecycleOperation",receipt(state));assertEquals(value.persisted().toString(),LifecycleSnapshots.copy(value).toString());
  }
  for(Object unknown:new Object[]{new JSONObject(),new JSONArray().put("unknown"),12,JSONObject.NULL}){Gateway value=node("entry.example.test");value.data.put("lastEntryMigration",unknown).put("lastLifecycleOperation",unknown);assertEquals(value.persisted().toString(),LifecycleSnapshots.copy(value).toString());}
 }
 @Test public void onlyActualGatewayExitStructureIsTraversed()throws Exception{
  Gateway value=node("entry.example.test");value.exit=node("exit.example.test");JSONObject originalReceipt=receipt("accepted");value.exit.data.put("lastLifecycleOperation",originalReceipt);JSONObject unrelated=new JSONObject().put("lastEntryMigration",receipt("accepted")).put("lastLifecycleOperation",receipt("accepted"));value.data.put("applicationMetadata",unrelated);
  JSONObject copy=LifecycleSnapshots.copy(value);assertFalse(copy.getJSONObject("pairExit").has("lastLifecycleOperation"));assertEquals(unrelated.toString(),copy.getJSONObject("applicationMetadata").toString());assertSame(originalReceipt,value.exit.data.getJSONObject("lastLifecycleOperation"));assertEquals(value.exit.sshPassword,copy.getJSONObject("pairExit").getString("sshPassword"));
 }
 @Test public void everyPendingOperationAndItsEmbeddedHistoryRemainsIntact()throws Exception{
  Gateway value=node("entry.example.test");for(String name:new String[]{"entryMigration","lifecycleOperation","helperUpdate","engineUpdate","pairedOsOperation"})value.data.put(name,new JSONObject().put("state","preparing").put("previous",new JSONObject().put("lastEntryMigration",receipt("accepted"))));value.data.put("lastHelperUpdate",receipt("accepted")).put("lastEngineUpdate",receipt("accepted")).put("lastPairedOsOperation",receipt("accepted")).put("lastOsReinstall",receipt("accepted"));assertEquals(value.persisted().toString(),LifecycleSnapshots.copy(value).toString());
 }
 @Test public void repeatedAlternatingEntryAndExitSnapshotsStayBounded()throws Exception{
  Gateway pair=node("entry.example.test");pair.exit=node("exit.example.test");int maximum=0;
  for(int i=0;i<250;i++){
   JSONObject previous=LifecycleSnapshots.copy(pair),candidate=LifecycleSnapshots.copy(pair.exit);JSONObject operation=new JSONObject().put("state",i%2==0?"accepted":"rolled-back").put("operation",String.format("%032x",i+1)).put("previous",previous).put("candidate",candidate);
   if(i%2==0)pair.data.put("lastEntryMigration",operation);else pair.exit.data.put("lastLifecycleOperation",operation);
   int size=pair.persisted().toString().getBytes(StandardCharsets.UTF_8).length;maximum=Math.max(maximum,size);assertTrue("Completed replacement history recursively grew at iteration "+i,size<16000);
  }
  assertTrue(maximum>0);assertTrue(pair.data.has("lastEntryMigration"));assertTrue(pair.exit.data.has("lastLifecycleOperation"));assertEquals("retained SSH secret",new Gateway(LifecycleSnapshots.copy(pair)).sshPassword);
 }
 @Test public void nonrememberedSecretsRemainNonpersistedAsBefore()throws Exception{
  Gateway value=node("entry.example.test");value.data.put("remember",false);JSONObject expected=value.persisted(),copy=LifecycleSnapshots.copy(value);assertEquals(expected.toString(),copy.toString());for(String name:new String[]{"sshPassword","privateKey","vpnPassword"})assertFalse(copy.has(name));assertEquals("retained SSH secret",value.sshPassword);
 }
}
