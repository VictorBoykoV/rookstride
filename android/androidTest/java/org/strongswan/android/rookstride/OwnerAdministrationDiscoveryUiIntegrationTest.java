package org.strongswan.android.rookstride;

import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.SystemClock;
import android.util.AtomicFile;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.hamcrest.Matchers;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeVpn;
import java.io.File;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Opt-in visible owner recovery of two retained modules; no direct UI handlers.
 * The reviewed Enable action may update helper files and pair links. Existing
 * device/grant/invitation records, VPN configuration and native profiles must stay. */
@RunWith(AndroidJUnit4.class)
public final class OwnerAdministrationDiscoveryUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 required(BySelector selector,long timeout){UiObject2 value=device.wait(Until.findObject(selector),timeout);assertNotNull("Required owner recovery control did not appear",value);return value;}
 private static void clearCache(Gateway node){ArrayList<String> keys=new ArrayList<>();node.data.keys().forEachRemaining(keys::add);for(String key:keys)if(key.startsWith("admin")&&!key.equals("admin"))node.data.remove(key);}
 private static Map<String,String> nativeFiles(android.content.Context context)throws Exception{TreeMap<String,String> result=new TreeMap<>();File[] files=new File(context.getNoBackupFilesDir(),"vpn-profiles").listFiles();if(files!=null)for(File file:files){assertTrue(file.isFile());result.put(file.getName(),PrivateAdministrationFixture.hash(file));}return result;}
 private static byte[] bytes(File file)throws Exception{return file.isFile()?Files.readAllBytes(file.toPath()):null;}
 private static void restore(File file,byte[] data)throws Exception{if(data==null)new AtomicFile(file).delete();else PrivateAdministrationFixture.atomic(file,data);}
 private static void restorePrefs(SharedPreferences prefs,Map<String,?> previous){SharedPreferences.Editor edit=prefs.edit().clear();for(Map.Entry<String,?> item:previous.entrySet()){Object value=item.getValue();String name=item.getKey();if(value instanceof String)edit.putString(name,(String)value);else if(value instanceof Boolean)edit.putBoolean(name,(Boolean)value);else if(value instanceof Integer)edit.putInt(name,(Integer)value);else if(value instanceof Long)edit.putLong(name,(Long)value);else if(value instanceof Float)edit.putFloat(name,(Float)value);else if(value instanceof Set)edit.putStringSet(name,new HashSet<>((Set<String>)value));}assertTrue(edit.commit());}
 private static final String OBSERVE=String.join("\n",
  "import hashlib,json,pathlib,sqlite3",
  "database=pathlib.Path('/var/lib/rookstride-access/authority.sqlite')",
  "with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as connection:",
  " config=json.loads(connection.execute('SELECT value FROM records WHERE kind=? AND id=?',('meta','config')).fetchone()[0])",
  " records=list(connection.execute(\"SELECT kind,id,value FROM records WHERE kind IN ('grant','device','invitation','credential','peer') ORDER BY kind,id\"))",
  " digest=hashlib.sha256(json.dumps(records,separators=(',',':')).encode()).hexdigest()",
  "files=[]",
  "for root in ('/etc/rookstride-pair','/var/lib/rookstride-single'):",
  " p=pathlib.Path(root)",
  " if p.exists(): files += [f for f in p.rglob('*') if f.is_file() and not f.is_symlink() and (root.endswith('pair') or f.name=='state.json')]",
  "h=hashlib.sha256()",
  "for path in sorted(files): h.update(str(path).encode()+b'\\0'+path.read_bytes()+b'\\0')",
  "manifest=json.loads(pathlib.Path('/etc/rookstride-pair/manifest.json').read_text())",
  "print(json.dumps({'server_id':config['server_id'],'deployment_id':config['deployment_id'],'manifest_deployment':manifest['plan']['pair'],'manifest_role':manifest['plan']['role'],'grants_digest':digest,'grant_record_count':len(records),'vpn_configuration_digest':h.hexdigest(),'machine':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()}))");
 private JSONObject observe(Gateway node)throws Exception{try(Ssh ssh=new Ssh(node)){String prefix=ssh.execute("id -u",null).trim().equals("0")?"":"sudo -n ";return new JSONObject(ssh.execute(prefix+"python3 -I -c "+InputRules.quote(OBSERVE),null));}}
 private Gateway saved(PrivateAdministrationFixture f,String id)throws Exception{long until=SystemClock.elapsedRealtime()+180000;while(SystemClock.elapsedRealtime()<until){for(Gateway node:new Vault(f.context).read())if(node.get("id").equals(id)&&node.data.optBoolean("adminEnabled")&&node.exit!=null&&node.exit.data.optBoolean("adminEnabled")&&node.data.optJSONObject("adminSnapshot")!=null)return node;if(device.hasObject(By.text("Action needs attention")))throw new AssertionError("Owner discovery failed; retain the exact diagnostic without retrying installation");Thread.sleep(200);}throw new AssertionError("The signed app did not persist owner discovery");}

 /** Explicit disposable-fixture synchronization after the external accepted
  * provider return. This is not a product import or automatic startup recovery. */
 private JSONObject seedVerifiedProviderReturn(PrivateAdministrationFixture f,Gateway expected,JSONObject entry,JSONObject exit)throws Exception{
  if(!f.request.optBoolean("allow_verified_provider_return_handoff"))return null;
  JSONObject review=f.request.getJSONObject("verified_provider_return_handoff");assertEquals(1,review.getInt("schema"));
  assertFalse("Finish local coordinator work before synchronizing the fixture",DeploymentService.active());assertFalse("Save the existing confirmed result first",DeploymentService.needsLocalSave());
  for(String protocol:new String[]{"awg","xray","openvpn","routes"})assertFalse("Stop native VPN engines before synchronizing the fixture",NativeVpn.isActive(NativeVpn.status(f.context,protocol).state));
  File handoff=reviewedFile(f,review.getString("file"),review.getString("sha256")),previousFile=reviewedFile(f,review.getString("prior_file"),review.getString("prior_sha256"));
  assertFalse("Use distinct actual handoff documents",handoff.equals(previousFile));
  JSONObject restoredDocument=new JSONObject(new String(Files.readAllBytes(handoff.toPath()),java.nio.charset.StandardCharsets.UTF_8));
  JSONObject previousDocument=new JSONObject(new String(Files.readAllBytes(previousFile.toPath()),java.nio.charset.StandardCharsets.UTF_8));
  assertEquals("The return was not based on this actual phone checkpoint",review.getString("prior_sha256"),restoredDocument.getString("source_phone_handoff_sha256"));
  assertEquals(canonical(previousDocument.getJSONObject("binary")),canonical(restoredDocument.getJSONObject("source_phone_binary")));
  Gateway returned=new Gateway(restoredDocument.getJSONObject("gateway")),previous=new Gateway(previousDocument.getJSONObject("gateway"));
  assertEquals("The requested pair differs from the immutable actual return handoff",canonical(expected.persisted()),canonical(returned.persisted()));
  for(Gateway owner:new Gateway[]{previous,returned}){assertTrue(owner.isPair());assertFalse(owner.data.optBoolean("clientOnly"));assertNull(owner.data.optJSONObject("adminAccess"));noActiveJobs(owner);}
  assertEquals(previous.get("id"),returned.get("id"));assertEquals(previous.get("pairId"),returned.get("pairId"));samePhysical(previous,returned,true);
  assertFalse("This handoff must actually replace the old VM exit",previous.exit.get("host").equals(returned.exit.get("host")));
  JSONObject sourceMarker=previous.data.getJSONObject("lastEntryMigration").getJSONObject("authorityReconciliation"),returnedMarker=returned.data.getJSONObject("lastEntryMigration").getJSONObject("authorityReconciliation");
  assertEquals("The app-produced entry authority marker must survive unchanged",canonical(sourceMarker),canonical(returnedMarker));assertEquals("accepted",sourceMarker.getString("state"));assertEquals(returned.get("machine"),sourceMarker.getString("machine"));assertEquals(returned.get("fingerprint"),sourceMarker.getString("fingerprint"));
  for(Gateway owner:new Gateway[]{previous,returned})for(Iterator<String> keys=owner.data.keys();keys.hasNext();){String key=keys.next();assertFalse("Do not manufacture entry cache retirement in this helper",key.startsWith("admin")&&!key.equals("admin"));}
  JSONObject operation=returned.data.getJSONObject("lastLifecycleOperation");assertEquals("accepted",operation.getString("state"));assertEquals(previous.data.getInt("deploymentRevision"),operation.getInt("expected_revision"));assertEquals(previous.data.getInt("deploymentRevision")+1,returned.data.getInt("deploymentRevision"));
  samePhysical(previous.exit,new Gateway(operation.getJSONObject("previous")),false);samePhysical(returned.exit,new Gateway(operation.getJSONObject("candidate")),true);
  for(int i=0;i<2;i++){Gateway node=i==0?returned:returned.exit;JSONObject observed=i==0?entry:exit;assertEquals(node.get("machine"),observed.getString("machine"));assertEquals(returned.get("pairId"),observed.getString("deployment_id"));assertEquals(returned.get("pairId"),observed.getString("manifest_deployment"));assertEquals(i==0?"entry":"exit",observed.getString("manifest_role"));assertFalse(observed.getString("server_id").isEmpty());if(!node.get("adminServerId").isEmpty())assertEquals("Retained physical authority cache contradicts actual server",node.get("adminServerId"),observed.getString("server_id"));}
  Vault vault=new Vault(f.context);ArrayList<Gateway> current=vault.read();int position=-1;TreeMap<String,String> unrelated=new TreeMap<>();
  for(int i=0;i<current.size();i++){Gateway node=current.get(i);if(node.get("id").equals(returned.get("id"))){assertEquals("Owner catalog ID is duplicated",-1,position);position=i;}else assertNull("Catalog IDs must be unique",unrelated.put(node.get("id"),canonical(node.persisted())));}
  assertTrue("The exact existing owner must be present",position>=0);Gateway prior=current.get(position);assertTrue(prior.isPair());assertFalse(prior.data.optBoolean("clientOnly"));assertNull(prior.data.optJSONObject("adminAccess"));noActiveJobs(prior);
  assertEquals(previous.get("pairId"),prior.get("pairId"));samePhysical(previous,prior,true);samePhysical(previous.exit,prior.exit,false);assertEquals(previous.data.getInt("deploymentRevision"),prior.data.getInt("deploymentRevision"));
  assertEquals(canonical(sourceMarker),canonical(prior.data.getJSONObject("lastEntryMigration").getJSONObject("authorityReconciliation")));
  byte[] pins=bytes(f.file("ssh-identities.enc"));Map<String,String> nativeBefore=nativeFiles(f.context);String beforeHash=PrivateAdministrationFixture.hash(f.file("gateways.enc"));
  File receipt=f.file("verified-provider-return-seed-result.json");assertFalse("Keep the existing synchronization receipt; inspect before repeating",receipt.exists());
  current.set(position,new Gateway(new JSONObject(returned.persisted().toString())));vault.write(current);
  ArrayList<Gateway> after=vault.read();assertEquals(current.size(),after.size());TreeMap<String,String> retained=new TreeMap<>();Gateway owner=null;for(Gateway node:after)if(node.get("id").equals(returned.get("id"))){assertNull(owner);owner=node;}else assertNull(retained.put(node.get("id"),canonical(node.persisted())));
  assertNotNull(owner);assertEquals(canonical(returned.persisted()),canonical(owner.persisted()));assertEquals("Unrelated/imported records changed",unrelated,retained);assertArrayEquals("SSH trust changed during local fixture synchronization",pins,bytes(f.file("ssh-identities.enc")));assertEquals(nativeBefore,nativeFiles(f.context));
  JSONObject result=new JSONObject().put("schema",1).put("explicit_disposable_fixture_only",true).put("provider_return_handoff_sha256",review.getString("sha256")).put("prior_actual_phone_handoff_sha256",review.getString("prior_sha256")).put("before_catalog_sha256",beforeHash).put("seeded_catalog_sha256",PrivateAdministrationFixture.hash(f.file("gateways.enc"))).put("fresh_pinned_authority_observations_before_write",true).put("only_matching_owner_replaced",true).put("unrelated_imported_native_and_pins_unchanged",true).put("entry_authority_marker_retained",true).put("synthetic_administrator_ids",false).put("final_restore_uses_seeded_public_pair",true);
  f.receipt(receipt.getName(),result);return result;
 }
 private static File reviewedFile(PrivateAdministrationFixture f,String name,String hash)throws Exception{assertTrue("Use a bounded app-private JSON basename",name.matches("[a-z0-9][a-z0-9-]{0,95}\\.json"));assertTrue(hash.matches("[a-f0-9]{64}"));File file=f.file(name);assertFalse(Files.isSymbolicLink(file.toPath()));assertEquals(f.context.getFilesDir().getCanonicalFile(),file.getCanonicalFile().getParentFile());assertTrue(file.isFile()&&file.length()>0&&file.length()<=2*1024*1024);assertEquals("The host-reviewed handoff bytes differ",hash,PrivateAdministrationFixture.hash(file));return file;}
 private static void samePhysical(Gateway expected,Gateway actual,boolean machine){assertNotNull(actual);for(String key:new String[]{"id","host","fingerprint"})assertEquals("The reviewed physical server differs: "+key,expected.get(key),actual.get(key));assertEquals(expected.port(),actual.port());if(machine||!expected.get("machine").isEmpty())assertEquals(expected.get("machine"),actual.get("machine"));}
 private static void noActiveJobs(Gateway node){for(Gateway part:new Gateway[]{node,node.exit})if(part!=null){assertTrue("Inspect the recorded server job first",part.get("job").isEmpty());for(String key:new String[]{"entryMigration","lifecycleOperation","pairedOsOperation","helperUpdateOperation","engineUpdateOperation"})assertFalse("Finish the recorded operation before fixture synchronization",part.data.has(key));}}
 private static String canonical(Object value)throws Exception{if(value instanceof JSONObject){JSONObject object=(JSONObject)value;ArrayList<String> keys=new ArrayList<>();object.keys().forEachRemaining(keys::add);Collections.sort(keys);StringBuilder result=new StringBuilder("{");for(String key:keys){if(result.length()>1)result.append(',');result.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));}return result.append('}').toString();}if(value instanceof JSONArray){JSONArray array=(JSONArray)value;StringBuilder result=new StringBuilder("[");for(int i=0;i<array.length();i++){if(i>0)result.append(',');result.append(canonical(array.get(i)));}return result.append(']').toString();}if(value==null||value==JSONObject.NULL)return "null";if(value instanceof String)return JSONObject.quote((String)value);return value.toString();}

 @Test public void retainedPairModulesReopenFromColdOwnerCacheWithoutReplacingAuthority()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("owner-administration-discovery-ui","allow_owner_administration_discovery");String attempt=f.request.optString("owner_discovery_attempt","");assertTrue("Use a bounded private owner-discovery attempt label",attempt.isEmpty()||attempt.matches("[a-z0-9-]{1,24}"));Gateway expected=f.pair();assertNotNull(expected.exit);assertTrue(expected.data.optBoolean("pairReady"));
  ConnectivityManager cm=f.context.getSystemService(ConnectivityManager.class);NetworkCapabilities network=cm.getNetworkCapabilities(cm.getActiveNetwork());assertTrue("Disconnect the disposable phone VPN first",network==null||!network.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
  JSONObject beforeEntry=observe(expected),beforeExit=observe(expected.exit);for(JSONObject state:new JSONObject[]{beforeEntry,beforeExit})assertEquals(expected.get("pairId"),state.getString("deployment_id"));assertEquals(expected.get("machine"),beforeEntry.getString("machine"));assertEquals(expected.exit.get("machine"),beforeExit.getString("machine"));
  JSONObject seeded=seedVerifiedProviderReturn(f,expected,beforeEntry,beforeExit);
  Vault vault=new Vault(f.context);ArrayList<Gateway> original=vault.read();Gateway prior=null;for(Gateway node:original)if(node.get("id").equals(expected.get("id")))prior=node;assertNotNull("Use the actual canonical owner record",prior);assertEquals(expected.get("fingerprint"),prior.get("fingerprint"));assertEquals(expected.exit.get("fingerprint"),prior.exit.get("fingerprint"));
  byte[] originalCatalog=bytes(f.file("gateways.enc")),originalPins=bytes(f.file("ssh-identities.enc"));Map<String,String> nativeBefore=nativeFiles(f.context);SharedPreferences prefs=f.context.getSharedPreferences("rookstride-ui",0);Map<String,?> oldPrefs=new HashMap<>(prefs.getAll());File backup=f.file("owner-discovery-original"+(attempt.isEmpty()?"":"-"+attempt));assertTrue("Keep the previous fixture backup; choose a fresh reviewed attempt label",backup.mkdir());PrivateAdministrationFixture.atomic(new File(backup,"gateways.enc"),originalCatalog);
  try{
   Gateway cold=new Gateway(new JSONObject(prior.persisted().toString()));clearCache(cold);clearCache(cold.exit);for(int i=0;i<original.size();i++)if(original.get(i).get("id").equals(cold.get("id")))original.set(i,cold);vault.write(original);
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    onView(withContentDescription("Servers")).perform(click());
    onView(Matchers.allOf(withTagValue(Matchers.is((Object)"server-management")),isDescendantOfA(withTagValue(Matchers.is((Object)("managed-server-"+cold.get("id"))))))).perform(scrollTo(),click());
    onView(withText("Server maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Access & administrators")).perform(scrollTo(),click());onView(withText("Administrators")).perform(scrollTo(),click());onView(withText("Enable administrator sharing")).perform(scrollTo(),click());required(By.text("Enable scoped administration?"),10000);required(By.res("android:id/button1"),10000).click();
    Gateway recovered=saved(f,cold.get("id"));assertEquals(beforeEntry.getString("server_id"),recovered.get("adminServerId"));assertEquals(beforeExit.getString("server_id"),recovered.exit.get("adminServerId"));assertEquals(cold.get("pairId"),recovered.get("adminDeploymentId"));assertEquals(cold.get("pairId"),recovered.exit.get("adminDeploymentId"));
    required(By.text("Invite administrator"),30000);device.waitForIdle(1500);SystemClock.sleep(250);assertTrue(device.takeScreenshot(f.file("owner-administration-discovery.png")));screen.recreate();recovered=saved(f,cold.get("id"));assertEquals(beforeEntry.getString("server_id"),recovered.get("adminServerId"));
    assertEquals(beforeEntry.toString(),observe(expected).toString());assertEquals(beforeExit.toString(),observe(expected.exit).toString());assertEquals(nativeBefore,nativeFiles(f.context));assertArrayEquals(originalPins,bytes(f.file("ssh-identities.enc")));
    f.receipt("owner-administration-discovered-private.json",new JSONObject().put("gateway",recovered.persisted()));
    f.receipt("owner-administration-discovery-result.json",new JSONObject().put("visible_enable_action",true).put("cold_owner_cache_recovered",true).put("both_canonical_authorities_preserved",true).put("existing_grant_device_invitation_credential_peer_records_unchanged",true).put("vpn_configuration_unchanged",true).put("native_ciphertexts_and_ssh_pins_unchanged",true).put("recreation_retains_discovery",true).put("native_tunnel_tested",false).put("owner_discovery_attempt",attempt).put("provider_return_seed",seeded==null?JSONObject.NULL:seeded));
   }
  }finally{restore(f.file("gateways.enc"),originalCatalog);restore(f.file("ssh-identities.enc"),originalPins);restorePrefs(prefs,oldPrefs);assertEquals(nativeBefore,nativeFiles(f.context));assertArrayEquals(originalCatalog,bytes(f.file("gateways.enc")));}
 }
}
