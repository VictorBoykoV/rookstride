package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.VpnService;
import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.uiautomator.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.*;
import java.io.*;
import java.util.*;
import static org.junit.Assert.*;

/** Explicit disposable fixture, exact signed APK, actual foreground controller and
 * embedded saved-profile traffic before/after update and rollback. No fixture or
 * action opt-in means no remote request. Never fabricates an old-version receipt. */
@RunWith(AndroidJUnit4.class)
public final class EngineUpdatesIntegrationTest {
 private static final String RECEIPT="engine-update-live-result.json";
 private final PairController.Progress quiet=phase->{};

 @Test public void reviewedEngineUpdateRollsBackAndReappliesWithTheSamePhoneIdentity()throws Exception {
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("engine-update-cycle","allow_engine_updates");
  assertTrue("Native traffic checks require explicit authorization",f.request.optBoolean("allow_native_vpn"));
  Gateway node=new Gateway(new JSONObject(f.request.getJSONObject("engine_gateway").toString()));String group=f.request.getString("engine_group");
  assertTrue(Arrays.asList("awg","openvpn","ikev2","xray","routes","trusttunnel").contains(group));
  assertNotEquals("This fixture uses an embedded native client; IKE package tests can use an AWG entry with an IKE exit","ikev2",node.get("protocol"));
  for(Gateway member:node.isPair()?Arrays.asList(node,node.exit):Collections.singletonList(node)){assertEquals("root",member.get("admin"));assertTrue("Independent SSH pin required",member.get("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}"));}
  assertFalse("Finish the recorded update rather than starting another",node.data.has("engineUpdate"));
  ArrayList<Gateway> nodes=new Vault(f.context).read();boolean found=false;
  for(int i=0;i<nodes.size();i++)if(nodes.get(i).get("id").equals(node.get("id"))){nodes.set(i,node);found=true;break;}
  assertTrue("Seed this explicitly reviewed server and saved client first",found);new Vault(f.context).write(nodes);
  NativeProfileStore store=new NativeProfileStore(f.context);assertTrue("A pre-update saved profile is mandatory",store.exists(node.get("id")));
  String profile=store.read(node.get("id")).getString("content"),profileHash=PrivateAdministrationFixture.hash(profile);
  assertEquals("The fixture must name the original saved client hash",f.request.getString("original_profile_sha256"),profileHash);
  assertNull("Grant Android VPN consent on the disposable emulator first",VpnService.prepare(f.context));
  assertEquals("Use all-app routing for independent traffic proof","all",AppRouting.read(f.context).mode);
  f.context.getPackageManager().getApplicationInfo("io.rookstride.probe",0);
  f.context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();
  JSONObject receipt=new JSONObject().put("group",group).put("profile_sha256",profileHash).put("live_client_traffic_tested",false);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(activity->{try{java.lang.reflect.Field field=RookstrideActivity.class.getDeclaredField("gateways");field.setAccessible(true);field.set(activity,nodes);}catch(Exception e){throw new AssertionError(e);}});
   traffic(f,screen,node,store,profile);receipt.put("baseline_saved_client",true);f.receipt(RECEIPT,receipt);
   JSONObject initial=EngineUpdates.inspect(node,()->f.context.getAssets().open("gateway_bundle.zip"),quiet);assertTrue("No compatible installed runtime",EngineUpdates.supports(initial,group));
   run(screen,node,"prepare",group,initial);JSONObject first=new JSONObject(node.data.getJSONObject("engineUpdate").toString());
   requireChanged(first);receipt.put("first_operation",sanitized(first)).put("prepared_changed_candidate",true);f.receipt(RECEIPT,receipt);
   run(screen,node,"apply",group,null);assertEquals("verified",node.data.getJSONObject("engineUpdate").getString("state"));
   traffic(f,screen,node,store,profile);receipt.put("updated_saved_client",true);f.receipt(RECEIPT,receipt);
   run(screen,node,"rollback",group,null);assertFalse(node.data.has("engineUpdate"));assertEquals("rolled-back",node.data.getJSONObject("lastEngineUpdate").getString("state"));
   JSONObject rolled=EngineUpdates.inspect(node,()->f.context.getAssets().open("gateway_bundle.zip"),quiet);assertHashes(initial,rolled,group);
   traffic(f,screen,node,store,profile);receipt.put("rollback_restored_runtime_hashes",true).put("rolled_back_saved_client",true);f.receipt(RECEIPT,receipt);
   run(screen,node,"prepare",group,rolled);JSONObject second=new JSONObject(node.data.getJSONObject("engineUpdate").toString());requireChanged(second);
   for(String role:new String[]{"single","entry","exit"})if(first.has(role))assertNotEquals("New reviewed cycle reused an old operation",first.getString(role),second.getString(role));
   run(screen,node,"apply",group,null);traffic(f,screen,node,store,profile);
   run(screen,node,"accept",group,null);assertEquals("accepted",node.data.getJSONObject("lastEngineUpdate").getString("state"));assertFalse(node.data.has("engineUpdate"));
   assertEquals(profile,store.read(node.get("id")).getString("content"));receipt.put("second_operation",sanitized(node.data.getJSONObject("lastEngineUpdate"))).put("accepted_after_second_saved_client_check",true).put("foreground_service_and_activity_recreation",true).put("saved_profile_unchanged",true).put("live_client_traffic_tested",true);f.receipt(RECEIPT,receipt);
  }finally{disconnect(f.context,node);}
 }
 private void run(ActivityScenario<RookstrideActivity> screen,Gateway node,String action,String group,JSONObject review)throws Exception{
  screen.onActivity(activity->{try{java.lang.reflect.Field field=RookstrideActivity.class.getDeclaredField("gateways");field.setAccessible(true);ArrayList<Gateway> records=(ArrayList<Gateway>)field.get(activity);for(int i=0;i<records.size();i++)if(records.get(i).get("id").equals(node.get("id")))records.set(i,node);NativePairIntegrationTest.invoke(activity,"startEngineUpdate",new Class<?>[]{Gateway.class,String.class,String.class,JSONObject.class},node,action,group,review);}catch(Exception e){throw new AssertionError(e);}});
  long end=SystemClock.elapsedRealtime()+35*60_000L;boolean navigated=false;DeploymentService.Session selected=DeploymentService.current();
  assertNotNull("The actual foreground controller did not start",selected);assertEquals("engine-update",selected.progress.kind);
  while(SystemClock.elapsedRealtime()<end){
   DeploymentService.Session active=DeploymentService.current();assertSame("Another operation replaced this runtime job",selected,active);
   if(!navigated&&active.progress.state.equals("running")){screen.onActivity(activity->{try{NativePairIntegrationTest.invoke(activity,"openScreen",new Class<?>[]{String.class},"Stories");}catch(Exception e){throw new AssertionError(e);}});screen.recreate();navigated=true;}
   if(!active.progress.state.equals("running")){if(active.error!=null)throw new AssertionError("Recorded runtime action needs attention; retain operation for resume",active.error);assertEquals(active.progress.phase,"complete",active.progress.state);return;}Thread.sleep(400);
  }
  throw new AssertionError("Runtime action still recorded; resume its existing operation instead of preparing a fresh one");
 }
 private static void requireChanged(JSONObject operation)throws Exception{boolean changed=false;for(String role:new String[]{"single","entry","exit"}){JSONObject status=operation.optJSONObject(role+"_status");if(status!=null)changed|=status.optBoolean("available");}assertTrue("This test requires a genuine old→reviewed runtime change, not a same-version restart",changed);}
 private static void assertHashes(JSONObject before,JSONObject after,String group)throws Exception{for(String role:new String[]{"single","entry","exit"}){JSONObject node=before.optJSONObject(role),old=node==null?null:EngineUpdates.group(node,group);if(old!=null&&old.optBoolean("supported")){JSONObject now=EngineUpdates.group(after.getJSONObject(role),group);assertTrue(now.optBoolean("supported"));assertEquals(old.getJSONArray("current_hashes").toString(),now.getJSONArray("current_hashes").toString());}}}
 private static JSONObject sanitized(JSONObject op)throws Exception{JSONObject result=new JSONObject().put("state",op.optString("state"));for(String role:new String[]{"single","entry","exit"})if(op.has(role)){JSONObject status=op.optJSONObject(role+"_status");result.put(role,new JSONObject().put("operation",op.getString(role)).put("old_hashes",status.optJSONArray("old_hashes")).put("new_hash",status.optString("new_hash")).put("candidate",status.optString("candidate")));}return result;}
 private static void traffic(PrivateAdministrationFixture f,ActivityScenario<RookstrideActivity> screen,Gateway node,NativeProfileStore store,String original)throws Exception{
  assertEquals("The cached client identity changed",original,store.read(node.get("id")).getString("content"));
  screen.onActivity(activity->{try{NativePairIntegrationTest.invoke(activity,"connectPhone",new Class<?>[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});
  NativePairIntegrationTest.connected(f.context,node);screen.recreate();NativePairIntegrationTest.connected(f.context,node);
  try(android.os.ParcelFileDescriptor fd=InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("am force-stop io.rookstride.probe");InputStream in=new android.os.ParcelFileDescriptor.AutoCloseInputStream(fd)){while(in.read()!=-1){}}
  NativePairIntegrationTest.verifyTraffic(NativePairIntegrationTest.probe(f.context,false,""),f.request.getString("expected_exit_ip"),"");disconnect(f.context,node);
 }
 private static void disconnect(Context context,Gateway node)throws Exception{NativeVpn.disconnect(context,node.get("protocol"));long end=SystemClock.elapsedRealtime()+15000;while(NativeVpn.status(context,node.get("protocol")).active(node.get("id"))&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);assertFalse("VPN did not disconnect",NativeVpn.status(context,node.get("protocol")).active(node.get("id")));}
}
