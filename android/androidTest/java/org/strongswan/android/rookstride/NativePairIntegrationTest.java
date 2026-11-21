package org.strongswan.android.rookstride;

import android.content.*;
import android.net.VpnService;
import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeVpn;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in authorized disposable VPS pair. Never selects existing phone administrators. */
@RunWith(AndroidJUnit4.class) public class NativePairIntegrationTest {
 static Object invoke(Object target,String name,Class<?>[] types,Object...args)throws Exception{Method m=target.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(target,args);}
 static void progress(Context c,String step)throws Exception{Files.write(new File(c.getFilesDir(),"native-pair-progress.json").toPath(),new JSONObject().put("step",step).toString().getBytes("UTF-8"));}
 static void connected(Context c,Gateway node)throws Exception{long end=SystemClock.elapsedRealtime()+90000;NativeVpn.Status status=NativeVpn.status(c,node.get("protocol"));while(!status.state.equals("connected")&&!status.state.equals("failed")&&SystemClock.elapsedRealtime()<end){Thread.sleep(300);status=NativeVpn.status(c,node.get("protocol"));}assertEquals(status.error,"connected",status.state);assertEquals(node.get("id"),status.id);}
 static JSONObject probe(Context c,boolean socketOnly,String canary)throws Exception{
  try(InputStream cleared=new android.os.ParcelFileDescriptor.AutoCloseInputStream(InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("run-as io.rookstride.probe rm -f files/result.json"))){while(cleared.read()!=-1){} }
  Intent i=new Intent().setClassName("io.rookstride.probe","io.rookstride.probe.Main").putExtra("socketOnly",socketOnly).putExtra("finishAfter",true).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK);if(!socketOnly&&!canary.isEmpty())i.putExtra("canary",canary);c.startActivity(i);
  long end=SystemClock.elapsedRealtime()+65000;
  while(SystemClock.elapsedRealtime()<end){
   try(android.os.ParcelFileDescriptor fd=InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("run-as io.rookstride.probe cat files/result.json");InputStream in=new android.os.ParcelFileDescriptor.AutoCloseInputStream(fd)){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>16384)throw new IOException("Probe too large");}String text=out.toString("UTF-8").trim();if(text.startsWith("{"))return new JSONObject(text);}
   Thread.sleep(300);
  }
  throw new AssertionError("Separate-app probe did not finish");
 }
 static void verifyTraffic(JSONObject result,String exit,String token)throws Exception{if(!token.isEmpty())assertEquals(token,result.getString("canary"));assertTrue(result.toString(),result.getBoolean("ok"));assertTrue(result.getBoolean("vpnTransport"));assertEquals(exit,result.getString("ipv4Exit"));assertTrue("Ad DNS bypassed exit filtering",result.getBoolean("dnsBlocked"));assertFalse("IPv6 socket escaped",result.getBoolean("ipv6Reachable"));}
 @Test public void packagedServerRuntimesRetainTheirPinnedCompressedBytes()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();RuntimeComponents.install(c);JSONObject pins=Ssh.runtimeSource.metadata().getJSONObject("assets");
  for(String architecture:new String[]{"x86_64","aarch64"}){java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");long size=0;try(InputStream in=Ssh.runtimeSource.open(architecture)){byte[] bytes=new byte[65536];int n;while((n=in.read(bytes))!=-1){digest.update(bytes,0,n);size+=n;}}StringBuilder hex=new StringBuilder();for(byte b:digest.digest())hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));assertEquals(pins.getJSONObject(architecture).getLong("archive_bytes"),size);assertEquals(pins.getJSONObject(architecture).getString("archive_sha256"),hex.toString());try(InputStream in=new java.util.zip.GZIPInputStream(Ssh.runtimeSource.open(architecture))){assertTrue(in.read()>=0);}}
 }
 @Test public void phoneDeploysBothNodesAndUsesTheCompleteGuardedRoute()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File file=new File(c.getFilesDir(),"native-pair-integration.json");assumeTrue("No disposable pair fixture",file.isFile());JSONObject fixture=new JSONObject(new String(Files.readAllBytes(file.toPath()),"UTF-8"));assumeTrue(fixture.optBoolean("disposable"));
  Gateway node=new Gateway(fixture.getJSONObject("gateway"));assertTrue(node.isPair());assertTrue(SingleProtocols.from(node.get("pairEntryProtocol")).embedded());assertNotEquals("ikev2",node.get("pairEntryProtocol"));assertNull("Grant VPN consent on this owned emulator first",VpnService.prepare(c));
  ArrayList<Gateway> before=new Vault(c).read(),nodes=new ArrayList<>(Arrays.asList(node));new Vault(c).write(nodes);c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();new File(c.getNoBackupFilesDir(),"app-routing.json").delete();
  JSONObject result=new JSONObject();boolean bridgeStopped=false;
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Field list=a.getClass().getDeclaredField("gateways");list.setAccessible(true);list.set(a,nodes);invoke(a,"openVpn",new Class<?>[]{Gateway.class},node);invoke(a,"runPair",new Class<?>[]{Gateway.class,boolean.class},node,true);}catch(Exception e){throw new AssertionError(e);}});
   progress(c,"installing both nodes");long end=SystemClock.elapsedRealtime()+45*60*1000L;while(DeploymentService.current()==null&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);assertNotNull(DeploymentService.current());
   screen.onActivity(a->{try{invoke(a,"openScreen",new Class<?>[]{String.class},"Stories");}catch(Exception e){throw new AssertionError(e);}});screen.recreate();
   String prior="";while(DeploymentService.active()&&SystemClock.elapsedRealtime()<end){String phase=DeploymentService.current().progress.phase;if(!phase.equals(prior)){progress(c,phase);prior=phase;}Thread.sleep(500);}
   DeploymentService.Session session=DeploymentService.current();assertEquals(session.progress.phase,"complete",session.progress.state);assertEquals(InstallationProgress.PAIR.length,session.progress.completed);assertTrue(session.progress.finished>0);String expected=session.result.getString("exit_ip");result.put("phone_installed_both_nodes",true).put("stories_and_recreation_did_not_cancel",true);
   screen.onActivity(a->{try{invoke(a,"openVpn",new Class<?>[]{Gateway.class},node);invoke(a,"connectPhone",new Class<?>[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});connected(c,node);progress(c,"checking separate-app traffic");verifyTraffic(probe(c,false,fixture.optString("canaryUrl")),expected,fixture.optString("canaryToken"));result.put("separate_app_https_exit_dns_ipv6",true);
   assertTrue("The outage-test endpoint must work before stopping the bridge",probe(c,true,fixture.optString("canaryUrl")).getBoolean("httpsIpv4Reachable"));
   try(Ssh ssh=new Ssh(node)){assertEquals("0",ssh.execute("id -u",null));ssh.execute("systemctl stop rookstride-pair-bridge",null);bridgeStopped=true;}
   progress(c,"checking bridge outage");Thread.sleep(1500);assertFalse("Client escaped through entry during bridge outage",probe(c,true,fixture.optString("canaryUrl")).getBoolean("httpsIpv4Reachable"));result.put("bridge_outage_no_entry_fallback",true);
   try(Ssh ssh=new Ssh(node)){ssh.execute("systemctl start rookstride-pair-bridge",null);bridgeStopped=false;}
   JSONObject restored=null;for(int attempt=0;attempt<5;attempt++){Thread.sleep(3000);restored=probe(c,false,fixture.optString("canaryUrl"));if(restored.optBoolean("ok"))break;}verifyTraffic(restored,expected,fixture.optString("canaryToken"));result.put("bridge_recovery",true);
   NativeVpn.disconnect(c,node.get("protocol"));long off=SystemClock.elapsedRealtime()+15000;while(NativeVpn.status(c,node.get("protocol")).active(node.get("id"))&&SystemClock.elapsedRealtime()<off)Thread.sleep(100);assertFalse(NativeVpn.status(c,node.get("protocol")).active(node.get("id")));
   try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){JSONObject added=ssh.single(bundle,new JSONObject().put("action","add-user").put("protocol",node.get("protocol")).put("login","offline-pair-user"));assertNotNull(added);try(InputStream export=c.getAssets().open("single_bundle.zip")){assertTrue(ssh.single(export,new JSONObject().put("action","profile").put("protocol",node.get("protocol")).put("login","offline-pair-user")) .getString("content").isEmpty()==false);}try(InputStream removal=c.getAssets().open("single_bundle.zip")){ssh.single(removal,new JSONObject().put("action","remove-user").put("protocol",node.get("protocol")).put("login","offline-pair-user"));}}result.put("disconnected_user_management",true);
   progress(c,"complete");Files.write(new File(c.getFilesDir(),"native-pair-result.json").toPath(),result.toString().getBytes("UTF-8"));
  }finally{if(bridgeStopped)try(Ssh ssh=new Ssh(node)){ssh.execute("systemctl start rookstride-pair-bridge",null);}NativeVpn.disconnect(c,node.get("protocol"));new NativeProfileStore(c).remove(node.get("id"));new Vault(c).write(before);}
 }
}
