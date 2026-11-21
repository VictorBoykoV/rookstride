package org.strongswan.android.rookstride;

import android.content.*;
import android.os.*;
import android.net.VpnService;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.*;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in synthetic disposable-lab profiles; never uses saved administrator data. */
@RunWith(AndroidJUnit4.class)
public class NativeEngineIntegrationTest {
 /** Prepare an opt-in lab profile, then end instrumentation before lifecycle tests. */
 @Test public void seedDisposableProfileForExternalLifecycleTest()throws Exception{
  assumeTrue("yes".equals(InstrumentationRegistry.getArguments().getString("seedOnly")));
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"native-engine-test.json");assumeTrue(fixture.isFile());
  JSONObject config=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));JSONObject p=config.getJSONArray("profiles").getJSONObject(0);
  Gateway node=new Gateway();node.set("protocol",p.getString("protocol"));node.set("name","Disposable lifecycle test");node.data.put("clientOnly",true);
  new NativeProfileStore(c).save(node.get("id"),node.get("protocol"),node.get("name"),p.getString("content"));java.util.ArrayList<Gateway> saved=new java.util.ArrayList<>();saved.add(node);new Vault(c).write(saved);
  Files.write(new File(c.getFilesDir(),"native-seed-result.json").toPath(),new JSONObject().put("id",node.get("id")).put("protocol",node.get("protocol")).toString().getBytes("UTF-8"));
 }
 @Test public void nativeSingleInstallUsesDefaultsAndTheBundledInstaller()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File input=new File(c.getFilesDir(),"native-install-test.json");assumeTrue(input.isFile());JSONObject fixture=new JSONObject(new String(Files.readAllBytes(input.toPath()),"UTF-8"));assumeTrue(fixture.optBoolean("disposable"));
  Gateway node=new Gateway(new JSONObject(fixture.getJSONObject("admin").toString()));node.set("id",java.util.UUID.randomUUID().toString());node.set("protocol","xray");node.set("name","Disposable phone installation");node.data.put("remember",true);node.data.put("vpnPort",9443);node.data.put("vpnPortAuto",false);java.util.ArrayList<Gateway> nodes=new java.util.ArrayList<>();nodes.add(node);new Vault(c).write(nodes);
  try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
   activity.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);f.set(a,nodes);java.lang.reflect.Method open=RookstrideActivity.class.getDeclaredMethod("openVpn",Gateway.class);open.setAccessible(true);open.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
   androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Install VPN")).perform(androidx.test.espresso.action.ViewActions.click());
   long deadline=SystemClock.elapsedRealtime()+420000;while(DeploymentService.current()==null&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);assertNotNull(DeploymentService.current());activity.recreate();
   while(DeploymentService.active()&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(400);DeploymentService.Session session=DeploymentService.current();assertEquals(session.progress.phase,"complete",session.progress.state);assertEquals("this-phone",node.get("vpnLogin"));assertFalse(session.config.has("sni"));assertEquals(7,session.progress.completed);
   JSONObject profile;try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){JSONObject status=ssh.single(bundle,new JSONObject().put("action","status").put("protocol","xray"));assertTrue(status.getBoolean("running"));assertTrue(status.getJSONObject("filtering").getBoolean("running"));profile=ssh.single(new JSONObject().put("action","profile").put("protocol","xray").put("login","this-phone"));}
   String content=profile.getString("content").replace(":9443?",":"+fixture.getInt("clientPort")+"?");JSONArray profiles=new JSONArray().put(new JSONObject().put("protocol","xray").put("content",content));fixture.put("profiles",profiles).put("adBlockingExpected",true);
   Files.write(new File(c.getFilesDir(),"native-engine-test.json").toPath(),fixture.toString().getBytes("UTF-8"));
   androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Open VPN")).perform(androidx.test.espresso.action.ViewActions.click());androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Connect")).perform(androidx.test.espresso.action.ViewActions.click());
   deadline=SystemClock.elapsedRealtime()+90000;NativeVpn.Status connected=NativeVpn.status(c,"xray");while(SystemClock.elapsedRealtime()<deadline&&!connected.state.equals("connected")&&!connected.state.equals("failed")){Thread.sleep(300);connected=NativeVpn.status(c,"xray");}
   Files.write(new File(c.getFilesDir(),"phone-connect-diagnostic.json").toPath(),new JSONObject().put("state",connected.state).put("error",connected.error).put("log",connected.log).toString().getBytes("UTF-8"));assertEquals(connected.error,"connected",connected.state);assertEquals(node.get("id"),connected.id);assertTrue(new NativeProfileStore(c).exists(node.get("id")));
   androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("VPNs")).perform(androidx.test.espresso.action.ViewActions.click());androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Connected")).check(androidx.test.espresso.assertion.ViewAssertions.matches(androidx.test.espresso.matcher.ViewMatchers.isDisplayed()));androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Disconnect")).perform(androidx.test.espresso.action.ViewActions.click());
   deadline=SystemClock.elapsedRealtime()+10000;while(NativeVpn.status(c,"xray").active(node.get("id"))&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);assertEquals("disconnected",NativeVpn.status(c,"xray").state);
   Files.write(new File(c.getFilesDir(),"phone-install-result.json").toPath(),new JSONObject().put("bundled_phone_install",true).put("default_identity",true).put("automatic_reality_target",true).put("checkpoints",7).put("recreated",true).put("normal_connect_button",true).put("profile_cached_automatically",true).put("home_connected_and_disconnect",true).toString().getBytes("UTF-8"));
  }
 }
 @Test public void resetDisposableNativeServerThroughTheActualReviewUi()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File input=new File(c.getFilesDir(),"native-install-test.json");assumeTrue(input.isFile());JSONObject fixture=new JSONObject(new String(Files.readAllBytes(input.toPath()),"UTF-8"));assumeTrue(fixture.optBoolean("disposable"));
  Gateway node=new Gateway(new JSONObject(fixture.getJSONObject("admin").toString()));node.set("id",java.util.UUID.randomUUID().toString());node.set("protocol","xray");node.set("name","Disposable reset test");node.data.put("remember",true);
  try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){JSONObject status=ssh.single(bundle,new JSONObject().put("action","status").put("protocol","xray"));node.data.put("snapshot",status);String profile=ssh.single(new JSONObject().put("action","profile").put("protocol","xray").put("login","this-phone")).getString("content");new NativeProfileStore(c).save(node.get("id"),"xray",node.get("name"),profile);}
  java.util.ArrayList<Gateway> nodes=new java.util.ArrayList<>();nodes.add(node);new Vault(c).write(nodes);assertTrue(new NativeProfileStore(c).exists(node.get("id")));
  try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
   activity.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);f.set(a,nodes);java.lang.reflect.Method open=RookstrideActivity.class.getDeclaredMethod("openVpn",Gateway.class);open.setAccessible(true);open.invoke(a,node);java.lang.reflect.Method settings=RookstrideActivity.class.getDeclaredMethod("openScreen",String.class);settings.setAccessible(true);settings.invoke(a,"ServerSettings");}catch(Exception e){throw new AssertionError(e);}});
   androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Remove all VPN setups")).perform(androidx.test.espresso.action.ViewActions.scrollTo(),androidx.test.espresso.action.ViewActions.click());
   androidx.test.uiautomator.UiDevice device=androidx.test.uiautomator.UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());assertNotNull(device.wait(androidx.test.uiautomator.Until.findObject(androidx.test.uiautomator.By.text("Remove all VPN setups?")),20000));
   androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("I understand that affected users will lose access.")).perform(androidx.test.espresso.action.ViewActions.scrollTo(),androidx.test.espresso.action.ViewActions.click());androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Remove")).perform(androidx.test.espresso.action.ViewActions.click());
   long deadline=SystemClock.elapsedRealtime()+60000;java.util.concurrent.atomic.AtomicBoolean busy=new java.util.concurrent.atomic.AtomicBoolean(true);
   do{Thread.sleep(200);activity.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("busy");f.setAccessible(true);busy.set(f.getBoolean(a));}catch(Exception e){throw new AssertionError(e);}});}while(busy.get()&&SystemClock.elapsedRealtime()<deadline);assertFalse("Reset/refresh did not finish",busy.get());
   assertFalse("Removed device profile remains cached",new NativeProfileStore(c).exists(node.get("id")));
  }
  try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){assertEquals("Root SSH credentials no longer work","0",ssh.execute("id -u",null));JSONObject inventory=ssh.single(bundle,new JSONObject().put("action","inspect"));assertEquals(0,inventory.getJSONArray("installed_protocols").length());assertTrue("IKEv2 preflight must be ready after cleanup",inventory.getBoolean("ikev2_ready"));assertFalse(inventory.getJSONObject("filtering").getBoolean("installed"));assertEquals("Unrelated canary service was removed","active",ssh.execute("systemctl is-active rookstride-lab-canary",null));}
  Files.write(new File(c.getFilesDir(),"phone-reset-result.json").toPath(),new JSONObject().put("reviewed_phone_reset",true).put("profiles_cleared",true).put("protocols_and_filter_removed",true).put("ssh_and_unrelated_service_preserved",true).put("ikev2_preflight_ready",true).toString().getBytes("UTF-8"));
 }
 @Test public void managedFilterJobUsesBundledInstallerAndPreservesDeviceProfiles()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"native-engine-test.json");assumeTrue(fixture.isFile());
  JSONObject config=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));assumeTrue(config.optBoolean("managedFiltering"));
  java.util.ArrayList<Gateway> before=new Vault(c).read();JSONArray results=new JSONArray();
  try{
   for(String protocol:new String[]{"awg","xray","openvpn"}){
    Gateway node=new Gateway(new JSONObject(config.getJSONObject("admin").toString()));node.set("id",java.util.UUID.randomUUID().toString());node.set("protocol",protocol);node.set("name","Disposable filter job");node.set("vpnLogin","lab-phone");
    node.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("filtering",new JSONObject().put("installed",false)));
    String previous;try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){previous=ssh.single(bundle,new JSONObject().put("action","profile").put("protocol",protocol).put("login","lab-phone")).getString("content");}
    try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
     activity.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);java.util.ArrayList<Gateway> nodes=new java.util.ArrayList<>();nodes.add(node);new Vault(c).write(nodes);f.set(a,nodes);java.lang.reflect.Method open=RookstrideActivity.class.getDeclaredMethod("openVpn",Gateway.class);open.setAccessible(true);open.invoke(a,node);java.lang.reflect.Method enable=RookstrideActivity.class.getDeclaredMethod("enableFiltering",Gateway.class);enable.setAccessible(true);enable.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
     androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Continue")).perform(androidx.test.espresso.action.ViewActions.click());
     long deadline=SystemClock.elapsedRealtime()+180000;
     while(DeploymentService.current()==null&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
     assertNotNull(DeploymentService.current());activity.recreate();
     while(DeploymentService.active()&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(300);
     DeploymentService.Session session=DeploymentService.current();assertEquals(session.progress.phase,"complete",session.progress.state);assertEquals("filter",session.progress.kind);assertEquals(5,session.progress.completed);assertTrue(session.progress.finished>0);
     try(Ssh ssh=new Ssh(node)){assertEquals("Profile changed during phone filter job",previous,ssh.single(new JSONObject().put("action","profile").put("protocol",protocol).put("login","lab-phone")).getString("content"));assertTrue(ssh.single(new JSONObject().put("action","status").put("protocol",protocol)).getJSONObject("filtering").getBoolean("running"));}
     results.put(new JSONObject().put("protocol",protocol).put("phone_job_complete",true).put("five_checkpoints",true).put("activity_recreated",true).put("profile_unchanged",true));
    }
   }
  }finally{new Vault(c).write(before);}
  Files.write(new File(c.getFilesDir(),"managed-filter-result.json").toPath(),new JSONObject().put("protocols",results).toString().getBytes("UTF-8"));
 }
 private void progress(Context c,String protocol,String stage)throws Exception{Files.write(new File(c.getFilesDir(),"native-engine-progress.json").toPath(),new JSONObject().put("protocol",protocol).put("stage",stage).toString().getBytes("UTF-8"));}

 private void appHttps(String protocol)throws Exception{
  // Use the same two-origin availability contract as the actual client check.
  // The independent-app canary and exact egress checks remain mandatory below.
  String errors="";
  for(String target:new String[]{"https://example.com/","https://www.cloudflare.com/cdn-cgi/trace"}){
   javax.net.ssl.HttpsURLConnection c=(javax.net.ssl.HttpsURLConnection)new URL(target).openConnection();c.setRequestProperty("Connection","close");c.setConnectTimeout(15000);c.setReadTimeout(15000);
   try{if(c.getResponseCode()==200){try(InputStream input=c.getInputStream()){if(input.read()>=0)return;}}}catch(IOException e){errors+=e.getClass().getSimpleName()+" ";}finally{c.disconnect();}
  }
  fail(protocol+" app HTTPS failed at both origins: "+errors);
 }

 private String shell(String command)throws Exception{android.os.ParcelFileDescriptor fd=InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand(command);try(InputStream in=new android.os.ParcelFileDescriptor.AutoCloseInputStream(fd)){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[1024];int n;while((n=in.read(b))!=-1)out.write(b,0,n);return out.toString("UTF-8");}}
 private JSONObject foreignProbe(Context context,String canary)throws Exception{
  return foreignProbe(context,canary,false);
 }
 private JSONObject foreignProbe(Context context,String canary,boolean negativeCanary)throws Exception{
  // An old Activity's request thread can outlive its window. Do not allow it
  // to overwrite this independent run's result after CLEAR_TASK.
  shell("am force-stop io.rookstride.probe");
  shell("run-as io.rookstride.probe rm -f files/result.json");context.startActivity(new Intent().setClassName("io.rookstride.probe","io.rookstride.probe.Main").putExtra("canary",canary).putExtra("negativeCanary",negativeCanary).putExtra("finishAfter",true).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK));
  long deadline=System.currentTimeMillis()+60000;while(System.currentTimeMillis()<deadline){String raw=shell("run-as io.rookstride.probe cat files/result.json").trim();if(raw.startsWith("{")){JSONObject r=new JSONObject(raw);assertTrue("Separate app HTTPS failed: "+r,r.optBoolean("ok"));return r;}Thread.sleep(500);}throw new AssertionError("Separate app probe timeout");
 }

 @Test public void embeddedEnginesConnectCarryTrafficAndDisconnect()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"native-engine-test.json");assumeTrue(fixture.isFile());
  JSONObject config=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));JSONArray profiles=config.getJSONArray("profiles");JSONArray results=new JSONArray();
  assertNull("Grant VPN consent on this owned emulator before running live tests",VpnService.prepare(c));
  try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
   for(int i=0;i<profiles.length();i++){
    JSONObject p=profiles.getJSONObject(i);Gateway node=new Gateway();String protocol=p.getString("protocol");node.set("protocol",protocol);node.set("name","Disposable "+protocol);node.data.put("clientOnly",true);
    new NativeProfileStore(c).save(node.get("id"),protocol,node.get("name"),p.getString("content"));progress(c,protocol,"starting");
    try{
     activity.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);java.util.ArrayList<Gateway> nodes=new Vault(c).read();nodes.add(node);new Vault(c).write(nodes);f.set(a,nodes);java.lang.reflect.Method open=RookstrideActivity.class.getDeclaredMethod("openVpn",Gateway.class);open.setAccessible(true);open.invoke(a,node);java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("connectPhone",Gateway.class);m.setAccessible(true);m.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
     if(!c.getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(c.getPackageName())&&!c.getSharedPreferences("rookstride-ui",0).getBoolean("nativeBatteryAsked",false)){
      androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Connect now")).perform(androidx.test.espresso.action.ViewActions.click());
     }
     long deadline=System.currentTimeMillis()+75000;NativeVpn.Status state=NativeVpn.status(c,protocol);
     while(System.currentTimeMillis()<deadline&&!state.state.equals("connected")&&!state.state.equals("failed")){Thread.sleep(400);state=NativeVpn.status(c,protocol);}
     assertEquals(protocol+": "+state.error,"connected",state.state);assertEquals(node.get("id"),state.id);progress(c,protocol,"connected");
     appHttps(protocol);
     JSONObject probe=foreignProbe(c,config.getString("canaryUrl"));assertTrue("Separate UID must use the Android VPN",probe.getBoolean("vpnTransport"));assertEquals("VPN-only private canary",config.getString("canaryToken"),probe.getString("canary"));assertEquals(protocol+" separate-app egress",config.getString("expectedExit"),probe.getString("ipv4Exit"));assertFalse("IPv6 socket escaped",probe.getBoolean("ipv6Reachable"));if(config.optBoolean("adBlockingExpected"))assertTrue("Ad DNS escaped server filtering",probe.getBoolean("dnsBlocked"));
     progress(c,protocol,"foreign-app-canary-passed");Gateway admin=new Gateway(config.getJSONObject("admin"));try(Ssh ssh=new Ssh(admin)){assertEquals("Protected SSH while connected","0",ssh.execute("id -u",null));}
     progress(c,protocol,"ssh-passed");
     // The VPN remains service-owned across Activity recreation and backgrounding.
     Thread.sleep(800);activity.recreate();assertEquals("connected",NativeVpn.status(c,protocol).state);androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.withText("Connected")).check(androidx.test.espresso.assertion.ViewAssertions.matches(androidx.test.espresso.matcher.ViewMatchers.isDisplayed()));
     progress(c,protocol,"activity-recreated");
     // The administrator channel must survive disconnecting its managed VPN.
     try(Ssh ssh=new Ssh(admin)){
      assertEquals("0",ssh.execute("id -u",null));NativeVpn.disconnect(c,protocol);long until=System.currentTimeMillis()+10000;while(NativeVpn.status(c,protocol).active(node.get("id"))&&System.currentTimeMillis()<until)Thread.sleep(100);assertEquals("disconnected",NativeVpn.status(c,protocol).state);
      android.net.ConnectivityManager manager=c.getSystemService(android.net.ConnectivityManager.class);long routeDeadline=System.currentTimeMillis()+8000;
      while(System.currentTimeMillis()<routeDeadline){android.net.NetworkCapabilities caps=manager.getNetworkCapabilities(manager.getActiveNetwork());if(caps==null||!caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN))break;Thread.sleep(100);}
      android.net.NetworkCapabilities after=manager.getNetworkCapabilities(manager.getActiveNetwork());assertTrue("VPN route remained after disconnect",after==null||!after.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN));
      Thread.sleep(2500);assertEquals("Keeper restarted an intentionally disconnected VPN","disconnected",NativeVpn.status(c,protocol).state);
      assertEquals("SSH survived VPN teardown","0",ssh.execute("id -u",null));
     }
     activity.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("connectPhone",Gateway.class);m.setAccessible(true);m.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
     deadline=System.currentTimeMillis()+75000;state=NativeVpn.status(c,protocol);while(System.currentTimeMillis()<deadline&&!state.state.equals("connected")&&!state.state.equals("failed")){Thread.sleep(300);state=NativeVpn.status(c,protocol);}assertEquals(protocol+" reconnect: "+state.error,"connected",state.state);
     java.net.URL canary=new java.net.URL(config.getString("canaryUrl"));try(java.net.Socket socket=new java.net.Socket()){socket.connect(new java.net.InetSocketAddress(canary.getHost(),canary.getPort()),6000);socket.setSoTimeout(6000);socket.getOutputStream().write(("GET "+canary.getPath()+" HTTP/1.0\r\nHost: "+canary.getHost()+"\r\n\r\n").getBytes("UTF-8"));ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] block=new byte[1024];int n;while((n=socket.getInputStream().read(block))!=-1){out.write(block,0,n);assertTrue(out.size()<16000);}assertTrue("Reconnected tunnel canary",out.toString("UTF-8").contains(config.getString("canaryToken")));}
     progress(c,protocol,"reconnected");results.put(new JSONObject().put("protocol",protocol).put("connected",true).put("https",true).put("background",true).put("foreign_uid_https",true).put("exit_matches_server",true).put("ipv6_socket_blocked",true).put("ad_dns_blocked",probe.getBoolean("dnsBlocked")).put("private_canary",true).put("protected_ssh",true).put("ssh_survives_disconnect",true).put("reconnected_canary",true));
    }finally{
     NativeVpn.disconnect(c,protocol);long end=System.currentTimeMillis()+8000;while(NativeVpn.status(c,protocol).active(node.get("id"))&&System.currentTimeMillis()<end)Thread.sleep(100);new NativeProfileStore(c).remove(node.get("id"));java.util.ArrayList<Gateway> saved=new Vault(c).read();saved.removeIf(n->n.get("id").equals(node.get("id")));new Vault(c).write(saved);
    }
   }
  }finally{NativeVpn.disconnectAll(c);}
  Files.write(new File(c.getFilesDir(),"native-engine-result.json").toPath(),new JSONObject().put("profiles",results).toString().getBytes("UTF-8"));
 }
}
