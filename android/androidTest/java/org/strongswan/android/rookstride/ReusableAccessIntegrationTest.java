package org.strongswan.android.rookstride;

import android.content.*;import android.net.VpnService;import android.os.*;
import androidx.test.core.app.ActivityScenario;import androidx.test.ext.junit.runners.AndroidJUnit4;import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;import org.junit.runner.RunWith;import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;import org.strongswan.android.logic.VpnStateService;import org.strongswan.android.rookstride.engine.*;
import java.io.*;import java.lang.reflect.*;import java.nio.file.Files;import java.util.*;
import static org.junit.Assert.*;import static org.junit.Assume.assumeTrue;
import static androidx.test.espresso.Espresso.onView;import static androidx.test.espresso.action.ViewActions.*;import static androidx.test.espresso.matcher.ViewMatchers.*;import static androidx.test.espresso.assertion.ViewAssertions.*;import static org.hamcrest.Matchers.is;

/** Explicit disposable-fixture tests. Never discovers or reuses operator access. */
@RunWith(AndroidJUnit4.class)
public class ReusableAccessIntegrationTest {
 Context c(){return InstrumentationRegistry.getInstrumentation().getTargetContext();}
 JSONObject fixture()throws Exception{File f=new File(c().getFilesDir(),"password-access-test.json");assumeTrue(f.isFile());JSONObject value=new JSONObject(new String(Files.readAllBytes(f.toPath()),"UTF-8"));assumeTrue(value.optBoolean("disposable"));return value;}
 Object value(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
 void call(Object object,String name,Class<?>[] types,Object... values)throws Exception{Method m=object.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(object,values);}
 void open(ActivityScenario<RookstrideActivity> screen,Gateway node){screen.onActivity(a->{try{ArrayList<Gateway> nodes=(ArrayList<Gateway>)value(a,"gateways");boolean found=false;for(int i=0;i<nodes.size();i++)if(nodes.get(i).get("id").equals(node.get("id"))){nodes.set(i,node);found=true;break;}if(!found)nodes.add(node);call(a,"openVpn",new Class[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});}
 void connect(ActivityScenario<RookstrideActivity> screen,Gateway node)throws Exception{
  assertNull("Grant VPN consent on the owned emulator first",VpnService.prepare(c()));open(screen,node);
  screen.onActivity(a->{try{call(a,"connectPhone",new Class[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});
  long end=SystemClock.elapsedRealtime()+100000;
  if(node.get("protocol").equals("ikev2")){
   final VpnStateService[] service={null};screen.onActivity(a->{try{service[0]=(VpnStateService)value(a,"vpn");}catch(Exception e){throw new AssertionError(e);}});assertNotNull(service[0]);
   while(SystemClock.elapsedRealtime()<end&&!(service[0].getState()==VpnStateService.State.CONNECTED&&service[0].getProfile()!=null&&service[0].getProfile().getUUID().toString().equals(node.get("profileUuid"))))Thread.sleep(250);
   assertEquals("IKEv2 username/password failed",VpnStateService.State.CONNECTED,service[0].getState());
   assertEquals(node.get("profileUuid"),service[0].getProfile().getUUID().toString());
  }else{
   NativeVpn.Status status=NativeVpn.status(c(),node.get("protocol"));while(SystemClock.elapsedRealtime()<end&&!(status.id.equals(node.get("id"))&&(status.state.equals("connected")||status.state.equals("failed")))){Thread.sleep(300);status=NativeVpn.status(c(),node.get("protocol"));}
   assertEquals("Status belongs to another saved VPN",node.get("id"),status.id);assertEquals(status.error+"\n"+status.log,"connected",status.state);
  }
  // strongSwan excludes its own UID for its certificate fetcher. Its default
  // network is deliberately the underlay; the separate UID below checks VPN traffic.
  if(node.get("protocol").equals("ikev2")){Thread.sleep(1000);return;}
  android.net.ConnectivityManager cm=c().getSystemService(android.net.ConnectivityManager.class);long routeEnd=SystemClock.elapsedRealtime()+15000;boolean ready=false;
  while(SystemClock.elapsedRealtime()<routeEnd){android.net.Network n=cm.getActiveNetwork();android.net.NetworkCapabilities caps=cm.getNetworkCapabilities(n);android.net.NetworkInfo info=cm.getNetworkInfo(n);if(caps!=null&&caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)&&info!=null&&info.isConnected()){ready=true;break;}Thread.sleep(100);}assertTrue("Android has not committed the VPN route",ready);
 }
 void disconnect(ActivityScenario<RookstrideActivity> screen,Gateway node)throws Exception{
  if(node.get("protocol").equals("ikev2"))screen.onActivity(a->{try{VpnStateService vpn=(VpnStateService)value(a,"vpn");if(vpn!=null)vpn.disconnect();}catch(Exception e){throw new AssertionError(e);}});else NativeVpn.disconnect(c(),node.get("protocol"));Thread.sleep(1600);
 }
 JSONObject probe(JSONObject config)throws Exception{
  Method probe=NativeEngineIntegrationTest.class.getDeclaredMethod("foreignProbe",Context.class,String.class);probe.setAccessible(true);JSONObject value=null;
  for(int attempt=0;attempt<3;attempt++)try{value=(JSONObject)probe.invoke(new NativeEngineIntegrationTest(),c(),config.getString("canaryUrl"));break;}catch(InvocationTargetException error){if(attempt==2||error.getCause()==null||!String.valueOf(error.getCause().getMessage()).contains("UnknownHostException"))throw error;output("password-dns-startup-retries.json",new JSONObject().put("protocol",config.getString("protocol")).put("retries",attempt+1));Thread.sleep(3000);}
  assertTrue(value.toString(),value.getBoolean("vpnTransport"));assertEquals(config.getString("canaryToken"),value.getString("canary"));assertEquals(config.getString("expectedExit"),value.getString("ipv4Exit"));assertTrue(value.getBoolean("dnsBlocked"));assertFalse(value.getBoolean("ipv6Reachable"));return value;
 }
 void output(String file,JSONObject value)throws Exception{Files.write(new File(c().getFilesDir(),file).toPath(),value.toString().getBytes("UTF-8"));}
 AutoCloseable blockDirectExit(JSONObject config,Gateway node){
  if(!config.optBoolean("blockDirectExit")||!node.isPair())return ()->{};
  com.jcraft.jsch.SocketFactory delegate=Ssh.socketFactory;assertNotNull(delegate);String blocked=node.exit.get("host");int port=node.exit.port();
  Ssh.socketFactory=new com.jcraft.jsch.SocketFactory(){public java.net.Socket createSocket(String host,int p)throws IOException{if(host.equals(blocked)&&p==port)throw new java.net.ConnectException("Disposable fixture: exit SSH unavailable directly");return delegate.createSocket(host,p);}public InputStream getInputStream(java.net.Socket socket)throws IOException{return delegate.getInputStream(socket);}public OutputStream getOutputStream(java.net.Socket socket)throws IOException{return delegate.getOutputStream(socket);}};
  return ()->Ssh.socketFactory=delegate;
 }
 void additionalPassphrase(ActivityScenario<RookstrideActivity> screen,Gateway admin,JSONObject config,ArrayList<Gateway> nodes)throws Exception{
  String password=config.getString("longPassword"),login="long.user",protocol=admin.get("protocol");assertTrue(password.length()>15);open(screen,admin);screen.onActivity(a->{try{call(a,"addUser",new Class[]{Gateway.class},admin);}catch(Exception e){throw new AssertionError(e);}});
  onView(withTagValue(is((Object)"Name"))).perform(scrollTo(),replaceText("Long passphrase user"));onView(withTagValue(is((Object)"VPN username"))).perform(scrollTo(),replaceText(login));onView(withTagValue(is((Object)"VPN password"))).perform(scrollTo(),replaceText(password));androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Create user")).perform(click());if(InputRules.weakVpnPassword(password))onView(withText("Use anyway")).perform(click());
  androidx.test.uiautomator.UiDevice device=androidx.test.uiautomator.UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());assertNotNull(device.wait(androidx.test.uiautomator.Until.findObject(androidx.test.uiautomator.By.text("Share sign-in details")),60000));onView(withText("Done")).perform(click());
  Gateway user=new Gateway();user.set("protocol",protocol);user.set("host",config.getString("vpnServer"));user.set("name","Long passphrase client");user.set("vpnLogin",login);user.set("accessMode","password");user.vpnPassword=password;user.data.put("clientOnly",true);user.data.put("rememberVpn",true);user.data.put("vpnPort",config.getInt("vpnPort"));JSONObject definition=PasswordSignIn.definition(protocol,config.getString("vpnServer")+":"+config.getInt("vpnPort"),login,password,protocol.equals("ikev2")?"":PublicTrustRoots.read());
  if(protocol.equals("ikev2"))screen.onActivity(a->{try{call(a,"installProfile",new Class[]{Gateway.class,JSONObject.class},user,definition);}catch(Exception e){throw new AssertionError(e);}});else new NativeProfileStore(c()).save(user.get("id"),protocol,user.get("name"),definition.toString());nodes.add(user);new Vault(c()).write(nodes);connect(screen,user);probe(config);disconnect(screen,user);
 }
 @Test public void signedAppInstallsPasswordModeCreatesAndSharesUserAndConnectsWithoutExport()throws Exception{
  JSONObject config=fixture();String protocol=config.getString("protocol"),chosenLogin=config.optString("chosenLogin","family.user"),chosenPassword=config.optString("chosenPassword","lettersOnly");Gateway admin=new Gateway(new JSONObject(config.getJSONObject("admin").toString()));admin.set("id",UUID.randomUUID().toString());admin.set("protocol",protocol);admin.set("name","Disposable password installer");admin.set("vpnServer",config.getString("vpnServer"));admin.data.put("vpnPort",config.getInt("vpnPort"));admin.data.put("vpnPortAuto",false);admin.data.put("remember",true);admin.set("fingerprint","");ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(admin);new Vault(c()).write(nodes);c().getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();c().getSharedPreferences("rookstride-deployment",0).edit().clear().commit();
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class);AutoCloseable fault=blockDirectExit(config,admin)){
   open(screen,admin);if(admin.isPair())screen.onActivity(a->{try{call(a,"runPair",new Class[]{Gateway.class,boolean.class},admin,true);}catch(Exception e){throw new AssertionError(e);}});else onView(withText("Install VPN")).perform(click());long end=SystemClock.elapsedRealtime()+650000;
   while(SystemClock.elapsedRealtime()<end){DeploymentService.Session session=DeploymentService.current();if(session!=null&&session.node.get("id").equals(admin.get("id"))&&session.progress.state.equals("complete"))break;if(session!=null&&session.error!=null&&!(session.error instanceof Ssh.HostTrust)&&!(session.error instanceof PairController.TrustNeeded))throw session.error;Thread.sleep(300);}
   DeploymentService.Session session=DeploymentService.current();assertNotNull(session);assertEquals(session.progress.phase,"complete",session.progress.state);if(admin.isPair()){assertEquals("password",session.result.getJSONObject("entry").getString("access_mode"));assertTrue(session.result.getJSONObject("entry").optBoolean("monitoring_available"));}else assertEquals("password",session.config.getString("access_mode"));assertEquals("password",admin.get("accessMode"));if(config.optBoolean("blockDirectExit"))assertEquals("exit-via-entry",admin.get("resolvedSshRoute"));final ArrayList<Gateway> catalog=session.gateways;boolean known=false;for(int i=0;i<config.getJSONObject("admin").getJSONArray("pins").length();i++)if(admin.get("fingerprint").equals(config.getJSONObject("admin").getJSONArray("pins").getString(i)))known=true;assertTrue("App selected a key outside independently attested VM identities",known);screen.recreate();
   if(protocol.equals("openvpn")){connect(screen,admin);probe(config);disconnect(screen,admin);}
   open(screen,admin);screen.onActivity(a->{try{call(a,"addUser",new Class[]{Gateway.class},admin);}catch(Exception e){throw new AssertionError(e);}});
   onView(withTagValue(is((Object)"Name"))).perform(scrollTo(),replaceText("Family user"));onView(withTagValue(is((Object)"VPN username"))).perform(scrollTo(),replaceText(chosenLogin));onView(withTagValue(is((Object)"VPN password"))).perform(scrollTo(),replaceText(chosenPassword));androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Create user")).perform(click());if(InputRules.weakVpnPassword(chosenPassword))onView(withText("Use anyway")).perform(click());
   androidx.test.uiautomator.UiDevice device=androidx.test.uiautomator.UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());assertNotNull(device.wait(androidx.test.uiautomator.Until.findObject(androidx.test.uiautomator.By.text("Share sign-in details")),60000));onView(withText("Copy sign-in details")).perform(scrollTo(),click());screen.onActivity(a->{ClipboardManager clip=(ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE);String text=clip.getPrimaryClip().getItemAt(0).getText().toString();assertTrue(text.contains("Username: "+chosenLogin));assertTrue(text.contains("Password: "+chosenPassword));assertFalse(text.contains(admin.sshPassword));clip.setPrimaryClip(ClipData.newPlainText("",""));});onView(withText("Done")).perform(click());
   Gateway user=new Gateway();user.set("protocol",protocol);user.set("host",config.getString("vpnServer"));user.set("name","Reusable family sign-in");user.set("vpnLogin",chosenLogin);user.set("accessMode","password");user.vpnPassword=chosenPassword;user.data.put("clientOnly",true);user.data.put("rememberVpn",true);user.data.put("vpnPort",config.getInt("vpnPort"));JSONObject definition=PasswordSignIn.definition(protocol,config.getString("vpnServer")+":"+config.getInt("vpnPort"),chosenLogin,chosenPassword,protocol.equals("ikev2")?"":PublicTrustRoots.read());
   if(protocol.equals("ikev2"))screen.onActivity(a->{try{call(a,"installProfile",new Class[]{Gateway.class,JSONObject.class},user,definition);}catch(Exception e){throw new AssertionError(e);}});else new NativeProfileStore(c()).save(user.get("id"),protocol,user.get("name"),definition.toString());catalog.add(user);new Vault(c()).write(catalog);screen.onActivity(a->{try{Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);assertSame("Test must use the live app catalog",catalog,f.get(a));}catch(Exception e){throw new AssertionError(e);}});
   connect(screen,user);probe(config);try(Ssh ssh=new Ssh(admin)){assertEquals("0",ssh.execute("id -u",null));}disconnect(screen,user);if(config.has("longPassword"))additionalPassphrase(screen,admin,config,catalog);screen.recreate();disconnect(screen,user);
   output("password-reuse-node.json",user.persisted());output("password-access-result.json",new JSONObject().put("protocol",protocol).put("signed_app_install",true).put("double_vpn",admin.isPair()).put("automatic_password_mode",true).put("chosen_user_and_password",true).put("readable_sharing",true).put("manual_connection_without_export",true).put("independent_uid_traffic_and_filtering",true).put("protected_admin_ssh",true).put("recreated",true).put("long_passphrase_real_tunnel",config.has("longPassword")).put("automatic_exit_relay",config.optBoolean("blockDirectExit")));
  }
 }
 @Test public void unchangedSavedClientReconnectsAfterServerReinstall()throws Exception{
  JSONObject config=fixture();File f=new File(c().getFilesDir(),"password-reuse-node.json");assertTrue("Configured frozen-client fixture is missing",f.isFile());Gateway user=new Gateway(new JSONObject(new String(Files.readAllBytes(f.toPath()),"UTF-8")));assertTrue(user.data.getBoolean("clientOnly"));assertTrue(user.sshPassword.isEmpty());assertEquals(config.optString("chosenLogin","family.user"),user.get("vpnLogin"));
  String before=user.get("protocol").equals("ikev2")?user.get("profileUuid"):new NativeProfileStore(c()).read(user.get("id")).getString("content");
  // Model a recipient phone with the same saved client, without the installer’s
  // administrator catalog/job polling. Do not re-import or edit the VPN profile.
  DeploymentService.Session prior=DeploymentService.current();assertFalse("An installation is still active",DeploymentService.active());if(prior!=null)DeploymentService.forget(c(),prior.node);
  new Vault(c()).write(new ArrayList<>(Arrays.asList(user)));c().getSharedPreferences("rookstride-ui",0).edit().putString("selected",user.get("id")).commit();
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){connect(screen,user);probe(config);disconnect(screen,user);String after=user.get("protocol").equals("ikev2")?user.get("profileUuid"):new NativeProfileStore(c()).read(user.get("id")).getString("content");assertEquals("Saved client changed across the server rebuild",before,after);output("password-reuse-result.json",new JSONObject().put("protocol",user.get("protocol")).put("unchanged_saved_client",true).put("reconnect_after_reinstall",true).put("independent_uid_traffic_and_filtering",true));}
 }
 @Test public void existingDisposableClientCanRetryTrafficWithoutChangingItsDefinition()throws Exception{
  JSONObject config=fixture();Gateway user=null;for(Gateway node:new Vault(c()).read())if(node.data.optBoolean("clientOnly")&&node.get("protocol").equals(config.getString("protocol"))&&node.get("vpnLogin").equals(config.optString("chosenLogin","family.user")))user=node;assertNotNull("Configured saved client is missing from the app catalog",user);
  output("password-reuse-node.json",user.persisted());try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){try{connect(screen,user);probe(config);}finally{disconnect(screen,user);}}
 }
}
