package org.strongswan.android.rookstride;

import android.content.*;
import android.net.*;
import android.os.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.VpnStateService;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Real official strongSwan import/connection plus visible Rookstride refresh.
 * Uses the exact connection produced by the preceding actual sharing journey;
 * does not inject profiles into either client's database or invoke private handlers. */
@RunWith(AndroidJUnit4.class)
public final class ForeignClientAdministrationUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 v=device.wait(Until.findObject(selector),timeout);assertNotNull("A required foreign-client control did not appear",v);return v;}
 private static Gateway saved(PrivateAdministrationFixture f,Gateway expected)throws Exception{for(Gateway n:new Vault(f.context).read())if(n.get("id").equals(expected.get("id")))return n;throw new AssertionError("The confirmed saved connection is missing");}
 private static String sshSource(Gateway admin)throws Exception{try(Ssh ssh=new Ssh(admin)){assertEquals("0",ssh.execute("id -u",null));String[] fields=ssh.execute("printf '%s' \"$SSH_CONNECTION\"",null).trim().split(" +");assertEquals(4,fields.length);return fields[0];}}
 private static JSONObject profile(PrivateAdministrationFixture f,Gateway client)throws Exception{VpnProfileDataSource source=new VpnProfileSource(f.context);source.open();try{VpnProfile p=source.getVpnProfile(UUID.fromString(client.get("profileUuid")));assertNotNull(p);return IkeProfileIdentityTestSupport.snapshot(p);}finally{source.close();}}
 private static void waitIke(PrivateAdministrationFixture f,Gateway client,boolean connected)throws Exception{AtomicReference<VpnStateService> state=new AtomicReference<>();ServiceConnection service=new ServiceConnection(){public void onServiceConnected(ComponentName n,IBinder b){state.set(((VpnStateService.LocalBinder)b).getService());}public void onServiceDisconnected(ComponentName n){state.set(null);}};assertTrue(f.context.bindService(new Intent(f.context,VpnStateService.class),service,Context.BIND_AUTO_CREATE));try{long end=SystemClock.elapsedRealtime()+100000;while(SystemClock.elapsedRealtime()<end){VpnStateService s=state.get();boolean on=s!=null&&s.getState()==VpnStateService.State.CONNECTED&&s.getProfile()!=null&&s.getProfile().getUUID().toString().equals(client.get("profileUuid"));if(connected?on:s!=null&&s.getState()==VpnStateService.State.DISABLED)return;Thread.sleep(250);}throw new AssertionError("The Rookstride IKE ownership transition did not finish");}finally{f.context.unbindService(service);}}
 @Test public void realExternalIkeClientKeepsVisibleServerAdministrationAvailable()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("foreign-client-administration-ui","allow_foreign_admin_ui");Gateway expected=new Gateway(f.request.getJSONObject("admin")),client=new Gateway(f.request.getJSONObject("client")),admin=saved(f,expected);assertTrue(admin.isPair());assertEquals("ikev2",admin.get("pairEntryProtocol"));assertEquals(expected.get("pairId"),admin.get("pairId"));assertEquals(expected.get("fingerprint"),admin.get("fingerprint"));assertEquals(expected.exit.get("fingerprint"),admin.exit.get("fingerprint"));client=saved(f,client);assertTrue(client.data.optBoolean("clientOnly"));assertFalse(client.get("profileUuid").isEmpty());JSONObject before=f.request.getJSONObject("original_client_identity");assertTrue("The original imported client changed before the check",IkeProfileIdentityTestSupport.same(before,profile(f,client)));assertTrue("The exported IKE connection must use public CA selection",f.request.getJSONObject("foreign_profile").getJSONObject("remote").optString("cert").isEmpty());
  f.context.getPackageManager().getPackageInfo("org.strongswan.android",0);String expectedExit=f.request.getString("expected_exit");String direct=sshSource(admin);assertNotEquals("Underlay already exits through the tested VPN; isolate it before this routing check",expectedExit,direct);Uri grant=null;
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("VPNs")).perform(click());onView(withContentDescription("Open "+client.get("name"))).perform(scrollTo(),click());onView(allOf(withText("Connect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());UiObject2 battery=device.findObject(By.text("Connect now"));if(battery!=null)battery.click();UiObject2 consent=device.wait(Until.findObject(By.pkg("com.android.vpndialogs").res("android:id/button1")),5000);if(consent!=null)consent.click();waitIke(f,client,true);
   JSONObject exported=f.request.getJSONObject("foreign_profile");grant=ProfileExportProvider.issue(f.context,"rookstride-external-admin-test.sswan",exported.toString());f.context.grantUriPermission("org.strongswan.android",grant,Intent.FLAG_GRANT_READ_URI_PERMISSION);Intent open=new Intent(Intent.ACTION_VIEW).setComponent(new ComponentName("org.strongswan.android","org.strongswan.android.ui.VpnProfileImportActivity")).setDataAndType(grant,"application/vnd.strongswan.sswan-profile").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_GRANT_READ_URI_PERMISSION);f.context.startActivity(open);
   waitFor(By.res("org.strongswan.android","menu_accept").enabled(true),15000).click();UiObject2 list=waitFor(By.res("org.strongswan.android","profile_list"),15000);UiObject2 row=list.findObject(By.text(exported.getString("name")));assertNotNull("The official client did not import the actual shared file",row);row.click();
   long end=SystemClock.elapsedRealtime()+100000;boolean foreignReady=false;while(SystemClock.elapsedRealtime()<end){UiObject2 ok=device.findObject(By.res("android","button1"));if(ok!=null&&("OK".equals(ok.getText())||"Connect".equals(ok.getText())))ok.click();NetworkCapabilities caps=f.context.getSystemService(ConnectivityManager.class).getNetworkCapabilities(f.context.getSystemService(ConnectivityManager.class).getActiveNetwork());if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)){try{if(expectedExit.equals(sshSource(admin))){foreignReady=true;break;}}catch(Ssh.Unreachable transientNetwork){}}Thread.sleep(500);}assertTrue("The external VPN did not carry SSH through the expected exit",foreignReady);waitIke(f,client,false);
   // Bring the already-running activity forward as a launcher tap would, without
   // calling any navigation handler or replacing its saved catalog.
   f.context.startActivity(new Intent(f.context,RookstrideActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_REORDER_TO_FRONT));waitFor(By.desc("Servers"),15000).click();String name=admin.get("serverName").isEmpty()?admin.get("host"):admin.get("serverName");onView(withContentDescription("Manage "+name)).perform(scrollTo(),click());long began=System.currentTimeMillis();onView(withText("Refresh server")).perform(scrollTo(),click());boolean refreshed=false;end=SystemClock.elapsedRealtime()+120000;while(SystemClock.elapsedRealtime()<end){Gateway current=saved(f,admin);if(current.data.optLong("checkedAt")>=began&&current.exit.data.optLong("checkedAt")>=began){refreshed=true;break;}if(device.findObject(By.text("Action needs attention"))!=null)throw new AssertionError("Visible refresh failed while the external VPN was connected");Thread.sleep(250);}assertTrue("Visible paired refresh did not finish",refreshed);assertEquals(expectedExit,sshSource(admin));assertTrue("Server refresh changed the user's saved IKE client",IkeProfileIdentityTestSupport.same(before,profile(f,client)));
   f.receipt("foreign-client-administration-ui-result.json",new JSONObject().put("exact_shared_file_imported_by_official_client",true).put("visible_official_connection",true).put("rook_ike_ownership_revoked",true).put("ssh_source_is_expected_vpn_exit",true).put("visible_refresh_both_servers",true).put("ordinary_client_unchanged",true).put("underlay_distinct",true));
  }finally{if(grant!=null)f.context.revokeUriPermission(grant,Intent.FLAG_GRANT_READ_URI_PERMISSION);device.executeShellCommand("am force-stop org.strongswan.android");}
 }
}
