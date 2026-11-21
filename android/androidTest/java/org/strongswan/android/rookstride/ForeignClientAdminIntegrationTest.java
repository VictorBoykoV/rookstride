package org.strongswan.android.rookstride;

import android.content.*;import android.net.*;import androidx.test.core.app.ActivityScenario;import androidx.test.ext.junit.runners.AndroidJUnit4;import androidx.test.platform.app.InstrumentationRegistry;import androidx.test.uiautomator.*;
import org.junit.Test;import org.junit.runner.RunWith;import org.json.*;import java.io.*;import java.nio.file.*;import java.util.*;
import org.strongswan.android.ui.RookstrideActivity;import org.strongswan.android.rookstride.engine.*;
import static org.junit.Assert.*;import static org.junit.Assume.assumeTrue;

/** Opt-in real foreign-client test. No operator credentials or servers are discovered.
 * The fixture supplies an independently pinned SSH address reachable ONLY inside
 * its real IKE tunnel, a working native profile and an unmodified strongSwan app.
 */
@RunWith(AndroidJUnit4.class) public final class ForeignClientAdminIntegrationTest {
 @Test public void administratorSshUsesTheForeignVpnAfterNativeOwnershipIsRevoked()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File file=new File(c.getFilesDir(),"foreign-admin-private.json");assumeTrue(file.isFile());JSONObject fixture=new JSONObject(new String(Files.readAllBytes(file.toPath()),"UTF-8"));assumeTrue(fixture.optBoolean("disposable"));
  Gateway admin=new Gateway(fixture.getJSONObject("admin")),nativeNode=new Gateway(fixture.getJSONObject("nativeNode"));assertFalse(admin.get("fingerprint").isEmpty());assertTrue(nativeNode.data.optBoolean("clientOnly"));
  new NativeProfileStore(c).save(nativeNode.get("id"),nativeNode.get("protocol"),"Foreign-client test",fixture.getString("nativeContent"));new Vault(c).write(new ArrayList<>(Arrays.asList(nativeNode)));c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();
  UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());Uri grant=null;boolean nativeWasConnected=false;
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   // The fixture must not accidentally be reachable without its VPN.
   try(Ssh ignored=new Ssh(admin)){fail("VPN-only administrator fixture is directly reachable");}catch(Ssh.Unreachable expected){}
   ReusableAccessIntegrationTest helper=new ReusableAccessIntegrationTest();helper.connect(screen,nativeNode);helper.probe(fixture.getJSONObject("nativeProbe"));nativeWasConnected=true;
   JSONObject profile=fixture.getJSONObject("foreignProfile");grant=ProfileExportProvider.issue(c,"rookstride-external-admin-test.sswan",profile.toString());c.grantUriPermission("org.strongswan.android",grant,Intent.FLAG_GRANT_READ_URI_PERMISSION);
   Intent importProfile=new Intent(Intent.ACTION_VIEW).setComponent(new ComponentName("org.strongswan.android","org.strongswan.android.ui.VpnProfileImportActivity")).setDataAndType(grant,"application/vnd.strongswan.sswan-profile").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_GRANT_READ_URI_PERMISSION);c.startActivity(importProfile);
   UiObject2 accept=device.wait(Until.findObject(By.res("org.strongswan.android","menu_accept")),15000);assertNotNull("Official client did not show its import action",accept);accept.click();device.waitForIdle();
   // Import finishes by launching the official profile list. Wait for that
   // frame before starting, otherwise its late navigation can cover the control
   // Activity launched by the test. Use the same row tap as an actual user.
   UiObject2 list=device.wait(Until.findObject(By.res("org.strongswan.android","profile_list")),15000);assertNotNull("Official profile list did not finish importing",list);
   UiObject2 imported=list.findObject(By.text(profile.getString("name")));assertNotNull("Imported profile is missing from the official list",imported);imported.click();
   long deadline=android.os.SystemClock.elapsedRealtime()+100000;String source="";Exception last=null;boolean verified=false;
   while(android.os.SystemClock.elapsedRealtime()<deadline){
    UiObject2 yes=device.findObject(By.res("android","button1"));if(yes!=null&&("OK".equals(yes.getText())||"Connect".equals(yes.getText())))yes.click();
    ConnectivityManager cm=c.getSystemService(ConnectivityManager.class);NetworkCapabilities caps=cm.getNetworkCapabilities(cm.getActiveNetwork());
    if(!NativeVpn.status(c,nativeNode.get("protocol")).active(nativeNode.get("id"))&&caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))try(Ssh ssh=new Ssh(admin)){
     assertEquals("0",ssh.execute("id -u",null));source=ssh.execute("printf '%s' \"$SSH_CONNECTION\"",null).split(" ")[0];assertTrue("Administrator SSH did not arrive through the foreign VPN",source.startsWith(fixture.getString("foreignPoolPrefix")));verified=true;break;
    }catch(Ssh.Unreachable e){last=e;}
    Thread.sleep(500);
   }
   assertTrue(last==null?"Foreign VPN did not carry the administrator connection":last.getMessage(),verified);assertFalse("Rookstride native service remained active",NativeVpn.status(c,nativeNode.get("protocol")).active(nativeNode.get("id")));
   JSONObject result=new JSONObject().put("native_was_connected",nativeWasConnected).put("foreign_client","official strongSwan").put("rook_permission_revoked",true).put("admin_ssh_from_vpn_pool",true).put("root_command_succeeded",true).put("fixture_unreachable_without_vpn",true);
   Files.write(new File(c.getFilesDir(),"foreign-admin-result.json").toPath(),result.toString().getBytes("UTF-8"));
  }finally{if(grant!=null)c.revokeUriPermission(grant,Intent.FLAG_GRANT_READ_URI_PERMISSION);NativeVpn.disconnect(c,nativeNode.get("protocol"));device.executeShellCommand("am force-stop org.strongswan.android");new NativeProfileStore(c).remove(nativeNode.get("id"));}
 }
}
