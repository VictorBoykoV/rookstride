package org.strongswan.android.rookstride;

import android.content.Context;
import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import com.jcraft.jsch.SocketFactory;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.*;
import java.io.*;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Exact saved pre-wipe phone identity. No SSH, profile export or installation. */
@RunWith(AndroidJUnit4.class)
public final class PairedRestoreTrafficIntegrationTest {
 @Test public void originalSavedPhoneConnectsAfterBothServersAreRestored()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("paired-native-traffic","allow_native_vpn");
  Gateway pair=f.savedPair(new Vault(f.context).read());JSONObject meta=pair.data.getJSONObject("privatePairedRestoreTest");
  assertEquals("restored",pair.data.getJSONObject("lastPairedOsOperation").getString("phase"));assertTrue(meta.has("completed_boots"));assertEquals("awg",pair.get("protocol"));
  f.verifyRecordedBinary(meta);
  NativeProfileStore store=new NativeProfileStore(f.context);assertTrue("Do not retrieve or replace the pre-wipe profile",store.exists(pair.get("id")));
  String original=store.read(pair.get("id")).getString("content");assertEquals(meta.getString("profile_sha256"),PrivateAdministrationFixture.hash(original));
  f.context.getPackageManager().getApplicationInfo("io.rookstride.probe",0);
  f.context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();
  assertEquals("This acceptance requires all-app routing","all",AppRouting.read(f.context).mode);
  AtomicInteger sshAttempts=new AtomicInteger();SocketFactory previous=Ssh.socketFactory;
  Ssh.socketFactory=new SocketFactory(){public Socket createSocket(String host,int port)throws IOException{sshAttempts.incrementAndGet();throw new IOException("Cached-profile acceptance forbids administrator retrieval");}public InputStream getInputStream(Socket socket)throws IOException{return socket.getInputStream();}public OutputStream getOutputStream(Socket socket)throws IOException{return socket.getOutputStream();}};
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   connect(screen,pair);consent();NativePairIntegrationTest.connected(f.context,pair);traffic(f.context,pair.exit.get("host"));
   screen.recreate();NativePairIntegrationTest.connected(f.context,pair);traffic(f.context,pair.exit.get("host"));
   disconnect(f.context,pair);connect(screen,pair);NativePairIntegrationTest.connected(f.context,pair);traffic(f.context,pair.exit.get("host"));
   assertEquals("A cached phone connection attempted administrator access",0,sshAttempts.get());assertEquals(original,store.read(pair.get("id")).getString("content"));
   f.receipt("paired-native-traffic-result.json",new JSONObject().put("operation",pair.data.getJSONObject("lastPairedOsOperation").getString("operation")).put("operation_started_binary",meta.getJSONObject("binary")).put("original_profile_sha256",meta.getString("profile_sha256")).put("saved_profile_unchanged",true).put("no_ssh_or_profile_refresh",true).put("native_awg_connected",true).put("foreign_uid_https_exit_dns_ipv6",true).put("activity_recreation_retained_tunnel",true).put("cached_profile_reconnect",true).put("live_client_traffic_tested",true));
  }finally{Ssh.socketFactory=previous;disconnect(f.context,pair);}
 }
 private static void connect(ActivityScenario<RookstrideActivity> screen,Gateway pair){screen.onActivity(activity->{try{NativePairIntegrationTest.invoke(activity,"connectPhone",new Class<?>[]{Gateway.class},pair);}catch(Exception e){throw new AssertionError(e);}});}
 private static void consent()throws Exception{UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());UiObject2 okay=device.wait(Until.findObject(By.pkg("com.android.vpndialogs").res("android:id/button1")),5000);if(okay!=null)okay.click();}
 private static void traffic(Context context,String exit)throws Exception{try(android.os.ParcelFileDescriptor fd=InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("am force-stop io.rookstride.probe");InputStream in=new android.os.ParcelFileDescriptor.AutoCloseInputStream(fd)){while(in.read()!=-1){}}NativePairIntegrationTest.verifyTraffic(NativePairIntegrationTest.probe(context,false,""),exit,"");}
 private static void disconnect(Context context,Gateway pair)throws Exception{NativeVpn.disconnect(context,"awg");long end=SystemClock.elapsedRealtime()+15000;while(NativeVpn.status(context,"awg").active(pair.get("id"))&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);assertFalse("Native VPN did not disconnect",NativeVpn.status(context,"awg").active(pair.get("id")));}
}
