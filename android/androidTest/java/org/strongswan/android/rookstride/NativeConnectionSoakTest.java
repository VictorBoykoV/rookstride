package org.strongswan.android.rookstride;
import android.content.*;
import android.os.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.lifecycle.Lifecycle;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in private fixtures. Never selects a saved phone profile or administrator. */
@RunWith(AndroidJUnit4.class)
public class NativeConnectionSoakTest {
 private void write(Context c,String file,JSONObject value)throws Exception{Files.write(new File(c.getFilesDir(),file).toPath(),value.toString().getBytes("UTF-8"));}
 private void https()throws Exception{android.net.ConnectivityManager cm=InstrumentationRegistry.getInstrumentation().getTargetContext().getSystemService(android.net.ConnectivityManager.class);android.net.Network network=cm.getActiveNetwork();assertTrue(cm.getNetworkCapabilities(network).hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN));javax.net.ssl.HttpsURLConnection con=(javax.net.ssl.HttpsURLConnection)network.openConnection(new URL("https://example.com/"));con.setConnectTimeout(10000);con.setReadTimeout(10000);try{assertEquals(200,con.getResponseCode());}finally{con.disconnect();}}
 @Test public void trafficSurvivesBackgroundAndOptionalProcessRestart()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File input=new File(c.getFilesDir(),"native-soak-test.json");assumeTrue(input.isFile());
  JSONObject f=new JSONObject(new String(Files.readAllBytes(input.toPath()),"UTF-8"));String protocol=f.getString("protocol");Gateway node=new Gateway();node.set("protocol",protocol);node.set("name","Owned connection fixture");node.data.put("clientOnly",true);
  boolean batteryChoice=c.getSharedPreferences("rookstride-ui",0).getBoolean("nativeBatteryAsked",false);c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).commit();
  int seconds=f.optInt("seconds",60);assertTrue(seconds>=30&&seconds<=1200);new NativeProfileStore(c).save(node.get("id"),protocol,node.get("name"),f.getString("content"));
  try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
   activity.onActivity(a->{try{java.lang.reflect.Method connect=RookstrideActivity.class.getDeclaredMethod("connectPhone",Gateway.class);connect.setAccessible(true);connect.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
   long deadline=SystemClock.elapsedRealtime()+75000;while(!NativeVpn.status(c,protocol).state.equals("connected")&&SystemClock.elapsedRealtime()<deadline){assertNotEquals(NativeVpn.status(c,protocol).error,"failed",NativeVpn.status(c,protocol).state);Thread.sleep(300);}
   assertEquals(NativeVpn.status(c,protocol).error,"connected",NativeVpn.status(c,protocol).state);
   if(f.optBoolean("recheckBurst")){
    for(int i=0;i<5;i++){NativeVpn.recheck(c,protocol);Thread.sleep(40);}
    deadline=SystemClock.elapsedRealtime()+45000;while(!NativeVpn.status(c,protocol).state.equals("connected")&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(200);
    assertEquals("Latest web check did not finish: "+NativeVpn.status(c,protocol).error,"connected",NativeVpn.status(c,protocol).state);
   }
   https();activity.moveToState(Lifecycle.State.CREATED);
   long began=SystemClock.elapsedRealtime(),lastProbe=began;int probes=1;write(c,"native-soak-progress.json",new JSONObject().put("stage","background").put("seconds",0));
   while(SystemClock.elapsedRealtime()-began<seconds*1000L){
    Thread.sleep(1000);long now=SystemClock.elapsedRealtime();
    if(now-lastProbe>=60000){deadline=now+45000;while(!NativeVpn.status(c,protocol).state.equals("connected")&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(300);assertEquals(NativeVpn.status(c,protocol).error,"connected",NativeVpn.status(c,protocol).state);https();probes++;lastProbe=SystemClock.elapsedRealtime();}
    write(c,"native-soak-progress.json",new JSONObject().put("stage","background").put("seconds",(now-began)/1000));
   }
   https();NativeVpn.Status state=NativeVpn.status(c,protocol);assertEquals(state.error,"connected",state.state);
   if(f.optBoolean("expectProcessRestart"))assertTrue("No sticky restart was observed",state.log.contains("Recovering VPN engine"));
   if(f.optBoolean("expectRekeys"))assertTrue("No renewed handshake was observed",state.log.contains("handshake renewed"));
   write(c,"native-soak-result.json",new JSONObject().put("protocol",protocol).put("seconds",seconds).put("https_probes",probes+1).put("state",state.state).put("recheck_burst",f.optBoolean("recheckBurst")).put("recovered",state.log.contains("Recovering VPN engine")).put("rekey_observed",state.log.contains("handshake renewed")));
  }finally{NativeVpn.disconnect(c,protocol);new NativeProfileStore(c).remove(node.get("id"));c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",batteryChoice).commit();}
 }
}
