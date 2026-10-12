package org.strongswan.android.rookstride;
import android.content.Context;
import android.content.Intent;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.data.*;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in live client check; use a shared login only on a server with uniqueids=never. */
@RunWith(AndroidJUnit4.class)
public class VpnConnectionTest {
 @Test public void actualIkev2ConnectionThroughEmbeddedEngine() throws Exception {
  Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();File config=new File(context.getFilesDir(),"vpn-test.json");assumeTrue(config.isFile());
  JSONObject value=new JSONObject(new String(Files.readAllBytes(config.toPath()),"UTF-8"));
  Gateway node=new Gateway();node.set("name","Live client integration test");node.set("vpnLogin",value.getJSONObject("profile").getJSONObject("local").getString("eap_id"));node.vpnPassword=value.getString("vpnPassword");
  AtomicReference<VpnStateService> service=new AtomicReference<>();
  try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)) {
   Thread.sleep(500);
   activity.onActivity(a->{try{
    Method install=RookstrideActivity.class.getDeclaredMethod("installProfile",Gateway.class,JSONObject.class);install.setAccessible(true);install.invoke(a,node,value.getJSONObject("profile"));
    Field vpn=RookstrideActivity.class.getDeclaredField("vpn");vpn.setAccessible(true);service.set((VpnStateService)vpn.get(a));
    Method connect=RookstrideActivity.class.getDeclaredMethod("connectPhone",Gateway.class);connect.setAccessible(true);connect.invoke(a,node);
   }catch(Exception e){throw new AssertionError(e);}});
   assertNotNull(service.get());long deadline=System.currentTimeMillis()+60000;
   while(service.get().getState()!=VpnStateService.State.CONNECTED && System.currentTimeMillis()<deadline)Thread.sleep(250);
   assertEquals("Embedded engine did not establish the tunnel; inspect private client log",VpnStateService.State.CONNECTED,service.get().getState());
   File result=new File(context.getFilesDir(),"vpn-ready.json");Files.write(result.toPath(),"{\"connected\":true}".getBytes("UTF-8"));
   context.startActivity(new Intent().setClassName("io.rookstride.probe","io.rookstride.probe.Main").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
   // The test probe runs as a separate UID; an external runner reads its result.
   Thread.sleep(Math.max(45000,Math.min(180000,value.optLong("holdSeconds",45)*1000)));
  }finally{
   if(service.get()!=null)service.get().disconnect();
   VpnProfileDataSource source=new VpnProfileSource(context);source.open();try{VpnProfile p=source.getVpnProfile(node.get("profileUuid"));if(p!=null)source.deleteVpnProfile(p);}finally{source.close();}
  }
 }
}
