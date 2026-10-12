package org.strongswan.android.rookstride;
import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.File;
import java.nio.file.Files;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Explicit opt-in only on a disposable/owner-authorized VPS. Deletes its managed VPN data. */
@RunWith(AndroidJUnit4.class)
public class ResetIntegrationTest {
 @Test public void reviewedResetThenFreshProbe() throws Exception {
  Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();File f=new File(context.getFilesDir(),"reset-test.json");assumeTrue(f.isFile());
  JSONObject cfg=new JSONObject(new String(Files.readAllBytes(f.toPath()),"UTF-8"));assertTrue(cfg.getBoolean("authorizeReset"));
  Gateway node=new Gateway(cfg.getJSONObject("gateway"));
  try(Ssh ssh=new Ssh(node)) {
   JSONObject plan;try(java.io.InputStream b=context.getAssets().open("gateway_bundle.zip")){plan=ssh.reset(b,new JSONObject().put("mode","plan"));}
   assertTrue(plan.getJSONArray("files").length()>0);
   try(java.io.InputStream b=context.getAssets().open("gateway_bundle.zip")){JSONObject r=ssh.reset(b,new JSONObject().put("mode","apply").put("token",plan.getString("token")).put("confirmation","DELETE VPN"));assertTrue(r.getBoolean("reset"));}
   JSONObject state=ssh.probe();assertFalse(state.getBoolean("existing"));assertFalse(state.getBoolean("gateway"));
  }
 }
}
