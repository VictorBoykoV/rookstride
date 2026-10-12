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

@RunWith(AndroidJUnit4.class)
public class ReadOnlySshTest {
 @Test public void hostKeyRejectionAndReadOnlyRootProbe() throws Exception {
  Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
  File file=new File(context.getFilesDir(),"readonly-ssh.json");assumeTrue(file.isFile());
  Gateway node=new Gateway(new JSONObject(new String(Files.readAllBytes(file.toPath()),"UTF-8")));
  String expected=node.get("fingerprint");assertFalse(expected.isEmpty());
  node.set("fingerprint","");
  try {new Ssh(node).close();fail("Unknown key accepted");}catch(Ssh.HostTrust e){assertFalse(e.changed);boolean matched=false;org.json.JSONArray trusted=node.data.getJSONArray("trustedKeys");for(int i=0;i<trusted.length();i++)if(e.fingerprint.equals(trusted.getString(i)))matched=true;assertTrue("Presented key differs from previously trusted keys",matched);expected=e.fingerprint;}
  node.set("fingerprint","SHA256:wrong-test-key");
  try {new Ssh(node).close();fail("Changed key accepted");}catch(Ssh.HostTrust e){assertTrue(e.changed);}
  node.set("fingerprint",expected);
  try(Ssh ssh=new Ssh(node)) {
   assertEquals("0",ssh.execute("id -u",null));
   JSONObject probe=ssh.probe();assertEquals("ubuntu",probe.getString("os"));
   assertFalse(probe.getString("version").isEmpty());
  }
 }
}
