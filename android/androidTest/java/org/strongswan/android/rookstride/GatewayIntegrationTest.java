package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in disposable-VPS test. Configuration lives only in the test app's private files. */
@RunWith(AndroidJUnit4.class)
public class GatewayIntegrationTest {
    @Test public void pinnedSshDeploymentAndManagement() throws Exception {
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        File file=new File(context.getFilesDir(),"integration.json");assumeTrue("No private integration configuration supplied",file.isFile());
        JSONObject config=new JSONObject(new String(Files.readAllBytes(file.toPath()),"UTF-8"));
        Gateway node=new Gateway(config.getJSONObject("gateway"));
        String pinned=node.get("fingerprint");assertFalse("Verify the key independently first",pinned.isEmpty());
        node.set("fingerprint","");
        try {new Ssh(node).close();fail("Unknown server key was accepted");}
        catch(Ssh.HostTrust e) {assertFalse(e.changed);assertEquals(pinned,e.fingerprint);}
        node.set("fingerprint","SHA256:intentionally-wrong-test-key");
        try {new Ssh(node).close();fail("Changed server key was accepted");}
        catch(Ssh.HostTrust e) {assertTrue(e.changed);}
        node.set("fingerprint",pinned);
        try(Ssh ssh=new Ssh(node)) {
            JSONObject probe=ssh.probe();assertEquals("ubuntu",probe.getString("os"));assertEquals("24.04",probe.getString("version"));
            if(config.optBoolean("install")) {
                assertFalse("Disposable VPS must be fresh",probe.getBoolean("existing"));
                JSONObject request=config.getJSONObject("deployment");
                JSONObject job;
                try(java.io.InputStream bundle=context.getAssets().open("gateway_bundle.zip")){job=ssh.deploy(bundle,request);}
                long deadline=System.currentTimeMillis()+25*60*1000;
                String id=job.getString("job");
                do {
                    Thread.sleep(5000);job=ssh.job(id);
                    if(job.getString("state").equals("failed"))fail(job.getString("phase"));
                    if(System.currentTimeMillis()>deadline)fail("Installation timed out");
                }while(!job.getString("state").equals("complete"));
            }
            JSONObject status=ssh.admin(new JSONObject().put("action","status"));
            assertTrue(status.getBoolean("monitoring_available"));
            String login="integration-device";
            JSONObject add=new JSONObject().put("action","add-user").put("login",login).put("password",config.getString("testPassword")).put("person","Integration person").put("device","Emulator").put("kind","device");
            ssh.admin(add);
            try {
                JSONObject profile=ssh.admin(new JSONObject().put("action","profile").put("login",login));
                assertEquals(1280,profile.getInt("mtu"));assertFalse(profile.toString().contains(config.getString("testPassword")));
                assertTrue(profile.getJSONObject("split-tunneling").getBoolean("block-ipv4"));
                assertTrue(profile.getJSONObject("split-tunneling").getBoolean("block-ipv6"));
                assertFalse(profile.getJSONObject("remote").getString("cert").isEmpty());
                ssh.admin(new JSONObject().put("action","adguard").put("level","strong"));
                JSONObject dns=ssh.admin(new JSONObject().put("action","adguard").put("level","standard"));
                assertTrue(dns.getJSONArray("filters").length()>0);
            }finally{ssh.admin(new JSONObject().put("action","remove-user").put("login",login));}
        }
    }
}
