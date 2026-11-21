package org.strongswan.android.rookstride;
import android.content.Context;import androidx.test.platform.app.InstrumentationRegistry;import androidx.test.ext.junit.runners.AndroidJUnit4;import androidx.test.core.app.ActivityScenario;import org.strongswan.android.ui.RookstrideActivity;import org.json.*;import java.nio.file.*;import java.io.*;import java.util.*;import org.junit.Test;import org.junit.runner.RunWith;import static org.junit.Assert.*;import static org.junit.Assume.assumeTrue;
/** Destructive opt-in only. Default CI has no fixture and cannot launch this job. */
@RunWith(AndroidJUnit4.class) public class OsReinstallIntegrationTest {
 @Test public void signedAppReinstallsTheExplicitDisposableServerAndVerifiesItsNewIdentity()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"os-reinstall-private.json");assumeTrue(fixture.isFile());JSONObject request=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));assumeTrue(request.optBoolean("allow_os_wipe"));
  Gateway node=new Gateway(request.getJSONObject("server"));if(node.get("id").isEmpty())node.set("id",java.util.UUID.randomUUID().toString());assertTrue(!node.get("fingerprint").isEmpty()||node.data.optJSONArray("trustedKeys")!=null);
  JSONArray attested=node.data.optJSONArray("trustedKeys");if(attested!=null){node.set("fingerprint","");try(Ssh ignored=new Ssh(node)){fail("Unpinned fixture key was accepted");}catch(Ssh.HostTrust e){boolean known=false;for(int i=0;i<attested.length();i++)if(e.fingerprint.equals(attested.getString(i)))known=true;assertTrue("Initial host key was not independently attested",known);node.set("fingerprint",e.fingerprint);}}
  assertEquals("root",node.get("admin"));node.data.put("remember",true);String oldMachine;JSONObject plan;
  try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("reinstall_bundle.zip")){
   oldMachine=ssh.probe().getString("machine");ssh.execute("mkdir -p /srv/rook-os-erase-canary && printf 'disposable fixture' > /srv/rook-os-erase-canary/check",null);plan=ssh.reinstall(bundle,new JSONObject().put("action","plan").put("version",request.getString("version")));
  }
  assertFalse(plan.getString("fingerprint").equals(node.get("fingerprint")));assertEquals(request.getString("version"),plan.getString("version"));
  ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);new Vault(c).write(nodes);new ServerIdentityPins(c).remember(node,node.get("fingerprint"));
  Files.write(new File(c.getFilesDir(),"os-old-machine.txt").toPath(),oldMachine.getBytes("UTF-8"));
  runAndVerify(c,node,plan,nodes,false,oldMachine);
 }
 @Test public void signedAppResumesRecordedReinstallWithoutSendingAnotherStart()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"os-reinstall-private.json");assumeTrue(fixture.isFile());JSONObject request=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));assumeTrue(request.optBoolean("allow_os_wipe"));
  ArrayList<Gateway> nodes=new Vault(c).read();assumeTrue(nodes.size()==1);Gateway node=nodes.get(0);JSONObject plan=node.data.optJSONObject("osReinstall");assumeTrue(plan!=null);File before=new File(c.getFilesDir(),"os-old-machine.txt");String oldMachine=before.exists()?new String(Files.readAllBytes(before.toPath()),"UTF-8"):"";
  runAndVerify(c,node,plan,nodes,true,oldMachine);
 }
 @Test public void completedRecordedReinstallIsVerifiedWithoutStartingAnotherWipe()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"os-reinstall-private.json");assumeTrue(fixture.isFile());JSONObject request=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));assumeTrue(request.optBoolean("allow_os_wipe"));
  ArrayList<Gateway> nodes=new Vault(c).read();assertEquals(1,nodes.size());Gateway node=nodes.get(0);assertEquals("complete",node.get("osReinstallState"));File before=new File(c.getFilesDir(),"os-old-machine.txt");String oldMachine=before.exists()?new String(Files.readAllBytes(before.toPath()),"UTF-8"):"";
  verifyComplete(c,node.data.getJSONObject("osReinstall"),oldMachine);
 }
 private void runAndVerify(Context c,Gateway node,JSONObject plan,ArrayList<Gateway> nodes,boolean resume,String oldMachine)throws Exception{
  Files.write(new File(c.getFilesDir(),"os-recovery-private.json").toPath(),new JSONObject(node.persisted().toString()).put("osReinstall",plan).toString().getBytes("UTF-8"));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->DeploymentService.launch(a,node,nodes,"os",plan,resume));long deadline=System.currentTimeMillis()+110*60*1000L;boolean journal=false;
   while(System.currentTimeMillis()<deadline){DeploymentService.Session s=DeploymentService.current();if(s!=null){
    if(!journal&&s.progress.completed>=1){screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("openScreen",String.class);m.setAccessible(true);m.invoke(a,"Stories");}catch(Exception e){throw new AssertionError(e);}});screen.recreate();journal=true;}
    if(!s.progress.state.equals("running")){if(s.error!=null)throw new AssertionError("Recorded OS job needs attention",s.error);assertEquals("complete",s.progress.state);break;}}
    Thread.sleep(3000);
   }
   assertEquals("complete",DeploymentService.current().progress.state);assertTrue(journal);
  }
  verifyComplete(c,plan,oldMachine);
 }
 private void verifyComplete(Context c,JSONObject plan,String oldMachine)throws Exception{
  ArrayList<Gateway> saved=new Vault(c).read();assertEquals(1,saved.size());Gateway result=saved.get(0);assertEquals("",result.get("protocol"));assertEquals("complete",result.get("osReinstallState"));assertEquals(plan.getString("fingerprint"),result.get("fingerprint"));Gateway draft=new Gateway();draft.set("host",result.get("host"));draft.data.put("port",result.port());assertEquals("A new setup draft still sees the erased server identity",plan.getString("fingerprint"),new ServerIdentityPins(c).get(draft));
  try(Ssh ssh=new Ssh(result)){JSONObject p=ssh.probe();assertEquals("ubuntu",p.getString("os"));assertEquals(plan.getString("version"),p.getString("version"));assertTrue(p.getString("machine").matches("[a-f0-9]{64}"));
   // KVM can derive machine-id from its stable firmware UUID. It is diagnostic
   // identity, not an erasure proof. Require an erased file and the new pinned key.
   assertEquals("erased",ssh.execute("if test -e /srv/rook-os-erase-canary/check; then printf retained; else printf erased; fi",null));assertFalse(p.optBoolean("gateway"));assertFalse(p.optBoolean("pair_helper"));
   Files.write(new File(c.getFilesDir(),"os-checks-result.json").toPath(),new JSONObject().put("version",p.getString("version")).put("machine_id_changed",!oldMachine.equals(p.getString("machine"))).put("canary_erased",true).put("planned_key_and_password_verified",true).put("empty_vpn_inventory",true).toString().getBytes("UTF-8"));}
  Files.write(new File(c.getFilesDir(),"os-result-private.json").toPath(),result.persisted().toString().getBytes("UTF-8"));
 }
}
