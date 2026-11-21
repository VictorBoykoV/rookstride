package org.strongswan.android.rookstride;

import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Last-stage opt-in destructive acceptance: actual five-screen constructor and
 * explicit removal review. No private handlers, catalog injection or wipe commands. */
@RunWith(AndroidJUnit4.class)
public final class PairReconfigureUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 value=device.wait(Until.findObject(selector),timeout);assertNotNull("A required Double VPN control did not appear",value);return value;}
 private void phase(PrivateAdministrationFixture f,String phase)throws Exception{f.receipt("pair-reconfigure-ui-progress.json",new JSONObject().put("phase",phase));}
 private static void archive(PrivateAdministrationFixture f,String id)throws Exception{
  assertTrue(id.matches("[a-z0-9-]{8,40}"));File archive=f.file("pair-reconfigure-original-"+id);assertFalse("Preserve the earlier archive and review the interrupted operation before a fresh reconfigure",archive.exists());assertTrue(archive.mkdir());
  for(String name:new String[]{"gateways.enc","ssh-identities.enc"}){File source=f.file(name);if(source.isFile())PrivateAdministrationFixture.atomic(new File(archive,name),Files.readAllBytes(source.toPath()));}
  File source=new File(f.context.getNoBackupFilesDir(),"vpn-profiles"),target=new File(archive,"vpn-profiles");if(source.isDirectory()){assertTrue(target.mkdir());File[] files=source.listFiles();assertNotNull(files);for(File file:files)if(file.isFile()&&file.getName().endsWith(".enc"))PrivateAdministrationFixture.atomic(new File(target,file.getName()),Files.readAllBytes(file.toPath()));}
 }
 private DeploymentService.Session completed(Gateway old)throws Exception{long until=SystemClock.elapsedRealtime()+30*60*1000L;while(SystemClock.elapsedRealtime()<until){DeploymentService.Session s=DeploymentService.current();if(s!=null&&s.progress.kind.equals("pair")&&!s.node.get("pairId").equals(old.get("pairId"))&&s.node.get("host").equals(old.get("host"))){if(s.progress.state.equals("complete"))return s;if(!s.progress.state.equals("running"))throw new AssertionError("Pair replacement stopped. Inspect and resume its recorded operation; do not replay this test");}if(device.findObject(By.text("Action needs attention"))!=null)throw new AssertionError("Pair reconfiguration requires attention; inspect the private operation log");Thread.sleep(350);}throw new AssertionError("Pair setup exceeded the acceptance window; inspect its durable job before any retry");}
 private void chooseSaved(Gateway node,String addressTag){onView(withText("Choose a saved server")).perform(scrollTo(),click());onView(withTagValue(is((Object)("saved-pair-server-"+node.get("id"))))).perform(click());onView(withTagValue(is((Object)addressTag))).check(matches(withText(node.get("host"))));onView(withText("Save administrator passwords on this phone")).check(matches(isChecked()));onView(withText("Next")).perform(click());}
 private static String reviewedProtocol(JSONObject plan,String field,String fallback){
  String selected=plan.optString(field,fallback);for(SingleProtocols protocol:SingleProtocols.values())if(protocol.id.equals(selected))return selected;
  throw new AssertionError("The explicitly reviewed "+field+" is not available in the constructor");
 }
 @Test public void visibleReconfigureToPublicIkeEntryAndAwgExit()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("pair-reconfigure-ui","allow_pair_reconfigure");JSONObject plan=f.request.getJSONObject("pair_reconfigure");assertTrue("Complete the other pair/lifecycle acceptance before this destructive final phase",plan.getBoolean("lifecycle_acceptance_complete"));assertTrue(plan.getBoolean("remove_all_owned_vpns_on_both_nodes"));Gateway expected=new Gateway(f.request.getJSONObject("pair"));assertTrue(expected.isPair());assertTrue(PairController.modern(expected));
  String entryProtocol=reviewedProtocol(plan,"entry_protocol","ikev2"),exitProtocol=reviewedProtocol(plan,"exit_protocol","awg");boolean ikeEntry=entryProtocol.equals("ikev2");
  assertTrue("Provide a valid unique disposable next user",InputRules.username(plan.getString("next_login")));
  if(PasswordSignIn.supported(entryProtocol))assertTrue("Provide the next entry user's chosen VPN password",InputRules.vpnPassword(plan.getString("next_password")));
  assertTrue("Retained public IKE clients can only be checked on another IKE entry",ikeEntry||!plan.has("retained_client"));
  Gateway old=null;for(Gateway node:new Vault(f.context).read())if(node.get("id").equals(expected.get("id")))old=node;assertNotNull("Reviewed existing pair is missing",old);assertTrue(old.isPair());assertEquals(expected.get("pairId"),old.get("pairId"));assertEquals(expected.get("host"),old.get("host"));assertEquals(expected.exit.get("host"),old.exit.get("host"));for(Gateway node:new Gateway[]{old,old.exit}){Gateway check=node==old?expected:expected.exit;assertEquals(check.get("fingerprint"),node.get("fingerprint"));assertFalse(node.sshPassword.isEmpty());assertTrue(node.remember());}
  archive(f,plan.getString("archive_id"));phase(f,"archived encrypted pre-reconfigure catalog and clients");
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   String name=old.get("serverName").isEmpty()?old.get("host"):old.get("serverName");onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage "+name)).perform(scrollTo(),click());onView(withText("Server maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Double VPN & recovery")).perform(scrollTo(),click());onView(withText("Change Double VPN protocols")).perform(scrollTo(),click());waitFor(By.text("Phone → first server"),10000);onView(withTagValue(is((Object)("pair-choice-"+entryProtocol)))).perform(scrollTo(),click());onView(withText("Next")).perform(click());waitFor(By.text("First server → exit server"),10000);onView(withTagValue(is((Object)("pair-choice-"+exitProtocol)))).perform(scrollTo(),click());onView(withText("Next")).perform(click());chooseSaved(old,"Entry VPS address");chooseSaved(old.exit,"Exit VPS address");
   waitFor(By.text("Review your Double VPN"),10000);onView(withText("Install")).perform(click());waitFor(By.text("Replace VPN setups?"),120000);onView(withText("I understand that affected users will lose access.")).perform(scrollTo(),click());phase(f,"explicitly reviewed replacement of owned VPNs on both nodes");onView(withText("Remove")).perform(click());
   DeploymentService.Session session=completed(old);assertEquals(entryProtocol,session.node.get("pairEntryProtocol"));assertEquals(exitProtocol,session.node.get("pairExitProtocol"));assertEquals(10,session.progress.steps().length);assertEquals(10,session.progress.completed);assertNotNull(session.result);
   JSONObject entry=session.result.getJSONObject("entry"),exit=session.result.getJSONObject("exit");
   if(ikeEntry){assertEquals("password",session.node.get("accessMode"));assertEquals("public",entry.getJSONObject("certificate").getString("trust"));assertTrue(entry.getJSONObject("certificate").getBoolean("manual_sign_in"));assertEquals(old.get("host"),entry.getJSONObject("certificate").getString("identity"));}
   else{assertEquals(entryProtocol,entry.getString("protocol"));assertTrue("Entry VPN must be running",entry.getBoolean("running"));}
   if(!exitProtocol.equals("ikev2")){assertEquals(exitProtocol,exit.getString("protocol"));assertTrue("Exit VPN must be running",exit.getBoolean("running"));}
   assertEquals(plan.getString("expected_exit"),session.result.getString("exit_ip"));assertTrue("Exit ad blocking must be running",exit.getJSONObject("services").optBoolean("adguard")||exit.getJSONObject("services").optBoolean("adguardhome"));
   onView(withTagValue(is((Object)"installation-complete"))).check(matches(isDisplayed()));UiObject2 done=waitFor(By.pkg(f.context.getPackageName()).text("Done").enabled(true).clickable(true),15000);assertFalse("Done must have visible bounds",done.getVisibleBounds().isEmpty());done.click();screen.recreate();Gateway installed=null;for(Gateway node:new Vault(f.context).read())if(node.isPair()&&node.get("pairId").equals(session.node.get("pairId")))installed=node;assertNotNull(installed);assertEquals(entryProtocol,installed.get("pairEntryProtocol"));assertEquals(exitProtocol,installed.get("pairExitProtocol"));
   if(ikeEntry)assertEquals("password",installed.get("accessMode"));
   assertFalse("Entry health instance must be persisted",installed.get("serverInstance").isEmpty());assertEquals(entry.getString("instance"),installed.get("serverInstance"));assertNotNull(installed.exit);assertFalse("Exit health instance must be persisted",installed.exit.get("serverInstance").isEmpty());assertEquals(exit.getString("instance"),installed.exit.get("serverInstance"));assertFalse(DeploymentService.active());
   byte[] pairBytes=installed.persisted().toString().getBytes(StandardCharsets.UTF_8);PrivateAdministrationFixture.atomic(f.file("reconfigured-pair-private.json"),pairBytes);
   if(ikeEntry)PrivateAdministrationFixture.atomic(f.file("reconfigured-ike-pair-private.json"),pairBytes);
   JSONObject next=new JSONObject().put("schema",1).put("disposable",true).put("expected_apk_sha256",f.binary.getString("apk_sha256")).put("expected_signer_sha256",f.binary.getString("signer_sha256")).put("allow_user_sharing",true).put("allow_native_vpn",true).put("pair",installed.persisted());
   JSONObject journey=new JSONObject().put("node_id",installed.get("id")).put("protocol",entryProtocol).put("server_instance",installed.get("serverInstance")).put("ssh_fingerprint",installed.get("fingerprint")).put("login",plan.getString("next_login")).put("display_name","Disposable "+SingleProtocols.from(entryProtocol).title+" check").put("new_disposable_user",true).put("expected_exit",plan.getString("expected_exit"));
   if(PasswordSignIn.supported(entryProtocol))journey.put("password",plan.getString("next_password"));
   if(plan.has("retained_client")){journey.put("retained_client",plan.getJSONObject("retained_client")).put("retained_client_identity",plan.getJSONObject("retained_client_identity"));}
   next.put("user_journey",journey);byte[] nextBytes=next.toString().getBytes(StandardCharsets.UTF_8);PrivateAdministrationFixture.atomic(f.file("pair-user-journey-private.json"),nextBytes);if(ikeEntry)PrivateAdministrationFixture.atomic(f.file("ike-user-journey-private.json"),nextBytes);
   JSONObject receipt=new JSONObject().put("entry_protocol",entryProtocol).put("exit_protocol",exitProtocol).put("five_visible_setup_screens",true).put("saved_nodes_reused",true).put("explicit_two_node_removal_review",true).put("all_ten_setup_checkpoints",true).put("exit_adblocking",true).put("both_member_instances_persisted",true).put("owner_record_recreated",true).put("original_clients_archived_encrypted",true).put("phone_traffic_tested",false).put("pair_handoff","reconfigured-pair-private.json").put("sharing_handoff","pair-user-journey-private.json");
   if(ikeEntry)receipt.put("public_ip_certificate",true).put("password_mode_default",true);
   f.receipt("pair-reconfigure-ui-result.json",receipt);phase(f,"complete; run the separate "+SingleProtocols.from(entryProtocol).title+" sharing journey");
  }
 }
}
