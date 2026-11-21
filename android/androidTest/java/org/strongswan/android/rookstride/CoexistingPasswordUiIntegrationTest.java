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
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Explicit signed-app installation through visible controls. This deliberately
 * retains the new independent listener for a separately authorized sharing and
 * client-traffic journey; it never resets or reinstalls the existing pair. */
@RunWith(AndroidJUnit4.class)
public final class CoexistingPasswordUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 value=device.wait(Until.findObject(selector),timeout);assertNotNull("A required coexistence control did not appear",value);return value;}
 private void phase(PrivateAdministrationFixture f,String value)throws Exception{f.receipt("coexisting-password-install-progress.json",new JSONObject().put("phase",value));}
 // Only hash the original pair and its AWG identity. The independent protocol,
 // shared DNS enrollment, operational counters and certificates may be added.
 private static final String SNAPSHOT="python3 - <<'PY'\nimport hashlib\nfrom pathlib import Path\nroot=Path('/etc/rookstride-pair')\npaths=[p for p in root.rglob('*') if p.is_file() and not p.is_symlink()]\nstate=Path('/var/lib/rookstride-single/awg/state.json')\nif state.is_file() and not state.is_symlink():paths.append(state)\nassert paths and state.is_file()\nh=hashlib.sha256()\nfor p in sorted(paths):h.update(str(p).encode()+b'\\0'+p.read_bytes()+b'\\0')\nprint(h.hexdigest())\nPY";
 private static JSONObject snapshot(Gateway pair)throws Exception{try(PairSsh ssh=PairSsh.connect(pair,p->{})){String entry=ssh.entry.execute(SNAPSHOT,null).trim(),exit=ssh.exit.execute(SNAPSHOT,null).trim();assertTrue("Entry identity snapshot failed",entry.matches("[a-f0-9]{64}"));assertTrue("Exit identity snapshot failed",exit.matches("[a-f0-9]{64}"));return new JSONObject().put("entry",entry).put("exit",exit);}}
 private DeploymentService.Session installed(Gateway pair)throws Exception{
  long until=SystemClock.elapsedRealtime()+15*60*1000L;
  while(SystemClock.elapsedRealtime()<until){DeploymentService.Session s=DeploymentService.current();if(s!=null&&s.node.get("protocol").equals("openvpn")&&s.node.get("coexistPair").equals(pair.get("pairId"))){if(s.progress.state.equals("complete"))return s;if(!s.progress.state.equals("running"))throw new AssertionError("OpenVPN installation needs attention; inspect the app's private operation record before retrying");}if(device.findObject(By.text("Action needs attention"))!=null)throw new AssertionError("The visible installation was rejected; inspect its private diagnostic without replaying setup");Thread.sleep(250);}
  throw new AssertionError("The authorized OpenVPN installation did not complete within 15 minutes; do not replay it");
 }
 private static void monitorReady(Gateway node)throws Exception{long end=SystemClock.elapsedRealtime()+30000;try(Ssh ssh=new Ssh(node)){while(SystemClock.elapsedRealtime()<end){JSONObject health=ssh.single(new JSONObject().put("action","status").put("protocol","openvpn"));assertEquals("Installed identity changed during monitoring startup",node.get("serverInstance"),health.getString("instance"));assertTrue("Installed OpenVPN stopped during monitoring startup",health.getBoolean("running"));if(health.optBoolean("monitoring_available"))return;Thread.sleep(1000);}}throw new AssertionError("OpenVPN usage monitoring did not become ready after its first status intervals");}
 @Test public void visibleSeparateOpenVpnInstallUsesPasswordModeAndPreservesPair()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("coexisting-password-install","allow_coexist_install_ui");JSONObject plan=f.request.getJSONObject("coexist_journey");assertTrue("Explicit new-listener authorization required",plan.getBoolean("new_disposable_protocol"));assertTrue("Explicit later-user authorization required",plan.getBoolean("new_disposable_user"));assertTrue(InputRules.username(plan.getString("next_login")));assertFalse(plan.getString("next_password").isEmpty());
  ArrayList<Gateway> beforeNodes=new Vault(f.context).read();Gateway pair=f.savedPair(beforeNodes);assertEquals("awg",pair.get("pairEntryProtocol"));assertEquals("awg",pair.get("pairExitProtocol"));assertFalse("Saved owner access required",pair.sshPassword.isEmpty());assertEquals(f.pair().get("fingerprint"),pair.get("fingerprint"));assertEquals(f.pair().exit.get("fingerprint"),pair.exit.get("fingerprint"));
  for(Gateway node:beforeNodes)assertFalse("OpenVPN already exists on this entry; inspect it instead of replaying installation",!node.isPair()&&!node.data.optBoolean("clientOnly")&&PairNodes.same(pair,node)&&node.get("protocol").equals("openvpn"));
  phase(f,"reading original pair identity");JSONObject before=snapshot(pair);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   String name=pair.get("serverName").isEmpty()?pair.get("host"):pair.get("serverName");onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage "+name)).perform(scrollTo(),click());onView(withText("Add a separate VPN")).perform(scrollTo(),click());waitFor(By.text("Install OpenVPN").enabled(true),90000);phase(f,"reviewed separate OpenVPN install");onView(withText("Install OpenVPN")).perform(click());
   DeploymentService.Session session=installed(pair);assertEquals("protocol",session.progress.kind);assertEquals("password",session.config.getString("access_mode"));assertEquals("this-phone",session.config.getString("login"));assertEquals(pair.get("pairId"),session.config.getString("coexist_pair"));assertEquals("password",session.node.get("accessMode"));assertNotNull(session.result);assertTrue("New VPN service failed its health check",session.result.getBoolean("running"));assertTrue("Installation did not enable username/password sign-in",session.result.getBoolean("manual_sign_in"));assertEquals(pair.get("pairId"),session.result.getString("coexist_pair"));assertTrue("Shared ad blocking was not enabled",session.result.getJSONObject("filtering").getBoolean("running"));
   phase(f,"confirming saved password-mode connection");onView(withTagValue(is((Object)"installation-complete"))).check(matches(isDisplayed()));onView(withText("Done")).perform(click());screen.recreate();Gateway created=null;for(Gateway node:new Vault(f.context).read())if(node.get("id").equals(session.node.get("id")))created=node;assertNotNull("Installed owner record was not persisted",created);assertEquals("password",created.get("accessMode"));assertEquals(pair.get("pairId"),created.get("coexistPair"));assertFalse(created.get("serverInstance").isEmpty());assertFalse("Generated first-user password was lost",created.vpnPassword.isEmpty());assertFalse(DeploymentService.active());monitorReady(created);
   JSONObject after=snapshot(pair);assertEquals("Independent installation changed entry pair/users",before.getString("entry"),after.getString("entry"));assertEquals("Independent installation changed exit pair/users",before.getString("exit"),after.getString("exit"));
   PrivateAdministrationFixture.atomic(f.file("coexist-installed-node-private.json"),created.persisted().toString().getBytes(StandardCharsets.UTF_8));
   JSONObject next=new JSONObject().put("schema",1).put("disposable",true).put("expected_apk_sha256",f.binary.getString("apk_sha256")).put("expected_signer_sha256",f.binary.getString("signer_sha256")).put("allow_user_sharing",true).put("allow_native_vpn",true).put("pair",new JSONObject(pair.persisted().toString()));
   JSONObject journey=new JSONObject().put("node_id",created.get("id")).put("protocol","openvpn").put("server_instance",created.get("serverInstance")).put("ssh_fingerprint",created.get("fingerprint")).put("login",plan.getString("next_login")).put("password",plan.getString("next_password")).put("display_name","Disposable password check").put("new_disposable_user",true).put("expected_exit",plan.getString("expected_exit"));next.put("user_journey",journey);
   PrivateAdministrationFixture.atomic(f.file("coexist-user-journey-private.json"),next.toString().getBytes(StandardCharsets.UTF_8));
   f.receipt("coexisting-password-install-result.json",new JSONObject().put("visible_setup_controls",true).put("password_mode_default",true).put("generated_first_password_retained",true).put("shared_adblocking",true).put("monitoring_available",true).put("pair_identity_and_users_unchanged",true).put("identity_hashes",after).put("recreation_retains_owner",true).put("next_user_journey_bound_to_confirmed_instance",true).put("phone_traffic_tested",false));
  }
 }
}
