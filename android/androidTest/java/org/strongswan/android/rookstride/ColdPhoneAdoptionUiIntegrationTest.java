package org.strongswan.android.rookstride;

import android.content.*;
import android.os.SystemClock;
import android.view.View;
import android.widget.EditText;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.espresso.*;
import androidx.test.uiautomator.*;
import androidx.test.platform.app.InstrumentationRegistry;
import org.hamcrest.Matcher;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Exact signed app, empty phone catalog, actual visible owner inputs and adoption.
 * Remote evidence reads only fixed owned identity/configuration paths. No setup,
 * reset, account mutation or private Activity handler is invoked by this test. */
@RunWith(AndroidJUnit4.class)
public final class ColdPhoneAdoptionUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 result=device.wait(Until.findObject(selector),timeout);assertNotNull("A required adoption control did not appear",result);return result;}
 private static void enter(String tag,String value){onView(withTagValue(is((Object)tag))).perform(scrollTo(),new ViewAction(){public Matcher<View> getConstraints(){return isAssignableFrom(EditText.class);}public String getDescription(){return "Enter reviewed private fixture field";}public void perform(UiController controller,View view){((EditText)view).setText(value);controller.loopMainThreadUntilIdle();}});}
 private static void restorePrefs(SharedPreferences preferences,Map<String,?> values){SharedPreferences.Editor editor=preferences.edit().clear();for(Map.Entry<String,?> item:values.entrySet()){String key=item.getKey();Object value=item.getValue();if(value instanceof String)editor.putString(key,(String)value);else if(value instanceof Boolean)editor.putBoolean(key,(Boolean)value);else if(value instanceof Integer)editor.putInt(key,(Integer)value);else if(value instanceof Long)editor.putLong(key,(Long)value);else if(value instanceof Float)editor.putFloat(key,(Float)value);else if(value instanceof Set)editor.putStringSet(key,new HashSet<>((Set<String>)value));}assertTrue(editor.commit());}
 private static final String SNAPSHOT="python3 - <<'PY'\nimport hashlib,json\nfrom pathlib import Path\npaths=[]\nfor root in ('/etc/rookstride-pair','/var/lib/rookstride-single'):\n p=Path(root)\n if p.exists():\n  paths += [f for f in p.rglob('*') if f.is_file() and not f.is_symlink() and (root.endswith('pair') or f.name=='state.json')]\nfor name in ('/etc/ipsec.secrets','/etc/ipsec.conf','/etc/ipsec.d/certs/single-vps-server-cert.pem','/etc/ipsec.d/private/single-vps-server-key.pem','/var/lib/rookstride/users.json'):\n p=Path(name)\n if p.is_file() and not p.is_symlink():paths.append(p)\nh=hashlib.sha256()\nfor p in sorted(set(paths)):\n h.update(str(p).encode()+b'\\0'+p.read_bytes()+b'\\0')\nprint(h.hexdigest())\nPY";
 private static JSONObject serverSnapshot(Gateway pair)throws Exception{try(PairSsh sessions=PairSsh.connect(pair,phase->{})){String entry=sessions.entry.execute(SNAPSHOT,null).trim(),exit=sessions.exit.execute(SNAPSHOT,null).trim();assertTrue("Invalid read-only entry digest",entry.matches("[a-f0-9]{64}"));assertTrue("Invalid read-only exit digest",exit.matches("[a-f0-9]{64}"));return new JSONObject().put("entry",entry).put("exit",exit);}}
 private Gateway saved(Context context,String host,boolean paired)throws Exception{long until=SystemClock.elapsedRealtime()+90000;while(SystemClock.elapsedRealtime()<until){for(Gateway node:new Vault(context).read())if(node.get("host").equals(host)&&node.isPair()==paired&&(paired||node.data.optLong("checkedAt")>0)&&!node.get("fingerprint").isEmpty())return node;UiObject2 error=device.findObject(By.text("Action needs attention"));if(error!=null)throw new AssertionError("Server recognition needs attention; inspect the private device log");Thread.sleep(200);}throw new AssertionError("The phone did not save the recognized server");}
 private void addServer(PrivateAdministrationFixture f,Gateway expected,String label)throws Exception{
  onView(withContentDescription("VPNs")).perform(click());UiObject2 add=device.findObject(By.text("Add VPN"));if(add!=null)add.click();waitFor(By.text("Manage a server"),10000).click();waitFor(By.text("Connect your server"),10000);
  enter("Server address",expected.get("host"));enter("Administrator login",expected.get("admin"));enter("Server password (SSH)",expected.sshPassword);Espresso.closeSoftKeyboard();
  onView(withText("Save server access on this phone")).check(matches(isChecked()));onView(withContentDescription("Connection options: optional name, ports and private key")).perform(scrollTo(),click());enter("VPN name",label);enter("SSH port",Integer.toString(expected.port()));Espresso.closeSoftKeyboard();onView(withText("Save")).perform(click());
  Gateway node=saved(f.context,expected.get("host"),false);assertEquals("First-use SSH identity differed from independently reviewed fixture",expected.get("fingerprint"),node.get("fingerprint"));assertTrue("Owner access should be remembered by default",node.remember());assertTrue("Saved access was not retained",node.sshPassword.equals(expected.sshPassword));
  waitFor(By.text("Refresh").enabled(true),90000);assertFalse("Adding for management must not launch deployment",DeploymentService.active());
 }
 @Test public void emptyPhoneRecognizesBothOwnedNodesWithoutChangingVpnIdentity()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("cold-phone-adoption","allow_pair_adoption");Gateway expected=f.pair();assertFalse("Supply the entry owner password",expected.sshPassword.isEmpty());assertFalse("Supply the exit owner password",expected.exit.sshPassword.isEmpty());
  JSONObject before=serverSnapshot(expected);Vault vault=new Vault(f.context),pins=new Vault(f.context,"ssh-identities.enc");ArrayList<Gateway> original=vault.read(),originalPins=pins.read();SharedPreferences ui=f.context.getSharedPreferences("rookstride-ui",0),deployment=f.context.getSharedPreferences("rookstride-deployment",0);Map<String,?> oldUi=new HashMap<>(ui.getAll()),oldDeployment=new HashMap<>(deployment.getAll());
  // Durable encrypted copies allow the operator to recover the catalog even if
  // instrumentation itself is killed before finally. They are app-private only.
  for(String name:new String[]{"gateways.enc","ssh-identities.enc"})assertFalse("A previous cold-phone test backup needs recovery first",f.file("cold-adoption-original-"+name).exists());
  for(String name:new String[]{"gateways.enc","ssh-identities.enc"}){File source=f.file(name),backup=f.file("cold-adoption-original-"+name);if(source.isFile())PrivateAdministrationFixture.atomic(backup,Files.readAllBytes(source.toPath()));}
  boolean restored=false;
  try{
   vault.write(new ArrayList<>());pins.write(new ArrayList<>());assertTrue(ui.edit().clear().commit());assertTrue(deployment.edit().clear().commit());
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    addServer(f,expected,"Adoption entry");addServer(f,expected.exit,"Adoption exit");
    onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage Adoption entry")).perform(scrollTo(),click());onView(withText("Maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Checks & updates")).perform(scrollTo(),click());onView(withText("Recognize an existing Double VPN")).perform(scrollTo(),click());waitFor(By.text("Select the existing exit server"),10000);waitFor(By.textStartsWith("Adoption exit · "),10000).click();
    waitFor(By.text("Recognize Double VPN"),90000);onView(withText("Both server identities and deployment records agree. Existing VPN users and configuration stay in place.")).check(matches(isDisplayed()));onView(withText("Add existing Double VPN")).perform(click());
    Gateway adopted=saved(f.context,expected.get("host"),true);assertEquals(expected.get("pairId"),adopted.get("pairId"));assertEquals(expected.get("pairEntryProtocol"),adopted.get("pairEntryProtocol"));assertEquals(expected.get("pairExitProtocol"),adopted.get("pairExitProtocol"));assertEquals(expected.exit.get("host"),adopted.exit.get("host"));assertEquals(expected.exit.get("fingerprint"),adopted.exit.get("fingerprint"));assertTrue(adopted.data.getJSONObject("deploymentInventory").getJSONObject("entry").getBoolean("recognized"));assertTrue(adopted.data.getJSONObject("deploymentInventory").getJSONObject("exit").getBoolean("recognized"));assertTrue("Read-only adoption must not schedule an installation job",adopted.get("job").isEmpty());
    assertFalse("Read-only adoption started a deployment service",DeploymentService.active());
    assertFalse("Read-only adoption recorded an OS reinstall",adopted.data.has("pairedOsOperation"));
    assertFalse("Owner adoption incorrectly became delegated access",adopted.data.optBoolean("adminAccess"));
    screen.recreate();Gateway persisted=saved(f.context,expected.get("host"),true);assertEquals(adopted.get("id"),persisted.get("id"));onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage Adoption entry")).perform(scrollTo()).check(matches(isDisplayed()));onView(withContentDescription("Manage Adoption exit")).perform(scrollTo()).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
    JSONObject after=serverSnapshot(expected);assertEquals("Recognition changed entry configuration or users",before.getString("entry"),after.getString("entry"));assertEquals("Recognition changed exit configuration or users",before.getString("exit"),after.getString("exit"));
    f.receipt("cold-phone-adoption-result.json",new JSONObject().put("empty_catalog",true).put("visible_owner_inputs",true).put("first_use_pins_match",true).put("default_saved_owner_access",true).put("visible_recognition_review",true).put("same_pair_and_protocols",true).put("recreation_retains_pair",true).put("both_physical_nodes_visible",true).put("server_identity_and_users_unchanged",true).put("identity_hashes",after));
   }
  }finally{vault.write(original);pins.write(originalPins);restorePrefs(ui,oldUi);restorePrefs(deployment,oldDeployment);restored=true;for(String name:new String[]{"gateways.enc","ssh-identities.enc"}){File backup=f.file("cold-adoption-original-"+name);if(backup.exists())assertTrue("Could not remove restored encrypted test backup",backup.delete());}}
  assertTrue(restored);
 }
}
