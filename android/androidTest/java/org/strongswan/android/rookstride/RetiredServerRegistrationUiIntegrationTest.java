package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.view.View;
import android.widget.EditText;
import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.Espresso;
import androidx.test.espresso.UiController;
import androidx.test.espresso.ViewAction;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.hamcrest.Matcher;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.is;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Opt-in registration of an already reset physical server through visible UI.
 * Does not assign a catalog ID, reset a node, provision a VPN or call a handler. */
@RunWith(AndroidJUnit4.class)
public final class RetiredServerRegistrationUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private static final String ACTION="retired-server-register-ui";
 private UiObject2 required(BySelector selector,long timeout){UiObject2 found=device.wait(Until.findObject(selector),timeout);assertNotNull("Required registration control did not appear",found);return found;}
 private static void enter(String tag,String value){onView(withTagValue(is((Object)tag))).perform(scrollTo(),new ViewAction(){public Matcher<View> getConstraints(){return isAssignableFrom(EditText.class);}public String getDescription(){return "Enter reviewed private server field";}public void perform(UiController controller,View view){((EditText)view).setText(value);controller.loopMainThreadUntilIdle();}});}
 private static Map<String,String> nativeFiles(Context context)throws Exception{TreeMap<String,String> out=new TreeMap<>();File dir=new File(context.getNoBackupFilesDir(),"vpn-profiles");File[] files=dir.listFiles();if(files!=null)for(File file:files){assertTrue("Unexpected native store entry",file.isFile());out.put(file.getName(),PrivateAdministrationFixture.hash(file));}return out;}
 private static Set<String> aliases()throws Exception{KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);return new TreeSet<>(Collections.list(store.aliases()));}
 private static byte[] bytes(File file)throws Exception{return file.isFile()?Files.readAllBytes(file.toPath()):null;}
 private static void restore(File file,byte[] value)throws Exception{if(value==null)new AtomicFile(file).delete();else PrivateAdministrationFixture.atomic(file,value);}
 private static void restorePrefs(SharedPreferences prefs,Map<String,?> values){SharedPreferences.Editor edit=prefs.edit().clear();for(Map.Entry<String,?> item:values.entrySet()){String k=item.getKey();Object v=item.getValue();if(v instanceof String)edit.putString(k,(String)v);else if(v instanceof Boolean)edit.putBoolean(k,(Boolean)v);else if(v instanceof Integer)edit.putInt(k,(Integer)v);else if(v instanceof Long)edit.putLong(k,(Long)v);else if(v instanceof Float)edit.putFloat(k,(Float)v);else if(v instanceof Set)edit.putStringSet(k,new HashSet<>((Set<String>)v));}assertTrue(edit.commit());}
 private Gateway saved(Context context,String host)throws Exception{
  long until=SystemClock.elapsedRealtime()+120000;
  while(SystemClock.elapsedRealtime()<until){
   for(Gateway n:new Vault(context).read())if(n.get("host").equals(host)&&!n.isPair()&&n.data.optLong("checkedAt")>0&&!n.get("fingerprint").isEmpty())return n;
   for(String title:new String[]{"Action needs attention","Server sign-in was rejected","Check this server's identity","Server identity changed"})if(device.hasObject(By.text(title)))throw new AssertionError("Registration needs attention; preserve the private screen and inspect without replaying a reset");
   Thread.sleep(200);
  }
  throw new AssertionError("The phone did not save a successfully inspected physical server");
 }
 private static final String OWNED_DIGEST="python3 - <<'PY'\nimport hashlib,json\nfrom pathlib import Path\np=[]\nfor root in ('/etc/rookstride-pair','/var/lib/rookstride-single'):\n d=Path(root)\n if d.exists(): p += [f for f in d.rglob('*') if f.is_file() and not f.is_symlink() and (root.endswith('pair') or f.name=='state.json')]\nfor name in ('/etc/single-vps-vpn/network.env','/etc/ipsec.secrets','/var/lib/rookstride/users.json'):\n f=Path(name)\n if f.is_file() and not f.is_symlink(): p.append(f)\nh=hashlib.sha256()\nfor f in sorted(set(p)): h.update(str(f).encode()+b'\\0'+f.read_bytes()+b'\\0')\nprint(h.hexdigest())\nPY";
 private static JSONObject observe(Gateway node)throws Exception{try(Ssh ssh=new Ssh(node)){JSONObject probe=ssh.probe();String hash=ssh.execute(OWNED_DIGEST,null).trim();assertTrue("Invalid owned-state observation",hash.matches("[a-f0-9]{64}"));return new JSONObject().put("machine",probe.getString("machine")).put("owned_digest",hash);}}

 @Test public void normalRegistrationCreatesFreshPhysicalIdentityWithoutChangingThePair()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load(ACTION,"allow_retired_server_registration");
  Gateway expected=new Gateway(new JSONObject(f.request.getJSONObject("server").toString()));
  String forbidden=f.request.getString("forbidden_catalog_id"),machine=f.request.getString("expected_machine");
  assertEquals("root",expected.get("admin"));assertFalse("Supply owner password",expected.sshPassword.isEmpty());
  assertTrue("Supply independently reviewed SSH pin",expected.get("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}"));assertTrue(machine.matches("[a-f0-9]{64}"));
  assertFalse("A physical-server fixture must not carry a pair",expected.isPair());assertFalse(forbidden.isEmpty());
  Context context=f.context;ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);NetworkCapabilities network=cm.getNetworkCapabilities(cm.getActiveNetwork());
  assertTrue("Disconnect the disposable phone's VPN first",network==null||!network.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
  JSONObject before=observe(expected);assertEquals("Actual machine differs from reviewed reset receipt",machine,before.getString("machine"));
  Vault vault=new Vault(context),pins=new Vault(context,"ssh-identities.enc");ArrayList<Gateway> original=vault.read();pins.read();
  Set<String> originalIds=new HashSet<>();for(Gateway n:original){originalIds.add(n.get("id"));if(n.exit!=null)originalIds.add(n.exit.get("id"));}
  Map<String,String> nativeBefore=nativeFiles(context);Set<String> aliasesBefore=aliases();
  SharedPreferences ui=context.getSharedPreferences("rookstride-ui",0),deployment=context.getSharedPreferences("rookstride-deployment",0);Map<String,?> oldUi=new HashMap<>(ui.getAll()),oldDeployment=new HashMap<>(deployment.getAll());
  byte[] catalogBytes=bytes(f.file("gateways.enc")),pinBytes=bytes(f.file("ssh-identities.enc"));
  File backup=f.file("retired-registration-original");assertTrue("Recover the previous private backup before repeating this test",backup.mkdir());
  if(catalogBytes!=null)PrivateAdministrationFixture.atomic(new File(backup,"gateways.enc"),catalogBytes);if(pinBytes!=null)PrivateAdministrationFixture.atomic(new File(backup,"ssh-identities.enc"),pinBytes);
  Gateway registered=null;JSONObject after=null;
  try{
   // Keep existing trust and pre-pin this independently verified physical node.
   // The visible new draft must reject a changed key before password authentication.
   ServerIdentityPins trust=new ServerIdentityPins(context);trust.remember(expected,expected.get("fingerprint"));assertEquals(expected.get("fingerprint"),trust.get(expected));
   vault.write(new ArrayList<>());assertTrue(ui.edit().clear().commit());assertTrue(deployment.edit().clear().commit());
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    onView(withContentDescription("VPNs")).perform(click());UiObject2 add=device.findObject(By.text("Add VPN"));if(add!=null)add.click();required(By.text("Manage a server"),10000).click();required(By.text("Connect your server"),10000);
    enter("Server address",expected.get("host"));enter("Administrator login",expected.get("admin"));enter("Server password (SSH)",expected.sshPassword);Espresso.closeSoftKeyboard();
    onView(withText("Save server access on this phone")).check(matches(isChecked()));
    onView(withContentDescription("Connection options: optional name, ports and private key")).perform(scrollTo(),click());enter("VPN name","Retired server registration");enter("SSH port",Integer.toString(expected.port()));Espresso.closeSoftKeyboard();onView(withText("Save")).perform(click());
    registered=saved(context,expected.get("host"));required(By.text("Refresh").enabled(true),120000);
    assertEquals(expected.get("fingerprint"),registered.get("fingerprint"));assertEquals(machine,registered.get("machine"));assertEquals(expected.get("admin"),registered.get("admin"));assertEquals(expected.port(),registered.port());
    assertTrue("Owner password saving must be enabled by default",registered.remember());assertTrue("Chosen owner password did not survive normal save",registered.sshPassword.equals(expected.sshPassword));
    assertFalse("Portable pair identity must not become the new physical catalog identity",registered.get("id").equals(forbidden));assertFalse("Registration reused an original catalog identity",originalIds.contains(registered.get("id")));UUID.fromString(registered.get("id"));
    assertTrue("Registration must remain management-only",registered.get("protocol").isEmpty());assertFalse(registered.data.optBoolean("clientOnly"));assertFalse(registered.data.optBoolean("adminAccess"));assertTrue(registered.get("job").isEmpty());assertFalse(DeploymentService.active());
    JSONObject probe=registered.data.getJSONObject("probe");assertFalse("An owned IKE gateway remains after the reviewed reset",probe.optBoolean("gateway"));assertEquals("Owned native VPN protocols remain after the reviewed reset",0,probe.getJSONObject("inventory").getJSONArray("installed_protocols").length());assertTrue(ServerProtocols.installed(new Vault(context).read(),registered).isEmpty());
    onView(withText("No VPN protocols installed. Add one to start connecting and sharing access.")).perform(scrollTo()).check(matches(isDisplayed()));
    device.waitForIdle(1500);SystemClock.sleep(200);assertTrue(device.takeScreenshot(f.file("retired-server-registration.png")));
    String id=registered.get("id");screen.recreate();registered=saved(context,expected.get("host"));assertEquals(id,registered.get("id"));assertTrue(registered.remember());assertTrue(registered.sshPassword.equals(expected.sshPassword));
    after=observe(expected);assertEquals(before.getString("owned_digest"),after.getString("owned_digest"));assertEquals(machine,after.getString("machine"));
    assertEquals("Registration changed native encrypted profiles",nativeBefore,nativeFiles(context));assertEquals("Registration changed Keystore aliases",aliasesBefore,aliases());
    f.receipt("retired-server-registration-private.json",new JSONObject().put("gateway",registered.persisted()));
   }
  }finally{
   assertFalse("Never overwrite a running deployment's catalog",DeploymentService.active());restore(f.file("gateways.enc"),catalogBytes);restore(f.file("ssh-identities.enc"),pinBytes);restorePrefs(ui,oldUi);restorePrefs(deployment,oldDeployment);
   assertArrayEquals("Original catalog ciphertext was not restored",catalogBytes,bytes(f.file("gateways.enc")));assertArrayEquals("Original SSH pins ciphertext was not restored",pinBytes,bytes(f.file("ssh-identities.enc")));assertEquals(nativeBefore,nativeFiles(context));assertEquals(aliasesBefore,aliases());
   File[] files=backup.listFiles();if(files!=null)for(File file:files)assertTrue(file.delete());assertTrue(backup.delete());
  }
  assertNotNull(registered);assertNotNull(after);
  f.receipt("retired-server-registration-result.json",new JSONObject().put("action",ACTION).put("visible_manage_server_registration",true).put("fresh_catalog_id",true).put("portable_pair_id_not_reused",true).put("independently_pinned_machine",true).put("known_ssh_pin_preserved_before_authentication",true).put("default_password_saved",true).put("no_owned_vpn_protocols",true).put("owned_state_unchanged",true).put("catalog_and_ssh_ciphertext_restored",true).put("native_ciphertexts_and_keystore_unchanged",true).put("recreation_retains_registration",true));
 }
}
