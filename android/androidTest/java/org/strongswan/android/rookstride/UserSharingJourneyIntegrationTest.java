package org.strongswan.android.rookstride;

import android.content.*;
import android.net.*;
import android.os.*;
import android.widget.EditText;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.VpnStateService;
import org.strongswan.android.rookstride.engine.*;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.Field;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/**
 * Signed-app, opt-in disposable-server acceptance through visible controls.
 * No private handlers, mocked SSH, profile injection or picker-result interception.
 * The only Activity reflection reads the pending server response for byte assertions.
 */
@RunWith(AndroidJUnit4.class)
public final class UserSharingJourneyIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 view=device.wait(Until.findObject(selector),timeout);assertNotNull("Missing visible journey control: "+selector,view);return view;}
 private void phase(PrivateAdministrationFixture f,String phase)throws Exception {f.receipt("user-sharing-journey-progress.json",new JSONObject().put("phase",phase));}
 private JSONObject pendingResponse(ActivityScenario<RookstrideActivity> screen){AtomicReference<JSONObject> value=new AtomicReference<>();screen.onActivity(a->{try{Field field=RookstrideActivity.class.getDeclaredField("newUserShare");field.setAccessible(true);NewUserShareState state=(NewUserShareState)field.get(a);assertTrue("Server did not confirm creation",state.confirmed);assertNotNull(state.profile);value.set(new JSONObject(state.profile.toString()));}catch(Exception e){throw new AssertionError(e);}});return value.get();}
 private String clipboard(Context context){AtomicReference<String> value=new AtomicReference<>();InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{ClipData clip=((ClipboardManager)context.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip();assertNotNull(clip);assertEquals(1,clip.getItemCount());value.set(clip.getItemAt(0).getText().toString());});return value.get();}
 private void downloads(){
  // "Downloads" also names the toolbar behind the drawer. Select its actual
  // root inside the drawer, then wait until that overlay is gone before a file tap.
  BySelector drawerSelector=By.res("com.android.documentsui","drawer_roots");
  UiObject2 drawer=device.findObject(drawerSelector);
  if(drawer==null){UiObject2 roots=device.findObject(By.desc("Show roots"));if(roots==null)return;roots.click();drawer=waitFor(drawerSelector,10000);}
  drawer=device.wait(Until.findObject(drawerSelector.hasDescendant(By.text("Downloads"))),10000);assertNotNull("Downloads root did not finish loading in the system drawer",drawer);UiObject2 downloads=drawer.findObject(By.text("Downloads"));assertNotNull("Downloads root is missing from the system drawer",downloads);downloads.click();
  assertTrue("System document drawer did not close",Boolean.TRUE.equals(device.wait(Until.gone(drawerSelector),10000)));device.waitForIdle(1000);
 }
 private void submitDocumentSave(String expectedName)throws Exception {
  // The system picker can still be laying out its toolbar after opening a root.
  // Re-resolve the enabled control and its visible bounds after that transition.
  for(int attempt=0;attempt<2;attempt++){
   device.waitForIdle(1500);UiObject2 name=waitFor(By.clazz(EditText.class).enabled(true),10000);assertEquals("Document name changed before saving",expectedName,name.getText());
   UiObject2 save=waitFor(By.pkg("com.android.documentsui").text(Pattern.compile("Save",Pattern.CASE_INSENSITIVE)).clickable(true).enabled(true),10000);
   android.graphics.Rect bounds=save.getVisibleBounds();assertTrue("System Save control is off screen",bounds.width()>0&&bounds.height()>0);assertTrue("System Save tap was not injected",device.click(bounds.centerX(),bounds.centerY()));
   if(Boolean.TRUE.equals(device.wait(Until.gone(By.pkg("com.android.documentsui")),5000)))return;
   // Repeating only this unchanged, enabled picker action never replays account
   // creation. A changed filename, overwrite dialog or busy control fails closed.
   if(attempt==1)throw new AssertionError("Android Documents UI did not finish saving the reviewed file");
  }
 }
 private String saveInDocumentsUi(String expectedName)throws Exception {
  waitFor(By.pkg("com.android.documentsui"),15000);downloads();
  UiObject2 name=waitFor(By.clazz(EditText.class).enabled(true),10000);String filename=name.getText();
  if(expectedName.endsWith(".conf"))assertTrue("AWG suggested filename must stay portable",filename.matches("rook-[a-f0-9]{10}\\.conf"));else assertEquals("Unexpected exported connection name",expectedName,filename);
  submitDocumentSave(filename);
  waitFor(By.text("File saved"),15000);onView(withText("Done")).perform(click());
  // File-saved confirmation closes first; the underlying creation/share sheet is still useful.
  onView(withText("Share connection")).check(matches(isDisplayed()));onView(withText("Done")).perform(click());return filename;
 }
 private void chooseDocument(String filename){
  waitFor(By.pkg("com.android.documentsui"),15000);downloads();device.waitForIdle(1000);
  UiObject2 file=waitFor(By.pkg("com.android.documentsui").text(filename),15000);android.graphics.Rect bounds=file.getVisibleBounds();
  assertTrue("The selected document has no visible tap target",bounds.width()>0&&bounds.height()>0);assertTrue("The selected document tap was not injected",device.click(bounds.centerX(),bounds.centerY()));
  assertTrue("The system document picker did not return the selected file",Boolean.TRUE.equals(device.wait(Until.gone(By.pkg("com.android.documentsui")),15000)));
 }
 private Gateway imported(Context context,Set<String> prior,String protocol)throws Exception {
  long end=SystemClock.elapsedRealtime()+20000;
  while(SystemClock.elapsedRealtime()<end){for(Gateway node:new Vault(context).read())if(!prior.contains(node.get("id"))&&node.data.optBoolean("clientOnly")&&SingleProtocols.from(node.get("protocol")).id.equals(protocol))return node;Thread.sleep(150);}
  throw new AssertionError("Import did not create a client-only connection");
 }
 private void connected(Context context,Gateway node)throws Exception {
  if(SingleProtocols.from(node.get("protocol"))!=SingleProtocols.IKEV2){NativePairIntegrationTest.connected(context,node);return;}
  AtomicReference<VpnStateService> state=new AtomicReference<>();ServiceConnection connection=new ServiceConnection(){public void onServiceConnected(ComponentName name,IBinder binder){state.set(((VpnStateService.LocalBinder)binder).getService());}public void onServiceDisconnected(ComponentName name){state.set(null);}};
  assertTrue(context.bindService(new Intent(context,VpnStateService.class),connection,Context.BIND_AUTO_CREATE));
  try{long end=SystemClock.elapsedRealtime()+90000;while(SystemClock.elapsedRealtime()<end){VpnStateService vpn=state.get();if(vpn!=null&&vpn.getState()==VpnStateService.State.CONNECTED&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(node.get("profileUuid")))return;Thread.sleep(250);}throw new AssertionError("The imported IKEv2 connection did not establish");}finally{context.unbindService(connection);}
 }
 private JSONObject ikeIdentity(Context context,Gateway client)throws Exception{VpnProfileDataSource source=new VpnProfileSource(context);source.open();try{VpnProfile saved=source.getVpnProfile(UUID.fromString(client.get("profileUuid")));assertNotNull(saved);return IkeProfileIdentityTestSupport.snapshot(saved);}finally{source.close();}}
 private File recoveryFile(PrivateAdministrationFixture f,JSONObject reference,int limit)throws Exception {
  String name=reference.getString("file");assertTrue("Recovery evidence must be an app-private basename",name.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"));File file=f.file(name);
  assertFalse("Recovery evidence may not be linked",Files.isSymbolicLink(file.toPath()));assertTrue("Recovery evidence is missing or too large",file.isFile()&&file.length()>0&&file.length()<=limit);
  assertEquals("Recovery evidence changed",reference.getString("sha256"),PrivateAdministrationFixture.hash(file));return file;
 }
 private Map<String,String> nativeSnapshot(Context context)throws Exception {
  Map<String,String> result=new TreeMap<>();File root=new File(context.getNoBackupFilesDir(),"vpn-profiles");File[] files=root.listFiles();
  if(files!=null)for(File file:files){assertFalse("Do not traverse native-profile links",Files.isSymbolicLink(file.toPath()));if(file.isFile())result.put(file.getName(),PrivateAdministrationFixture.hash(file));}return result;
 }
 private static void existingFiles(Map<String,String> result,File file,String label)throws Exception {
  assertFalse("Do not traverse stored-evidence links",Files.isSymbolicLink(file.toPath()));if(!file.exists()){result.put(label,"absent");return;}
  if(file.isDirectory()){result.put(label,"directory");File[] children=file.listFiles();assertNotNull(children);for(File child:children)existingFiles(result,child,label+"/"+child.getName());}
  else{assertTrue("Unexpected existing storage file",file.isFile()&&file.length()<=64L*1024*1024);result.put(label,PrivateAdministrationFixture.hash(file));}
 }
 private static Map<String,String> existingIkeFiles(Context context)throws Exception {
  Map<String,String> result=new TreeMap<>();File files=context.getFilesDir().getCanonicalFile(),data=files.getParentFile();
  for(String name:new String[]{"gateways.enc","ssh-identities.enc"})for(String suffix:new String[]{"",".bak",".new"})existingFiles(result,new File(files,name+suffix),name+suffix);
  existingFiles(result,new File(data,"databases"),"databases");existingFiles(result,new File(data,"no_backup/vpn-profiles"),"native-profiles");existingFiles(result,new File(data,"shared_prefs/rookstride-deployment.xml"),"deployment-progress");return result;
 }
 private static Map<String,String> existingKeyAliases(java.security.KeyStore keys)throws Exception {
  Map<String,String> result=new TreeMap<>();for(String alias:Collections.list(keys.aliases())){Date created=keys.getCreationDate(alias);result.put(alias,created==null?"unknown":Long.toString(created.getTime()));}return result;
 }
 @Test public void existingImportedIkeClientProducesForeignClientHandoff()throws Exception {
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("existing-ike-handoff","allow_existing_ike_handoff");assertEquals(f.request.getString("expected_test_apk_sha256"),f.binary.getString("test_apk_sha256"));assertEquals(Boolean.TRUE,f.request.opt("no_remote_access"));assertNull("Finish and release the existing coordinator first",DeploymentService.current());assertFalse(DeploymentService.needsLocalSave());
  JSONObject plan=f.request.getJSONObject("existing_ike_handoff");String login=plan.getString("login"),secret=plan.getString("password");assertTrue(InputRules.username(login));assertTrue(InputRules.vpnPassword(secret));
  File savedFile=recoveryFile(f,plan.getJSONObject("saved_profile"),512000),failedFile=recoveryFile(f,plan.getJSONObject("failed_receipt"),1024*1024),progressFile=recoveryFile(f,plan.getJSONObject("failed_progress"),65536);
  JSONObject failed=new JSONObject(new String(Files.readAllBytes(failedFile.toPath()),StandardCharsets.UTF_8)),progress=new JSONObject(new String(Files.readAllBytes(progressFile.toPath()),StandardCharsets.UTF_8));
  assertEquals("user-sharing-journey",failed.getString("action"));assertFalse("Keep the original sharing failure",failed.getBoolean("passed"));assertEquals(getClass().getName()+"#visibleAccountCreationSharingFileSaveImportAndConnection",failed.getString("class"));assertEquals("connecting the imported client",progress.getString("phase"));JSONObject sourceBinary=progress.getJSONObject("binary");assertEquals(failed.getString("app"),sourceBinary.getString("apk_sha256"));assertEquals(failed.getString("test"),sourceBinary.getString("test_apk_sha256"));assertEquals(f.binary.getString("apk_sha256"),sourceBinary.getString("apk_sha256"));assertEquals(f.binary.getString("signer_sha256"),sourceBinary.getString("signer_sha256"));
  JSONObject exported=new JSONObject(new String(Files.readAllBytes(savedFile.toPath()),StandardCharsets.UTF_8));assertEquals("ikev2-eap",exported.getString("type"));String uuid=exported.getString("uuid");assertEquals(uuid,UUID.fromString(uuid).toString());assertEquals(login,exported.getJSONObject("local").getString("eap_id"));assertEquals(secret,exported.getJSONObject("local").getString("shared_secret"));assertTrue("Existing public-trust export required",exported.getJSONObject("remote").optString("cert").isEmpty());String savedFilename=plan.getString("saved_filename");assertTrue(savedFilename.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\\.sswan"));
  for(String output:new String[]{"ike-shared-client-private.json","existing-ike-handoff-result.json"})assertFalse("Preserve prior handoff evidence before another observation",Files.exists(f.file(output).toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS));
  com.jcraft.jsch.SocketFactory previous=Ssh.socketFactory;assertTrue(previous==null||previous instanceof AdminSocketFactory);java.util.concurrent.atomic.AtomicInteger sockets=new java.util.concurrent.atomic.AtomicInteger();com.jcraft.jsch.SocketFactory deny=new com.jcraft.jsch.SocketFactory(){public java.net.Socket createSocket(String host,int port)throws java.io.IOException{sockets.incrementAndGet();throw new java.io.IOException("Existing IKE handoff forbids SSH");}public java.io.InputStream getInputStream(java.net.Socket socket)throws java.io.IOException{throw new java.io.IOException("No SSH streams");}public java.io.OutputStream getOutputStream(java.net.Socket socket)throws java.io.IOException{throw new java.io.IOException("No SSH streams");}};
  java.security.KeyStore keys=java.security.KeyStore.getInstance("AndroidKeyStore");keys.load(null);Map<String,String> aliases=existingKeyAliases(keys),before=existingIkeFiles(f.context);Ssh.socketFactory=deny;
  try{
   for(String suffix:new String[]{".bak",".new"})assertFalse("Do not recover catalog sidecars",Files.exists(f.file("gateways.enc"+suffix).toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS));assertTrue(keys.containsAlias("rookstride.gateway.v1"));byte[] cipher=Files.readAllBytes(f.file("gateways.enc").toPath()),plain=null;JSONArray catalog;
   try{plain=VaultCipher.decrypt("gateways.enc",cipher,(javax.crypto.SecretKey)keys.getKey("rookstride.gateway.v1",null));catalog=new JSONArray(new String(plain,StandardCharsets.UTF_8));}finally{Arrays.fill(cipher,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
   Gateway owner=null,client=null;for(int i=0;i<catalog.length();i++){Gateway node=new Gateway(catalog.getJSONObject(i));if(node.get("id").equals(plan.getString("node_id"))){assertNull("Ambiguous saved owner",owner);owner=node;}if(node.data.optBoolean("clientOnly")&&uuid.equals(node.get("profileUuid"))){assertNull("Ambiguous imported client",client);client=node;}}
   assertNotNull("Actual current owner is missing",owner);assertEquals("root",owner.get("admin"));assertFalse(owner.data.optBoolean("clientOnly"));assertFalse(owner.data.optBoolean("adminAccess"));assertTrue(owner.isPair());assertEquals("ikev2",owner.get("pairEntryProtocol"));assertEquals(SingleProtocols.IKEV2,SingleProtocols.from(owner.get("protocol")));assertEquals(owner.get("host"),exported.getJSONObject("remote").getString("addr"));
   assertNotNull("The existing normally imported client is missing",client);assertEquals(SingleProtocols.IKEV2,SingleProtocols.from(client.get("protocol")));assertFalse(client.isPair());assertFalse(client.data.optBoolean("adminAccess"));assertTrue(client.sshPassword.isEmpty());assertTrue(client.privateKey.isEmpty());assertTrue(client.get("adminKey").isEmpty());
   VpnProfileDataSource source=new VpnProfileSource(f.context);JSONObject identity;source.open();try{VpnProfile profile=source.getVpnProfile(UUID.fromString(uuid));assertNotNull(profile);assertEquals(uuid,profile.getUUID().toString());assertEquals(login,profile.getUsername());assertEquals(secret,profile.getPassword());assertEquals(exported.getJSONObject("remote").getString("addr"),profile.getGateway());assertEquals(exported.getString("type"),profile.getVpnType().getIdentifier());identity=IkeProfileIdentityTestSupport.snapshot(profile);}finally{source.close();}
   assertEquals(before,existingIkeFiles(f.context));assertEquals(aliases,existingKeyAliases(keys));assertEquals(0,sockets.get());assertSame(deny,Ssh.socketFactory);assertFalse(DeploymentService.active());assertNull(DeploymentService.current());
   recoveryFile(f,plan.getJSONObject("saved_profile"),512000);recoveryFile(f,plan.getJSONObject("failed_receipt"),1024*1024);recoveryFile(f,plan.getJSONObject("failed_progress"),65536);
   JSONObject handoff=new JSONObject().put("schema",1).put("disposable",true).put("expected_apk_sha256",f.binary.getString("apk_sha256")).put("expected_signer_sha256",f.binary.getString("signer_sha256")).put("allow_foreign_admin_ui",true).put("admin",owner.persisted()).put("client",client.persisted()).put("foreign_profile",exported).put("expected_exit",plan.getString("expected_exit")).put("saved_filename",savedFilename).put("source_sharing_binary",sourceBinary).put("original_client_identity",identity).put("binary",new JSONObject(f.binary.toString())).put("source_failed_receipt_sha256",plan.getJSONObject("failed_receipt").getString("sha256")).put("source_saved_profile_sha256",plan.getJSONObject("saved_profile").getString("sha256")).put("read_only_existing_client_handoff",true).put("full_sharing_journey_passed",false);
   PrivateAdministrationFixture.atomic(f.file("ike-shared-client-private.json"),handoff.toString().getBytes(StandardCharsets.UTF_8));f.receipt("existing-ike-handoff-result.json",new JSONObject().put("existing_client_verified",true).put("catalog_database_native_files_unchanged",true).put("keystore_aliases_unchanged",true).put("ssh_socket_attempts",0).put("no_remote_access",true).put("profile_created",false).put("account_creation_replayed",false).put("live_client_traffic_tested",false).put("full_sharing_journey_passed",false).put("source_binary",sourceBinary).put("source_failed_receipt_sha256",plan.getJSONObject("failed_receipt").getString("sha256")).put("source_saved_profile_sha256",plan.getJSONObject("saved_profile").getString("sha256")));
  }finally{try{assertEquals(before,existingIkeFiles(f.context));assertEquals(aliases,existingKeyAliases(keys));assertSame(deny,Ssh.socketFactory);assertEquals(0,sockets.get());}finally{Ssh.socketFactory=previous;}}
 }
 @Test public void resumeTheSavedOpenVpnFileWithoutCreatingTheUserAgain()throws Exception {
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("user-sharing-resume-import","allow_user_sharing_resume_import");assertEquals("Use the reviewed current test APK",f.request.getString("expected_test_apk_sha256"),f.binary.getString("test_apk_sha256"));JSONObject plan=f.request.getJSONObject("user_sharing_resume");
  assertTrue("Explicit saved-file and client traffic authorization required",f.request.optBoolean("allow_documents_ui")&&f.request.optBoolean("allow_native_vpn"));
  assertTrue("This continuation only imports the already-created account",plan.getBoolean("existing_account_only"));assertEquals("openvpn",plan.getString("protocol"));
  String login=plan.getString("login"),secret=plan.getString("password"),id=plan.getString("node_id");assertTrue(InputRules.username(login));assertTrue(InputRules.vpnPassword(secret));
  File failedFile=recoveryFile(f,plan.getJSONObject("failed_receipt"),1024*1024),progressFile=recoveryFile(f,plan.getJSONObject("failed_progress"),65536),savedFile=recoveryFile(f,plan.getJSONObject("saved_profile"),512000);
  JSONObject failed=new JSONObject(new String(Files.readAllBytes(failedFile.toPath()),StandardCharsets.UTF_8)),progress=new JSONObject(new String(Files.readAllBytes(progressFile.toPath()),StandardCharsets.UTF_8));
  assertEquals("user-sharing-journey",failed.getString("action"));assertFalse("Preserve the original failed result",failed.getBoolean("passed"));assertEquals(getClass().getName()+"#visibleAccountCreationSharingFileSaveImportAndConnection",failed.getString("class"));
  assertEquals("importing the saved file through the normal app picker",progress.getString("phase"));JSONObject sourceBinary=progress.getJSONObject("binary");
  assertEquals(plan.getString("source_apk_sha256"),failed.getString("app"));assertEquals(plan.getString("source_test_apk_sha256"),failed.getString("test"));assertEquals(failed.getString("app"),sourceBinary.getString("apk_sha256"));assertEquals(failed.getString("test"),sourceBinary.getString("test_apk_sha256"));assertEquals(f.binary.getString("signer_sha256"),sourceBinary.getString("signer_sha256"));
  if(!sourceBinary.getString("apk_sha256").equals(f.binary.getString("apk_sha256")))assertTrue("A new app requires reviewed continuation of this exact saved file",plan.getBoolean("allow_source_apk_migration"));
  String raw=new String(Files.readAllBytes(savedFile.toPath()),StandardCharsets.UTF_8).trim(),filename=plan.getString("saved_filename");assertTrue(filename.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\\.ovpn"));NativeProfiles.validate("openvpn",raw);assertTrue("The saved portable profile must request the existing username/password",NativeProfiles.openVpnNeedsPassword(raw));
  ArrayList<Gateway> before=new Vault(f.context).read();Gateway owner=null;Set<String> prior=new HashSet<>();Map<String,String> owners=new TreeMap<>();NativeProfileStore store=new NativeProfileStore(f.context);
  for(Gateway node:before){prior.add(node.get("id"));owners.put(node.get("id"),node.persisted().toString());if(node.get("id").equals(id))owner=node;if(node.data.optBoolean("clientOnly")&&node.get("protocol").equals("openvpn")&&store.exists(node.get("id")))assertFalse("The saved file was already imported; review that client rather than duplicating it",raw.equals(NativeProfiles.openVpnConfiguration(store.read(node.get("id")).getString("content"))));}
  assertNotNull("The original saved administrator record is required",owner);assertFalse(owner.data.optBoolean("clientOnly"));assertFalse(owner.data.optBoolean("adminAccess"));assertEquals("openvpn",owner.get("protocol"));assertEquals(plan.getString("server_instance"),owner.get("serverInstance"));assertEquals(plan.getString("ssh_fingerprint"),owner.get("fingerprint"));
  assertEquals("all",AppRouting.read(f.context).mode);f.context.getPackageManager().getApplicationInfo("io.rookstride.probe",0);for(String protocol:new String[]{"awg","xray","openvpn","routes"})assertFalse("Disconnect the current VPN before this client-only continuation",NativeVpn.isActive(NativeVpn.status(f.context,protocol).state));
  Map<String,String> nativeBefore=nativeSnapshot(f.context);String attempt=plan.getString("attempt");assertTrue(attempt.matches("[a-f0-9]{32}"));File marker=f.file("user-sharing-resume-"+attempt+".json");assertTrue("Do not replay an uncertain saved-file import; inspect its recorded client first",marker.createNewFile());
  f.receipt(marker.getName(),new JSONObject().put("phase","starting normal saved-file import").put("source_receipt_sha256",plan.getJSONObject("failed_receipt").getString("sha256")).put("profile_sha256",plan.getJSONObject("saved_profile").getString("sha256")));
  Gateway client=null;boolean ownConnect=false;JSONObject result=new JSONObject().put("protocol","openvpn").put("continued_after_saved_file",true).put("account_creation_replayed",false).put("source_binary",sourceBinary).put("source_receipt_sha256",plan.getJSONObject("failed_receipt").getString("sha256")).put("saved_profile_sha256",plan.getJSONObject("saved_profile").getString("sha256"));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   f.receipt("user-sharing-resume-progress.json",new JSONObject().put("phase","importing the existing saved file"));onView(withContentDescription("VPNs")).perform(click());onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Import a VPN")).perform(scrollTo(),click());onView(withText(SingleProtocols.OPENVPN.title)).perform(scrollTo(),click());chooseDocument(filename);
   waitFor(By.text("OpenVPN sign-in"),15000);onView(withTagValue(is((Object)"VPN username"))).perform(replaceText(login));onView(withTagValue(is((Object)"VPN password"))).perform(replaceText(secret));androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Continue")).perform(click());
   client=imported(f.context,prior,"openvpn");assertTrue(client.sshPassword.isEmpty());assertTrue(client.privateKey.isEmpty());assertTrue(client.get("adminKey").isEmpty());assertFalse(client.data.optBoolean("adminAccess"));assertFalse(client.isPair());String content=store.read(client.get("id")).getString("content");assertEquals("The actual picker imported different profile bytes",raw,NativeProfiles.openVpnConfiguration(content));JSONObject credentials=NativeProfiles.openVpnCredentials(content);assertEquals(login,credentials.getString("login"));assertEquals(secret,credentials.getString("password"));
   f.receipt("user-sharing-resumed-client-private.json",new JSONObject().put("client",client.persisted()).put("source_receipt_sha256",plan.getJSONObject("failed_receipt").getString("sha256")).put("saved_profile_sha256",plan.getJSONObject("saved_profile").getString("sha256")));result.put("normal_file_picker_import",true).put("chosen_credentials_preserved",true).put("client_only_no_admin_access",true);
   f.receipt("user-sharing-resume-progress.json",new JSONObject().put("phase","connecting the imported existing account").put("client_id",client.get("id")));ownConnect=true;onView(allOf(withText("Connect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());UiObject2 background=device.findObject(By.text("Connect now"));if(background!=null)background.click();UiObject2 consent=device.wait(Until.findObject(By.pkg("com.android.vpndialogs").res("android:id/button1")),5000);if(consent!=null)consent.click();connected(f.context,client);
   JSONObject probe=NativePairIntegrationTest.probe(f.context,false,plan.optString("canary_url"));NativePairIntegrationTest.verifyTraffic(probe,plan.getString("expected_exit"),plan.optString("canary_token"));result.put("imported_client_connected",true).put("foreign_uid_https_exit_dns_ipv6",true);
   onView(allOf(withText("Disconnect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());waitFor(By.text("Disconnected"),15000);assertFalse(NativeVpn.status(f.context,"openvpn").active(client.get("id")));ownConnect=false;result.put("visible_disconnect",true);
   ArrayList<Gateway> after=new Vault(f.context).read();assertEquals("Only this one imported client may be added",before.size()+1,after.size());for(Gateway node:after)if(prior.contains(node.get("id")))assertEquals("An existing saved owner/client changed",owners.get(node.get("id")),node.persisted().toString());Map<String,String> nativeAfter=nativeSnapshot(f.context);for(Map.Entry<String,String> entry:nativeBefore.entrySet())assertEquals("An existing native profile changed",entry.getValue(),nativeAfter.get(entry.getKey()));
   result.put("existing_catalog_and_native_profiles_preserved",true);f.receipt("user-sharing-resume-result.json",result);f.receipt("user-sharing-resume-progress.json",new JSONObject().put("phase","completed").put("client_id",client.get("id")));
  }finally{if(ownConnect&&client!=null&&NativeVpn.status(f.context,"openvpn").active(client.get("id")))NativeVpn.disconnect(f.context,"openvpn");}
 }

 @Test public void visibleAccountCreationSharingFileSaveImportAndConnection()throws Exception {
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("user-sharing-journey","allow_user_sharing");
  JSONObject plan=f.request.getJSONObject("user_journey");assertTrue("Explicit client traffic authorization required",f.request.optBoolean("allow_native_vpn"));
  String id=plan.getString("node_id"),login=plan.getString("login"),secret=plan.optString("password"),protocol=plan.getString("protocol");
  assertTrue("Use a disposable, unique VPN user",plan.optBoolean("new_disposable_user"));assertTrue(InputRules.username(login));
  ArrayList<Gateway> nodes=new Vault(f.context).read();Gateway admin=null;Set<String> prior=new HashSet<>();for(Gateway node:nodes){prior.add(node.get("id"));if(node.get("id").equals(id))admin=node;}
  assertNotNull("Use the existing saved administrator record",admin);assertFalse(admin.data.optBoolean("clientOnly"));assertFalse(admin.data.optBoolean("adminAccess"));assertEquals(protocol,SingleProtocols.from(admin.get("protocol")).id);
  assertEquals("The server was replaced since fixture review",plan.getString("server_instance"),admin.get("serverInstance"));assertEquals(plan.getString("ssh_fingerprint"),admin.get("fingerprint"));assertFalse("Saved server access is required for this owner journey",admin.sshPassword.isEmpty());
  assertEquals("This acceptance checks all-app routing","all",AppRouting.read(f.context).mode);f.context.getPackageManager().getApplicationInfo("io.rookstride.probe",0);
  Gateway physical=admin;for(Gateway server:PairNodes.catalog(nodes))if(PairNodes.same(server,admin)){physical=server;break;}final String physicalId=physical.get("id");
  Gateway retained=null;if(plan.has("retained_client")){assertEquals("Only the public IKE identity is covered by this unchanged-client check","ikev2",protocol);JSONObject expectedClient=plan.getJSONObject("retained_client");for(Gateway n:nodes)if(n.get("id").equals(expectedClient.getString("id")))retained=n;assertNotNull("The original client must remain saved before recreating the account",retained);assertTrue(retained.data.optBoolean("clientOnly"));assertEquals(expectedClient.getString("profileUuid"),retained.get("profileUuid"));assertTrue("Original IKE profile changed before recreation",IkeProfileIdentityTestSupport.same(plan.getJSONObject("retained_client_identity"),ikeIdentity(f.context,retained)));}
  final Gateway owner=admin;Gateway client=null;JSONObject result=new JSONObject().put("protocol",protocol).put("double_vpn",owner.isPair());
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   phase(f,"opening saved VPN settings");onView(withContentDescription("VPNs")).perform(click());
   String name=owner.isPair()?(owner.get("serverName").isEmpty()?owner.get("host"):owner.get("serverName")):ServerProtocols.name(owner);
   UiObject2 disclosure=device.findObject(By.desc("Show connections for "+name));if(disclosure!=null)disclosure.click();
   onView(allOf(withContentDescription("Settings for "+SingleProtocols.from(protocol).title),isDescendantOfA(withTagValue(is((Object)("server-connections-"+physicalId)))))).perform(scrollTo(),click());
   onView(withContentDescription("VPN users")).perform(scrollTo(),click());onView(withText("Add new user")).perform(scrollTo(),click());
   boolean passwordBased=device.findObject(By.text("VPN username"))!=null;
   // Fields carry semantic tags; the test never calls the screen's add-user handler.
   if(passwordBased){assertFalse("Provide a disposable chosen VPN secret",secret.isEmpty());onView(withTagValue(is((Object)"Name"))).perform(scrollTo(),replaceText(plan.optString("display_name","Journey reader")));onView(withTagValue(is((Object)"VPN username"))).perform(scrollTo(),replaceText(login));onView(withTagValue(is((Object)"VPN password"))).perform(scrollTo(),replaceText(secret));}
   else onView(withTagValue(is((Object)"Device name"))).perform(scrollTo(),replaceText(login));
   androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Create user")).perform(click());
   if(passwordBased&&InputRules.weakVpnPassword(secret)){waitFor(By.text("Use anyway"),10000).click();}
   phase(f,"awaiting the server-created connection");waitFor(By.text("Share connection"),90000);
   JSONObject response=pendingResponse(screen);ConnectionExport expected=ConnectionExport.fromResponse(response);assertEquals(protocol,expected.protocol);
   if(passwordBased){onView(withText("Copy sign-in details")).perform(scrollTo(),click());String details=clipboard(f.context);assertTrue("Readable sharing must name the account",details.contains("Username: "+login));assertTrue("Readable sharing omitted the chosen password",details.contains("Password: "+secret));assertTrue(details.contains("Server: "));assertFalse("Server administrator credentials leaked into user sharing",details.contains(owner.sshPassword));result.put("readable_chosen_credentials",true);}
   else{onView(withText("Copy configuration")).perform(scrollTo(),click());assertEquals("Configuration copy changed backend bytes",expected.content,clipboard(f.context));result.put("exact_native_configuration_copy",true);}
   result.put("created_response_sha256",PrivateAdministrationFixture.hash(expected.content));phase(f,"saving through Android Documents UI");onView(withText("Save connection file")).perform(scrollTo(),click());String savedFilename=saveInDocumentsUi(expected.name);result.put("documents_ui_saved",true);
   phase(f,"importing the saved file through the normal app picker");onView(withContentDescription("VPNs")).perform(click());onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Import a VPN")).perform(scrollTo(),click());onView(withText(SingleProtocols.from(protocol).title)).perform(scrollTo(),click());chooseDocument(savedFilename);
   if(protocol.equals("ikev2"))waitFor(By.res(f.context.getPackageName(),"menu_accept").enabled(true),15000).click();
   if(protocol.equals("openvpn")&&NativeProfiles.openVpnNeedsPassword(expected.content)){waitFor(By.text("OpenVPN sign-in"),15000);onView(withTagValue(is((Object)"VPN username"))).perform(replaceText(login));onView(withTagValue(is((Object)"VPN password"))).perform(replaceText(secret));androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Continue")).perform(click());}
   client=imported(f.context,prior,protocol);assertTrue(client.sshPassword.isEmpty());assertTrue(client.get("adminKey").isEmpty());assertFalse(client.data.optBoolean("adminAccess"));
   if(!protocol.equals("ikev2")){String saved=new NativeProfileStore(f.context).read(client.get("id")).getString("content");assertEquals("Saved/imported native profile changed",expected.content.trim(),protocol.equals("openvpn")?NativeProfiles.openVpnConfiguration(saved):saved);if(protocol.equals("openvpn")&&passwordBased){JSONObject credentials=NativeProfiles.openVpnCredentials(saved);assertEquals(login,credentials.getString("login"));assertEquals(secret,credentials.getString("password"));}}
   else{VpnProfileDataSource source=new VpnProfileSource(f.context);source.open();try{VpnProfile saved=source.getVpnProfile(UUID.fromString(client.get("profileUuid")));assertNotNull(saved);assertEquals(login,saved.getUsername());assertEquals(secret,saved.getPassword());}finally{source.close();}}
   result.put("normal_file_picker_import",true).put("client_only_no_admin_access",true);phase(f,"connecting the imported client");
   if(protocol.equals("ikev2")){onView(withContentDescription("VPNs")).perform(click());onView(withContentDescription("Open "+client.get("name"))).perform(scrollTo(),click());}
   onView(allOf(withText("Connect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());UiObject2 background=device.findObject(By.text("Connect now"));if(background!=null)background.click();UiObject2 consent=device.wait(Until.findObject(By.pkg("com.android.vpndialogs").res("android:id/button1")),5000);if(consent!=null)consent.click();
   connected(f.context,client);result.put("imported_client_connected",true);phase(f,"checking traffic from another Android app");JSONObject probe=NativePairIntegrationTest.probe(f.context,false,plan.optString("canary_url"));NativePairIntegrationTest.verifyTraffic(probe,plan.getString("expected_exit"),plan.optString("canary_token"));result.put("foreign_uid_https_exit_dns_ipv6",true);
   onView(allOf(withText("Disconnect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());waitFor(By.text("Disconnected"),15000);result.put("visible_disconnect",true);
   if(retained!=null){
    assertTrue("Recreating the account rewrote the original phone profile",IkeProfileIdentityTestSupport.same(plan.getJSONObject("retained_client_identity"),ikeIdentity(f.context,retained)));phase(f,"connecting the unchanged pre-reinstall client");onView(withContentDescription("VPNs")).perform(click());onView(withContentDescription("Open "+retained.get("name"))).perform(scrollTo(),click());onView(allOf(withText("Connect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());connected(f.context,retained);JSONObject oldProbe=NativePairIntegrationTest.probe(f.context,false,plan.optString("canary_url"));NativePairIntegrationTest.verifyTraffic(oldProbe,plan.getString("expected_exit"),plan.optString("canary_token"));onView(allOf(withText("Disconnect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());waitFor(By.text("Disconnected"),15000);assertTrue(IkeProfileIdentityTestSupport.same(plan.getJSONObject("retained_client_identity"),ikeIdentity(f.context,retained)));result.put("unchanged_pre_reinstall_client_connected",true);
   }
   if(protocol.equals("ikev2")){
    JSONObject handoff=new JSONObject().put("schema",1).put("disposable",true).put("expected_apk_sha256",f.binary.getString("apk_sha256")).put("expected_signer_sha256",f.binary.getString("signer_sha256")).put("allow_foreign_admin_ui",true).put("admin",owner.persisted()).put("client",client.persisted()).put("foreign_profile",new JSONObject(expected.content)).put("expected_exit",plan.getString("expected_exit")).put("saved_filename",savedFilename).put("source_sharing_binary",f.binary);
    org.strongswan.android.data.VpnProfileDataSource source=new VpnProfileSource(f.context);source.open();try{VpnProfile saved=source.getVpnProfile(UUID.fromString(client.get("profileUuid")));assertNotNull(saved);handoff.put("original_client_identity",IkeProfileIdentityTestSupport.snapshot(saved));}finally{source.close();}
    PrivateAdministrationFixture.atomic(f.file("ike-shared-client-private.json"),handoff.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
   }
   f.receipt("user-sharing-journey-result.json",result);phase(f,"completed");
  }finally{
   // No server cleanup occurs implicitly. The account and file remain for independent client checks.
   // Emergency local stop only prevents a failed test from leaving its own test tunnel on.
   if(client!=null&&SingleProtocols.from(client.get("protocol"))!=SingleProtocols.IKEV2)NativeVpn.disconnect(f.context,SingleProtocols.from(client.get("protocol")).id);
   InstrumentationRegistry.getInstrumentation().runOnMainSync(()->((ClipboardManager)f.context.getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("","")));
  }
 }
}
