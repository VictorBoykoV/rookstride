package org.strongswan.android.rookstride;

import android.content.*;
import android.os.SystemClock;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.view.View;
import android.widget.EditText;
import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.*;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.hamcrest.Matcher;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import org.strongswan.android.rookstride.engine.NativeVpn;
import java.io.*;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Signed app owner/recipient journey through actual Android document pickers.
 * Explicit disposable fixture only. All successful mutations use visible app
 * controls; direct owner calls verify results and retire this test's exact IDs
 * on failure. No Activity handler or picker result is invoked by reflection. */
@RunWith(AndroidJUnit4.class)
public final class AdminInvitationUiIntegrationTest {
 private final UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
 private UiObject2 waitFor(BySelector selector,long timeout){UiObject2 v=device.wait(Until.findObject(selector),timeout);assertNotNull("Required administrator journey control did not appear",v);return v;}
 private static void enter(String tag,String value){onView(withTagValue(is((Object)tag))).perform(scrollTo(),new ViewAction(){public Matcher<View> getConstraints(){return isAssignableFrom(EditText.class);}public String getDescription(){return "Enter reviewed private fixture field";}public void perform(UiController ui,View view){((EditText)view).setText(value);ui.loopMainThreadUntilIdle();}});}
 private void phase(PrivateAdministrationFixture f,String phase)throws Exception{f.receipt("administrator-file-journey-progress.json",new JSONObject().put("phase",phase));}
 private static JSONObject call(Ssh ssh,String op)throws Exception{return AdminAccessController.request(ssh,new JSONObject().put("operation",op));}
 private static JSONObject request(Ssh ssh,String op,String object,JSONObject parameters)throws Exception{return AdminAccessController.request(ssh,new JSONObject().put("operation",op).put("object_id",object).put("parameters",parameters));}
 private static JSONObject record(JSONArray values,String id){for(int i=0;i<values.length();i++){JSONObject value=values.optJSONObject(i);if(value!=null&&id.equals(value.optString("id")))return value;}return null;}
 private static boolean contains(JSONArray values,String value){for(int i=0;i<values.length();i++)if(value.equals(values.optString(i)))return true;return false;}
 private static boolean hasUser(JSONObject result,String login){JSONArray users=result.optJSONArray("users");if(users!=null)for(int i=0;i<users.length();i++)if(login.equals(users.optJSONObject(i).optString("login")))return true;return false;}
 private static JSONObject user(JSONObject result,String login){JSONArray users=result.optJSONArray("users");if(users!=null)for(int i=0;i<users.length();i++){JSONObject row=users.optJSONObject(i);if(row!=null&&login.equals(row.optString("login")))return row;}return null;}
 private static JSONObject entryObject(JSONObject caps,Gateway pair,String serverId)throws Exception{JSONArray objects=caps.getJSONArray("objects");for(int i=0;i<objects.length();i++){JSONObject object=objects.getJSONObject(i);if(object.optString("server_id").equals(serverId)&&object.optString("deployment_id").equals(pair.get("pairId"))&&object.optString("protocol").equals("awg"))return object;}throw new AssertionError("The reviewed entry AWG scope is absent");}
 private static String profile(Ssh ssh,String object,String login)throws Exception{return ConnectionExport.fromResponse(request(ssh,"users.profile",object,new JSONObject().put("login",login))).content;}
 private void downloads(){UiObject2 roots=device.findObject(By.desc("Show roots"));if(roots!=null){roots.click();waitFor(By.text("Downloads"),10000).click();}}
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
 private String saveDocument(String filename,String title)throws Exception{waitFor(By.pkg("com.android.documentsui"),15000);downloads();UiObject2 name=waitFor(By.clazz(EditText.class).enabled(true),10000);if(filename.endsWith(".conf")){filename=name.getText();assertTrue("AWG suggested filename must stay portable",filename.matches("rook-[a-f0-9]{10}\\.conf"));}else name.setText(filename);submitDocumentSave(filename);waitFor(By.text(title),15000);onView(withText("Done")).perform(click());return filename;}
 private void openDocument(String filename){waitFor(By.pkg("com.android.documentsui"),15000);downloads();waitFor(By.text(filename),15000).click();}
 private void openOwner(Gateway owner){onView(withContentDescription("Servers")).perform(click());String name=owner.get("serverName").isEmpty()?owner.get("host"):owner.get("serverName");onView(withContentDescription("Manage "+name)).perform(scrollTo(),click());onView(withText("Server maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Access & administrators")).perform(scrollTo(),click());onView(withText("Administrators")).perform(scrollTo(),click());waitFor(By.text("Invite administrator").enabled(true),90000);}
 private void enrollmentDiagnostic(PrivateAdministrationFixture f,Set<String> prior,ActivityScenario<RookstrideActivity> screen,String stage)throws Exception{
  JSONObject report=new JSONObject().put("stage",stage).put("deployment_active",DeploymentService.active());int added=0,drafts=0,enrolled=0,keys=0;
  for(Gateway row:new Vault(f.context).read())if(!prior.contains(row.get("id"))){added++;if(row.data.optJSONObject("adminEnrollment")!=null)drafts++;if(row.data.optBoolean("adminAccess")&&!row.get("adminDeviceId").isEmpty())enrolled++;if(!row.privateKey.isEmpty())keys++;}
  report.put("added_records",added).put("enrollment_drafts",drafts).put("enrolled_records",enrolled).put("records_with_device_key",keys);
  screen.onActivity(a->{try{for(String name:new String[]{"busy","message","selected"}){Field field=RookstrideActivity.class.getDeclaredField(name);field.setAccessible(true);Object value=field.get(a);if(name.equals("busy"))report.put("activity_busy",value);else if(name.equals("message")){String message=String.valueOf(value);report.put("message_category",message.isEmpty()?"empty":message.equals("Enrolling this administrator phone")?"enrollment":message.startsWith("Reading")?"reading":message.startsWith("Checking")?"checking":"other");}else if(value instanceof Gateway){Gateway node=(Gateway)value;report.put("selected_has_job",!node.get("job").isEmpty()).put("selected_has_enrollment",node.data.optJSONObject("adminEnrollment")!=null);}}report.put("activity_finishing",a.isFinishing()).put("activity_destroyed",a.isDestroyed());}catch(Exception e){throw new AssertionError("Could not capture bounded enrollment state",e);}});
  JSONArray stacks=new JSONArray();for(Map.Entry<Thread,StackTraceElement[]> entry:Thread.getAllStackTraces().entrySet()){boolean relevant=false;for(StackTraceElement frame:entry.getValue())if(frame.getClassName().startsWith("org.strongswan.android.rookstride.")||frame.getClassName().equals("org.strongswan.android.ui.RookstrideActivity")){relevant=true;break;}if(relevant&&stacks.length()<12){JSONArray frames=new JSONArray();for(StackTraceElement frame:entry.getValue()){if(frames.length()>=20)break;frames.put(frame.getClassName()+"."+frame.getMethodName());}stacks.put(new JSONObject().put("state",entry.getKey().getState().name()).put("frames",frames));}}
  report.put("worker_stacks",stacks);f.receipt("administrator-enrollment-diagnostic.json",report);
 }
 private Gateway enrolled(PrivateAdministrationFixture f,Set<String> prior,String object,ActivityScenario<RookstrideActivity> screen)throws Exception{long until=SystemClock.elapsedRealtime()+90000,nextDiagnostic=0;while(SystemClock.elapsedRealtime()<until){for(Gateway n:new Vault(f.context).read())if(!prior.contains(n.get("id"))&&n.data.optBoolean("adminAccess")&&!n.data.has("adminEnrollment")&&!n.get("adminDeviceId").isEmpty()){assertEquals("user_manager",n.get("adminRole"));assertEquals(object,n.data.getJSONObject("adminScope").getString("id"));return n;}if(SystemClock.elapsedRealtime()>=nextDiagnostic){enrollmentDiagnostic(f,prior,screen,"waiting_after_visible_accept");nextDiagnostic=SystemClock.elapsedRealtime()+10000;}if(device.findObject(By.text("Server sign-in was rejected"))!=null){enrollmentDiagnostic(f,prior,screen,"server_sign_in_rejected");device.takeScreenshot(new File(f.context.getFilesDir(),"administrator-enrollment-timeout.png"));throw new AssertionError("Administrator enrollment server sign-in was rejected; bounded state receipt captured");}if(device.findObject(By.text("Action needs attention"))!=null){enrollmentDiagnostic(f,prior,screen,"action_needs_attention");throw new AssertionError("Administrator enrollment failed; inspect the private device log");}Thread.sleep(200);}enrollmentDiagnostic(f,prior,screen,"timed_out_after_visible_accept");device.takeScreenshot(new File(f.context.getFilesDir(),"administrator-enrollment-timeout.png"));throw new AssertionError("The file invitation did not enroll this phone; bounded state receipt captured");}
 private JSONObject pendingProfile(ActivityScenario<RookstrideActivity> screen){AtomicReference<JSONObject> result=new AtomicReference<>();screen.onActivity(a->{try{Field field=RookstrideActivity.class.getDeclaredField("newUserShare");field.setAccessible(true);NewUserShareState state=(NewUserShareState)field.get(a);assertTrue(state.confirmed);assertNotNull(state.scopedObject);assertNotNull(state.profile);result.set(new JSONObject(state.profile.toString()));}catch(Exception e){throw new AssertionError(e);}});return result.get();}
 private String clipboard(Context context){AtomicReference<String> result=new AtomicReference<>();InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{ClipData clip=((ClipboardManager)context.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip();assertNotNull(clip);result.set(clip.getItemAt(0).getText().toString());});return result.get();}
 private void dismissRemainingSheets(){
  BySelector closeButton=By.res("android:id/button2").text(Pattern.compile("Close",Pattern.CASE_INSENSITIVE)).clickable(true).enabled(true);
  for(int i=0;i<4;i++){
   device.waitForIdle(1500);UiObject2 close=device.wait(Until.findObject(closeButton),1000);
   if(close==null){assertNull("The VPN user sheet still covers navigation",device.findObject(By.text("VPN users · "+SingleProtocols.AWG.title)));return;}
   // Android renders dialog buttons in uppercase to accessibility on some
   // versions. Click the visible negative button, never a private close handler.
   onView(allOf(withId(android.R.id.button2),withText("Close"),isDisplayed())).perform(click());device.waitForIdle(1500);
  }
  assertNull("Remaining user sheets did not dismiss",device.findObject(By.text("VPN users · "+SingleProtocols.AWG.title)));
 }
 private void openExactDeviceRevocation(PrivateAdministrationFixture f,String deviceName){
  // Scrolling only the name can leave its action below the viewport, where
  // UiAutomator omits it. Match the actual button in this exact device card
  // through the full in-app hierarchy, then expose and click that control.
  Matcher<View> revoke=allOf(withText("Revoke administrator device"),
      isAssignableFrom(android.widget.Button.class),hasSibling(withText(deviceName)));
  device.takeScreenshot(new File(f.context.getFilesDir(),"administrator-revocation-before-scroll.png"));
  try{
   onView(revoke).perform(scrollTo()).check(matches(allOf(isCompletelyDisplayed(),isEnabled())));
   // Accessibility layout can settle before the compositor presents the scroll.
   // Capture the settled pixels, then retain the exact visible-action assertion.
   device.waitForIdle(1500);SystemClock.sleep(200);
   onView(revoke).check(matches(allOf(isCompletelyDisplayed(),isEnabled())));
   device.takeScreenshot(new File(f.context.getFilesDir(),"administrator-revocation-after-scroll.png"));
   onView(revoke).perform(click());
  }catch(RuntimeException|AssertionError failure){
   device.takeScreenshot(new File(f.context.getFilesDir(),"administrator-revocation-control-failure.png"));
   throw failure;
  }
 }
 private Gateway importedOrdinaryClient(Context context,Set<String> prior)throws Exception{
  long until=SystemClock.elapsedRealtime()+20000;
  while(SystemClock.elapsedRealtime()<until){for(Gateway row:new Vault(context).read())if(!prior.contains(row.get("id"))&&row.data.optBoolean("clientOnly")&&row.get("protocol").equals("awg"))return row;Thread.sleep(150);}
  throw new AssertionError("The saved delegated user's file did not create an ordinary client");
 }
 private static void removeExactImportedClient(Context context,Set<String> prior,String content)throws Exception{
  if(content.isEmpty())return;
  NativeProfileStore store=new NativeProfileStore(context);ArrayList<Gateway> rows=new Vault(context).read();Gateway found=null;
  for(Gateway row:rows)if(!prior.contains(row.get("id"))&&row.data.optBoolean("clientOnly")&&row.get("protocol").equals("awg")&&store.exists(row.get("id"))&&content.trim().equals(store.read(row.get("id")).getString("content"))){assertNull("Ambiguous new imported connection; retain it for review",found);found=row;}
  if(found==null)return;
  String id=found.get("id");NativeVpn.Status status=NativeVpn.status(context,"awg");
  if(id.equals(status.id)&&NativeVpn.isActive(status.state)){
   NativeVpn.disconnect(context,"awg");long until=SystemClock.elapsedRealtime()+15000;
   while(NativeVpn.status(context,"awg").active(id)&&SystemClock.elapsedRealtime()<until)Thread.sleep(100);
   assertFalse("The exact test tunnel is still active; retain its profile",NativeVpn.status(context,"awg").active(id));
  }
  store.remove(id);rows.removeIf(row->row.get("id").equals(id));new Vault(context).write(rows);
 }
 private static Gateway byId(ArrayList<Gateway> rows,String id){for(Gateway row:rows)if(id.equals(row.get("id")))return row;throw new AssertionError("Saved owner record is missing");}
 private static String clientIdentity(Gateway node)throws Exception{JSONObject data=new JSONObject(node.persisted().toString());JSONObject identity=new JSONObject();for(String field:new String[]{"id","host","vpnServer","vpnLogin","vpnPassword","profileUuid","nativeProfile","protocol","pairId","pairEntryProtocol","pairExitProtocol"})if(data.has(field))identity.put(field,data.get(field));return identity.toString();}
 @Test public void ownerSavesInvitationRecipientImportsCreatesAndSharesThenOwnerRevokes()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("administrator-file-journey","allow_admin_invitation_ui");
  assertTrue("Explicit ordinary-client traffic authorization required",f.request.optBoolean("allow_native_vpn"));
  assertEquals("This acceptance checks all-app routing","all",AppRouting.read(f.context).mode);f.context.getPackageManager().getApplicationInfo("io.rookstride.probe",0);
  ConnectivityManager networks=f.context.getSystemService(ConnectivityManager.class);NetworkCapabilities active=networks.getNetworkCapabilities(networks.getActiveNetwork());
  assertTrue("Disconnect an existing VPN before this journey",active==null||!active.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
  JSONObject plan=f.request.getJSONObject("admin_invitation_journey");assertTrue("Only a unique disposable user is authorized",plan.optBoolean("new_disposable_user"));String expectedExit=plan.getString("expected_exit");assertFalse("Review the expected current exit",expectedExit.isEmpty());String login=plan.getString("login"),deviceName=plan.optString("device_name","Signed UI delegate");assertTrue(InputRules.username(login));assertTrue(deviceName.length()>0&&deviceName.length()<=80);
  ArrayList<Gateway> catalog=new Vault(f.context).read();Gateway owner=byId(catalog,plan.getString("owner_id"));Gateway fixture=f.pair();assertEquals(fixture.get("pairId"),owner.get("pairId"));assertEquals(fixture.get("fingerprint"),owner.get("fingerprint"));assertTrue(owner.isPair());assertTrue("Enable the reviewed administrator module before this test",owner.data.optBoolean("adminEnabled"));assertFalse(owner.data.optBoolean("adminAccess"));Set<String> prior=new HashSet<>();for(Gateway n:catalog)prior.add(n.get("id"));String ownerIdentity=clientIdentity(owner),serverId=owner.get("adminServerId");assertFalse(serverId.isEmpty());Gateway delegate=null;String invitationId="",objectId="";boolean created=false,uiRevoked=false;String createdProfileContent="";Set<String> oldInvitations=new HashSet<>();
  try(PairSsh sessions=PairSsh.connect(owner,phase->{})){
   Ssh ssh=sessions.entry;JSONObject capabilities=call(ssh,"capabilities");assertEquals("owner",capabilities.getString("role"));JSONObject object=entryObject(capabilities,owner,serverId);objectId=object.getString("id");assertFalse("Do not overwrite an existing VPN user",hasUser(request(ssh,"users.list",objectId,new JSONObject()),login));String before=profile(ssh,objectId,owner.get("vpnLogin"));JSONObject accessBefore=call(ssh,"access.list");for(int i=0;i<accessBefore.getJSONArray("invitations").length();i++)oldInvitations.add(accessBefore.getJSONArray("invitations").getJSONObject(i).getString("id"));
   try{
    try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
     phase(f,"owner reviews exact user-manager scope");openOwner(owner);onView(withText("Invite administrator")).perform(scrollTo(),click());waitFor(By.text("Choose administrator role"),10000);onView(withText("VPN user manager")).perform(click());waitFor(By.text("Choose exact authority scope"),10000);onView(withText(SingleProtocols.AWG.title+" · Entry server")).perform(click());waitFor(By.text("Which VPN users can they manage?"),10000);onView(withText("Only users issued by this phone")).perform(click());waitFor(By.text("Review administrator invitation"),10000);enter("Administrator or device name",deviceName);Espresso.closeSoftKeyboard();onView(withText("Create invitation")).perform(click());waitFor(By.text("Administrator invitation ready"),90000);
     JSONObject access=call(ssh,"access.list");JSONArray invitations=access.getJSONArray("invitations");for(int i=0;i<invitations.length();i++){JSONObject row=invitations.getJSONObject(i);if(!oldInvitations.contains(row.getString("id"))&&deviceName.equals(row.optString("name"))){assertTrue("Ambiguous disposable invitation",invitationId.isEmpty());invitationId=row.getString("id");assertEquals("user_manager",row.getString("role"));assertEquals(objectId,row.getJSONObject("scope").getString("id"));assertEquals("own",row.getJSONObject("scope").getString("users"));}}assertFalse("Owner UI did not issue the named invitation",invitationId.isEmpty());
     String filename="rookstride-admin-"+login+".rookadmin";phase(f,"saving administrator file through Android picker");onView(withText("Save invitation file")).perform(click());saveDocument(filename,"Invitation file saved");onView(withContentDescription("VPNs")).perform(click());onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Accept administrator invitation")).perform(scrollTo(),click());openDocument(filename);waitFor(By.text("Accept administrator invitation"),10000);enrollmentDiagnostic(f,prior,screen,"before_visible_accept");phase(f,"recipient confirms invitation and waits for enrollment");onView(withText("Accept invitation")).perform(click());enrollmentDiagnostic(f,prior,screen,"after_visible_accept");delegate=enrolled(f,prior,objectId,screen);assertEquals(invitationId,delegate.get("adminInvitationId"));assertTrue(delegate.sshPassword.isEmpty());assertFalse("Recipient retained the one-use bootstrap",delegate.data.has("adminEnrollment"));assertFalse(delegate.privateKey.isEmpty());
     phase(f,"recipient creates a scoped VPN user");waitFor(By.text(SingleProtocols.AWG.title+" · This server").enabled(true),90000);onView(withText(SingleProtocols.AWG.title+" · This server")).perform(scrollTo(),click());waitFor(By.text("VPN users · "+SingleProtocols.AWG.title),30000);onView(withText("Add VPN user")).perform(scrollTo(),click());enter("VPN username",login);Espresso.closeSoftKeyboard();onView(withText("Create user")).perform(click());waitFor(By.text("Share connection"),90000);created=true;ConnectionExport share=ConnectionExport.fromResponse(pendingProfile(screen));assertEquals("awg",share.protocol);createdProfileContent=share.content;onView(withText("Copy configuration")).perform(scrollTo(),click());assertTrue("Copied native connection differs from the confirmed profile",share.content.equals(clipboard(f.context)));assertTrue("Owner SSH secret leaked into VPN access",owner.sshPassword.isEmpty()||!share.content.contains(owner.sshPassword));assertFalse("Delegate private key leaked into VPN access",share.content.contains(delegate.privateKey));onView(withText("Save connection file")).perform(scrollTo(),click());String savedConnectionFile=saveDocument(share.name,"File saved");onView(withText("Done")).perform(click());dismissRemainingSheets();
     try(Ssh limited=new Ssh(delegate)){
      JSONObject current=call(limited,"capabilities");assertEquals("user_manager",current.getString("role"));assertFalse(contains(current.getJSONArray("capabilities"),"invitations.manage"));assertFalse(contains(current.getJSONArray("capabilities"),"services.manage"));JSONObject oldUser=user(request(limited,"users.list",objectId,new JSONObject()),login);assertNotNull("Own newly issued user absent",oldUser);assertFalse("Own-user scope exposed the owner's ordinary user",hasUser(request(limited,"users.list",objectId,new JSONObject()),owner.get("vpnLogin")));String unchangedDevice=oldUser.optString("device"),unchangedProfile=profile(limited,objectId,login),renamed="Edited "+login;
      phase(f,"recipient edits only the user name and keeps the device label");waitFor(By.text(SingleProtocols.AWG.title+" · This server").enabled(true),30000);onView(withText(SingleProtocols.AWG.title+" · This server")).perform(scrollTo(),click());waitFor(By.text("VPN users · "+SingleProtocols.AWG.title),30000);onView(withText("Edit VPN user")).perform(scrollTo(),click());waitFor(By.text("Edit VPN user"),10000);enter("Name",renamed);
      // The form explicitly says an empty label keeps its current value. This
      // exercises the real omitted-field request rather than submitting both.
      enter("Device","");Espresso.closeSoftKeyboard();onView(withText("Save")).perform(click());long editedUntil=SystemClock.elapsedRealtime()+90000;JSONObject changed=null;
      while(SystemClock.elapsedRealtime()<editedUntil){changed=user(request(limited,"users.list",objectId,new JSONObject()),login);if(changed!=null&&renamed.equals(changed.optString("person")))break;if(device.findObject(By.text("Action needs attention"))!=null)throw new AssertionError("Visible scoped metadata edit failed");Thread.sleep(1000);}
      assertNotNull("Edited scoped user disappeared",changed);assertEquals("Visible name-only edit did not persist",renamed,changed.optString("person"));assertEquals("An omitted device label was overwritten",unchangedDevice,changed.optString("device"));assertEquals("Editing labels changed the account identity or its scoped ownership",unchangedProfile,profile(limited,objectId,login));waitFor(By.text(renamed),30000);dismissRemainingSheets();
     }
     phase(f,"owner revokes only administrator authority");openOwner(owner);openExactDeviceRevocation(f,deviceName);waitFor(By.text("Revoke this administrator device?"),10000);onView(withText("Continue")).perform(click());long until=SystemClock.elapsedRealtime()+90000;while(SystemClock.elapsedRealtime()<until){JSONObject row=record(call(ssh,"access.list").getJSONArray("devices"),delegate.get("adminDeviceId"));if(row!=null&&row.optBoolean("revoked")){uiRevoked=true;break;}Thread.sleep(250);}assertTrue("Visible revocation was not confirmed by server",uiRevoked);
     try(Ssh forbidden=new Ssh(delegate)){fail("Revoked administrator still authenticates");}catch(Ssh.SignInRejected expected){call(ssh,"capabilities");}
     assertTrue("Administrator revocation changed ordinary VPN account identity",before.equals(profile(ssh,objectId,owner.get("vpnLogin"))));assertTrue("Revoking administrator authority revoked its ordinary VPN user",hasUser(request(ssh,"users.list",objectId,new JSONObject()),login));assertTrue("Revocation changed the saved ordinary connection",ownerIdentity.equals(clientIdentity(byId(new Vault(f.context).read(),owner.get("id")))));
     phase(f,"importing the same ordinary connection after administrator revocation");
     onView(withContentDescription("VPNs")).perform(click());onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Import a VPN")).perform(scrollTo(),click());onView(withText(SingleProtocols.AWG.title)).perform(scrollTo(),click());openDocument(savedConnectionFile);
     Gateway ordinary=importedOrdinaryClient(f.context,prior);assertFalse(prior.contains(ordinary.get("id")));assertTrue(ordinary.sshPassword.isEmpty());assertTrue(ordinary.privateKey.isEmpty());assertTrue(ordinary.get("adminKey").isEmpty());assertFalse(ordinary.data.optBoolean("adminAccess"));
     assertEquals("The saved/imported ordinary connection changed",share.content.trim(),new NativeProfileStore(f.context).read(ordinary.get("id")).getString("content"));
     phase(f,"connecting the delegated user's ordinary VPN after admin revocation");
     onView(allOf(withText("Connect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());UiObject2 background=device.findObject(By.text("Connect now"));if(background!=null)background.click();UiObject2 consent=device.wait(Until.findObject(By.pkg("com.android.vpndialogs").res("android:id/button1")),5000);if(consent!=null)consent.click();
     NativePairIntegrationTest.connected(f.context,ordinary);JSONObject traffic=NativePairIntegrationTest.probe(f.context,false,plan.optString("canary_url"));NativePairIntegrationTest.verifyTraffic(traffic,expectedExit,plan.optString("canary_token"));
     onView(allOf(withText("Disconnect"),isDescendantOfA(withTagValue(is((Object)"connection-controls"))))).perform(scrollTo(),click());waitFor(By.text("Disconnected"),15000);
     f.receipt("administrator-file-journey-result.json",new JSONObject().put("owner_reviewed_exact_protocol_own_user_scope",true).put("documents_ui_invitation_saved",true).put("normal_document_picker_import",true).put("recipient_generated_device_key",true).put("visible_scoped_user_creation",true).put("native_share_copy_and_file_save",true).put("visible_scoped_name_only_edit",true).put("omitted_device_label_and_native_identity_preserved",true).put("server_enforced_scope",true).put("visible_owner_revocation",true).put("ordinary_vpn_identity_and_access_unchanged",true).put("normal_picker_import_after_admin_revocation",true).put("revoked_admin_ordinary_client_connected",true).put("revoked_admin_ordinary_client_foreign_uid_https_exit_dns_ipv6",true).put("ipv6_positive_underlay_qualification",false).put("visible_ordinary_client_disconnect",true).put("profile_sha256",PrivateAdministrationFixture.hash(share.content)));phase(f,"completed");
    }
   }finally{
    // Use only IDs absent at preflight and demonstrably created by this test.
    // Retire authority before deleting local enrollment credentials. An uncertain
    // remote cleanup keeps the encrypted recipient key for owner reconciliation.
    if(invitationId.isEmpty()){JSONArray rows=call(ssh,"access.list").getJSONArray("invitations");for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(!oldInvitations.contains(row.getString("id"))&&deviceName.equals(row.optString("name"))){if(!invitationId.isEmpty())throw new IOException("Ambiguous invitation cleanup; retain owner evidence");invitationId=row.getString("id");}}}
    if(delegate==null)for(Gateway n:new Vault(f.context).read())if(!prior.contains(n.get("id"))&&invitationId.equals(n.get("adminInvitationId")))delegate=n;
    if(!invitationId.isEmpty()){mutate(ssh,"invitations.revoke","invitation_id",invitationId);JSONObject row=record(call(ssh,"access.list").getJSONArray("invitations"),invitationId);assertNotNull(row);assertTrue(row.optBoolean("revoked"));String claim=row.isNull("claimed_device")?"":row.optString("claimed_device");if(!claim.isEmpty()){assertNotNull("Retain the invitation's device for reconciliation",delegate);assertEquals(delegate.get("adminDeviceId"),claim);JSONObject d=record(call(ssh,"access.list").getJSONArray("devices"),claim);if(d==null||!d.optBoolean("revoked"))mutate(ssh,"devices.revoke","device_id",claim);assertTrue(record(call(ssh,"access.list").getJSONArray("devices"),claim).getBoolean("revoked"));}}
    removeExactImportedClient(f.context,prior,createdProfileContent);
    if(created||hasUser(request(ssh,"users.list",objectId,new JSONObject()),login))AdminAccessController.request(ssh,new JSONObject().put("operation","users.revoke").put("object_id",objectId).put("parameters",new JSONObject().put("login",login)).put("operation_id",UUID.randomUUID().toString()).put("expected_revision",call(ssh,"capabilities").getLong("revision")));
    if(delegate!=null){String id=delegate.get("id");ArrayList<Gateway> rows=new Vault(f.context).read();rows.removeIf(n->n.get("id").equals(id));new Vault(f.context).write(rows);new ServerIdentityPins(f.context).forgetIfUnreferenced(delegate,rows);}
    InstrumentationRegistry.getInstrumentation().runOnMainSync(()->((ClipboardManager)f.context.getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("","")));
   }
  }
 }
 private static void mutate(Ssh owner,String op,String key,String id)throws Exception{AdminAccessController.request(owner,new JSONObject().put("operation",op).put(key,id).put("expected_revision",call(owner,"capabilities").getLong("revision")));}
}
