package org.strongswan.android.rookstride;

import android.content.*;
import android.view.*;
import android.widget.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.matcher.RootMatchers.isPlatformPopup;

/** New release journeys, using local fixtures only. No server command is sent. */
@RunWith(AndroidJUnit4.class)
public class MajorNavigationUiTest {
 private Context context;private Vault vault,pins;private ArrayList<Gateway> previous,previousPins;private Gateway server;private String progress;
 private static final String OLD="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",NEXT="SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
 @Before public void setup()throws Exception{
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);pins=new Vault(context,"ssh-identities.enc");previous=vault.read();previousPins=pins.read();
  progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();context.getSharedPreferences("rookstride-ui",0).edit().remove("selected").remove("lastConnectedId").putBoolean("rememberServerAccess",true).commit();
  server=new Gateway();server.set("name","North server");server.set("serverName","North server");server.set("host","north.example.net");server.set("admin","root");server.set("protocol","awg");server.set("fingerprint",OLD);server.data.put("favorite",true);server.data.put("checkedAt",System.currentTimeMillis());server.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("users",new JSONArray()));vault.write(new ArrayList<>(Arrays.asList(server)));pins.write(new ArrayList<>());new ServerIdentityPins(context).remember(server,OLD);
 }
 @After public void restore()throws Exception{vault.write(previous);pins.write(previousPins);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();}
 private Object field(RookstrideActivity a,String name){try{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(a);}catch(Exception e){throw new AssertionError(e);}}
 private void call(RookstrideActivity a,String name,Class<?>[] types,Object...args){try{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(a,args);}catch(Exception e){throw new AssertionError(e);}}
 @Test public void homeConnectAndServerUsersAndMaintenanceNeedNoDisclosure()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Connect AmneziaWG 3.1 on North server")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));
   screen.onActivity(a->((ScrollView)field(a,"pageScroll")).scrollTo(0,0));ScreenshotProof.save(context,"major-home-direct-actions");onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage North server")).perform(scrollTo(),click());
   onView(withText("Maintenance")).perform(scrollTo()).check(matches(isDisplayed())).check((view,error)->{if(error!=null)throw error;assertEquals("Maintenance label must fit without splitting",1,((android.widget.TextView)view).getLineCount());});onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Add protocol")).perform(scrollTo()).check(matches(isDisplayed()));
   screen.onActivity(a->((ScrollView)field(a,"pageScroll")).scrollTo(0,0));ScreenshotProof.save(context,"major-server-protocol-users");onView(withText("Not installed")).check(doesNotExist());onView(withText("Maintenance")).perform(scrollTo(),click());
   onView(withContentDescription("Expand Access & administrators")).perform(scrollTo(),click());onView(withText("Administrator access")).perform(scrollTo()).check(matches(isDisplayed()));onView(withContentDescription("Expand Remove or rebuild")).perform(scrollTo(),click());onView(withText("Wipe server & reinstall Ubuntu")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Advanced")).check(doesNotExist());ScreenshotProof.save(context,"major-maintenance-visible");
   androidx.test.espresso.Espresso.pressBack();onView(withText("Add protocol")).perform(scrollTo()).check(matches(isDisplayed()));
  }
 }
 @Test public void signInSavingStartsEnabledAndPreservesExplicitOptOut()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->call(a,"passwordDialog",new Class<?>[]{Gateway.class,Runnable.class},server,(Runnable)()->{}));
   onView(withText("Save server access on this phone")).check(matches(isChecked()));onView(withText("Cancel")).perform(click());
   server.data.put("saveAccessChosen",true);server.data.put("remember",false);
   screen.onActivity(a->call(a,"passwordDialog",new Class<?>[]{Gateway.class,Runnable.class},server,(Runnable)()->{}));onView(withText("Save server access on this phone")).check(matches(isNotChecked()));onView(withText("Cancel")).perform(click());
  }
 }
 @Test public void identityErrorRequiresReviewAndPinsBeforeAnyRetry()throws Exception{
  AtomicInteger retries=new AtomicInteger();
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{Gateway live=((ArrayList<Gateway>)field(a,"gateways")).get(0);call(a,"trust",new Class<?>[]{Gateway.class,Ssh.HostTrust.class,Runnable.class},live,new Ssh.HostTrust(NEXT,true,live),(Runnable)()->{try{assertEquals(NEXT,new ServerIdentityPins(context).get(live));assertEquals(NEXT,vault.read().get(0).get("fingerprint"));retries.incrementAndGet();}catch(Exception e){throw new AssertionError(e);}});});
   onView(withText("Trust replacement")).check(matches(not(isEnabled())));assertEquals(0,retries.get());onView(withText("Cancel")).perform(click());assertEquals(OLD,new ServerIdentityPins(context).get(server));
   screen.onActivity(a->{Gateway live=((ArrayList<Gateway>)field(a,"gateways")).get(0);call(a,"trust",new Class<?>[]{Gateway.class,Ssh.HostTrust.class,Runnable.class},live,new Ssh.HostTrust(NEXT,true,live),(Runnable)()->{try{assertEquals(NEXT,new ServerIdentityPins(context).get(live));retries.incrementAndGet();}catch(Exception e){throw new AssertionError(e);}});});
   onView(withText("I verified this replacement server and its new fingerprint")).perform(scrollTo(),click());ScreenshotProof.save(context,"major-reviewed-identity-replacement");onView(withText("Trust replacement")).perform(click());assertEquals(1,retries.get());assertEquals(NEXT,vault.read().get(0).get("fingerprint"));
  }
 }
 @Test public void lastPhysicalRemovalForgetsPinButAliasesAndImportedVpnKeepOwnTrust()throws Exception{
  Gateway sibling=ServerProtocols.create(server,SingleProtocols.XRAY),imported=new Gateway();imported.set("host",server.get("host"));imported.set("fingerprint","imported-certificate-unchanged");imported.data.put("clientOnly",true);
  ServerIdentityPins identities=new ServerIdentityPins(context);ArrayList<Gateway> remaining=new ArrayList<>(Arrays.asList(sibling,imported));vault.write(remaining);identities.forgetIfUnreferenced(server,remaining);assertEquals(OLD,identities.get(server));
  remaining.remove(sibling);vault.write(remaining);identities.forgetIfUnreferenced(sibling,remaining);assertEquals("",identities.get(server));assertEquals("imported-certificate-unchanged",vault.read().get(0).get("fingerprint"));
 }
 @Test public void staleIdentityReviewCannotOverwriteNewTrustOrMutateAliases()throws Exception{
  ServerIdentityPins identities=new ServerIdentityPins(context);ArrayList<Gateway> active=new ArrayList<>(Arrays.asList(server));identities.replaceReviewed(server,OLD,NEXT,active);
  try{identities.replaceReviewed(server,OLD,"SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",active);fail("stale review accepted");}catch(java.io.IOException expected){}
  assertEquals(NEXT,identities.get(server));assertEquals(NEXT,server.get("fingerprint"));
 }
 @Test public void removingLastServerFromPhoneRetiresOnlyItsEndpointPin()throws Exception{
  Gateway unrelated=new Gateway();unrelated.set("host","other.example.net");unrelated.set("name","Other server");unrelated.set("fingerprint",NEXT);vault.write(new ArrayList<>(Arrays.asList(server,unrelated)));new ServerIdentityPins(context).remember(unrelated,NEXT);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage North server")).perform(scrollTo(),click());onView(withText("Maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Remove or rebuild")).perform(scrollTo(),click());onView(withText("Remove server from this phone")).perform(scrollTo(),click());onView(withText("Continue")).perform(click());
   assertEquals("",new ServerIdentityPins(context).get(server));assertEquals(NEXT,new ServerIdentityPins(context).get(unrelated));assertEquals(1,vault.read().size());assertEquals(unrelated.get("id"),vault.read().get(0).get("id"));
  }
 }
 @Test public void delegatedUserManagerSeesScopedUsersWithoutOwnerControls()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Gateway live=((ArrayList<Gateway>)field(a,"gateways")).get(0);live.data.put("adminAccess",true);live.data.put("adminSnapshot",new JSONObject().put("role","user_manager").put("revision",3).put("scope",new JSONObject().put("kind","protocol").put("id","fixture-instance").put("users","own")).put("capabilities",new JSONArray().put("users.read").put("users.create")).put("objects",new JSONArray().put(new JSONObject().put("id","fixture-instance").put("protocol","awg").put("server_id","fixture-server"))));call(a,"openScreen",new Class<?>[]{String.class},"Administrators");}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("VPN user manager")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Invite administrator")).check(doesNotExist());onView(withText("Wipe server & reinstall Ubuntu")).check(doesNotExist());onView(withText("AmneziaWG 3.1 · This server")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"major-scoped-administrator");
  }
 }
 @Test public void enrollmentFailureKeepsTheSameDraftAndNeverRequestsOwnerPassword()throws Exception{
  JSONObject invitation=new JSONObject().put("fixture",true);server.data.put("adminAccess",true).put("remember",true).put("adminEnrollment",invitation);server.privateKey="retained-private-fixture";vault.write(new ArrayList<>(Arrays.asList(server)));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{Gateway draft=((ArrayList<Gateway>)field(a,"gateways")).get(0);call(a,"openAdministrators",new Class<?>[]{Gateway.class},draft);assertEquals(false,field(a,"busy"));call(a,"showAdminEnrollmentFailure",new Class<?>[]{JSONObject.class,Gateway.class,Exception.class},invitation,draft,new Ssh.SignInRejected(new java.io.IOException("private fixture")));});
   onView(withText("Administrator setup paused")).check(matches(isCompletelyDisplayed())).check((view,error)->{if(error!=null)throw error;android.text.Layout layout=((android.widget.TextView)view).getLayout();assertNotNull(layout);for(int line=0;line<layout.getLineCount();line++)assertEquals("Recovery title must remain complete at large text",0,layout.getEllipsisCount(line));});onView(withText("Continue setup")).check(matches(isCompletelyDisplayed()));onView(withText("Server access")).check(doesNotExist());onView(withText("Close")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"enrollment-error-actions");onView(withText("Close")).perform(click());
   onView(withText("Resume invitation enrollment")).check(matches(isDisplayed()));screen.onActivity(a->assertEquals(false,field(a,"busy")));assertEquals("retained-private-fixture",vault.read().get(0).privateKey);assertEquals(invitation.toString(),vault.read().get(0).data.getJSONObject("adminEnrollment").toString());
  }
 }
 @Test public void unchangedLiteralIpClientsCannotBePromisedAnEntryMove()throws Exception{
  Gateway pair=server;pair.set("pairEngine","native-v2");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","awg");pair.set("vpnServer","203.0.113.10");pair.exit=new Gateway();pair.exit.set("host","exit.example.net");Gateway candidate=new Gateway();candidate.set("host","new.example.net");candidate.set("fingerprint",NEXT);
  JSONObject probe=new JSONObject().put("os","ubuntu").put("version","24.04");
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->call(a,"reviewEntryReplacement",new Class<?>[]{Gateway.class,Gateway.class,JSONObject.class,boolean.class,boolean.class},pair,candidate,probe,false,false));
   onView(withText("Updated client profiles are required")).check(matches(isDisplayed()));onView(withText("Stage replacement entry")).check(doesNotExist());onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void pairedWipeReviewRequiresAnExplicitEraseChoiceAndCancelStartsNothing()throws Exception{
  Gateway pair=server;pair.exit=new Gateway();pair.exit.set("host","exit.example.net");JSONObject plans=new JSONObject();for(String role:new String[]{"entry","exit"})plans.put(role,new JSONObject().put("version","24.04").put("disk","/dev/vda").put("fingerprint",role.equals("entry")?OLD:NEXT));JSONObject plan=new JSONObject().put("warning","Both system disks and VPN users are erased.").put("order",new JSONArray().put("exit").put("entry")).put("plans",plans);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->call(a,"reviewPairOs",new Class<?>[]{Gateway.class,JSONObject.class},pair,plan));onView(withText("Erase & reinstall both")).check(matches(not(isEnabled())));onView(withText("Erase both reviewed system disks and their VPN data")).perform(scrollTo(),click());onView(withText("Erase & reinstall both")).check(matches(isEnabled()));ScreenshotProof.save(context,"major-paired-wipe-review");onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());assertFalse(server.data.has("pairedOsOperation"));
  }
 }
 @Test public void pairedUbuntuChoicesAreIndependentAndDoNotStartAJob()throws Exception{
  Gateway pair=server;pair.exit=new Gateway();pair.exit.set("host","exit.example.net");OsWipeNetwork.Source source=OsWipeNetwork.source;
  try{OsWipeNetwork.source=c->new OsWipeNetwork.State(false,true);
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    screen.onActivity(a->call(a,"choosePairOs",new Class<?>[]{Gateway.class},pair));
    onView(withTagValue(is((Object)"Entry Ubuntu version"))).perform(scrollTo(),click());onData(allOf(is(instanceOf(String.class)),is("26.04"))).inRoot(isPlatformPopup()).perform(click());
    onView(withTagValue(is((Object)"Exit Ubuntu version"))).perform(scrollTo(),click());onData(allOf(is(instanceOf(String.class)),is("22.04"))).inRoot(isPlatformPopup()).perform(click());
    onView(withTagValue(is((Object)"Entry Ubuntu version"))).check((view,error)->{if(error!=null)throw error;assertEquals("26.04",((Spinner)view).getSelectedItem());});
    onView(withTagValue(is((Object)"Exit Ubuntu version"))).check((view,error)->{if(error!=null)throw error;assertEquals("22.04",((Spinner)view).getSelectedItem());});
    onView(withText("Check & prepare review")).check(matches(not(isEnabled())));ScreenshotProof.save(context,"major-independent-ubuntu-versions");onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());assertFalse(pair.data.has("pairedOsOperation"));
   }
  }finally{OsWipeNetwork.source=source;}
 }
 @Test public void helperTerminalIntentOnlyOffersItsMatchingResume()throws Exception{
  Gateway pair=server;pair.exit=new Gateway();pair.exit.set("host","exit.example.net");
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   for(String state:new String[]{"accepting","rolling-back"}){pair.data.put("helperUpdate",new JSONObject().put("state",state));screen.onActivity(a->call(a,"openMaintenance",new Class<?>[]{Gateway.class},pair));
    onView(withText("Review change")).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());
    onView(withContentDescription("Collapse Checks & updates")).perform(scrollTo()).check(matches(isDisplayed()));
    screen.onActivity(a->assertEquals("Review change must reveal local actions without starting server work",false,field(a,"busy")));assertFalse(DeploymentService.active());
    onView(withText(state.equals("accepting")?"Resume helper update acceptance":"Resume helper update rollback")).perform(scrollTo()).check(matches(isDisplayed()));
    onView(withText(state.equals("accepting")?"Resume helper update rollback":"Resume helper update acceptance")).check(doesNotExist());onView(withText("Accept helper update after client check")).check(doesNotExist());onView(withText("Roll back management helper update")).check(doesNotExist());
   }assertFalse(DeploymentService.active());
  }
 }

}
