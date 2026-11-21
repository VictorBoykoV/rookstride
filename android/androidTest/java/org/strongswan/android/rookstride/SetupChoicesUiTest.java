package org.strongswan.android.rookstride;

import android.content.*;
import android.graphics.Rect;
import androidx.test.espresso.UiController;
import androidx.test.espresso.ViewAction;
import org.hamcrest.Matcher;
import android.view.*;
import android.widget.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.action.GeneralClickAction;
import androidx.test.espresso.action.Tap;
import androidx.test.espresso.action.Press;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Local fixtures. These tests never send SSH credentials or change a VPS. */
@RunWith(AndroidJUnit4.class) public class SetupChoicesUiTest {
 Context context;Vault vault;ArrayList<Gateway> previous;String previousHistory;boolean previousUnread;
 static Object call(Object a,String name,Class<?>[] types,Object...args)throws Exception{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(a,args);}
 static Field field(Class<?> c,String name)throws Exception{Field f=c.getDeclaredField(name);f.setAccessible(true);return f;}
 @Before public void setup()throws Exception{context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);previous=vault.read();previousHistory=context.getSharedPreferences("rookstride-ui",0).getString("activityHistory",null);previousUnread=context.getSharedPreferences("rookstride-ui",0).getBoolean("activityUnread",false);context.getSharedPreferences("rookstride-ui",0).edit().remove("activityHistory").putBoolean("activityUnread",false).commit();assertFalse(DeploymentService.active());field(DeploymentService.class,"current").set(null,null);vault.write(new ArrayList<>());context.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();}
 @After public void cleanup()throws Exception{field(DeploymentService.class,"current").set(null,null);context.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();vault.write(previous);context.getSharedPreferences("rookstride-ui",0).edit().putString("activityHistory",previousHistory).putBoolean("activityUnread",previousUnread).commit();}
 private void open(ActivityScenario<RookstrideActivity> screen,String method){screen.onActivity(a->{try{call(a,method,new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});}
 private static void input(String tag,String value){androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withTagValue(is((Object)tag))).perform(scrollTo(),replaceText(value));}
 private static ViewAction visibleWhitespace(){return new ViewAction(){
  public Matcher<View> getConstraints(){return isDisplayingAtLeast(1);}
  public String getDescription(){return "Tap visible card padding, including a partially visible large-text card";}
  public void perform(UiController ui,View view){Rect visible=new Rect();assertTrue(view.getGlobalVisibleRect(visible));float inset=6*view.getResources().getDisplayMetrics().density;new GeneralClickAction(Tap.SINGLE,v->new float[]{visible.right-inset,visible.exactCenterY()},Press.FINGER).perform(ui,view);}
 };}
 private void syntheticWizardProof(ActivityScenario<RookstrideActivity> screen,String name)throws Exception{
  // Ordinary protocol choices and the non-secret review allow screenshots.
  final Window[] window={null};screen.onActivity(a->{try{android.app.Dialog d=(android.app.Dialog)field(a.getClass(),"pairWizard").get(a);window[0]=d.getWindow();assertFalse((window[0].getAttributes().flags&WindowManager.LayoutParams.FLAG_SECURE)!=0);}catch(Exception e){throw new AssertionError(e);}});
  ScreenshotProof.save(context,name);
 }
 @Test public void oldIkeHelperNeedsItsExplicitNonDestructiveUpdate()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Gateway n=new Gateway();n.set("host","server.example.net");n.set("protocol","ikev2");n.data.put("snapshot",new JSONObject().put("services",new JSONObject()).put("password_policy",new JSONObject().put("minimum",8).put("maximum",15)));call(a,"openVpn",new Class[]{Gateway.class},n);call(a,"addUser",new Class[]{Gateway.class},n);}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Update server management")).check(matches(isDisplayed()));onView(withText("Update")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void weakPasswordIsAdviceAndCanBeExplicitlyKept()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   open(screen,"pairUserSettings");input("VPN user name","1");input("VPN password","1");androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Save")).perform(click());onView(withText("Use this password?")).check(matches(isDisplayed()));onView(withText("Change password")).perform(click());onView(withText("Save")).perform(click());onView(withText("Use anyway")).perform(click());
   screen.onActivity(a->{try{PairSetupState draft=(PairSetupState)field(a.getClass(),"pairDraft").get(a);assertEquals("1",draft.get("login",""));assertEquals("1",draft.get("password",""));}catch(Exception e){throw new AssertionError(e);}});
  }
 }
 @Test public void automaticServerAccessIsVisibleWithoutAdvanced()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"newPairDraft",new Class[]{});PairSetupState draft=(PairSetupState)field(a.getClass(),"pairDraft").get(a);draft.step=4;draft.put("entryHost","entry.example.net");draft.put("exitHost","exit.example.net");call(a,"showPairStep",new Class[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Automatic · use the reachable server if needed")).perform(scrollTo()).check(matches(isChecked()));onView(withText("Install")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"automatic-ssh-review");onView(withText("Cancel")).perform(click());
  }
 }
 @Test public void existingPairCanChooseAutomaticManagementWithoutReinstalling()throws Exception{
  Gateway node=new Gateway();node.set("host","entry.example.net");node.set("sshRoute","direct");node.exit=new Gateway();node.exit.set("host","exit.example.net");node.sshPassword="fictional-entry";node.exit.sshPassword="fictional-exit";node.data.put("remember",true);node.exit.data.put("remember",true);vault.write(new ArrayList<>(Arrays.asList(node)));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   // Add the sentinel after launch: startup correctly resumes saved unfinished jobs.
   // This local dialog test must never initiate that independent SSH lifecycle.
   screen.onActivity(a->{try{Gateway loaded=((ArrayList<Gateway>)field(a.getClass(),"gateways").get(a)).get(0);loaded.set("job","recorded-job-unchanged");call(a,"choosePairSshRoute",new Class[]{Gateway.class},loaded);}catch(Exception e){throw new AssertionError(e);}});onView(withText("Automatic · use the reachable server if needed")).perform(click());onView(withText("Save")).perform(click());Gateway saved=vault.read().get(0);assertEquals("auto",saved.get("sshRoute"));assertEquals("recorded-job-unchanged",saved.get("job"));assertEquals("fictional-entry",saved.sshPassword);assertEquals("fictional-exit",saved.exit.sshPassword);assertFalse(DeploymentService.active());
  }
 }
 @Test public void osEraseNeverMistakesAKeyPassphraseForTheRootPassword()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Gateway n=new Gateway();n.set("host","server.example.net");n.set("admin","root");n.sshPassword="fictional-key-passphrase";n.privateKey="fictional-private-key";JSONObject plan=new JSONObject().put("version","24.04").put("scope",new JSONObject().put("disk","/dev/vda"));call(a,"reviewOsReinstall",new Class[]{Gateway.class,JSONObject.class},n,plan);}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Root access needed")).check(matches(isDisplayed()));onView(withText("Wipe & reinstall")).check(doesNotExist());onView(withText("Done")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void osEraseNeedsItsOwnVisibleConfirmation()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Gateway n=new Gateway();n.set("host","server.example.net");n.set("admin","root");n.sshPassword="fictionalRootPass";JSONObject plan=new JSONObject().put("version","24.04").put("scope",new JSONObject().put("disk","/dev/vda"));call(a,"reviewOsReinstall",new Class[]{Gateway.class,JSONObject.class},n,plan);}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Wipe & reinstall")).check(matches(isCompletelyDisplayed())).check(matches(not(isEnabled())));onView(withText("I understand that this server’s system disk will be erased")).perform(scrollTo(),click());onView(withText("Wipe & reinstall")).check(matches(isEnabled()));ScreenshotProof.save(context,"os-erase-review");onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void titleDescriptionAndWhitespaceSelectWhileDetailsAloneExplains()throws Exception{
  for(SingleProtocols protocol:SingleProtocols.values())try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"openScreen",new Class<?>[]{String.class},"Protocols");}catch(Exception e){throw new AssertionError(e);}});
   onView(withContentDescription("Details about "+protocol.title)).perform(scrollTo(),click());onView(withText("Official documentation")).check(matches(isDisplayed()));onView(withText("Close")).perform(click());if(protocol==SingleProtocols.AWG)ScreenshotProof.save(context,"protocol-card-selection");
   onView(allOf(withText(protocol.title),isDescendantOfA(withContentDescription("Choose "+protocol.title)))).perform(scrollTo(),click());onView(withText("Connect your server")).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());
   onView(withContentDescription("Choose "+protocol.title)).perform(visibleWhitespace());onView(withText("Connect your server")).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());
   final String[] summary={""};screen.onActivity(a->{try{summary[0]=(String)call(a,"protocolSummary",new Class<?>[]{SingleProtocols.class},protocol);}catch(Exception e){throw new AssertionError(e);}});onView(withText(summary[0])).perform(scrollTo(),click());onView(withText("Connect your server")).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());
  }
 }
 @Test public void doubleVpnWizardShowsBothLegsAndPreservesChoicesOnBackAndRotation()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   open(screen,"addPair");onView(withText("Step 1 of 5")).check(matches(isDisplayed()));onView(withText("IKEv2")).perform(scrollTo(),click());onView(withText("Next")).perform(click());onView(withText("Step 2 of 5")).check(matches(isDisplayed()));
   for(SingleProtocols protocol:SingleProtocols.values())onView(withText(protocol.title)).perform(scrollTo()).check(matches(isEnabled()));
   syntheticWizardProof(screen,"double-vpn-exit-choices");onView(withText("VLESS · REALITY (TCP)")).perform(scrollTo(),click());onView(withText("Next")).perform(click());input("Entry VPS address","entry.example.net");input("Server administrator password","fixture-password");androidx.test.espresso.Espresso.closeSoftKeyboard();screen.recreate();
   onView(withText("Step 3 of 5")).check(matches(isDisplayed()));onView(withTagValue(is((Object)"Entry VPS address"))).check(matches(withText("entry.example.net")));onView(withTagValue(is((Object)"Server administrator password"))).check(matches(withText("fixture-password")));
   androidx.test.espresso.Espresso.closeSoftKeyboard();androidx.test.espresso.Espresso.pressBack();onView(withText("VLESS · REALITY (TCP)")).perform(scrollTo()).check(matches(isChecked()));onView(withText("Next")).perform(click());onView(withTagValue(is((Object)"Entry VPS address"))).check(matches(withText("entry.example.net")));androidx.test.espresso.Espresso.closeSoftKeyboard();androidx.test.espresso.Espresso.pressBack();onView(withText("Back")).perform(click());onView(withText("IKEv2")).perform(scrollTo()).check(matches(isChecked()));onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void reviewNeedsTwoDistinctServersAndShowsNoStoriesActions()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   open(screen,"addPair");onView(withText("Next")).perform(click());onView(withText("IKEv2")).perform(scrollTo(),click());onView(withText("Next")).perform(click());input("Entry VPS address","entry.example.net");input("Server administrator password","fixture-password");androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Next")).perform(click());
   input("Exit VPS address","entry.example.net");input("Server administrator password","fixture-password");androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Next")).perform(click());onView(withText("Step 4 of 5")).perform(scrollTo()).check(matches(isDisplayed()));
   input("Exit VPS address","exit.example.net");androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withText("Next")).perform(click());onView(withText("Step 5 of 5")).check(matches(isDisplayed()));onView(withText("Install")).check(matches(isCompletelyDisplayed()));onView(withText("Back")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));onView(withText("Read Rook’s stories")).check(doesNotExist());Thread.sleep(3500);syntheticWizardProof(screen,"double-vpn-review");onView(withText("Cancel")).perform(click());
  }
 }
 @Test public void abandoningStaleSetupPersistsWithoutDeletingServerRecordsOrJobIds()throws Exception{
  Gateway node=new Gateway();node.set("name","Failed pair");node.set("host","entry.example.net");node.exit=new Gateway();node.exit.set("host","exit.example.net");node.set("pairId",PairController.newId());node.set("job","a1234567890123456789012345678901a");vault.write(new ArrayList<>(Arrays.asList(node)));
  InstallationProgress progress=new InstallationProgress("pair",node.get("id"),System.currentTimeMillis()-86400000);progress.state="needs-attention";progress.completed=2;progress.phase="Fixture: the servers changed";context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress.json().toString()).commit();
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"openScreen",new Class<?>[]{String.class},"Progress");}catch(Exception e){throw new AssertionError(e);}});ScreenshotProof.save(context,"failed-setup-status");onView(withText("How this setup works ↗")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Read Rook’s stories")).check(doesNotExist());onView(withText("Abandon setup")).perform(scrollTo(),click());onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));onView(withText("Abandon")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"abandon-confirmation");onView(withText("Cancel")).perform(click());onView(withText("Check and resume")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"failed-setup-actions");onView(withText("Abandon setup")).perform(scrollTo(),click());onView(allOf(withText("Abandon"),isAssignableFrom(Button.class))).perform(click());
   screen.recreate();assertFalse(context.getSharedPreferences("rookstride-deployment",0).contains("progress"));ArrayList<Gateway> saved=vault.read();assertEquals(1,saved.size());assertNotNull(saved.get(0).exit);assertEquals(node.get("job"),saved.get(0).get("job"));assertEquals("true",saved.get(0).get("setupAbandoned"));onView(withText(containsString("Setup needs attention"))).check(doesNotExist());
  }
 }
 @Test public void staleAbandonCannotDismissAnActiveOrDifferentInstallation()throws Exception{
  Gateway node=new Gateway();InstallationProgress stale=new InstallationProgress("pair",node.get("id"),1);DeploymentService.Session active=new DeploymentService.Session(node,new ArrayList<>(),"pair",null,false,2);field(DeploymentService.class,"current").set(null,active);assertFalse(DeploymentService.abandon(context,stale));active.progress.state="needs-attention";assertFalse(DeploymentService.abandon(context,stale));assertSame(active,DeploymentService.current());
 }
 @Test public void successfulCheckNamesTheServerAndInventoryAndExpiresIntoActivity()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   final String[] notice={""};screen.onActivity(a->{try{Gateway node=new Gateway();node.set("host","vpn.example.net");JSONObject inventory=new JSONObject().put("gateway",true).put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg")));notice[0]=(String)call(a,"serverCheckSummary",new Class<?>[]{Gateway.class,JSONObject.class},node,inventory);field(a.getClass(),"message").set(a,notice[0]);call(a,"recordActivity",new Class<?>[]{String.class,Gateway.class},"Server checked",node);call(a,"render",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
   assertTrue(notice[0].contains("vpn.example.net"));assertTrue(notice[0].contains("2 installed VPNs"));onView(withText(notice[0])).check(matches(isDisplayed()));ScreenshotProof.save(context,"neutral-server-check");Thread.sleep(4700);onView(withText(notice[0])).check(matches(not(isDisplayed())));onView(withContentDescription("Activity, new updates")).perform(click());onView(withText("Server checked")).check(matches(isDisplayed()));
  }
 }
}
