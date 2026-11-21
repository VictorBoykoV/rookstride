package org.strongswan.android.rookstride;

import android.content.*;
import android.os.*;
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
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Actual screen interactions with synthetic payloads. Live SSH/export/import is a separate gate. */
@RunWith(AndroidJUnit4.class)
public class SharingNavigationRevisionUiTest {
 private Context context;private Vault vault;private ArrayList<Gateway> original;private Gateway server,empty,imported;private String progress;
 @Before public void fixture()throws Exception{
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);original=vault.read();
  progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
  server=new Gateway();server.set("name","North server");server.set("serverName","North server");server.set("host","north.example.net");server.set("protocol","awg");server.set("serverInstance","fixture-instance");server.data.put("checkedAt",System.currentTimeMillis());server.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("users",new JSONArray()));
  empty=new Gateway();empty.set("name","Empty server");empty.set("serverName","Empty server");empty.set("host","empty.example.net");empty.set("protocol","");empty.data.put("checkedAt",System.currentTimeMillis());
  imported=new Gateway();imported.set("name","Shared VPN");imported.set("host","shared.example.net");imported.set("protocol","awg");imported.data.put("clientOnly",true);
  vault.write(new ArrayList<>(Arrays.asList(server,empty,imported)));context.getSharedPreferences("rookstride-ui",0).edit().remove("selected").remove("lastConnectedId").putBoolean("connectionsExpanded:"+server.get("id"),true).commit();
 }
 @After public void restore()throws Exception{vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();context.getSharedPreferences("rookstride-ui",0).edit().remove("connectionsExpanded:"+server.get("id")).commit();InstrumentationRegistry.getInstrumentation().runOnMainSync(()->((ClipboardManager)context.getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("","")));}
 private Object field(Object a,String name){try{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(a);}catch(Exception e){throw new AssertionError(e);}}
 private void call(Object a,String name,Class<?>[] types,Object...args){try{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(a,args);}catch(Exception e){throw new AssertionError(e);}}
 private JSONObject ike(String user)throws Exception{return new JSONObject().put("type","ikev2-eap").put("name","Test IKEv2").put("remote",new JSONObject().put("addr","north.example.net")).put("local",new JSONObject().put("eap_id",user));}
 private JSONObject awg()throws Exception{return new JSONObject().put("format","awg").put("name","rook-0123456789.conf").put("content","[Interface]\nPrivateKey = synthetic-private-key\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = synthetic-server-key\nEndpoint = north.example.net:51820\n");}
 @Test public void fiveTabsSeparateConnectionsFromPhysicalAdministration()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->assertTrue("Light app surface requires dark system navigation icons",androidx.core.view.WindowCompat.getInsetsController(a.getWindow(),a.getWindow().getDecorView()).isAppearanceLightNavigationBars()));ScreenshotProof.save(context,"system-navigation-contrast");
   for(String tab:new String[]{"VPNs","Servers","Split","Journal","App settings"})onView(withContentDescription(tab)).check(matches(isCompletelyDisplayed()));
   onView(withContentDescription("Open Shared VPN")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Empty server")).check(doesNotExist());
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage Empty server")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Shared VPN")).check(doesNotExist());onView(withContentDescription("Manage North server")).perform(scrollTo(),click());onView(withText("Maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Remove or rebuild")).perform(scrollTo(),click());onView(withText("Wipe server & reinstall Ubuntu")).perform(scrollTo()).check(matches(isDisplayed()));onView(withContentDescription("Back to Servers")).perform(scrollTo(),click());onView(withText("Your servers")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"revision-server-destination");
  }
 }
 @Test public void disclosurePersistsAcrossTabsAndRecreationWithoutHidingManagement()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   String tag="server-connections-"+server.get("id");onView(withContentDescription("Hide connections for North server")).perform(scrollTo(),click());onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.GONE)));onView(withContentDescription("Manage North server")).check(matches(isDisplayed()));
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("VPNs")).perform(click());onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.GONE)));screen.recreate();onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.GONE)));onView(withContentDescription("Show connections for North server")).perform(scrollTo(),click());onView(withContentDescription("Connect AmneziaWG 3.1 on North server")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"revision-collapsible-connections");
  }
 }
 @Test public void detailsAndSettingsHaveSeparateDiscoverableTargets()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(allOf(withContentDescription("Details about AmneziaWG 3.1"),isDescendantOfA(withTagValue(is((Object)("server-connections-"+server.get("id"))))))).perform(scrollTo(),click());onView(withText("Official documentation")).check(matches(isCompletelyDisplayed()));onView(withText("Close")).perform(click());
   onView(withContentDescription("Settings for AmneziaWG 3.1")).perform(scrollTo(),click());onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();onView(withContentDescription("Manage North server")).perform(scrollTo(),click());onView(withContentDescription("Details about AmneziaWG 3.1")).perform(scrollTo(),click());onView(withText("Close")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void repeatedServerTabTapsKeepTheSameScrolledView()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage Empty server")).perform(scrollTo());final ScrollView[] page={null};final int[] y={0};screen.onActivity(a->{page[0]=(ScrollView)field(a,"pageScroll");y[0]=page[0].getScrollY();});for(int i=0;i<5;i++)onView(withContentDescription("Servers")).perform(click());screen.onActivity(a->{assertSame(page[0],field(a,"pageScroll"));assertEquals(y[0],page[0].getScrollY());});
  }
 }
 @Test public void malformedNewUserExportHasOneDismissibleRecoveryDialog()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{NewUserShareState pending=(NewUserShareState)field(a,"newUserShare");pending.created(server.get("id"),"reader","");pending.profile=new JSONObject().put("format","awg").put("name","wrong.txt").put("content","synthetic");call(a,"restoreCreatedUserShare",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Connection could not be prepared")).check(matches(isDisplayed()));Thread.sleep(2300);onView(withText("Later")).check(matches(isCompletelyDisplayed())).perform(click());Thread.sleep(1300);onView(withText("Connection could not be prepared")).check(doesNotExist());onView(withText("Action needs attention")).check(doesNotExist());screen.onActivity(a->assertFalse(((NewUserShareState)field(a,"newUserShare")).pending));
  }
 }
 @Test public void knownBeforeMutationVersionRefusalOffersReviewedUpdateAndStaysDismissed()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{NewUserShareState pending=(NewUserShareState)field(a,"newUserShare");pending.begin(server.get("id"),"reader","");pending.loading=false;pending.failureCode="pair_helper_update_required";pending.failureDetail="This Double VPN needs a reviewed management update before it can create or change VPN users. No account was created by this request.";call(a,"restoreCreatedUserShare",new Class<?>[]{});});
   onView(withText("Management update needed")).check(matches(isDisplayed()));onView(withText("Review update")).check(matches(isCompletelyDisplayed()));onView(withText("Close")).perform(click());Thread.sleep(1300);onView(withText("Management update needed")).check(doesNotExist());screen.onActivity(a->assertFalse(((NewUserShareState)field(a,"newUserShare")).pending));assertFalse(DeploymentService.active());
  }
 }
 @Test public void newlyCreatedAwgIniCanBeCopiedAndRemainsShareableAfterRecreation()throws Exception{
  JSONObject profile=awg();try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{NewUserShareState pending=(NewUserShareState)field(a,"newUserShare");pending.created(server.get("id"),"reader","");pending.profile=profile;call(a,"restoreCreatedUserShare",new Class<?>[]{});});onView(withText("Share connection file")).perform(scrollTo()).check(matches(isDisplayed()));screen.recreate();onView(withText("Copy configuration")).perform(scrollTo(),click());screen.onActivity(a->{ClipData clip=((ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip();assertNotNull(clip);assertEquals(profile.optString("content"),clip.getItemAt(0).getText().toString());});onView(withText("Done")).perform(click());onView(withText("Action needs attention")).check(doesNotExist());
  }
 }
 @Test public void scopedUserCreationOnlyAsksForCredentialsTheProtocolUses()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   for(String[] item:new String[][]{{"awg","", "false"},{"xray","", "false"},{"ikev2","password","true"},{"openvpn","password","true"},{"openvpn","profile","false"},{"hysteria2","profile","false"},{"trusttunnel","password","true"},{"naive","","false"}}){
    JSONObject object=new JSONObject().put("id","fixture-scope").put("protocol",item[0]).put("access_mode",item[1]);boolean asksPassword=Boolean.parseBoolean(item[2]);screen.onActivity(a->call(a,"scopedAddUser",new Class<?>[]{Gateway.class,JSONObject.class},server,object));
    onView(withTagValue(is((Object)"VPN username"))).check(matches(isDisplayed()));
    if(asksPassword)onView(withTagValue(is((Object)"VPN password"))).check(matches(isDisplayed()));else onView(withTagValue(is((Object)"VPN password"))).check(doesNotExist());
    onView(withText("Create user")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).perform(click());
    JSONObject user=new JSONObject().put("login","reader");screen.onActivity(a->call(a,"scopedEditUser",new Class<?>[]{Gateway.class,JSONObject.class,JSONObject.class},server,object,user));
    if(asksPassword)onView(withTagValue(is((Object)"New VPN password (optional)"))).perform(scrollTo()).check(matches(isDisplayed()));else onView(withTagValue(is((Object)"New VPN password (optional)"))).check(doesNotExist());
    onView(withText("Leave a label empty to keep its current value.")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
   }
  }
 }
 @Test public void unknownIkePasswordIsExplicitAndTypedSecretAppearsInReadableShare()throws Exception{
  JSONObject profile=ike("reader");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->call(a,"shareProtocolProfile",new Class<?>[]{JSONObject.class},profile));onView(withText("Include the VPN password")).check(matches(isDisplayed()));onView(withTagValue(is((Object)"Existing VPN password"))).perform(scrollTo(),replaceText("SyntheticPass8"),androidx.test.espresso.action.ViewActions.closeSoftKeyboard());onView(withText("Continue")).perform(click());onView(withText("Copy sign-in details")).perform(click());screen.onActivity(a->{String shared=((ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip().getItemAt(0).getText().toString();assertTrue(shared.contains("Server: north.example.net"));assertTrue(shared.contains("Username: reader"));assertTrue(shared.contains("Password: SyntheticPass8"));});assertFalse(profile.getJSONObject("local").has("shared_secret"));
  }
 }
 @Test public void createdIkeReadableShareContainsChosenPasswordAndFileHasSameSecret()throws Exception{
  JSONObject profile=PasswordSignIn.withKnownPassword(ike("reader"),"reader","SyntheticPass8");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{NewUserShareState pending=(NewUserShareState)field(a,"newUserShare");pending.created(server.get("id"),"reader","SyntheticPass8");pending.profile=profile;call(a,"restoreCreatedUserShare",new Class<?>[]{});});onView(withText("Copy sign-in details")).perform(scrollTo(),click());screen.onActivity(a->{String shared=((ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip().getItemAt(0).getText().toString();assertTrue(shared.contains("Password: SyntheticPass8"));});assertEquals("SyntheticPass8",new JSONObject(ConnectionExport.fromResponse(profile).content).getJSONObject("local").getString("shared_secret"));onView(withText("Done")).perform(click());
  }
 }
 @Test public void compactCardsDoNotRepeatAddressAndKeepDetailsAnAccessibleTarget()throws Exception{
  server.set("name",server.get("host"));server.set("serverName",server.get("host"));vault.write(new ArrayList<>(Arrays.asList(server)));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withText(server.get("host"))).perform(scrollTo()).check(matches(isDisplayed()));
   onView(withContentDescription("Details about AmneziaWG 3.1")).perform(scrollTo()).check(matches(isCompletelyDisplayed())).check((view,error)->{if(error!=null)throw error;assertTrue(view.getHeight()>=48*context.getResources().getDisplayMetrics().density);});
   onView(withContentDescription("Servers")).perform(click());onView(withText(server.get("host"))).perform(scrollTo()).check(matches(isDisplayed()));
  }
 }
 @Test public void separateVpnOptionIsLimitedToTheSupportedEntry()throws Exception{
  server.set("pairEntryProtocol","awg");server.set("pairExitProtocol","awg");server.set("pairEngine","native-v2");server.set("pairId",String.join("",Collections.nCopies(32,"a")));server.exit=empty;empty.set("serverName","Exit server");vault.write(new ArrayList<>(Arrays.asList(server)));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage North server")).perform(scrollTo(),click());onView(withText("Add a separate VPN")).perform(scrollTo()).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();
   onView(withContentDescription("Manage Exit server")).perform(scrollTo(),click());onView(withText("Add a separate VPN")).check(doesNotExist());androidx.test.espresso.Espresso.pressBack();
   screen.onActivity(a->{for(Gateway node:(ArrayList<Gateway>)field(a,"gateways"))if(node.isPair())node.set("pairEntryProtocol","xray");});onView(withContentDescription("Manage North server")).perform(scrollTo(),click());onView(withText("Add a separate VPN")).check(doesNotExist());assertFalse(DeploymentService.active());
  }
 }

}
