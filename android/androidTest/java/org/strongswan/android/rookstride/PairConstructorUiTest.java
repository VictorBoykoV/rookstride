package org.strongswan.android.rookstride;

import android.content.*;
import android.view.*;
import android.widget.*;
import androidx.test.core.app.ActivityScenario;
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

/** Fictional saved servers and read-only review fixtures; no remote actions. */
@RunWith(AndroidJUnit4.class) public class PairConstructorUiTest {
 Context context;Vault vault;ArrayList<Gateway> old;Gateway entry,exit;
 static Object call(Object a,String n,Class<?>[] t,Object...v)throws Exception{Method m=a.getClass().getDeclaredMethod(n,t);m.setAccessible(true);return m.invoke(a,v);}
 static Field field(Class<?> c,String n)throws Exception{Field f=c.getDeclaredField(n);f.setAccessible(true);return f;}
 Gateway fixture(String name,String host)throws Exception{Gateway n=new Gateway();n.set("name",name);n.set("serverName",name);n.set("host",host);n.set("protocol","");n.set("admin","root");n.sshPassword="fixture-not-a-real-password";n.set("fingerprint","SHA256:fictional");n.data.put("remember",true);n.data.put("checkedAt",System.currentTimeMillis());return n;}
 @Before public void setup()throws Exception{context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);old=vault.read();assertFalse(DeploymentService.active());field(DeploymentService.class,"current").set(null,null);context.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();entry=fixture("First bridge","entry.example.net");exit=fixture("Far bridge","exit.example.net");vault.write(new ArrayList<>(Arrays.asList(entry,exit)));}
 @After public void cleanup()throws Exception{field(DeploymentService.class,"current").set(null,null);context.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();vault.write(old);}
 void invoke(ActivityScenario<RookstrideActivity> s,String n,Class<?>[] t,Object...v){s.onActivity(a->{try{call(a,n,t,v);}catch(Exception e){throw new AssertionError(e);}});}
 void start(ActivityScenario<RookstrideActivity> s){invoke(s,"addPair",new Class<?>[]{});}
 void secure(ActivityScenario<RookstrideActivity> s,boolean expected){s.onActivity(a->{try{android.app.Dialog d=(android.app.Dialog)field(a.getClass(),"pairWizard").get(a);assertEquals(expected,(d.getWindow().getAttributes().flags&WindowManager.LayoutParams.FLAG_SECURE)!=0);}catch(Exception e){throw new AssertionError(e);}});}
 void saved(String name){onView(withText("Choose a saved server")).perform(scrollTo(),click());onView(withText(startsWith(name+"\n"))).perform(click());}
 @Test public void screenshotProtectionFollowsSecretsRatherThanTheWholeWizard()throws Exception{try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){start(s);secure(s,false);onView(withText("Next")).perform(click());secure(s,false);onView(withText("Next")).perform(click());secure(s,true);saved("First bridge");secure(s,true);onView(withText("Next")).perform(click());secure(s,true);saved("Far bridge");onView(withText("Next")).perform(click());secure(s,false);onView(withText("Install")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"pair-reuse-review");onView(withText("Cancel")).perform(click());}}
 @Test public void allFourBorderedCardsSelectByPaddingOrDescriptionOnBothLegs()throws Exception{
  String[][] choices={
   {"awg","Suggested for a simple, fast start when UDP is available. If it cannot connect, try an HTTPS option such as TrustTunnel."},
   {"ikev2","A fast, familiar option for everyday networks. Try another protocol if your network blocks its connection."},
   {"openvpn","A widely supported option to try when other VPNs cannot connect. It can be slower on unstable networks."},
   {"xray","Useful when your network blocks ordinary VPN connections. It resembles a secure web connection."}
  };
  try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){
   start(s);
   for(int leg=0;leg<2;leg++){
    for(String[] choice:choices){String id=choice[0];
     onView(withTagValue(is((Object)("pair-choice-"+id)))).perform(scrollTo(),click());
     onView(allOf(withTagValue(is((Object)id)),isAssignableFrom(RadioButton.class))).check(matches(isChecked()));
     onView(allOf(withText(choice[1]),isAssignableFrom(TextView.class),not(isAssignableFrom(RadioButton.class)),isDescendantOfA(withTagValue(is((Object)("pair-choice-"+id)))))).perform(scrollTo(),click());
     onView(allOf(withTagValue(is((Object)id)),isAssignableFrom(RadioButton.class))).check(matches(isChecked()));
    }
    ScreenshotProof.save(context,leg==0?"pair-entry-four-cards":"pair-exit-four-cards");onView(withText("Next")).perform(click());
   }
   onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }

 @Test public void savedAccessSurvivesRotationAndKeepsTheSameNodeIdentity()throws Exception{try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){start(s);onView(withText("Next")).perform(click());onView(withText("Next")).perform(click());saved("First bridge");s.recreate();secure(s,true);onView(withTagValue(is((Object)"Entry VPS address"))).check(matches(withText(entry.get("host"))));s.onActivity(a->{try{Gateway draft=(Gateway)call(a,"pairDraftNode",new Class<?>[]{String.class},"entry");assertEquals(entry.get("id"),draft.get("id"));assertEquals(entry.sshPassword,draft.sshPassword);assertEquals(entry.get("fingerprint"),draft.get("fingerprint"));assertTrue(draft.remember());}catch(Exception e){throw new AssertionError(e);}});onView(withText("Next")).perform(click());onView(withText("Choose a saved server")).perform(scrollTo(),click());onView(withText(startsWith("First bridge\n"))).check(doesNotExist());onView(withText(startsWith("Far bridge\n"))).perform(click());onView(withText("Next")).perform(click());onView(withText("Swap entry and exit servers")).perform(scrollTo(),click());s.recreate();secure(s,false);onView(withText("Entry: "+exit.get("host")+"\nExit: "+entry.get("host"))).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());assertEquals(2,vault.read().size());assertFalse(DeploymentService.active());}}
 Gateway pair()throws Exception{Gateway p=PairNodes.copy(entry);p.exit=PairNodes.copy(exit);p.set("name","Two bridges");p.set("pairId",PairController.newId());p.set("protocol","awg");p.set("pairEntryProtocol","awg");p.set("pairExitProtocol","openvpn");return p;}
 @Test public void pencilRenamesEntryAndExitIndependentlyAndSavedServerPickerUsesTheAlias()throws Exception{
  Gateway p=pair();vault.write(new ArrayList<>(Arrays.asList(p)));try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage Far bridge")).perform(scrollTo(),click());onView(withContentDescription("Rename server")).perform(click());onView(withTagValue(is((Object)"Server name"))).perform(replaceText("West station"));onView(withText("Save")).perform(click());s.recreate();onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage server West station")).perform(scrollTo()).check(matches(isDisplayed()));onView(withContentDescription("Manage First bridge")).perform(scrollTo(),click());onView(withContentDescription("Rename server")).perform(click());onView(withTagValue(is((Object)"Server name"))).perform(replaceText("East station"));onView(withText("Save")).perform(click());s.recreate();onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage server East station")).perform(scrollTo()).check(matches(isDisplayed()));Gateway stored=vault.read().get(0);assertEquals("Two bridges",stored.get("name"));assertEquals("West station",stored.exit.get("serverName"));assertEquals("East station",stored.get("serverName"));assertEquals(p.get("pairId"),stored.get("pairId"));
   ScreenshotProof.save(context,"renamed-pair-home");start(s);onView(withText("Next")).perform(click());onView(withText("Next")).perform(click());saved("East station");onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
  }
 }
 @Test public void bothPhysicalServersAppearWithRolesAndOpenTheirOwnScreen()throws Exception{Gateway p=pair();p.data.put("vpnPort",51821);p.data.put("tunnelPort",1195);vault.write(new ArrayList<>(Arrays.asList(p)));try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){onView(withContentDescription("Servers")).perform(click());onView(withText("Double VPN · Entry server")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Double VPN · Exit server")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"pair-managed-both-servers");onView(withContentDescription("Manage Far bridge")).perform(scrollTo(),click());onView(withText("Open Double VPN")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Server maintenance")).perform(scrollTo(),click());onView(withContentDescription("Expand Double VPN & recovery")).perform(scrollTo(),click());onView(withText("Change Double VPN protocols")).perform(scrollTo(),click());secure(s,false);onView(withText("AmneziaWG 3.1")).perform(scrollTo()).check(matches(isChecked())).perform(click());s.onActivity(a->{try{assertEquals("51821",((PairSetupState)field(a.getClass(),"pairDraft").get(a)).get("vpnPort",""));}catch(Exception e){throw new AssertionError(e);}});onView(withText("Next")).perform(click());onView(withText("OpenVPN")).perform(scrollTo()).check(matches(isChecked())).perform(click());s.onActivity(a->{try{assertEquals("1195",((PairSetupState)field(a.getClass(),"pairDraft").get(a)).get("tunnelPort",""));}catch(Exception e){throw new AssertionError(e);}});onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());}}
 @Test public void removalReviewHidesRawPathsKeepsActionsVisibleAndCancelPreservesAccess()throws Exception{Gateway p=pair();vault.write(new ArrayList<>(Arrays.asList(p)));try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){s.onActivity(a->{try{Field source=field(a.getClass(),"pairReviewSource");source.set(a,Proxy.newProxyInstance(source.getType().getClassLoader(),new Class<?>[]{source.getType()},(proxy,m,args)->{JSONObject review=new JSONObject();for(String role:new String[]{"entry","exit"})review.put(role,new JSONObject().put("kind","pair").put("role",role).put("protocols",new JSONArray().put(role.equals("entry")?"awg":"openvpn")).put("filtering",role.equals("exit")).put("files",new JSONArray().put("/etc/systemd/system/rookstride-pair-bridge.service").put("/var/lib/rookstride-pair/private-state")));return review;}));call(a,"resetPair",new Class<?>[]{Gateway.class},p);}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(900);onView(withText("Remove both VPN setups?")).check(matches(isDisplayed()));onView(withText("Remove")).check(matches(isCompletelyDisplayed())).check(matches(not(isEnabled())));onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));onView(allOf(withText(containsString("/etc/")),isDisplayed())).check(doesNotExist());ScreenshotProof.save(context,"pair-reset-readable-review");onView(withText("Cancel")).perform(click());ArrayList<Gateway> saved=vault.read();assertEquals(1,saved.size());assertEquals(p.get("pairId"),saved.get(0).get("pairId"));assertEquals(entry.sshPassword,saved.get(0).sshPassword);assertFalse(DeploymentService.active());}}
 @Test public void anEmptyManagedServerHasNoInventedIkeConnection()throws Exception{try(ActivityScenario<RookstrideActivity> s=ActivityScenario.launch(RookstrideActivity.class)){onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage First bridge")).perform(scrollTo(),click());onView(withText("Maintenance")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Connection statistics")).check(doesNotExist());s.onActivity(a->{try{assertEquals("Protocols",field(a.getClass(),"tab").get(a));}catch(Exception e){throw new AssertionError(e);}});}}
}
