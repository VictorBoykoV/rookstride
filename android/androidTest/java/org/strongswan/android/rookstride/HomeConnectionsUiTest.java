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
import org.strongswan.android.rookstride.engine.NativeVpn;
import java.lang.reflect.*;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Controlled engine callbacks exercise the exact signed UI; no remote server or VPN is started. */
@RunWith(AndroidJUnit4.class)
public class HomeConnectionsUiTest {
 private Context c;private Vault vault;private ArrayList<Gateway> before;private Gateway server,awg,hy;
 private boolean hadSaved;private Map<String,Bundle> states;private final Map<String,Bundle> oldStates=new HashMap<>();
 private final Map<String,String> oldPrefs=new HashMap<>();private String oldProgress;private Object oldSession;private Field session;
 @Before public void fixture()throws Exception{
  c=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(c);before=vault.read();
  SharedPreferences ui=c.getSharedPreferences("rookstride-ui",0);hadSaved=ui.getBoolean("hasSavedVpn",false);for(String key:new String[]{"selected","lastConnectedId","seenCompletion"}){oldPrefs.put(key,ui.getString(key,null));}ui.edit().remove("selected").remove("lastConnectedId").remove("seenCompletion").commit();
  oldProgress=c.getSharedPreferences("rookstride-deployment",0).getString("progress",null);c.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
  session=DeploymentService.class.getDeclaredField("current");session.setAccessible(true);oldSession=session.get(null);session.set(null,null);
  Field f=NativeVpn.class.getDeclaredField("errors");f.setAccessible(true);states=(Map<String,Bundle>)f.get(null);oldStates.putAll(states);states.clear();
  server=new Gateway();server.set("host","north.example.net");server.set("name","North station");server.set("protocol","");server.data.put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg").put("hysteria2"))));
  awg=ServerProtocols.create(server,SingleProtocols.AWG);hy=ServerProtocols.create(server,SingleProtocols.HYSTERIA2);for(Gateway g:Arrays.asList(awg,hy)){g.set("setupIntent","");g.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));}
  Gateway empty=new Gateway();empty.set("host","empty.example.net");empty.set("name","Empty station");empty.set("protocol","");
  vault.write(new ArrayList<>(Arrays.asList(server,awg,hy,empty)));ui.edit().putString("lastConnectedId",hy.get("id")).commit();
 }
 @After public void restore()throws Exception{session.set(null,oldSession);states.clear();states.putAll(oldStates);vault.write(before);SharedPreferences.Editor edit=c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",hadSaved);for(Map.Entry<String,String> item:oldPrefs.entrySet())edit.putString(item.getKey(),item.getValue());edit.commit();c.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();}
 private Object call(RookstrideActivity a,String name,Class<?>[] types,Object... args){try{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(a,args);}catch(Exception e){throw new AssertionError(e);}}
 private Object value(RookstrideActivity a,String name){try{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(a);}catch(Exception e){throw new AssertionError(e);}}
 private void state(String next){Bundle b=new Bundle();b.putString("id",hy.get("id"));b.putString("state",next);states.put("routes",b);}
 private View tagged(RookstrideActivity a,String tag){return a.findViewById(android.R.id.content).findViewWithTag(tag);}
 @Test public void scrolledConnectionTransitionsNeverReplaceThePageOrMoveAnAnchor()throws Exception{
  state("connected");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   final ScrollView[] scroll={null};final View[] quick={null},anchor={null};final int[] baseline={0,0,0},frames={0};final List<String> failures=new ArrayList<>();
   screen.onActivity(a->{scroll[0]=(ScrollView)value(a,"pageScroll");quick[0]=tagged(a,"quick-connection");anchor[0]=a.findViewById(android.R.id.content).findViewWithTag("quick-connection-control");scroll[0].scrollTo(0,48);baseline[0]=scroll[0].getScrollY();assertTrue(baseline[0]>0);int[] xy=new int[2];anchor[0].getLocationOnScreen(xy);baseline[1]=xy[1];baseline[2]=quick[0].getHeight();scroll[0].getViewTreeObserver().addOnPreDrawListener(()->{frames[0]++;if(scroll[0]!=value(a,"pageScroll"))failures.add("ScrollView replaced");if(scroll[0].getScrollY()!=baseline[0])failures.add("Scroll changed to "+scroll[0].getScrollY());anchor[0].getLocationOnScreen(xy);if(xy[1]!=baseline[1])failures.add("Control moved to "+xy[1]);if(quick[0].getHeight()!=baseline[2])failures.add("Quick card resized");return true;});});
   // Real Disconnect tap exercises immediate acknowledgement. Controlled subsequent
   // callbacks cover both directions without starting a transport in this UI fixture.
   onView(withTagValue(is((Object)"quick-connection-control"))).perform(click());
   for(String next:new String[]{"disconnected","connecting","checking","limited","connected","stopping","disconnected"}){
    screen.onActivity(a->{state(next);a.stateChanged();});Thread.sleep(180);
   }
   screen.onActivity(a->call(a,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},hy,false));
   for(String next:new String[]{"connecting","checking","connected"}){screen.onActivity(a->{state(next);a.stateChanged();});Thread.sleep(180);}
   screen.onActivity(a->{assertSame(scroll[0],value(a,"pageScroll"));assertSame(quick[0],tagged(a,"quick-connection"));assertTrue("No rendered transition frames",frames[0]>=8);assertTrue(failures.toString(),failures.isEmpty());});ScreenshotProof.save(c,"home-stable-scrolled-connected");
  }
 }
 @Test public void serverProtocolsOfferDisclosureDirectSettingsAndSeparateServerManagement()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   String tag="server-connections-"+server.get("id");onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));
   onView(withContentDescription("Connect AmneziaWG 3.1 on North station")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));onView(withContentDescription("Connect Hysteria 2 on North station")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));
   screen.recreate();onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));ScreenshotProof.save(c,"home-expanded-protocols");
   onView(allOf(withText("AmneziaWG 3.1"),isDescendantOfA(withTagValue(is((Object)tag))))).perform(scrollTo(),click());
   screen.onActivity(a->{assertEquals("VPN",value(a,"tab"));assertEquals(awg.get("id"),((Gateway)value(a,"selected")).get("id"));});
   onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();
   onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));
   onView(withContentDescription("Settings for Hysteria 2")).perform(scrollTo(),click());
   screen.onActivity(a->{assertEquals("VPN",value(a,"tab"));assertEquals(hy.get("id"),((Gateway)value(a,"selected")).get("id"));});
   onView(withText("Ad blocking")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(c,"home-shortcut-protocol-settings");androidx.test.espresso.Espresso.pressBack();
   onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));
   onView(withContentDescription("Manage North station")).perform(scrollTo(),click());onView(withContentDescription("Rename server")).check(matches(isDisplayed()));onView(withText("Refresh")).check(matches(isDisplayed()));onView(withContentDescription("VPNs")).perform(click());onView(withTagValue(is((Object)tag))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));assertFalse(DeploymentService.active());
   onView(withContentDescription("Servers")).perform(click());onView(withText("Empty station")).perform(scrollTo(),click());onView(withText("Add protocol")).perform(scrollTo()).check(matches(isDisplayed()));
  }
 }
 @Test public void expandedShortcutReflectsActiveStateAndDisconnectsWithoutOpeningAnotherPage()throws Exception{
  state("connected");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Disconnect Hysteria 2 on North station")).perform(scrollTo(),click());screen.onActivity(a->{state("disconnected");a.stateChanged();assertEquals("Home",value(a,"tab"));assertFalse((Boolean)value(a,"busy"));});onView(withContentDescription("Connect Hysteria 2 on North station")).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
  }
 }
 @Test public void onePairConnectionAndBothManagedNodesRemainDistinct()throws Exception{
  Gateway pair=server;pair.set("name","Two stations");pair.set("serverName","North station");pair.set("protocol","awg");pair.set("pairId","fixture-pair");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","naive");pair.data.put("snapshot",new JSONObject().put("services",new JSONObject()));pair.exit=new Gateway();pair.exit.set("host","south.example.net");pair.exit.set("serverName","South station");vault.write(new ArrayList<>(Arrays.asList(pair)));
  Bundle active=new Bundle();active.putString("id",pair.get("id"));active.putString("state","connected");states.put("awg",active);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   for(Gateway node:Arrays.asList(pair)){
    onView(allOf(withContentDescription("Disconnect AmneziaWG 3.1 · Double VPN"),isDescendantOfA(withTagValue(is((Object)("server-connections-"+node.get("id"))))))).perform(scrollTo()).check(matches(isCompletelyDisplayed()));
    onView(allOf(withText("AmneziaWG 3.1"),isDescendantOfA(withTagValue(is((Object)("server-connections-"+node.get("id"))))))).perform(scrollTo(),click());
    screen.onActivity(a->{assertEquals("VPN",value(a,"tab"));assertEquals(pair.get("id"),((Gateway)value(a,"selected")).get("id"));});
    onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();
   }onView(withTagValue(is((Object)("server-connections-"+pair.exit.get("id"))))).check(doesNotExist());onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage North station")).perform(scrollTo()).check(matches(isDisplayed()));onView(withContentDescription("Manage South station")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(c,"home-pair-route-shortcuts");assertFalse(DeploymentService.active());
  }
 }
 @Test public void pairAndExplicitIndependentConnectionsSharePhysicalServersWithoutHidingClients()throws Exception{
  Gateway pair=server;pair.set("name","Two stations");pair.set("serverName","North station");pair.set("protocol","awg");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","naive");pair.data.put("snapshot",new JSONObject().put("services",new JSONObject()));pair.exit=new Gateway();pair.exit.set("host","south.example.net");pair.exit.set("serverName","South station");
  Gateway independent=ServerProtocols.create(pair.exit,SingleProtocols.HYSTERIA2);independent.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));vault.write(new ArrayList<>(Arrays.asList(pair,independent)));
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Connect AmneziaWG 3.1 · Double VPN")).perform(scrollTo()).check(matches(isDisplayed()));
   onView(withContentDescription("Connect Hysteria 2 on South station")).perform(scrollTo()).check(matches(isDisplayed()));
   onView(withContentDescription("Settings for Hysteria 2")).perform(scrollTo(),click());screen.onActivity(a->assertEquals(independent.get("id"),((Gateway)value(a,"selected")).get("id")));
  }
 }
 @Test public void restoredPairRemainsConnectableOfflineWithoutAServerSnapshot()throws Exception{
  Gateway pair=server;pair.set("protocol","awg");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","awg");pair.data.remove("snapshot");pair.data.remove("probe");pair.data.put("pairReady",true);pair.data.put("lastPairedOsOperation",new JSONObject().put("phase","restored"));pair.exit=new Gateway();pair.exit.set("host","exit.example.net");vault.write(new ArrayList<>(Arrays.asList(pair)));c.getSharedPreferences("rookstride-ui",0).edit().putString("lastConnectedId",pair.get("id")).commit();
  org.strongswan.android.rookstride.engine.NativeProfileStore profiles=new org.strongswan.android.rookstride.engine.NativeProfileStore(c);String config="[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51820\n";profiles.save(pair.get("id"),"awg","Saved pair",config);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withTagValue(is((Object)"quick-connection-control"))).check(matches(isDisplayed()));onView(withContentDescription("Connect AmneziaWG 3.1 · Double VPN")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("No VPN connections yet. Set up a VPN or import access shared with you.")).check(doesNotExist());onView(withContentDescription("Settings for AmneziaWG 3.1")).perform(scrollTo(),click());onView(withText("Installation incomplete")).check(doesNotExist());onView(withText("Resume installation")).check(doesNotExist());onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));
  }finally{profiles.remove(pair.get("id"));}
 }
 @Test public void everyProtocolAndPairStageRendersItsOwnIllustration()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   Set<String> seen=new HashSet<>();for(String kind:new String[]{"protocol","pair","single","filter","enroll"}){
    DeploymentService.Session fake=new DeploymentService.Session(hy,vault.read(),kind,new JSONObject(),false,System.currentTimeMillis());InstallationProgress p=fake.progress;for(int i=0;i<p.steps().length;i++){p.stage(i,p.steps()[i]);c.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",p.json().toString()).commit();
     // A real foreground-session fixture prevents interrupted-job recovery semantics.
     session.set(null,fake);
     screen.onActivity(a->{call(a,"openScreen",new Class<?>[]{String.class},"Progress");ImageView image=(ImageView)tagged(a,"installation-rook-"+p.illustration());assertNotNull(p.illustration(),image);assertNotNull(image.getDrawable());assertEquals(View.IMPORTANT_FOR_ACCESSIBILITY_NO,image.getImportantForAccessibility());});if(seen.add(p.illustration()))ScreenshotProof.save(c,"stage-"+p.illustration());
    }
   }assertEquals(14,seen.size());
  }
 }
}
