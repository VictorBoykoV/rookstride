package org.strongswan.android.rookstride;

import android.content.*;
import android.os.*;
import android.view.*;
import android.webkit.WebView;
import android.widget.*;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Local UI/SSH-response fixtures. These cases do not claim a real server tunnel. */
@RunWith(AndroidJUnit4.class) public class RefinedNavigationUiTest {
 RookstrideActivity statisticsActivity;Context c;Vault vault;ArrayList<Gateway> old;Gateway node;String priorProgress;
 static Field field(Object a,String name)throws Exception{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f;}
 static Object invoke(Object a,String name,Class<?>[] types,Object...args)throws Exception{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(a,args);}
 static JSONObject snapshot(int counter)throws Exception{JSONArray peers=new JSONArray();for(int i=0;i<5;i++)peers.put(new JSONObject().put("user","User "+i).put("recent",true).put("upload",counter*2000000L).put("download",counter*4000000L));return new JSONObject().put("users",new JSONArray()).put("services",new JSONObject().put("protocol",true)).put("filtering",new JSONObject().put("installed",true)).put("monitoring_available",true).put("recent_peers",5).put("connections",peers);}
 @Before public void fixture()throws Exception{
  c=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(c);old=vault.read();node=new Gateway();node.set("host","vpn.example.net");node.set("name","Test server");node.set("serverName","Test server");node.set("admin","root");node.set("protocol","awg");node.sshPassword="documentation-only";node.set("fingerprint","documentation-pin");node.data.put("remember",true);node.data.put("checkedAt",System.currentTimeMillis());node.data.put("snapshot",snapshot(1));ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);for(int i=0;i<6;i++){Gateway other=new Gateway();other.set("name","Extra server "+i);other.set("host","extra"+i+".example.net");nodes.add(other);}vault.write(nodes);priorProgress=c.getSharedPreferences("rookstride-deployment",0).getString("progress",null);c.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();c.getSharedPreferences("rookstride-ui",0).edit().remove("activityHistory").remove("activityUnread").remove("lastConnectedId").commit();new java.io.File(c.getNoBackupFilesDir(),"app-routing.json").delete();
 }
 @After public void restore()throws Exception{vault.write(old);c.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",priorProgress).commit();new java.io.File(c.getNoBackupFilesDir(),"app-routing.json").delete();}
 interface Reader {JSONObject read()throws Exception;}
 void statistics(ActivityScenario<RookstrideActivity> screen,Reader reader){statistics(screen,reader,true);}
 void statistics(ActivityScenario<RookstrideActivity> screen,Reader reader,boolean automatic){screen.onActivity(a->{try{statisticsActivity=a;Class<?> type=Class.forName("org.strongswan.android.ui.RookstrideActivity$StatisticsSource");field(a,"statisticsSource").set(a,Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},(proxy,method,args)->reader.read()));field(a,"selected").set(a,node);invoke(a,"openScreen",new Class<?>[]{String.class},"Sessions");if(!automatic)field(a,"statisticsPaused").setBoolean(a,true);}catch(Exception e){throw new AssertionError(e);}});}
 void waitFor(AtomicInteger value,int target)throws Exception{
  long end=SystemClock.elapsedRealtime()+9000;boolean[] ready={false};
  while(SystemClock.elapsedRealtime()<end){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{try{ready[0]=value.get()>=target&&!field(statisticsActivity,"statisticsLoading").getBoolean(statisticsActivity);}catch(Exception e){throw new AssertionError(e);}});if(ready[0])break;Thread.sleep(50);}
  assertTrue("Statistics callback did not finish",ready[0]);InstrumentationRegistry.getInstrumentation().waitForIdleSync();
 }
 @Test public void repeatingTheActiveVpnTabPreservesTheActualScrolledView()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage server Extra server 5")).perform(scrollTo());final ScrollView[] view={null};final int[] y={0};screen.onActivity(a->{try{view[0]=(ScrollView)field(a,"pageScroll").get(a);y[0]=view[0].getScrollY();assertTrue(y[0]>0);}catch(Exception e){throw new AssertionError(e);}});
   for(int i=0;i<4;i++)onView(withContentDescription("Servers")).perform(click());screen.onActivity(a->{try{assertSame(view[0],field(a,"pageScroll").get(a));assertEquals(y[0],view[0].getScrollY());}catch(Exception e){throw new AssertionError(e);}});ScreenshotProof.save(c,"active-tab-preserves-scroll");
  }
 }
 @Test public void repeatingJournalKeepsThePageInstance()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Journal")).perform(click());final Object[] reader={null};screen.onActivity(a->{try{reader[0]=field(a,"pageScroll").get(a);}catch(Exception e){throw new AssertionError(e);}});for(int i=0;i<4;i++)onView(withContentDescription("Journal")).perform(click());screen.onActivity(a->{try{assertSame(reader[0],field(a,"pageScroll").get(a));}catch(Exception e){throw new AssertionError(e);}});
  }
 }
 @Test public void completedFeedbackExpiresWithoutReplacingThePageAndStaysInActivity()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   final Object[] page={null};screen.onActivity(a->{try{invoke(a,"recordActivity",new Class<?>[]{String.class,Gateway.class},"Server refreshed",node);field(a,"message").set(a,"Server refreshed");invoke(a,"render",new Class<?>[]{});page[0]=field(a,"pageScroll").get(a);}catch(Exception e){throw new AssertionError(e);}});onView(withText("Server refreshed")).check(matches(isDisplayed()));onView(withContentDescription("Dismiss update")).check(doesNotExist());Thread.sleep(4700);onView(withText("Server refreshed")).check(matches(not(isDisplayed())));screen.onActivity(a->{try{assertSame(page[0],field(a,"pageScroll").get(a));}catch(Exception e){throw new AssertionError(e);}});onView(withContentDescription("Activity, new updates")).perform(click());onView(withText("Server refreshed")).check(matches(isDisplayed()));
  }
 }
 @Test public void appPickerIsSearchableBoundedAndCancelKeepsTheDraft()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{invoke(a,"openScreen",new Class<?>[]{String.class},"Routing");}catch(Exception e){throw new AssertionError(e);}});onView(withText("Only selected apps")).perform(click());onView(withTagValue(is((Object)"app-picker-list"))).check(doesNotExist());onView(withTagValue(is((Object)"choose-apps"))).perform(scrollTo(),click());
   onView(withContentDescription("Search apps")).perform(click(),replaceText("settings"),androidx.test.espresso.action.ViewActions.closeSoftKeyboard());onView(withContentDescription("Route app com.android.settings")).perform(click());onView(withText("1 selected")).check(matches(isDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());onView(withText("Choose apps · 0 selected")).check(matches(isDisplayed()));
   onView(withTagValue(is((Object)"choose-apps"))).perform(click());onView(withContentDescription("Search apps")).perform(click(),replaceText("settings"));onView(withText("Done")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(c,"app-picker-with-keyboard");androidx.test.espresso.Espresso.closeSoftKeyboard();onView(withContentDescription("Route app com.android.settings")).perform(click());onView(withText("Done")).perform(click());onView(withText("Save")).perform(scrollTo(),click());assertEquals("only",AppRouting.read(c).mode);assertTrue(AppRouting.read(c).packages.contains("com.android.settings"));screen.recreate();onView(withText("Choose apps · 1 selected")).check(matches(isDisplayed()));ScreenshotProof.save(c,"searchable-app-selection");
  }
 }
 @Test public void statisticsUpdateInPlaceAndStopAfterLeavingTheScreen()throws Exception{
  AtomicInteger reads=new AtomicInteger();try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   statistics(screen,()->snapshot(reads.incrementAndGet()));waitFor(reads,1);onView(withText("User 4")).perform(scrollTo());final ScrollView[] view={null};final int[] y={0};screen.onActivity(a->{try{view[0]=(ScrollView)field(a,"pageScroll").get(a);y[0]=view[0].getScrollY();}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(5600);assertEquals("Statistics must not poll every few seconds",1,reads.get());screen.onActivity(a->{try{field(a,"statisticsAttempt").setLong(a,SystemClock.elapsedRealtime()-300001);((Runnable)field(a,"statisticsTick").get(a)).run();}catch(Exception e){throw new AssertionError(e);}});waitFor(reads,2);screen.onActivity(a->{try{assertSame(view[0],field(a,"pageScroll").get(a));assertEquals(y[0],view[0].getScrollY());assertTrue(node.data.optLong("statisticsCheckedAt")>0);}catch(Exception e){throw new AssertionError(e);}});ScreenshotProof.save(c,"statistics-auto-update");
   onView(withContentDescription("VPNs")).perform(click());int stopped=reads.get();Thread.sleep(5600);assertEquals("Polling continued away from Statistics",stopped,reads.get());assertEquals("Automatic reads should not fill Activity",0,new JSONArray(c.getSharedPreferences("rookstride-ui",0).getString("activityHistory","[]")).length());
  }
 }
 @Test public void aLateStatisticsResponseCannotUpdateAnotherScreen()throws Exception{
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   statistics(screen,()->{entered.countDown();if(!release.await(15,TimeUnit.SECONDS))throw new Exception("Fixture timeout");return snapshot(999);});assertTrue(entered.await(8,TimeUnit.SECONDS));onView(withContentDescription("VPNs")).perform(click());release.countDown();Thread.sleep(500);screen.onActivity(a->{try{assertEquals("Home",field(a,"tab").get(a));assertFalse(node.data.has("statisticsCheckedAt"));assertFalse(field(a,"statisticsLoading").getBoolean(a));}catch(Exception e){throw new AssertionError(e);}});
  }finally{release.countDown();}
 }
 @Test public void manualStatisticsRefreshUsesTheCorrectActivityName()throws Exception{
  AtomicInteger reads=new AtomicInteger();try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   statistics(screen,()->snapshot(reads.incrementAndGet()),false);screen.onActivity(a->{try{invoke(a,"refreshStatistics",new Class<?>[]{boolean.class},true);}catch(Exception e){throw new AssertionError(e);}});waitFor(reads,1);onView(withText("Statistics refreshed")).check(matches(isDisplayed()));JSONArray events=new JSONArray(c.getSharedPreferences("rookstride-ui",0).getString("activityHistory","[]"));assertEquals("Statistics refreshed",events.getJSONObject(0).getString("title"));onView(withText("Protocol refreshed")).check(doesNotExist());
  }
 }
 @Test public void statisticsPauseInBackgroundAndResumeOnReturn()throws Exception{
  AtomicInteger reads=new AtomicInteger();try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   statistics(screen,()->snapshot(reads.incrementAndGet()));waitFor(reads,1);screen.moveToState(Lifecycle.State.CREATED);int paused=reads.get();Thread.sleep(5600);assertEquals(paused,reads.get());screen.moveToState(Lifecycle.State.RESUMED);Thread.sleep(1200);assertEquals("A short background visit should keep the recent snapshot",paused,reads.get());screen.onActivity(a->{try{field(a,"statisticsAttempt").setLong(a,SystemClock.elapsedRealtime()-300001);((Runnable)field(a,"statisticsTick").get(a)).run();}catch(Exception e){throw new AssertionError(e);}});waitFor(reads,paused+1);onView(withText("Connection statistics")).check(matches(isDisplayed()));
  }
 }
 @Test public void failedStatisticsKeepTheSnapshotWithoutRepeatedDialogsAndCanRetry()throws Exception{
  AtomicInteger reads=new AtomicInteger();AtomicBoolean fail=new AtomicBoolean(true);try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   statistics(screen,()->{reads.incrementAndGet();if(fail.get())throw new java.io.IOException("Fixture unavailable");return snapshot(2);});waitFor(reads,1);Thread.sleep(300);onView(withText("User 0")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Action needs attention")).check(doesNotExist());screen.onActivity(a->{try{assertTrue(field(a,"statisticsPaused").getBoolean(a));assertFalse(node.data.has("statisticsCheckedAt"));}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(5600);assertEquals(1,reads.get());fail.set(false);screen.onActivity(a->{try{invoke(a,"refreshStatistics",new Class<?>[]{boolean.class},true);}catch(Exception e){throw new AssertionError(e);}});waitFor(reads,2);onView(withText("Statistics refreshed")).check(matches(isDisplayed()));
  }
 }
 @Test public void protocolToolsAndFilteringSelectionAreExplicit()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{field(a,"selected").set(a,node);invoke(a,"openScreen",new Class<?>[]{String.class},"VPN");}catch(Exception e){throw new AssertionError(e);}});for(String label:new String[]{"VPN users","Logs","Usage","Ad blocking","About this protocol"})onView(withText(label)).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("VPN users")).perform(scrollTo());screen.onActivity(a->{ViewGroup tools=a.findViewById(android.R.id.content).findViewWithTag("protocol-tools");for(int i=0;i<tools.getChildCount();i++){ViewGroup row=(ViewGroup)tools.getChildAt(i);assertEquals(row.getChildAt(0).getHeight(),row.getChildAt(1).getHeight());for(int k=0;k<row.getChildCount();k++)assertTrue("Protocol tool clipped by its row",row.getChildAt(k).getBottom()<=row.getHeight());}});ScreenshotProof.save(c,"protocol-tools");onView(withText("VPN users")).perform(click());onView(withText("Add new user")).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();onView(withText("Protocol settings")).check(doesNotExist());onView(withText("This phone’s profile")).check(doesNotExist());onView(withText("Uninstall this protocol")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("About this protocol")).perform(scrollTo()).check(matches(isDisplayed()));
   JSONObject response=new JSONObject().put("blocked",12).put("queries",100).put("protection_enabled",true).put("filters",new JSONArray().put(new JSONObject().put("name","HaGeZi Multi PRO").put("enabled",true).put("rules",1000)));
   screen.onActivity(a->{try{invoke(a,"showAdguard",new Class<?>[]{Gateway.class,JSONObject.class},node,response);}catch(Exception e){throw new AssertionError(e);}});onView(withText("Strong  ✓ Selected")).perform(scrollTo()).check(matches(isDisplayed()));onView(withTagValue(is((Object)"filter-preset-strong"))).check(matches(isSelected()));onView(allOf(withText("Details"),isDescendantOfA(withTagValue(is((Object)"filter-preset-strong"))))).perform(scrollTo(),click());onView(withText("Strong blocking")).check(matches(isDisplayed()));onView(withText("Official details")).check(matches(isCompletelyDisplayed()));onView(withText("Close")).perform(click());ScreenshotProof.save(c,"ad-blocking-selection");
  }
 }
}
