package org.strongswan.android.rookstride;

import android.content.*;
import android.os.*;
import android.view.*;
import android.webkit.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.action.*;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeVpn;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Real phone journeys with documentation fixtures. No operator VPS is contacted. */
@RunWith(AndroidJUnit4.class)
public class PhoneFeedbackUiTest {
 private Context context;private Vault vault;private ArrayList<Gateway> before;private Gateway one,two,awg;private String oldProgress;
 private final Map<String,String> prefs=new HashMap<>();private boolean hadSaved;
 private Object oldEngine,oldSession;private Field engine,current;private Map<String,Bundle> states;private Bundle oldAwg;
 @Before public void fixture()throws Exception{
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);before=vault.read();
  SharedPreferences ui=context.getSharedPreferences("rookstride-ui",0);hadSaved=ui.getBoolean("hasSavedVpn",false);for(String key:new String[]{"selected","lastConnectedId","seenCompletion"})prefs.put(key,ui.getString(key,null));ui.edit().remove("lastConnectedId").remove("seenCompletion").commit();
  oldProgress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
  one=new Gateway();one.set("host","one.example.net");one.set("name","First server");one.set("admin","root");one.set("protocol","ikev2");one.data.put("probe",new JSONObject().put("gateway",false).put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg"))));
  two=new Gateway();two.set("host","two.example.net");two.set("name","Second server");two.set("protocol","ikev2");
  awg=ServerProtocols.create(one,SingleProtocols.AWG);awg.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));
  vault.write(new ArrayList<>(Arrays.asList(one,awg,two)));
  engine=DeploymentService.class.getDeclaredField("engine");engine.setAccessible(true);oldEngine=engine.get(null);current=DeploymentService.class.getDeclaredField("current");current.setAccessible(true);oldSession=current.get(null);current.set(null,null);
  Field errors=NativeVpn.class.getDeclaredField("errors");errors.setAccessible(true);states=(Map<String,Bundle>)errors.get(null);oldAwg=states.get("awg");states.remove("awg");
 }
 @After public void restore()throws Exception{
  engine.set(null,oldEngine);current.set(null,oldSession);if(oldAwg==null)states.remove("awg");else states.put("awg",oldAwg);vault.write(before);
  SharedPreferences.Editor edit=context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",hadSaved);for(Map.Entry<String,String> p:prefs.entrySet())edit.putString(p.getKey(),p.getValue());edit.commit();context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();
 }
 private Object invoke(RookstrideActivity a,String name,Class<?>[] types,Object...args){try{Method m=RookstrideActivity.class.getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(a,args);}catch(Exception e){throw new AssertionError(e);}}
 private void state(String status){Bundle b=new Bundle();b.putString("id",awg.get("id"));b.putString("state",status);states.put("awg",b);}
 private org.hamcrest.Matcher<View> quickText(String text){return allOf(withText(text),isDescendantOfA(withTagValue(is((Object)("quick-card-"+awg.get("id"))))),isDisplayed());}
 @Test public void homeShowsTheActiveConnectionAndThenTheLastConnectedVpn()throws Exception{
  state("connected");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withTagValue(is((Object)"quick-connection"))).check(matches(isDisplayed()));onView(quickText("Connected")).check(matches(isDisplayed()));onView(quickText("AmneziaWG 3.1")).check(matches(isDisplayed()));onView(quickText("Disconnect")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"home-active-vpn");
   onView(quickText("Disconnect")).perform(click());screen.onActivity(a->invoke(a,"render",new Class<?>[]{}));onView(quickText("Recent connection")).check(matches(isDisplayed()));onView(quickText("Connect")).check(matches(isCompletelyDisplayed()));screen.recreate();onView(quickText("Recent connection")).check(matches(isDisplayed()));
  }
 }
 @Test public void limitedVpnOffersDisconnectAndNeverClaimsVerifiedInternet()throws Exception{
  state("limited");try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(allOf(quickText("Check internet"),withTagValue(is((Object)"quick-connection-status")))).check(matches(withContentDescription("VPN on · Check web access")));
   onView(quickText("Disconnect")).check(matches(isCompletelyDisplayed())).check(matches(withContentDescription(containsString("VPN on · Check web access"))));onView(quickText("Connected")).check(doesNotExist());
   assertEquals("A web-check warning must not promote the tunnel to verified connectivity","limited",NativeVpn.status(context,"awg").state);assertTrue("The limited tunnel must remain available to disconnect",NativeVpn.status(context,"awg").active(awg.get("id")));
   onView(withTagValue(is((Object)("quick-card-"+awg.get("id"))))).perform(scrollTo(),click());onView(withText("Disconnect")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).check(doesNotExist());onView(withText("Connected")).check(doesNotExist());onView(withText("The VPN is on, but website access is not confirmed. Try a website or check again.")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Check web access again")).perform(scrollTo()).check(matches(isDisplayed()));
  }
 }
 @Test public void failedNativeConnectionOffersDismissibleTypedHelpAndReviewedSafeReport()throws Exception{
  state("failed");states.get("awg").putString("diagnostic",VpnDiagnosis.of("vpn_auth_rejected").observation().put("password","private-fixture-secret").put("server","sensitive.example.net").toString());
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Settings for AmneziaWG 3.1")).perform(scrollTo(),click());
   onView(withText("Connection help")).perform(scrollTo(),click());onView(withText("VPN sign-in was rejected")).check(matches(isDisplayed()));onView(withText("Close")).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"native-error-actions");onView(withText("Close")).perform(click());
   onView(withText("VPN sign-in was rejected")).check(doesNotExist());onView(withText("Connection help")).perform(scrollTo(),click());onView(withText("Support report")).perform(scrollTo(),click());
   onView(withText("Review support report")).check(matches(isDisplayed()));final boolean[] previewScrolls={false};onView(withTagValue(is((Object)RookDialogs.BODY_TAG))).check((view,error)->{if(error!=null)throw error;previewScrolls[0]=view.canScrollVertically(1);});if(previewScrolls[0]){onView(withTagValue(is((Object)RookDialogs.BODY_TAG))).perform(swipeUp()).check((view,error)->{if(error!=null)throw error;assertTrue("Report preview did not respond to its scroll gesture",((android.widget.ScrollView)view).getScrollY()>0);});}onView(withText(containsString("vpn_auth_rejected"))).check(matches(previewScrolls[0]?isDisplayed():isCompletelyDisplayed()));ScreenshotProof.save(context,"native-support-report-scroll");onView(withText(containsString("private-fixture-secret"))).check(doesNotExist());onView(withText(containsString("sensitive.example.net"))).check(doesNotExist());
   onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());onView(withText("Connection help")).check(matches(isDisplayed()));
  }
 }
 @Test public void pairServerStatusUpdatesItsButtonWithoutReplacingOrScrollingThePage()throws Exception{
  awg.set("pairEngine","native-v2");awg.set("pairEntryProtocol","awg");awg.set("pairExitProtocol","awg");awg.data.put("pairReady",true);awg.exit=new Gateway();awg.exit.set("host","exit.example.net");vault.write(new ArrayList<>(Arrays.asList(awg)));state("connecting");
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->invoke(a,"openPairServer",new Class<?>[]{Gateway.class,Gateway.class},awg,awg));
   onView(withTagValue(is((Object)"pair-server-connection"))).perform(scrollTo()).check(matches(withText("Cancel")));
   final android.widget.ScrollView[] original={null};final int[] offset={0};final View[] control={null};
   screen.onActivity(a->{try{original[0]=(android.widget.ScrollView)field(a,"pageScroll").get(a);original[0].scrollTo(0,Math.min(original[0].getScrollY()+60,original[0].getChildAt(0).getHeight()-original[0].getHeight()));offset[0]=original[0].getScrollY();control[0]=a.findViewById(android.R.id.content).findViewWithTag("pair-server-connection");}catch(Exception e){throw new AssertionError(e);}});
   for(String[] transition:new String[][]{{"connected","Disconnect"},{"disconnected","Connect"}}){
    screen.onActivity(a->state(transition[0]));long deadline=SystemClock.uptimeMillis()+5000;final boolean[] updated={false};
    while(SystemClock.uptimeMillis()<deadline&&!updated[0]){screen.onActivity(a->updated[0]=transition[1].contentEquals(((android.widget.Button)control[0]).getText()));if(!updated[0])Thread.sleep(100);}
    assertTrue("Pair server did not receive the native status callback",updated[0]);
    screen.onActivity(a->{try{assertSame("Connection change rebuilt the page",original[0],field(a,"pageScroll").get(a));assertEquals("Connection change moved the viewport",offset[0],original[0].getScrollY());assertSame(control[0],a.findViewById(android.R.id.content).findViewWithTag("pair-server-connection"));assertTrue(control[0].isEnabled());}catch(Exception e){throw new AssertionError(e);}});
   }
   ScreenshotProof.save(context,"pair-server-live-connection");
  }
 }
 @Test public void aProtocolInstallsOnTheFirstTapWithoutOptionalIdentityPrompts()throws Exception{
  CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);java.util.concurrent.atomic.AtomicReference<JSONObject> configuration=new java.util.concurrent.atomic.AtomicReference<>();
  engine.set(null,(DeploymentService.Engine)(service,s)->{configuration.set(new JSONObject(s.config.toString()));started.countDown();if(!finish.await(30,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("services",new JSONObject().put("protocol",true));});
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);List<Gateway> nodes=(List<Gateway>)f.get(a);Gateway target=ServerProtocols.create(nodes.get(0),SingleProtocols.XRAY);target.sshPassword="documentation-fixture";target.set("fingerprint","fixture-pin");nodes.add(target);nodes.get(0).data.put("checkedAt",System.currentTimeMillis());invoke(a,"openServer",new Class<?>[]{Gateway.class},nodes.get(0));}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Add protocol")).perform(scrollTo(),click());onView(withText("VLESS · REALITY (TCP)")).perform(scrollTo(),click());onView(withText("Install VPN")).perform(scrollTo(),click());assertTrue(started.await(10,TimeUnit.SECONDS));onView(withText("Installing VPN")).check(matches(isDisplayed()));onView(withText("First device name")).check(doesNotExist());onView(withText("Advanced")).check(doesNotExist());onView(withText("REALITY server name")).check(doesNotExist());assertEquals("this-phone",configuration.get().getString("login"));assertFalse(configuration.get().has("sni"));
   finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);InstrumentationRegistry.getInstrumentation().waitForIdleSync();assertFalse(DeploymentService.active());
   onView(allOf(withTagValue(is((Object)"completion-heading")),withText("VPN installed"),isDisplayed())).check(matches(isCompletelyDisplayed()));onView(withText("Done")).check(matches(isCompletelyDisplayed()));onView(withText("Open VPN")).check(matches(isCompletelyDisplayed()));
   ScreenshotProof.save(context,"completion-top");onView(withText("Read Rook’s stories")).check(doesNotExist());screen.onActivity(a->{View root=a.findViewById(android.R.id.content);View success=root.findViewWithTag("installation-complete");assertNotNull(success);assertTrue(success.isShown());});ScreenshotProof.save(context,"clear-completion");onView(withText("Done")).perform(click());onView(withText("Your VPNs")).check(matches(isDisplayed()));
   boolean completedNotice=false;for(android.service.notification.StatusBarNotification n:context.getSystemService(android.app.NotificationManager.class).getActiveNotifications())if(n.getId()==7352)completedNotice=true;assertTrue("No completion notification",completedNotice);
  }finally{finish.countDown();}
 }
 @Test public void serverWorkIsProminentAndReadOnlyNavigationStillWorks()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Field b=RookstrideActivity.class.getDeclaredField("busy"),m=RookstrideActivity.class.getDeclaredField("message");b.setAccessible(true);m.setAccessible(true);b.setBoolean(a,true);m.set(a,"Checking First server");invoke(a,"render",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withTagValue(is((Object)"server-operation"))).check(matches(isDisplayed()));onView(withText("Checking First server")).check(matches(isDisplayed()));onView(withContentDescription("Server action in progress")).check(matches(isDisplayed()));onView(withText("Add VPN")).check(matches(not(isEnabled())));ScreenshotProof.save(context,"visible-server-work");
   onView(withContentDescription("Journal")).perform(click());onView(withText("A new chapter is coming.")).perform(scrollTo()).check(matches(isDisplayed()));onView(isAssignableFrom(WebView.class)).check(doesNotExist());
  }
 }
 @Test public void helpAndFullLicensesOpenOfflineWithoutLaunchingTheUpstreamClient()throws Exception{
  UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("App settings")).perform(click());onView(withText("Licenses & advanced client settings")).check(doesNotExist());onView(withText("Licensing")).perform(scrollTo(),click());
   assertNotNull("Licensing heading missing",device.wait(Until.findObject(By.text("Licensing")),30000));ScreenshotProof.save(context,"offline-licenses");
   onView(isAssignableFrom(WebView.class)).check(matches(isDisplayed()));
   onView(withContentDescription("Back to Settings")).perform(click());onView(withText("Help & FAQ")).perform(scrollTo(),click());onView(withText("Read technical guide")).perform(scrollTo(),click());assertNotNull("Guide did not open from Help",device.wait(Until.findObject(By.text("Get started")),30000));

  }
 }
 @Test public void incompletePairOnlyOffersThePairResumeAction()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   Gateway pair=new Gateway();pair.set("name","Pair fixture");pair.set("host","entry.example.net");pair.exit=new Gateway();pair.exit.set("host","exit.example.net");
   screen.onActivity(a->invoke(a,"openVpn",new Class<?>[]{Gateway.class},pair));onView(withText("Install VPN")).check(doesNotExist());onView(withText("Resume installation")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));assertFalse(DeploymentService.active());
  }
 }
 @Test public void completeNoticesStreamAndUnlistedPathsNeverReachTheNetwork()throws Exception{
  OfflineDocuments docs=new OfflineDocuments(context);WebResourceResponse response=docs.shouldInterceptRequest(null,request(OfflineDocuments.url("licenses.html")));assertEquals(200,response.getStatusCode());int bytes=0;try(java.io.InputStream in=response.getData()){byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1)bytes+=n;}assertTrue("The license test no longer exceeds the old reader cap",bytes>250000);
  for(String url:new String[]{"file:///etc/passwd","https://evil.example/","https://rookstride.invalid/docs/../licenses.html","https://rookstride.invalid/docs/%6cicenses.html","https://rookstride.invalid/docs/licenses.html?remote=1"})assertEquals(404,docs.shouldInterceptRequest(null,request(url)).getStatusCode());
 }
 private WebResourceRequest request(String url){return new WebResourceRequest(){public android.net.Uri getUrl(){return android.net.Uri.parse(url);}public boolean isForMainFrame(){return true;}public boolean isRedirect(){return false;}public boolean hasGesture(){return false;}public String getMethod(){return "GET";}public Map<String,String> getRequestHeaders(){return Collections.emptyMap();}};}
 @Test public void aLongHoldReordersServersAndAShortSwipeDoesNotRevealDelete()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());
   onView(withContentDescription("Manage server First server")).perform(scrollTo(),new androidx.test.espresso.action.GeneralSwipeAction(Swipe.SLOW,view->coordinates(view,.85f,.5f),view->coordinates(view,.65f,.5f),Press.FINGER));onView(withContentDescription("Delete First server")).check(matches(not(isDisplayed())));
   onView(allOf(withText("Second server"),isDescendantOfA(withContentDescription("Manage server Second server")))).perform(scrollTo());
   final float[][] points=new float[2][];screen.onActivity(a->{View root=a.findViewById(android.R.id.content);View first=find(root,"Manage server First server"),second=find(root,"Manage server Second server");assertNotNull(first);assertNotNull(second);android.graphics.Rect visible=new android.graphics.Rect(),viewport=new android.graphics.Rect();assertTrue(first.getGlobalVisibleRect(visible));points[0]=new float[]{visible.exactCenterX(),visible.exactCenterY()};try{((View)field(a,"pageScroll").get(a)).getGlobalVisibleRect(viewport);}catch(Exception e){throw new AssertionError(e);}points[1]=coordinates(second,.5f,.8f);points[1][1]=Math.min(points[1][1],viewport.bottom-12*first.getResources().getDisplayMetrics().density);});
   android.app.Instrumentation instrumentation=InstrumentationRegistry.getInstrumentation();long down=SystemClock.uptimeMillis();pointer(instrumentation,down,MotionEvent.ACTION_DOWN,points[0][0],points[0][1]);Thread.sleep(ViewConfiguration.getLongPressTimeout()+250);
   screen.onActivity(a->{View first=find(a.findViewById(android.R.id.content),"Manage server First server");assertNotNull(a.findViewById(android.R.id.content).findViewWithTag("server-insertion-space"));assertFalse(((SwipeRevealLayout)first.getParent()).isRevealed());assertTrue("Long hold did not start server reordering",first.isActivated());View root=a.findViewById(android.R.id.content).getRootView();invoke(a,"render",new Class<?>[]{});assertSame("Status redraw replaced the active drag list",first,find(a.findViewById(android.R.id.content),"Manage server First server"));});
   for(int i=1;i<=15;i++){pointer(instrumentation,down,MotionEvent.ACTION_MOVE,points[0][0],points[0][1]+(points[1][1]-points[0][1])*i/15);Thread.sleep(25);}
   for(int extra=0;extra<30;extra++){final boolean[] moved={false};screen.onActivity(a->{View first=find(a.findViewById(android.R.id.content),"Manage server First server"),second=find(a.findViewById(android.R.id.content),"Manage server Second server");ViewGroup list=(ViewGroup)first.getParent().getParent();moved[0]=list.indexOfChild((View)second.getParent())<list.indexOfChild((View)first.getParent());});if(moved[0])break;pointer(instrumentation,down,MotionEvent.ACTION_MOVE,points[1][0]+extra%2,points[1][1]);Thread.sleep(40);}
   screen.onActivity(a->{View first=find(a.findViewById(android.R.id.content),"Manage server First server"),second=find(a.findViewById(android.R.id.content),"Manage server Second server");ViewGroup list=(ViewGroup)first.getParent().getParent();assertTrue("Live gap did not move before release",list.indexOfChild((View)second.getParent())<list.indexOfChild((View)first.getParent()));});ScreenshotProof.save(context,"server-live-insertion");pointer(instrumentation,down,MotionEvent.ACTION_UP,points[1][0],points[1][1]);instrumentation.waitForIdleSync();for(int i=0;i<50&&!ServerProtocols.servers(vault.read()).get(0).get("name").equals("Second server");i++)Thread.sleep(100);
   ScreenshotProof.save(context,"server-drop-result");assertEquals("Second server",ServerProtocols.servers(vault.read()).get(0).get("name"));screen.recreate();assertEquals("Second server",ServerProtocols.servers(vault.read()).get(0).get("name"));ScreenshotProof.save(context,"server-reordered");
   onView(withContentDescription("Manage server First server")).perform(scrollTo(),swipeLeft());onView(withContentDescription("Delete First server")).check(matches(isDisplayed()));assertEquals(3,vault.read().size());
  }
 }
 @Test public void completedNoticeExpiresOnHomeAndStaysDismissed()throws Exception{
  InstallationProgress progress=new InstallationProgress("protocol",one.get("id"),System.currentTimeMillis()-60000);progress.finish();context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress.json().toString()).commit();
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withText("Your VPN is installed")).check(matches(isDisplayed()));onView(withContentDescription("Dismiss installation notice")).check(doesNotExist());Thread.sleep(4600);onView(withText("Your VPN is installed")).check(doesNotExist());screen.recreate();onView(withText("Your VPN is installed")).check(doesNotExist());onView(withText("Your VPNs")).check(matches(isDisplayed()));
  }
 }
 @Test public void connectionRequestsImmediatelyAcknowledgeTheTapWithoutClaimingConnected()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);Gateway node=((ArrayList<Gateway>)f.get(a)).get(1);invoke(a,"openServer",new Class<?>[]{Gateway.class},((ArrayList<Gateway>)f.get(a)).get(0));invoke(a,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},node,false);}catch(Exception e){throw new AssertionError(e);}});
   onView(allOf(isAssignableFrom(android.widget.Button.class),anyOf(withText("Connecting…"),withText("Starting")),withContentDescription("Starting, working"))).perform(scrollTo()).check(matches(not(isEnabled()))).check(matches(isDisplayed()));onView(allOf(withText("Connected"),isDisplayed())).check(doesNotExist());
   onView(withContentDescription("Journal")).perform(click());final View[] reader={null};screen.onActivity(a->{try{reader[0]=(View)field(a,"pageScroll").get(a);}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(8500);
   screen.onActivity(a->{try{assertSame("Connection timeout rebuilt the Journal",reader[0],field(a,"pageScroll").get(a));assertNull("Placeholder unexpectedly loaded a remote reader",field(a,"storyView").get(a));}catch(Exception e){throw new AssertionError(e);}});androidx.test.espresso.Espresso.pressBack();
   state("connected");screen.onActivity(a->invoke(a,"render",new Class<?>[]{}));onView(withContentDescription("Disconnect AmneziaWG 3.1")).perform(scrollTo(),click());
   assertFalse("Disconnect tap did not reach the native engine",states.containsKey("awg"));
   long stoppedBy=SystemClock.elapsedRealtime()+5000;while(NativeVpn.status(context,"awg").active(awg.get("id"))&&SystemClock.elapsedRealtime()<stoppedBy)Thread.sleep(50);
   assertFalse("Native disconnect did not finish",NativeVpn.status(context,"awg").active(awg.get("id")));
  }
 }
 @Test public void freshServerNavigationUsesCacheAndRedrawsPreserveScroll()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);Gateway node=((ArrayList<Gateway>)f.get(a)).get(0);node.data.put("checkedAt",System.currentTimeMillis());node.sshPassword="fixture-never-sent";node.set("fingerprint","fixture-pin");node.data.getJSONObject("probe").getJSONObject("inventory").put("installed_protocols",new JSONArray().put("awg").put("openvpn").put("xray").put("xhttp").put("hysteria2").put("naive").put("trusttunnel"));assertFalse((Boolean)invoke(a,"serverCheckDue",new Class<?>[]{Gateway.class},node));invoke(a,"openServer",new Class<?>[]{Gateway.class},node);assertFalse(field(a,"busy").getBoolean(a));}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Add protocol")).perform(scrollTo());final int[] y={0};final View[] old={null};
   screen.onActivity(a->{try{android.widget.ScrollView scroll=(android.widget.ScrollView)field(a,"pageScroll").get(a);scroll.scrollTo(0,10000);y[0]=scroll.getScrollY();old[0]=scroll;assertTrue(y[0]>0);invoke(a,"render",new Class<?>[]{});invoke(a,"render",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});InstrumentationRegistry.getInstrumentation().waitForIdleSync();
   screen.onActivity(a->{try{assertEquals(y[0],((android.widget.ScrollView)field(a,"pageScroll").get(a)).getScrollY());invoke(a,"openScreen",new Class<?>[]{String.class},"ServerSettings");}catch(Exception e){throw new AssertionError(e);}});androidx.test.espresso.Espresso.pressBack();
   screen.onActivity(a->{try{assertEquals(y[0],((android.widget.ScrollView)field(a,"pageScroll").get(a)).getScrollY());Gateway node=((ArrayList<Gateway>)field(a,"gateways").get(a)).get(0);node.data.put("checkedAt",System.currentTimeMillis()-31*60*1000);assertTrue((Boolean)invoke(a,"serverCheckDue",new Class<?>[]{Gateway.class},node));assertFalse("Stale cache started background SSH without an open action",field(a,"busy").getBoolean(a));}catch(Exception e){throw new AssertionError(e);}});ScreenshotProof.save(context,"server-scroll-preserved");
  }
 }
 @Test public void movingAServerKeepsTheSameListAndScrollPosition()throws Exception{
  ArrayList<Gateway> many=vault.read();for(int i=0;i<6;i++){Gateway n=new Gateway();n.set("name","Extra server "+i);n.set("host","extra"+i+".example.net");many.add(n);}vault.write(many);
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   final View[] list={null};final int[] y={0};screen.onActivity(a->{try{android.widget.ScrollView scroll=(android.widget.ScrollView)field(a,"pageScroll").get(a);scroll.scrollTo(0,200);list[0]=scroll;y[0]=scroll.getScrollY();ArrayList<Gateway> nodes=(ArrayList<Gateway>)field(a,"gateways").get(a);invoke(a,"moveServer",new Class<?>[]{Gateway.class,Gateway.class,boolean.class},nodes.get(0),nodes.get(nodes.size()-1),true);}catch(Exception e){throw new AssertionError(e);}});InstrumentationRegistry.getInstrumentation().waitForIdleSync();screen.onActivity(a->{try{assertSame(list[0],field(a,"pageScroll").get(a));assertEquals(y[0],((android.widget.ScrollView)list[0]).getScrollY());}catch(Exception e){throw new AssertionError(e);}});assertEquals("Extra server 5",ServerProtocols.servers(vault.read()).get(6).get("name"));assertEquals("First server",ServerProtocols.servers(vault.read()).get(7).get("name"));
  }
 }
 private Field field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f;}
 @Test public void offlineDocumentsStayInsideTheViewportWithLongExpandedNotices()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   for(String document:new String[]{"app-guide.html","licenses.html","guide-en-full.html"}){
    screen.onActivity(a->invoke(a,"openDocument",new Class<?>[]{String.class},document));
    long deadline=SystemClock.uptimeMillis()+30000;boolean ready=false;
    while(SystemClock.uptimeMillis()<deadline){String result=documentJs(screen,"location.href.endsWith('"+document+"') && document.readyState === 'complete' && !!document.querySelector('h1') && document.documentElement.clientWidth > 0");if(result.equals("true")){ready=true;break;}Thread.sleep(200);}
    assertTrue("Document did not finish loading: "+document,ready);
    documentJs(screen,"(function(){document.querySelectorAll('details').forEach(function(d){d.open=true});var p=document.createElement('p');p.textContent='https://example.net/'+Array(41).join('veryLongLicenseModuleName');document.body.appendChild(p);document.querySelectorAll('summary,.owner').forEach(function(e){e.appendChild(document.createTextNode(' '+Array(21).join('LongAttributionToken')))});return true})()");Thread.sleep(250);
    String dimensionsJson=documentJs(screen,"JSON.stringify({page:document.documentElement.scrollWidth,viewport:document.documentElement.clientWidth,body:document.body.scrollWidth,wrap:getComputedStyle(document.body).wordWrap,mode:document.compatMode,href:location.href})");JSONObject dimensions=new JSONObject(new org.json.JSONTokener(dimensionsJson).nextValue().toString());ScreenshotProof.save(context,"wrapped-"+document.replace(".html",""));assertTrue(document+" overflows: "+dimensions,dimensions.getInt("page")<=dimensions.getInt("viewport")+1);
   }
  }
 }
 // Test-only DOM measurements; the shipped document reader keeps scripting disabled.
 private String documentJs(ActivityScenario<RookstrideActivity> screen,String script)throws Exception{
  CountDownLatch done=new CountDownLatch(1);final String[] value={null};screen.onActivity(a->{WebView web=a.findViewById(android.R.id.content).findViewWithTag("offline-document");assertNotNull(web);web.getSettings().setJavaScriptEnabled(true);web.evaluateJavascript(script,result->{value[0]=result;web.getSettings().setJavaScriptEnabled(false);done.countDown();});});assertTrue("Document renderer did not answer",done.await(10,TimeUnit.SECONDS));return value[0];
 }
 private static float[] coordinates(View view,float x,float y){int[] p=new int[2];view.getLocationOnScreen(p);return new float[]{p[0]+view.getWidth()*x,p[1]+view.getHeight()*y};}
 private static void pointer(android.app.Instrumentation i,long down,int action,float x,float y){MotionEvent e=MotionEvent.obtain(down,SystemClock.uptimeMillis(),action,x,y,0);e.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);assertTrue("Gesture injection failed",i.getUiAutomation().injectInputEvent(e,true));e.recycle();}
 private View find(View v,String description){if(description.contentEquals(v.getContentDescription()==null?"":v.getContentDescription()))return v;if(v instanceof android.view.ViewGroup)for(int i=0;i<((android.view.ViewGroup)v).getChildCount();i++){View match=find(((android.view.ViewGroup)v).getChildAt(i),description);if(match!=null)return match;}return null;}
}
