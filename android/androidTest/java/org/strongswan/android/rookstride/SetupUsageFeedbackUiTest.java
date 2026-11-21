package org.strongswan.android.rookstride;

import android.content.*;
import android.os.SystemClock;
import android.view.View;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.*;
import java.lang.reflect.*;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Real signed UI with documentation-only data and deliberately blocked transports.
 * Never contacts a VPS or starts an installer. Restores the prior catalog/preferences. */
@RunWith(AndroidJUnit4.class)
public class SetupUsageFeedbackUiTest {
    private Context context;private Vault vault;private ArrayList<Gateway> prior;private Gateway server;
    private final Map<String,Map<String,?>> prefs=new HashMap<>();
    private com.jcraft.jsch.SocketFactory originalSockets;
    private CountDownLatch started,release;
    private static Object call(Object target,String method,Class<?>[] types,Object... args)throws Exception{Method m=target.getClass().getDeclaredMethod(method,types);m.setAccessible(true);return m.invoke(target,args);}
    private static Field field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f;}
    private static void set(Object target,String name,Object value)throws Exception{field(target,name).set(target,value);}
    @Before public void setup()throws Exception{
        assertFalse("No real installation may be interrupted",DeploymentService.active());
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);prior=vault.read();originalSockets=Ssh.socketFactory;
        for(String name:new String[]{"rookstride-ui","rookstride-deployment"}){SharedPreferences p=context.getSharedPreferences(name,0);prefs.put(name,new HashMap<>(p.getAll()));p.edit().clear().commit();}
        server=new Gateway();server.set("name","Saved North");server.set("serverName","Saved North");server.set("host","vpn.example.net");server.set("admin","root");server.set("protocol","awg");server.set("fingerprint","fixture-server-pin");server.sshPassword="documentation-only";server.data.put("remember",true).put("saveAccessChosen",true);
        server.data.put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg"))));
        server.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("filtering",new JSONObject().put("installed",true)).put("monitoring_available",true).put("statistics_kind","handshake").put("recent_peers",1).put("connections",new JSONArray().put(new JSONObject().put("user","navid").put("recent",true).put("upload",2000000).put("download",7000000))));
        Gateway imported=new Gateway();imported.set("host","shared.example.net");imported.set("name","Shared access");imported.data.put("clientOnly",true);
        vault.write(new ArrayList<>(Arrays.asList(server,imported)));
    }
    @After public void restore()throws Exception{
        if(release!=null)release.countDown();Ssh.socketFactory=originalSockets;vault.write(prior);
        for(Map.Entry<String,Map<String,?>> p:prefs.entrySet()){
            SharedPreferences.Editor e=context.getSharedPreferences(p.getKey(),0).edit().clear();
            for(Map.Entry<String,?> item:p.getValue().entrySet()){Object v=item.getValue();String k=item.getKey();if(v instanceof String)e.putString(k,(String)v);else if(v instanceof Boolean)e.putBoolean(k,(Boolean)v);else if(v instanceof Integer)e.putInt(k,(Integer)v);else if(v instanceof Long)e.putLong(k,(Long)v);else if(v instanceof Float)e.putFloat(k,(Float)v);else if(v instanceof Set)e.putStringSet(k,new HashSet<>((Set<String>)v));}
            assertTrue(e.commit());
        }
        assertFalse(DeploymentService.active());
    }
    private void blockSsh(){
        started=new CountDownLatch(1);release=new CountDownLatch(1);
        Ssh.socketFactory=new com.jcraft.jsch.SocketFactory(){
            public Socket createSocket(String host,int port)throws IOException{started.countDown();try{release.await(30,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}throw new IOException("Local UI transport fixture ended");}
            public InputStream getInputStream(Socket socket)throws IOException{throw new IOException("No fixture network socket");}
            public OutputStream getOutputStream(Socket socket)throws IOException{throw new IOException("No fixture network socket");}
        };
    }
    private void open(ActivityScenario<RookstrideActivity> screen,String route)throws Exception{
        screen.onActivity(a->{try{set(a,"selected",server);if(route.equals("Sessions"))set(a,"statisticsPaused",true);call(a,"openScreen",new Class[]{String.class},route);if(route.equals("Sessions")){set(a,"statisticsPaused",true);}}catch(Exception e){throw new AssertionError(e);}});
    }
    @Test public void savedServerChoiceReusesInstalledConnectionAndExcludesImportedAccess()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"Setup");onView(withText("Single-server VPN")).perform(scrollTo(),click());onView(withContentDescription("Choose AmneziaWG 3.1")).perform(scrollTo(),click());
            onView(withText("Use a saved server")).perform(scrollTo(),click());onView(withTagValue(is((Object)("saved-single-server-"+server.get("id"))))).check(matches(isDisplayed()));onView(withText(containsString("shared.example.net"))).check(doesNotExist());
            onView(withTagValue(is((Object)("saved-single-server-"+server.get("id"))))).perform(click());onView(withText("VPN users")).perform(scrollTo()).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
            ArrayList<Gateway> saved=vault.read();Gateway retained=null;int owned=0;for(Gateway n:saved)if(!n.data.optBoolean("clientOnly")&&n.get("host").equals("vpn.example.net")){owned++;retained=n;}assertEquals(1,owned);assertNotNull(retained);assertEquals("fixture-server-pin",retained.get("fingerprint"));assertEquals("documentation-only",retained.sshPassword);
            ScreenshotProof.save(context,"alpha6-saved-server-installed");
        }
    }
    @Test public void savedServerNewProtocolImmediatelyShowsFullCheckAndSurvivesInterruptedRecreation()throws Exception{
        blockSsh();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"Setup");onView(withText("Single-server VPN")).perform(scrollTo(),click());onView(withContentDescription("Choose OpenVPN")).perform(scrollTo(),click());onView(withText("Use a saved server")).perform(scrollTo(),click());onView(withTagValue(is((Object)("saved-single-server-"+server.get("id"))))).perform(click());assertTrue(started.await(5,TimeUnit.SECONDS));
            onView(withText("Checking your servers")).check(matches(isDisplayed()));onView(withText("Choose your setup")).check(doesNotExist());onView(withTagValue(is((Object)"setup-server-check"))).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
            ArrayList<Gateway> saved=vault.read();Gateway newProtocol=ServerProtocols.find(saved,saved.get(0),"openvpn");assertNotNull(newProtocol);assertEquals("fixture-server-pin",newProtocol.get("fingerprint"));assertEquals("documentation-only",newProtocol.sshPassword);
            ScreenshotProof.save(context,"alpha6-single-server-check");screen.recreate();onView(withText("Choose your setup")).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
        }
    }
    @Test public void doubleVpnPreflightShowsTargetsAndReturnsFromJournalWithoutStartingInstall()throws Exception{
        started=new CountDownLatch(1);release=new CountDownLatch(1);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(a->{try{Gateway pair=PairNodes.copy(server);pair.exit=PairNodes.copy(server);pair.exit.set("id","exit-fixture");pair.exit.set("host","exit.example.net");pair.exit.set("serverName","Saved South");Class<?> source=field(a,"pairReviewSource").getType();Object fake=Proxy.newProxyInstance(source.getClassLoader(),new Class[]{source},(p,m,args)->{started.countDown();release.await(30,TimeUnit.SECONDS);throw new IOException("Local review fixture ended");});set(a,"pairReviewSource",fake);call(a,"openScreen",new Class[]{String.class},"Setup");call(a,"reviewPairChange",new Class[]{Gateway.class,boolean.class},pair,false);}catch(Exception e){throw new AssertionError(e);}});
            assertTrue(started.await(5,TimeUnit.SECONDS));onView(withText("Checking your servers")).check(matches(isDisplayed()));onView(withText("Entry · Saved North")).check(matches(isDisplayed()));onView(withText("Exit · Saved South")).check(matches(isDisplayed()));onView(withText("Your installation plan")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"alpha6-pair-server-check");
            onView(withContentDescription("Journal")).perform(click());onView(withContentDescription("View installation progress")).perform(click());onView(withText("Checking your servers")).perform(scrollTo()).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
            release.countDown();Thread.sleep(400);final String[] elapsed={null};screen.onActivity(a->{try{assertFalse(field(a,"busy").getBoolean(a));elapsed[0]=(String)call(a,"setupCheckElapsedCopy",new Class[]{});}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(1100);screen.onActivity(a->{try{assertEquals(elapsed[0],call(a,"setupCheckElapsedCopy",new Class[]{}));}catch(Exception e){throw new AssertionError(e);}});
        }
    }
    @Test public void ikeUsageShowsMonthlyOfflineTotalsSeparatelyFromLiveBytes()throws Exception{
        server.set("protocol","ikev2");server.data.put("snapshot",new JSONObject().put("services",new JSONObject()).put("statistics_enabled",true).put("monitoring_available",true).put("monthly",new JSONArray().put(new JSONObject().put("user","mina").put("upload",3000000).put("download",9000000))).put("connections",new JSONArray().put(new JSONObject().put("user","navid").put("upload",1000000).put("download",2000000).put("age",3600).put("id","session-fixture"))));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"Sessions");onView(allOf(withText("Uploaded · 3.0 MB"),isDescendantOfA(withTagValue(is((Object)"usage-totals-This month"))))).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("mina")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Current connections")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Connected for 1h 0m · session session-fixture")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"alpha6-ike-usage");
        }
    }
    @Test public void nativeUsageHasExplicitTransferLabelsAndUsersRefreshIsNamedCorrectly()throws Exception{
        server.data.getJSONObject("snapshot").put("users",new JSONArray().put(new JSONObject().put("login","navid")));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"Sessions");onView(withTagValue(is((Object)"usage-totals-Reported traffic"))).perform(scrollTo()).check(matches(isDisplayed()));onView(allOf(withText("Downloaded · 7.0 MB"),isDescendantOfA(withTagValue(is((Object)"usage-totals-Reported traffic"))))).perform(scrollTo()).check(matches(isDisplayed()));open(screen,"People");onView(withText("Refresh users")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Refresh access")).check(doesNotExist());blockSsh();onView(withText("Refresh users")).perform(scrollTo(),click());assertTrue(started.await(5,TimeUnit.SECONDS));onView(withText("Checking your servers")).check(doesNotExist());
        }
    }
    @Test public void missingTransferCountersStayUnavailableRatherThanInventingZero()throws Exception{
        server.data.getJSONObject("snapshot").getJSONArray("connections").getJSONObject(0).put("upload",JSONObject.NULL).put("download",JSONObject.NULL);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"Sessions");onView(allOf(withText("Upload total unavailable"),isDescendantOfA(withTagValue(is((Object)"usage-totals-Reported traffic"))))).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Uploaded · 0.0 KB")).check(doesNotExist());
        }
    }
    @Test public void adBlockingTapGetsImmediateLocalTimerWithoutOtherModulesLoading()throws Exception{
        blockSsh();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            open(screen,"VPN");onView(withText("Ad blocking")).perform(scrollTo(),click());assertTrue(started.await(5,TimeUnit.SECONDS));onView(withTagValue(is((Object)"module-wait-time"))).check(matches(withText(startsWith("Loading · ")))).check(matches(isDisplayed()));
            screen.onActivity(a->{try{set(a,"moduleWaitStarted",SystemClock.elapsedRealtime()-18000);}catch(Exception e){throw new AssertionError(e);}});Thread.sleep(1200);onView(withTagValue(is((Object)"module-wait-time"))).check(matches(withText(startsWith("Waiting · ")))).check(matches(isDisplayed()));onView(withTagValue(is((Object)"module-VPN users"))).check(matches(withContentDescription("VPN users")));onView(withTagValue(is((Object)"module-Usage"))).check(matches(withContentDescription("Usage")));ScreenshotProof.save(context,"alpha6-adblock-wait");assertFalse(DeploymentService.active());
        }
    }
}
