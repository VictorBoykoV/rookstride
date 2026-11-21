package org.strongswan.android.rookstride;
import android.content.Context;
import android.graphics.Rect;
import android.os.SystemClock;
import android.view.*;
import android.widget.ScrollView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.json.*;
import java.util.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.Espresso.pressBack;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Documentation fixtures only; no submitted SSH/install/reset commands. */
@RunWith(AndroidJUnit4.class)
public class ServerProtocolsUiTest {
    /** Espresso scrollTo accepts ninety-percent visibility. A real horizontal
     * gesture needs the whole collapsed card positioned within this viewport. */
    private void positionWholeCard(String description,String proof)throws Exception{
        onView(withContentDescription(description)).perform(scrollTo());JSONArray observations=new JSONArray();
        for(int attempt=0;attempt<4;attempt++){
            final Rect full=new Rect(),visible=new Rect(),viewport=new Rect();final int[] scroll={0};
            onView(withContentDescription(description)).check((view,error)->{
                if(error!=null)throw error;int[] xy=new int[2];view.getLocationOnScreen(xy);full.set(xy[0],xy[1],xy[0]+view.getWidth(),xy[1]+view.getHeight());assertTrue(view.getGlobalVisibleRect(visible));
                ViewParent parent=view.getParent();while(parent!=null&&!(parent instanceof ScrollView))parent=parent.getParent();assertTrue("Card has no vertical scrolling parent",parent instanceof ScrollView);ScrollView page=(ScrollView)parent;assertTrue(page.getGlobalVisibleRect(viewport));scroll[0]=page.getScrollY();
            });
            observations.put(new JSONObject().put("card",full.flattenToString()).put("visible",visible.flattenToString()).put("viewport",viewport.flattenToString()).put("scroll_y",scroll[0]));
            if(attempt==0)ScreenshotProof.save(context,proof+"-before-positioning");
            if(visible.contains(full)){ScreenshotProof.save(context,proof+"-after-positioning");saveCardGeometry(proof,observations);onView(withContentDescription(description)).check(matches(isCompletelyDisplayed()));return;}
            assertTrue("The collapsed card must fit in the viewport",full.height()<=viewport.height()&&full.width()<=viewport.width());
            assertEquals("A vertical adjustment must not conceal horizontal clipping",full.width(),visible.width());
            if(attempt==3)break;
            float from=viewport.centerY(),distance=full.bottom>viewport.bottom?-(full.bottom-viewport.bottom+32):(viewport.top-full.top+32);
            float to=Math.max(viewport.top+12,Math.min(viewport.bottom-12,from+distance));
            dragCardViewport(viewport.left+12,from,to);
        }
        saveCardGeometry(proof,observations);ScreenshotProof.save(context,proof+"-positioning-failed");onView(withContentDescription(description)).check(matches(isCompletelyDisplayed()));
    }
    private void saveCardGeometry(String proof,JSONArray observations)throws Exception{
        java.nio.file.Files.write(new java.io.File(context.getExternalFilesDir(null),"ui-proof-"+proof+"-geometry.json").toPath(),observations.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    private void dragCardViewport(float x,float from,float to)throws Exception{
        android.app.Instrumentation input=InstrumentationRegistry.getInstrumentation();long down=SystemClock.uptimeMillis();MotionEvent event=MotionEvent.obtain(down,down,MotionEvent.ACTION_DOWN,x,from,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}
        for(int n=1;n<=24;n++){Thread.sleep(18);event=MotionEvent.obtain(down,SystemClock.uptimeMillis(),MotionEvent.ACTION_MOVE,x,from+(to-from)*n/24f,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}}
        Thread.sleep(120);event=MotionEvent.obtain(down,SystemClock.uptimeMillis(),MotionEvent.ACTION_UP,x,to,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}input.waitForIdleSync();Thread.sleep(350);
    }
    @Test public void pencilRenamesEveryProtocolAndSurvivesHomeAndRecreationWithoutServerSignIn()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Manage Server fixture")).perform(scrollTo(),click());onView(withContentDescription("Rename server")).perform(click());onView(withTagValue(is((Object)"Server name"))).perform(replaceText("North bridge"));onView(withText("Cancel")).perform(click());assertEquals("Server fixture",ServerProtocols.name(vault.read().get(0)));
            onView(withContentDescription("Rename server")).perform(click());onView(withTagValue(is((Object)"Server name"))).perform(replaceText(" "));onView(withText("Save")).perform(click());onView(withTagValue(is((Object)"Server name"))).check(matches(hasErrorText("Enter a server name of 1–80 characters.")));
            onView(withTagValue(is((Object)"Server name"))).perform(replaceText("North bridge")).check(matches(withText("North bridge"))).check(matches(not(hasErrorText("Enter a server name of 1–80 characters."))));onView(withText("Save")).perform(click());onView(withTagValue(is((Object)"Server name"))).check(doesNotExist());for(Gateway node:vault.read()){assertEquals("North bridge",ServerProtocols.name(node));assertEquals("vpn.example.net",node.get("host"));assertEquals("fixture-pin",node.get("fingerprint"));}screen.recreate();onView(withContentDescription("Rename server")).check(matches(isDisplayed()));onView(withContentDescription("VPNs")).perform(click());onView(withContentDescription("Hide connections for North bridge")).perform(scrollTo(),click());positionWholeCard("Open North bridge","renamed-card");ScreenshotProof.save(context,"renamed-server-home");
        }
    }
    private Context context;private Vault vault;private ArrayList<Gateway> before;private Gateway ike,awg;private boolean savedBefore;private String selectedBefore;
    @Before public void fixture()throws Exception{
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);before=vault.read();savedBefore=context.getSharedPreferences("rookstride-ui",0).getBoolean("hasSavedVpn",false);selectedBefore=context.getSharedPreferences("rookstride-ui",0).getString("selected",null);
        ike=new Gateway();ike.set("host","vpn.example.net");ike.set("name","Server fixture");ike.set("protocol","ikev2");ike.set("fingerprint","fixture-pin");ike.set("machine","fixture-machine");
        ike.data.put("snapshot",new JSONObject().put("services",new JSONObject()).put("edit_users",true).put("users",new JSONArray().put(new JSONObject().put("login","fixture-user").put("person","Alex").put("device","Phone"))).put("password_policy",new JSONObject().put("minimum",8).put("maximum",15)));
        ike.data.put("probe",new JSONObject().put("gateway",true).put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg"))));
        awg=ServerProtocols.create(ike,SingleProtocols.AWG);awg.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",false)).put("users",new JSONArray()));
        vault.write(new ArrayList<>(Arrays.asList(ike,awg)));
    }
    @After public void restore()throws Exception{vault.write(before);context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",savedBefore).putString("selected",selectedBefore).commit();}
    private void select(ActivityScenario<RookstrideActivity> screen,Gateway node){
        screen.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);List<Gateway> nodes=(List<Gateway>)f.get(a);for(int i=0;i<nodes.size();i++)if(nodes.get(i).get("id").equals(node.get("id")))nodes.set(i,node);java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("openVpn",Gateway.class);m.setAccessible(true);m.invoke(a,node);}catch(Exception e){throw new AssertionError(e);}});
    }
    @Test public void installedProtocolsSelectExistingRecordsAndBackReturnsToTheList()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText(awg.get("name"))).check(doesNotExist());onView(withContentDescription("Manage Server fixture")).perform(scrollTo(),click());
            onView(withText("VPN protocols")).perform(scrollTo()).check(matches(isDisplayed()));
            for(int i=0;i<2;i++){
                onView(allOf(withText("AmneziaWG 3.1"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo(),click());onView(allOf(withText("AmneziaWG 3.1"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).check(matches(isDisplayed()));
                pressBack();onView(allOf(withText("IKEv2"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo(),click());onView(allOf(withText("IKEv2"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).check(matches(isDisplayed()));pressBack();
            }
            screen.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("gateways");f.setAccessible(true);assertEquals(2,((List<?>)f.get(a)).size());}catch(Exception e){throw new AssertionError(e);}});
            screen.recreate();onView(withText("Refresh")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"server-protocol-groups");
        }
    }
    @Test public void nativeFilteringCanBeAddedLaterWithoutAnAccountOrServerReset()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            awg.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("filtering",new JSONObject().put("installed",false).put("running",false)));
            select(screen,awg);onView(withText("Ad blocking")).perform(scrollTo(),click());
            onView(withText("Enable ad blocking?")).check(matches(isDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());assertFalse(DeploymentService.active());
            awg.data.getJSONObject("snapshot").put("filtering",new JSONObject().put("installed",true).put("running",true));select(screen,awg);onView(withText("Ad blocking")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Enable ad blocking for this protocol")).check(doesNotExist());onView(withText("Shared ad blocking settings")).check(doesNotExist());screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("openServer",Gateway.class);m.setAccessible(true);m.invoke(a,awg);}catch(Exception e){throw new AssertionError(e);}});onView(withText("Maintenance")).perform(scrollTo(),click());onView(withText("Shared ad blocking settings")).check(doesNotExist());onView(withContentDescription("Expand Access & administrators")).perform(scrollTo(),click());onView(withText("Administrator access")).perform(scrollTo()).check(matches(isDisplayed()));assertEquals(2,vault.read().size());
        }
    }
    @Test public void nativeBackgroundChoiceIsOptionalAndItsActionsRemainVisible()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("nativeBatteryChoice",Gateway.class);m.setAccessible(true);m.invoke(a,awg);}catch(Exception e){throw new AssertionError(e);}});
            for(String label:new String[]{"Cancel","Connect now","Allow background"})onView(withText(label)).check(matches(isCompletelyDisplayed()));
            onView(withText("Cancel")).perform(click());assertEquals(2,vault.read().size());
        }
    }
    @Test public void emptyServerInventoryClearsInstalledStateAndKeepsTheServer()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Manage Server fixture")).perform(scrollTo(),click());
            screen.onActivity(a->{try{
                java.lang.reflect.Field field=RookstrideActivity.class.getDeclaredField("gateways");field.setAccessible(true);List<Gateway> nodes=(List<Gateway>)field.get(a);Gateway root=nodes.get(0);
                JSONObject inventory=new JSONObject().put("installed_protocols",new JSONArray()).put("installed_instances",new JSONObject());JSONObject probe=new JSONObject().put("gateway",false).put("inventory",inventory);
                java.lang.reflect.Method method=RookstrideActivity.class.getDeclaredMethod("reconcileServerInventory",Gateway.class,JSONObject.class,JSONObject.class);method.setAccessible(true);method.invoke(a,root,probe,inventory);
                for(Gateway node:nodes){assertFalse(node.data.has("snapshot"));assertEquals("",node.get("profileUuid"));assertEquals("",node.get("vpnLogin"));}
                java.lang.reflect.Method render=RookstrideActivity.class.getDeclaredMethod("render");render.setAccessible(true);render.invoke(a);
            }catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Installed")).check(doesNotExist());onView(withText("No VPN protocols installed. Add one to start connecting and sharing access.")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Add protocol")).perform(scrollTo()).check(matches(isDisplayed()));onView(allOf(withText("Server fixture"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo()).check(matches(isDisplayed()));
        }
    }
    @Test public void serverSettingsContainOnlyServerActionsAndExplainTheOsRebuild()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Manage Server fixture")).perform(scrollTo(),click());onView(withText("Maintenance")).perform(scrollTo(),click());
            onView(withText("Uninstall this protocol")).check(doesNotExist());onView(withContentDescription("Expand Remove or rebuild")).perform(scrollTo(),click());onView(withText("Remove VPN setups")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Wipe server & reinstall Ubuntu")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Remove server from this phone")).perform(scrollTo(),click());onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());
        }
    }
    @Test public void swipeRevealsServerTrashAndConfirmationRemovesEveryLocalProtocol()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Delete Server fixture")).check(matches(org.hamcrest.Matchers.not(isDisplayed())));
            onView(withContentDescription("Hide connections for Server fixture")).perform(scrollTo(),click());
            positionWholeCard("Open Server fixture","swipe-card");onView(withContentDescription("Open Server fixture")).perform(swipeLeft());
            onView(withContentDescription("Delete Server fixture")).check(matches(isDisplayed())).perform(click());
            assertEquals("Swipe must not delete",2,vault.read().size());onView(withText("Cancel")).perform(click());assertEquals(2,vault.read().size());
            onView(withContentDescription("Delete Server fixture")).perform(click());onView(withText("Continue")).perform(click());assertTrue(vault.read().isEmpty());onView(withText("Add VPN")).check(matches(isDisplayed()));
        }
    }
    @Test public void accountsOfferDirectEditAndConfirmedSwipeDeletion()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            select(screen,ike);onView(withText("VPN users")).perform(scrollTo(),click());onView(withText("Edit")).perform(scrollTo(),click());
            onView(withText("Edit account")).check(matches(isDisplayed()));onView(withText("Save")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).perform(click());
            onView(withContentDescription("fixture-user")).perform(scrollTo(),swipeLeft());onView(withContentDescription("Delete fixture-user")).perform(click());
            onView(withText("Delete account?")).check(matches(isDisplayed()));onView(withText("Cancel")).perform(click());assertEquals(2,vault.read().size());
        }
    }
    @Test public void allProtocolReviewKeepsActionsVisibleAndRequiresTheCheckbox()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            JSONObject plan=new JSONObject().put("scope","Remove the four owned VPNs, connection keys and account data. Ubuntu, SSH and unrelated applications stay.").put("protocols",new JSONArray().put("ikev2").put("awg").put("xray").put("openvpn"));
            screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("reviewServerReset",Gateway.class,JSONObject.class);m.setAccessible(true);m.invoke(a,ike,plan);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Remove")).check(matches(isCompletelyDisplayed())).check(matches(org.hamcrest.Matchers.not(isEnabled())));onView(isAssignableFrom(android.widget.EditText.class)).check(doesNotExist());onView(withText("I understand that affected users will lose access.")).perform(scrollTo(),click());onView(withText("Remove")).check(matches(isEnabled()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());assertEquals(2,vault.read().size());
        }
    }
    private void route(ActivityScenario<RookstrideActivity> screen,String name){screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("openScreen",String.class);m.setAccessible(true);m.invoke(a,name);}catch(Exception e){throw new AssertionError(e);}});}
    private int[] markPosition(ActivityScenario<RookstrideActivity> screen){final int[] position=new int[2];screen.onActivity(a->{android.view.View mark=a.findViewById(android.R.id.content).findViewWithTag("brand-mark");assertNotNull(mark);assertTrue(mark.isShown());mark.getLocationOnScreen(position);});return position;}
    @Test public void brandStaysFixedAndProtocolControlsNeverBecomeServerControls()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            int[] mark=markPosition(screen);onView(withTagValue(org.hamcrest.Matchers.is((Object)"brand-mark"))).check(matches(isDisplayed()));
            onView(withText("Add VPN")).check(matches(isDisplayed()));onView(withContentDescription("Manage Server fixture")).perform(scrollTo(),click());assertArrayEquals(mark,markPosition(screen));
            onView(allOf(withText("AmneziaWG 3.1"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo(),click());assertArrayEquals(mark,markPosition(screen));
            onView(withText("All protocols")).check(doesNotExist());onView(withText("Server settings")).check(doesNotExist());onView(withText("VPN users")).perform(scrollTo(),click());
            onView(withText("AmneziaWG 3.1 · Server fixture")).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();
            onView(withText("Protocol settings")).check(doesNotExist());onView(withText("Edit server access")).check(doesNotExist());onView(withText("Remove all VPN setups")).check(doesNotExist());onView(withText("Uninstall this protocol")).perform(scrollTo()).check(matches(isDisplayed()));
            select(screen,ike);onView(withText("Protocol settings")).check(doesNotExist());onView(withText("Phone connection options")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withContentDescription("App settings")).perform(click());assertArrayEquals(mark,markPosition(screen));onView(withText("Save server access on this phone")).check(matches(isChecked()));
            screen.recreate();assertArrayEquals(mark,markPosition(screen));ScreenshotProof.save(context,"persistent-rook-brand");
        }
    }
    @Test public void protocolInformationDoesNotStartInstallation()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Add VPN")).perform(click());onView(withText("Set up a VPN")).perform(scrollTo(),click());onView(withText("Single-server VPN")).perform(scrollTo(),click());
            onView(withContentDescription("Details about VLESS · REALITY (TCP)")).perform(scrollTo(),click());onView(withText("Close")).check(matches(isCompletelyDisplayed())).perform(click());
            assertFalse(DeploymentService.active());onView(allOf(withText("Choose a protocol"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(context,"protocol-information-cards");
        }
    }
    @Test public void serverSignInIsClearlyNamedSavedEncryptedAndReusedAfterRecreation()throws Exception{
        ike.set("admin","root");awg.set("admin","root");vault.write(new ArrayList<>(Arrays.asList(ike,awg)));final java.util.concurrent.atomic.AtomicInteger calls=new java.util.concurrent.atomic.AtomicInteger();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("passwordDialog",Gateway.class,Runnable.class);m.setAccessible(true);m.invoke(a,ike,(Runnable)calls::incrementAndGet);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Server sign-in")).check(matches(isDisplayed()));onView(withText("root@vpn.example.net")).check(matches(isDisplayed()));
            onView(org.hamcrest.Matchers.allOf(withTagValue(org.hamcrest.Matchers.is((Object)"Server administrator password or key passphrase")),isAssignableFrom(android.widget.EditText.class))).perform(replaceText("fixture-save-once"));onView(withText("Continue")).perform(click());assertEquals(1,calls.get());
            screen.recreate();ArrayList<Gateway> saved=vault.read();for(Gateway node:saved){assertTrue(node.remember());assertEquals("fixture-save-once",node.sshPassword);}
            assertEquals(0,context.getApplicationInfo().flags&android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP);assertFalse(new String(java.nio.file.Files.readAllBytes(new java.io.File(context.getFilesDir(),"gateways.enc").toPath()),"ISO-8859-1").contains("fixture-save-once"));
        }
    }

    @Test public void aDifferentConnectionsNativeStatusAndLogAreNeverShown()throws Exception{
        java.lang.reflect.Field field=org.strongswan.android.rookstride.engine.NativeVpn.class.getDeclaredField("errors");field.setAccessible(true);Map<String,android.os.Bundle> states=(Map<String,android.os.Bundle>)field.get(null);android.os.Bundle previous=states.get("awg");
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            android.os.Bundle foreign=new android.os.Bundle();foreign.putString("id",java.util.UUID.randomUUID().toString());foreign.putString("state","limited");foreign.putString("error","Other connection private error");foreign.putString("log","Other connection private log");states.put("awg",foreign);select(screen,awg);
            onView(withText("Check web access again")).check(doesNotExist());onView(withText("Other connection private error")).check(doesNotExist());onView(withText("Logs")).perform(scrollTo(),click());
            onView(withSubstring("No recent log for this connection")).check(matches(isDisplayed()));onView(withSubstring("Other connection private log")).check(doesNotExist());onView(withText("Close")).perform(click());
            foreign.putString("id",awg.get("id"));foreign.putString("state","checking");select(screen,awg);onView(withText("Checking web access…")).check(matches(isDisplayed()));onView(withText("Other connection private error")).check(doesNotExist());
        }finally{if(previous==null)states.remove("awg");else states.put("awg",previous);}
    }

}
