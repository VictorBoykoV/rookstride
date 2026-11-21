package org.strongswan.android.rookstride;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import android.widget.ScrollView;
import androidx.appcompat.app.AlertDialog;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.data.*;
import org.strongswan.android.ui.RookstrideActivity;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.Espresso.pressBack;
import static androidx.test.espresso.Espresso.closeSoftKeyboard;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Real UI only: documentation-range fixtures and no network/deployment actions. */
@RunWith(AndroidJUnit4.class)
public class NavigationUiTest {
    private Context context;private Vault vault;private ArrayList<Gateway> original;private boolean savedBefore;private String selectedBefore;
    private VpnProfileDataSource profiles;private VpnProfile profile;
    @Before public void fixture()throws Exception{
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);original=vault.read();
        savedBefore=context.getSharedPreferences("rookstride-ui",0).getBoolean("hasSavedVpn",false);
        selectedBefore=context.getSharedPreferences("rookstride-ui",0).getString("selected",null);
        profiles=new VpnProfileSource(context);profiles.open();profile=new VpnProfile();profile.setName("Saved VPN fixture");profile.setGateway("vpn.example.net");profile.setVpnType(VpnType.IKEV2_EAP);profile.setUsername("fixture");profiles.insertProfile(profile);
        Gateway node=new Gateway();node.set("name",profile.getName());node.set("profileUuid",profile.getUUID().toString());node.data.put("clientOnly",true);
        ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);vault.write(nodes);
    }
    @After public void restore()throws Exception{
        if(profiles!=null){if(profile!=null)profiles.deleteVpnProfile(profile);profiles.close();}
        vault.write(original);context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",savedBefore).putString("selected",selectedBefore).commit();
    }
    @Test public void savedVpnComesFirstAndBackReturnsThroughActualSteps()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Connect")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));onView(withText("Set up a VPN")).check(doesNotExist());onView(withText("Manage a server")).check(doesNotExist());
            ScreenshotProof.save(context,"saved-vpn-home");
            android.app.Instrumentation instrumentation=InstrumentationRegistry.getInstrumentation();
            android.app.Instrumentation.ActivityMonitor connection=instrumentation.addMonitor("org.strongswan.android.ui.VpnProfileControlActivity",new android.app.Instrumentation.ActivityResult(0,null),true);
            try{onView(withText("Connect")).perform(click());assertEquals("Home did not launch the embedded connection",1,connection.getHits());}finally{instrumentation.removeMonitor(connection);}
            // Home Connect now stays on Home. The intercepted client never reports a state;
            // expire only this synthetic request instead of pressing Back into the exit prompt.
            screen.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("tapUntil");f.setAccessible(true);f.setLong(a,0);java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("render");m.setAccessible(true);m.invoke(a);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Set up a VPN")).perform(scrollTo(),click());onView(withText("Single-server VPN")).perform(click());
            onView(withText("IKEv2")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));final int[] protocolScrollY={0};
            screen.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("pageScroll");f.setAccessible(true);protocolScrollY[0]=((ScrollView)f.get(a)).getScrollY();}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("IKEv2")).perform(click());pressBack();
            screen.onActivity(a->{try{java.lang.reflect.Field route=RookstrideActivity.class.getDeclaredField("tab"),scroll=RookstrideActivity.class.getDeclaredField("pageScroll");route.setAccessible(true);scroll.setAccessible(true);assertEquals("Back must return to protocol selection","Protocols",route.get(a));assertEquals("Back must retain the protocol-list position instead of jumping to the top",protocolScrollY[0],((ScrollView)scroll.get(a)).getScrollY());}catch(Exception e){throw new AssertionError(e);}});
            // The title may correctly be above the retained viewport. Reveal it
            // through ordinary scrolling before continuing the Back journey.
            onView(allOf(withText("Choose a protocol"),not(isDescendantOfA(withTagValue(is((Object)"context-navigation")))))).perform(scrollTo()).check(matches(isDisplayed()));
            pressBack();onView(withText("Single-server VPN")).check(matches(isDisplayed()));
            pressBack();onView(withText("Add a VPN")).check(matches(isDisplayed()));
            screen.recreate();onView(withText("Add a VPN")).check(matches(isDisplayed()));
            pressBack();onView(withText("Connect")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Saved VPN fixture")).perform(scrollTo(),click());onView(withText("Connection preferences")).perform(scrollTo(),click());onView(withContentDescription("Journal")).perform(click());
            pressBack();onView(withText("Edit connection")).check(matches(isDisplayed()));
            pressBack();onView(withText("Connect")).perform(scrollTo()).check(matches(isDisplayed()));pressBack();
            pressBack();onView(withText("Leave Rookstride?")).check(matches(isDisplayed()));onView(withText("Stay")).perform(click());
            screen.onActivity(a->assertFalse(a.isFinishing()));onView(withText("Add VPN")).check(matches(isDisplayed()));
            pressBack();pressBack();onView(withText("Add VPN")).check(matches(isDisplayed()));
        }
    }
    @Test public void removingLastVpnKeepsAddChoicesOffTheReturningHome()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Saved VPN fixture")).perform(scrollTo(),click());onView(withText("Connection preferences")).perform(scrollTo(),click());onView(withText("Remove VPN")).perform(scrollTo(),click());onView(withText("Continue")).perform(click());
            onView(withText("Set up a VPN")).check(doesNotExist());onView(withText("Add VPN")).check(matches(isDisplayed()));
        }
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Set up a VPN")).check(doesNotExist());onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Set up a VPN")).check(matches(isDisplayed()));pressBack();onView(withText("Add VPN")).check(matches(isDisplayed()));
        }
    }
    @Test public void rootLeaveMovesTheTaskToBackgroundWithoutFinishingIt()throws Exception{
        AtomicReference<RookstrideActivity> activity=new AtomicReference<>();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity::set);pressBack();onView(withText("Leave app")).perform(click());
            InstrumentationRegistry.getInstrumentation().waitForIdleSync();assertFalse(activity.get().isFinishing());assertFalse(activity.get().isDestroyed());
        }
    }
    @Test public void longPairFormKeepsBothActionsVisibleWithKeyboard()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Add VPN")).perform(scrollTo(),click());onView(withText("Set up a VPN")).perform(scrollTo(),click());onView(withText("Double VPN")).perform(scrollTo(),click());
            onView(withText("Next")).perform(click());onView(withText("Next")).perform(click());onView(withText("Connection options")).perform(scrollTo(),click());assertActions();onView(allOf(withTagValue(is((Object)"Server administrator password")),isAssignableFrom(android.widget.EditText.class))).perform(scrollTo(),click());
            onView(isRoot()).perform(new androidx.test.espresso.ViewAction(){
                public org.hamcrest.Matcher<View> getConstraints(){return isRoot();}
                public String getDescription(){return "Open the focused field keyboard and wait for its usable-window layout";}
                public void perform(androidx.test.espresso.UiController ui,View view){
                    View focused=view.findFocus();assertNotNull("The password field did not receive focus",focused);
                    ((android.view.inputmethod.InputMethodManager)view.getContext().getSystemService(Context.INPUT_METHOD_SERVICE)).showSoftInput(focused,android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
                    long deadline=android.os.SystemClock.uptimeMillis()+5000;
                    do{ui.loopMainThreadForAtLeast(100);Rect frame=new Rect();view.getWindowVisibleDisplayFrame(frame);
                        if(context.getResources().getDisplayMetrics().heightPixels-frame.bottom>100*context.getResources().getDisplayMetrics().density){ui.loopMainThreadForAtLeast(300);return;}
                    }while(android.os.SystemClock.uptimeMillis()<deadline);
                }
            });
            assertActions();
            onView(withText("Next")).check((view,error)->{
                if(error!=null)throw error;View root=view.getRootView();ScrollView scroll=root.findViewWithTag(RookDialogs.BODY_TAG);assertNotNull(scroll);assertTrue(scroll.getChildAt(0).getHeight()>scroll.getHeight());
                Rect frame=new Rect();view.getWindowVisibleDisplayFrame(frame);int[] xy=new int[2];view.getLocationOnScreen(xy);assertTrue("Action below usable window",xy[1]+view.getHeight()<=frame.bottom);
                assertTrue("The onscreen keyboard was not shown",context.getResources().getDisplayMetrics().heightPixels-frame.bottom>100*context.getResources().getDisplayMetrics().density);
                int before=xy[1];scroll.scrollTo(0,0);view.getLocationOnScreen(xy);assertEquals("Action moved with content",before,xy[1]);
            });
            closeSoftKeyboard();onView(withText("Cancel")).perform(click());onView(withText("Single-server VPN")).check(matches(isDisplayed()));
        }
    }
    private void assertActions(){
        for(String label:new String[]{"Cancel","Next","Back"})onView(withText(label)).check(matches(isCompletelyDisplayed())).check(matches(isClickable())).check(matches(not(isDescendantOfA(withTagValue(is((Object)RookDialogs.BODY_TAG)))))).check((view,error)->{if(error!=null)throw error;assertTrue(view.getHeight()>=48*context.getResources().getDisplayMetrics().density);});
    }
}
