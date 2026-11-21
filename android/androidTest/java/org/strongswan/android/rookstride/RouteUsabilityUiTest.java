package org.strongswan.android.rookstride;
import android.content.*;
import android.graphics.Rect;
import android.view.*;
import android.widget.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.util.*;
import java.lang.reflect.*;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Local UI fixtures only. This class never installs or removes a server. */
@RunWith(AndroidJUnit4.class) public class RouteUsabilityUiTest {
 Context context;Vault vault;ArrayList<Gateway> previous;Gateway node;
 static Field field(Object a,String name)throws Exception{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f;}
 static Object call(Object a,String name,Class<?>[] types,Object...args)throws Exception{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(a,args);}
 @Before public void setup()throws Exception{
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);previous=vault.read();node=new Gateway();node.set("name","Route fixture");node.set("serverName","Route fixture");node.set("host","vpn.example.net");node.set("admin","root");node.set("protocol","awg");node.data.put("checkedAt",System.currentTimeMillis());node.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)).put("filtering",new JSONObject().put("installed",true)).put("users",new JSONArray()));
  vault.write(new ArrayList<>(Arrays.asList(node)));context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("rememberServerAccess",true).commit();
 }
 @After public void cleanup()throws Exception{vault.write(previous);}
 @Test public void quickConnectionUsesItsOwnServerAndAncestorHasNoChildBackLoop()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{Gateway other=new Gateway();other.set("name","Previous server");other.set("host","other.example.net");Field list=field(a,"gateways");((ArrayList<Gateway>)list.get(a)).add(other);field(a,"pendingServerId").set(a,other.get("id"));call(a,"openVpn",new Class<?>[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});
   final JSONObject touchProof=new JSONObject();final float[] point=new float[2];onView(withContentDescription("Back to Route fixture")).check(matches(isDisplayed()));
   ScreenshotProof.save(context,"breadcrumb-before-press");
   screen.onActivity(a->{try{View link=findDescription((View)field(a,"root").get(a),"Back to Route fixture");int[] at=new int[2];link.getLocationOnScreen(at);point[0]=at[0]+link.getWidth()/2f;point[1]=at[1]+link.getHeight()/2f;touchProof.put("point_x",point[0]).put("point_y",point[1]).put("width",link.getWidth()).put("height",link.getHeight());}catch(Exception e){throw new AssertionError(e);}});
   long now=android.os.SystemClock.uptimeMillis();MotionEvent down=MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,point[0],point[1],0);down.setSource(InputDevice.SOURCE_TOUCHSCREEN);
   try{InstrumentationRegistry.getInstrumentation().sendPointerSync(down);screen.onActivity(a->{try{View link=findDescription((View)field(a,"root").get(a),"Back to Route fixture");touchProof.put("down_received",field(a,"pointerDown").getBoolean(a)).put("pressed",link.isPressed()).put("touch_mode",link.isInTouchMode());call(a,"render",new Class<?>[]{});assertTrue("Status repaint detached the pressed breadcrumb",link.isAttachedToWindow());}catch(Exception e){throw new AssertionError(e);}});}finally{MotionEvent up=MotionEvent.obtain(now,android.os.SystemClock.uptimeMillis(),MotionEvent.ACTION_UP,point[0],point[1],0);up.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{InstrumentationRegistry.getInstrumentation().sendPointerSync(up);}finally{down.recycle();up.recycle();}}
   InstrumentationRegistry.getInstrumentation().waitForIdleSync();screen.onActivity(a->{try{touchProof.put("tab_after_up",field(a,"tab").get(a)).put("held_after_up",field(a,"pointerDown").getBoolean(a));java.nio.file.Files.write(new java.io.File(context.getFilesDir(),"touch-probe.json").toPath(),touchProof.toString().getBytes("UTF-8"));}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Refresh")).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();onView(withText("Your VPNs")).check(matches(isDisplayed()));
  }
 }
 static View findDescription(View view,String description){if(view==null)return null;if(description.contentEquals(view.getContentDescription()==null?"":view.getContentDescription()))return view;if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++){View found=findDescription(((ViewGroup)view).getChildAt(i),description);if(found!=null)return found;}return null;}
 @Test public void breadcrumbsOpenAnAncestorAndBackDoesNotReturnToItsChild()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"openServer",new Class<?>[]{Gateway.class},node);call(a,"openVpn",new Class<?>[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("VPN users")).perform(scrollTo(),click());onView(withContentDescription("Back to AmneziaWG 3.1")).perform(scrollTo(),click());onView(withText("Uninstall this protocol")).perform(scrollTo()).check(matches(isDisplayed()));
   onView(withContentDescription("Back to Route fixture")).perform(scrollTo(),click());onView(withText("Refresh")).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();onView(withText("Your VPNs")).check(matches(isDisplayed()));ScreenshotProof.save(context,"breadcrumb-parents");
  }
 }
 @Test public void administratorSavingIsVisibleAndSelectedWithoutAdvanced()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"passwordDialog",new Class<?>[]{Gateway.class,Runnable.class},node,(Runnable)()->{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Save server access on this phone")).perform(scrollTo()).check(matches(isChecked())).check(matches(isCompletelyDisplayed())).perform(click()).check(matches(not(isChecked()))).perform(click()).check(matches(isChecked()));
   onView(withText("Advanced")).check(doesNotExist());for(String action:new String[]{"Cancel","Continue"})onView(withText(action)).check(matches(isCompletelyDisplayed()));
   onView(isAssignableFrom(android.widget.EditText.class)).perform(scrollTo(),click());
   onView(isRoot()).perform(new androidx.test.espresso.ViewAction(){public org.hamcrest.Matcher<View> getConstraints(){return isRoot();}public String getDescription(){return "Show the password keyboard and wait for native dialog resize";}public void perform(androidx.test.espresso.UiController ui,View root){View input=root.findFocus();assertTrue(input instanceof android.widget.EditText);((android.view.inputmethod.InputMethodManager)root.getContext().getSystemService(Context.INPUT_METHOD_SERVICE)).showSoftInput(input,android.view.inputmethod.InputMethodManager.SHOW_FORCED);long end=android.os.SystemClock.uptimeMillis()+5000;do{ui.loopMainThreadForAtLeast(100);Rect frame=new Rect();root.getWindowVisibleDisplayFrame(frame);if(context.getResources().getDisplayMetrics().heightPixels-frame.bottom>100*context.getResources().getDisplayMetrics().density){ui.loopMainThreadForAtLeast(300);return;}}while(android.os.SystemClock.uptimeMillis()<end);fail("Password keyboard was not shown");}});
   for(String action:new String[]{"Cancel","Continue"})onView(withText(action)).check(matches(isCompletelyDisplayed())).check(matches(not(isDescendantOfA(withTagValue(is((Object)RookDialogs.BODY_TAG)))))).check((view,error)->{if(error!=null)throw error;Rect frame=new Rect();view.getWindowVisibleDisplayFrame(frame);int[] xy=new int[2];view.getLocationOnScreen(xy);assertTrue(xy[1]+view.getHeight()<=frame.bottom);});
   /* Credential windows deliberately prevent screen capture. */onView(withText("Cancel")).perform(click());androidx.test.espresso.Espresso.closeSoftKeyboard();
  }
 }
 @Test public void adBlockingLoadingIsShownOnThePressedTile()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"openVpn",new Class<?>[]{Gateway.class},node);field(a,"pendingModule").set(a,"Ad blocking");field(a,"busy").setBoolean(a,true);field(a,"message").set(a,"Loading ad blocking");call(a,"render",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withTagValue(is((Object)"server-operation"))).check(doesNotExist());onView(withContentDescription("Ad blocking, loading")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));onView(allOf(isAssignableFrom(ProgressBar.class),isDescendantOfA(withTagValue(is((Object)"module-Ad blocking"))))).check(matches(isDisplayed()));ScreenshotProof.save(context,"ad-blocking-tile-loading");
  }
 }
 @Test public void pairChoicesExplainTheHopsAndHideOptionalPorts()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"addPair",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Phone → first server")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Next")).perform(click());onView(withText("First server → exit server")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Next")).perform(click());onView(withTagValue(is((Object)"SSH port"))).check(matches(not(isDisplayed())));onView(withText("Next")).check(matches(isCompletelyDisplayed()));/* Credential windows deliberately prevent screen capture. */onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
   screen.onActivity(a->{try{Gateway pair=new Gateway();pair.exit=new Gateway();pair.set("protocol","awg");pair.set("pairEntryProtocol","awg");assertEquals(Boolean.TRUE,call(a,"otherProtocol",new Class<?>[]{Gateway.class},pair));pair.set("protocol","ikev2");assertEquals(Boolean.FALSE,call(a,"otherProtocol",new Class<?>[]{Gateway.class},pair));}catch(Exception e){throw new AssertionError(e);}});
  }
 }
}
