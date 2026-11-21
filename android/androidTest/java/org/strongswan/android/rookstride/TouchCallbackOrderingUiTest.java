package org.strongswan.android.rookstride;

import android.app.Instrumentation;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.InputDevice;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeVpn;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Real system DOWN/UP input with deterministic callback ordering. Only the
 * local catalog/status is synthetic; no SSH command or VPN engine is started. */
@RunWith(AndroidJUnit4.class)
public final class TouchCallbackOrderingUiTest {
 private Context context;
 private Vault vault;
 private ArrayList<Gateway> original;
 private Gateway server;
 private String progress;
 private boolean progressCaptured;
 private Map<String,?> preferences;
 private Map<String,Bundle> states;
 private Map<String,Bundle> originalStates;

 @Before public void fixture() throws Exception {
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();
  assertFalse("The fixture must not interrupt a deployment",DeploymentService.active());
  vault=new Vault(context);original=vault.read();
  preferences=new HashMap<>(context.getSharedPreferences("rookstride-ui",0).getAll());
  progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
  progressCaptured=true;
  context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
  context.getSharedPreferences("rookstride-ui",0).edit().remove("selected").remove("lastConnectedId").commit();
  Field errors=NativeVpn.class.getDeclaredField("errors");errors.setAccessible(true);
  states=(Map<String,Bundle>)errors.get(null);originalStates=new HashMap<>(states);states.clear();
  server=new Gateway();server.set("name","Original server");server.set("serverName","Original server");server.set("host","original.example.net");server.set("protocol","awg");
  server.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));
  ArrayList<Gateway> catalog=new ArrayList<>(Arrays.asList(server));
  for(int i=1;i<=6;i++){
   Gateway extra=new Gateway();extra.set("name","Scroll server "+i);extra.set("serverName","Scroll server "+i);extra.set("host","scroll"+i+".example.net");extra.set("protocol","awg");
   extra.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));catalog.add(extra);
  }
  vault.write(catalog);
 }
 @After public void restore() throws Exception {
  if(states!=null&&originalStates!=null){states.clear();states.putAll(originalStates);}
  if(vault!=null&&original!=null)vault.write(original);
  if(context!=null&&progressCaptured)context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();
  if(context==null||preferences==null)return;
  SharedPreferences.Editor edit=context.getSharedPreferences("rookstride-ui",0).edit().clear();
  for(Map.Entry<String,?> entry:preferences.entrySet()){
   Object value=entry.getValue();String key=entry.getKey();
   if(value instanceof String)edit.putString(key,(String)value);
   else if(value instanceof Boolean)edit.putBoolean(key,(Boolean)value);
   else if(value instanceof Integer)edit.putInt(key,(Integer)value);
   else if(value instanceof Long)edit.putLong(key,(Long)value);
   else if(value instanceof Float)edit.putFloat(key,(Float)value);
   else if(value instanceof Set)edit.putStringSet(key,new HashSet<>((Set<String>)value));
  }
  edit.commit();
 }

 @Test public void firstServersTapSurvivesAQueuedCatalogRebuildBeforeTheFrameworkClick() throws Exception {
  Gateway revision=new Gateway();revision.set("name","Catalog revision");revision.set("serverName","Catalog revision");revision.set("host","revision.example.net");revision.set("protocol","");
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   int[] callbacks={0};boolean[] keptPressedView={false};float[] point=new float[2];
   screen.onActivity(a->{
    View target=find(a.findViewById(android.R.id.content),"Servers");assertNotNull(target);
    center(target,point);
    target.setOnTouchListener((v,event)->{
     if(event.getActionMasked()==MotionEvent.ACTION_UP)new Handler(Looper.getMainLooper()).post(()->{
      callbacks[0]++;
      ((ArrayList<Gateway>)field(a,"gateways")).add(revision);
      call(a,"save");call(a,"render");
      keptPressedView[0]=target.isAttachedToWindow();
     });
     return false;
    });
   });
   tapOnce(point);
   screen.onActivity(a->{
    assertEquals("The single physical tap must queue exactly one callback",1,callbacks[0]);
    assertTrue("A queued rebuild detached the pressed view before its click",keptPressedView[0]);
    assertEquals("The first Servers tap was lost", "Servers",field(a,"tab"));
    assertTrue("The legitimate catalog revision was not rendered",((ArrayList<Gateway>)field(a,"gateways")).stream().anyMatch(n->n.get("name").equals("Catalog revision")));
   });
   onView(withContentDescription("Manage Catalog revision")).perform(scrollTo()).check(matches(isDisplayed()));
   assertFalse(DeploymentService.active());
  }
 }

 @Test public void queuedConnectionRefreshAfterARepeatedHomeTapKeepsTheSamePageAndScroll() throws Exception {
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withText("Scroll server 6")).perform(scrollTo()).check(matches(isDisplayed()));
   int[] callbacks={0};ScrollView[] page={null};int[] scrollY={0};float[] point=new float[2];
   screen.onActivity(a->{
    page[0]=(ScrollView)field(a,"pageScroll");scrollY[0]=page[0].getScrollY();assertTrue("The fixture must actually scroll",scrollY[0]>0);
    View target=find(a.findViewById(android.R.id.content),"VPNs");assertNotNull(target);center(target,point);
    target.setOnTouchListener((v,event)->{
     if(event.getActionMasked()==MotionEvent.ACTION_UP)new Handler(Looper.getMainLooper()).post(()->{
      callbacks[0]++;Bundle status=new Bundle();status.putString("id",server.get("id"));status.putString("state","connected");states.put("awg",status);a.stateChanged();
     });
     return false;
    });
   });
   tapOnce(point);
   screen.onActivity(a->{
    assertEquals(1,callbacks[0]);assertEquals("Home",field(a,"tab"));
    assertSame("A status-only callback rebuilt the Home page",page[0],field(a,"pageScroll"));
    assertEquals("A status-only callback reset scroll",scrollY[0],page[0].getScrollY());
   });
   onView(allOf(withContentDescription("Disconnect AmneziaWG 3.1 on Original server"),isDescendantOfA(withTagValue(is((Object)("server-connections-"+server.get("id"))))))).perform(scrollTo()).check(matches(isDisplayed()));
   assertFalse(DeploymentService.active());
  }
 }
 @Test public void anOlderReleaseCannotFlushARebuildWhileTheNextGestureIsStillDown() throws Exception {
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   int[] secondEvents={0,0};boolean[] heldRootPreserved={false};String[] routeBeforeSecondRelease={null};float[] firstPoint=new float[2];
   screen.onActivity(a->{
    View first=find(a.findViewById(android.R.id.content),"Servers"),second=find(a.findViewById(android.R.id.content),"Journal");assertNotNull(first);assertNotNull(second);center(first,firstPoint);int[] secondWindow=new int[2];second.getLocationInWindow(secondWindow);float[] secondPoint={secondWindow[0]+second.getWidth()/2f,secondWindow[1]+second.getHeight()/2f};View page=(View)field(a,"root");
    first.setOnTouchListener((v,event)->{
     if(event.getActionMasked()==MotionEvent.ACTION_UP)new Handler(Looper.getMainLooper()).post(()->{
      // The first gesture is real system input. The deliberately interleaved
      // second gesture uses native Activity/View dispatch on the main queue,
      // not performClick, so its old root must survive until its own UP.
      long secondDown=SystemClock.uptimeMillis();dispatch(a,secondDown,MotionEvent.ACTION_DOWN,secondPoint);secondEvents[0]++;
      call(a,"render");
      new Handler(Looper.getMainLooper()).post(()->{
       heldRootPreserved[0]=page==field(a,"root")&&second.isAttachedToWindow();
       routeBeforeSecondRelease[0]=(String)field(a,"tab");
       dispatch(a,secondDown,MotionEvent.ACTION_UP,secondPoint);secondEvents[1]++;
      });
     });
     return false;
    });
   });
   tapOnce(firstPoint);
   screen.onActivity(a->{
    assertEquals(1,secondEvents[0]);assertEquals(1,secondEvents[1]);
    assertTrue("The older release detached the next gesture's target",heldRootPreserved[0]);
    assertEquals("The first native click was not delivered before the second release","Servers",routeBeforeSecondRelease[0]);
    assertEquals("The next native click was lost","Stories",field(a,"tab"));
   });
   assertFalse(DeploymentService.active());
  }
 }
 private static void dispatch(RookstrideActivity activity,long down,int action,float[] point){
  MotionEvent event=MotionEvent.obtain(down,SystemClock.uptimeMillis(),action,point[0],point[1],0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);
  try{assertTrue("The interleaved event was not consumed",activity.dispatchTouchEvent(event));}finally{event.recycle();}
 }
 private void tapOnce(float[] point){
  Instrumentation input=InstrumentationRegistry.getInstrumentation();long down=SystemClock.uptimeMillis();
  pointer(input,down,MotionEvent.ACTION_DOWN,point);pointer(input,down,MotionEvent.ACTION_UP,point);input.waitForIdleSync();
 }
 private void pointer(Instrumentation input,long down,int action,float[] point){
  MotionEvent event=MotionEvent.obtain(down,SystemClock.uptimeMillis(),action,point[0],point[1],0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);
  try{input.sendPointerSync(event);}finally{event.recycle();}
 }
 private static void center(View view,float[] point){int[] xy=new int[2];view.getLocationOnScreen(xy);point[0]=xy[0]+view.getWidth()/2f;point[1]=xy[1]+view.getHeight()/2f;assertTrue(view.isShown());assertTrue(view.getWidth()>0&&view.getHeight()>0);}
 private static Object field(Object object,String name){try{Field field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);}catch(Exception failure){throw new AssertionError(failure);}}
 private static void call(Object object,String name){try{Method method=object.getClass().getDeclaredMethod(name);method.setAccessible(true);method.invoke(object);}catch(Exception failure){throw new AssertionError(failure);}}
 private static View find(View view,String description){
  if(description.contentEquals(view.getContentDescription()==null?"":view.getContentDescription()))return view;
  if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++){View found=find(((ViewGroup)view).getChildAt(i),description);if(found!=null)return found;}
  return null;
 }
}

