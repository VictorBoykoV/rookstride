package org.strongswan.android.rookstride;

import android.content.*;
import android.graphics.Rect;
import android.os.SystemClock;
import android.view.*;
import android.widget.ScrollView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.Field;
import java.util.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;

/** Explicit pointer events, not scrollTo/accessibility scrolling. A drag starting
 * on an actionable row must scroll its parent and cancel the row's click. */
@RunWith(AndroidJUnit4.class)
public final class GestureScrollingUiTest {
 private Context context;private Vault vault;private ArrayList<Gateway> original;private String progress;private Gateway pair;
 private Object field(Object target,String name){try{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}catch(Exception e){throw new AssertionError(e);}}
 @Before public void setup()throws Exception{
  context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);original=vault.read();assertFalse(DeploymentService.active());progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
  pair=new Gateway();pair.set("host","entry.example.net");pair.set("serverName","Gesture entry");pair.set("name","Gesture pair");pair.set("protocol","awg");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","awg");pair.set("pairEngine","native-v2");pair.set("pairId",String.join("",Collections.nCopies(32,"a")));pair.data.put("pairReady",true);pair.exit=new Gateway();pair.exit.set("host","exit.example.net");pair.exit.set("serverName","Gesture exit");vault.write(new ArrayList<>(Arrays.asList(pair)));context.getSharedPreferences("rookstride-ui",0).edit().remove("selected").remove("lastConnectedId").commit();
 }
 @After public void restore()throws Exception{vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();}
 private void drag(float x,float from,float to)throws Exception{
  android.app.Instrumentation input=InstrumentationRegistry.getInstrumentation();long down=SystemClock.uptimeMillis();MotionEvent event=MotionEvent.obtain(down,down,MotionEvent.ACTION_DOWN,x,from,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}
  // Count events, not a wall-clock deadline. Even a slow emulator receives every MOVE.
  for(int n=1;n<=24;n++){Thread.sleep(18);long now=SystemClock.uptimeMillis();event=MotionEvent.obtain(down,now,MotionEvent.ACTION_MOVE,x,from+(to-from)*n/24f,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}}
  Thread.sleep(120);event=MotionEvent.obtain(down,SystemClock.uptimeMillis(),MotionEvent.ACTION_UP,x,to,0);event.setSource(InputDevice.SOURCE_TOUCHSCREEN);try{input.sendPointerSync(event);}finally{event.recycle();}input.waitForIdleSync();Thread.sleep(350);
 }
 private void visibleClick(ActivityScenario<RookstrideActivity> screen,org.hamcrest.Matcher<View> matcher)throws Exception{
  for(int attempt=0;attempt<5;attempt++){
   try{onView(matcher).check(matches(isCompletelyDisplayed()));onView(matcher).perform(click());return;}
   catch(AssertionError clipped){
    if(attempt==4)throw clipped;
    final Rect viewport=new Rect(),target=new Rect();final ScrollView[] scroll={null};final int[] before={0};final int[] slop={0};
    screen.onActivity(a->{scroll[0]=(ScrollView)field(a,"pageScroll");assertNotNull(scroll[0]);assertTrue("The page has no visible scroll viewport",scroll[0].getGlobalVisibleRect(viewport));before[0]=scroll[0].getScrollY();slop[0]=ViewConfiguration.get(a).getScaledTouchSlop();});
    // Global visible bounds discard the clipped portion. Use the target's full
    // laid-out rectangle so an earlier swipe cannot send an above-screen row
    // farther away. A collapsed/oversized/horizontally clipped target still fails.
    onView(matcher).check((view,error)->{if(error!=null)throw error;assertTrue("The target is hidden, not vertically clipped",view.isShown());assertTrue("The target has no laid-out area",view.getWidth()>0&&view.getHeight()>0);ViewParent parent=view.getParent();while(parent!=null&&parent!=scroll[0])parent=parent.getParent();assertSame("The target is outside this page's ScrollView",scroll[0],parent);int[] xy=new int[2];view.getLocationOnScreen(xy);target.set(xy[0],xy[1],xy[0]+view.getWidth(),xy[1]+view.getHeight());});
    assertTrue("The entire target cannot fit the viewport: "+target+" / "+viewport,target.height()<=viewport.height());
    assertTrue("Vertical gestures cannot fix horizontal clipping: "+target+" / "+viewport,target.left>=viewport.left&&target.right<=viewport.right);
    final boolean upward=target.bottom>viewport.bottom;
    if(!upward&&target.top>=viewport.top)throw clipped;
    int inset=Math.max(16,slop[0]*2),maximum=viewport.height()-2*inset;assertTrue("The viewport has no usable pointer travel",maximum>slop[0]*2);
    int needed=upward?target.bottom-viewport.bottom:viewport.top-target.top;
    int distance=Math.min(maximum,Math.max(slop[0]*2+1,needed+slop[0]*2));
    float from=upward?viewport.bottom-inset:viewport.top+inset,to=upward?from-distance:from+distance;
    android.util.Log.i("RookGesture","reveal "+attempt+" "+(upward?"up":"down")+" target="+target+" viewport="+viewport+" scroll="+before[0]);
    drag(viewport.left+8,from,to);
    screen.onActivity(a->{assertSame("Revealing a target rebuilt the scrolling page",scroll[0],field(a,"pageScroll"));int after=scroll[0].getScrollY();assertTrue("The real pointer gesture did not move in the required direction: "+before[0]+" -> "+after,upward?after>before[0]:after<before[0]);});
   }
  }
 }
 @Test public void realDragFromMaintenanceButtonScrollsWithoutActivatingIt()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   onView(withContentDescription("Servers")).perform(click());visibleClick(screen,withContentDescription("Manage Gesture entry"));
   visibleClick(screen,withText("Server maintenance"));visibleClick(screen,withContentDescription("Expand Access & administrators"));final ScrollView[] view={null};final float[] points=new float[3];final int[] initial={0};
   screen.onActivity(a->{view[0]=(ScrollView)field(a,"pageScroll");initial[0]=view[0].getScrollY();Rect bounds=new Rect();view[0].getGlobalVisibleRect(bounds);points[0]=bounds.centerX();points[1]=bounds.bottom-90;points[2]=bounds.top+40;});
   // Initial bottom rows are harmless local administrator/route editors. A lost
   // MOVE would open a dialog, which is explicitly rejected below.
   drag(points[0],points[1],points[2]);
   screen.onActivity(a->{assertSame("Dragging rebuilt the page",view[0],field(a,"pageScroll"));assertTrue("The real drag did not move the viewport",view[0].getScrollY()>initial[0]+100);assertEquals("ServerSettings",field(a,"tab"));assertFalse("A drag started a server command",(Boolean)field(a,"busy"));});
   onView(withText("Server connection")).check(doesNotExist());onView(withText("Server administrator password or key passphrase")).check(doesNotExist());assertFalse(DeploymentService.active());ScreenshotProof.save(context,"maintenance-real-pointer-scroll");
   final int[] moved={0};screen.onActivity(a->moved[0]=view[0].getScrollY());drag(8,points[2],points[1]);screen.onActivity(a->{assertSame(view[0],field(a,"pageScroll"));assertTrue("Reverse drag did not move the viewport back",view[0].getScrollY()<moved[0]);});ScreenshotProof.save(context,"maintenance-real-pointer-return");
  }
 }
}
