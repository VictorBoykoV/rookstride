package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.viewpager2.widget.ViewPager2;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.rookstride.engine.NativeVpn;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.action.ViewActions.swipeLeft;
import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/** Rendered interaction with synthetic catalogs/engine status and the real UI factory.
 * No real server action, VPN transport or human participant study is claimed. */
@RunWith(AndroidJUnit4.class)
public final class PresentationFollowupUiTest {
    private Context context;private Vault vault;private ArrayList<Gateway> before;
    private Map<String,?> beforeUi;private String progress;private Field session;private Object oldSession;
    private Map<String,Bundle> states;private final Map<String,Bundle> previousStates=new HashMap<>();
    private Gateway server,awg,xhttp,imported;
    @Before public void fixture()throws Exception{
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();vault=new Vault(context);before=vault.read();
        SharedPreferences ui=context.getSharedPreferences("rookstride-ui",0);beforeUi=new HashMap<>(ui.getAll());
        ui.edit().clear().putBoolean("hasSavedVpn",true).commit();
        progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
        session=DeploymentService.class.getDeclaredField("current");session.setAccessible(true);oldSession=session.get(null);session.set(null,null);
        Field errors=NativeVpn.class.getDeclaredField("errors");errors.setAccessible(true);states=(Map<String,Bundle>)errors.get(null);previousStates.putAll(states);states.clear();
        server=new Gateway();server.set("host","north.example.net");server.set("name","North station");server.set("serverName","North station");server.set("protocol","");
        server.data.put("checkedAt",System.currentTimeMillis()).put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg").put("xhttp"))));
        awg=ServerProtocols.create(server,SingleProtocols.AWG);xhttp=ServerProtocols.create(server,SingleProtocols.XHTTP);
        for(Gateway node:Arrays.asList(awg,xhttp)){node.set("setupIntent","");node.data.put("favorite",true).put("snapshot",new JSONObject().put("services",new JSONObject().put("protocol",true)));}
        imported=new Gateway();imported.set("name",SingleProtocols.AWG.title);imported.set("host",server.get("host"));imported.set("protocol","awg");imported.set("vpnLogin","family-guest");imported.data.put("clientOnly",true);
        vault.write(new ArrayList<>(Arrays.asList(server,awg,xhttp,imported)));
        ui.edit().putString("lastConnectedId",awg.get("id")).commit();
    }
    @After public void restore()throws Exception{
        session.set(null,oldSession);states.clear();states.putAll(previousStates);vault.write(before);
        SharedPreferences.Editor edit=context.getSharedPreferences("rookstride-ui",0).edit().clear();
        for(Map.Entry<String,?> entry:beforeUi.entrySet()){
            String k=entry.getKey();Object v=entry.getValue();if(v instanceof String)edit.putString(k,(String)v);else if(v instanceof Boolean)edit.putBoolean(k,(Boolean)v);else if(v instanceof Integer)edit.putInt(k,(Integer)v);else if(v instanceof Long)edit.putLong(k,(Long)v);else if(v instanceof Float)edit.putFloat(k,(Float)v);else if(v instanceof Set)edit.putStringSet(k,(Set<String>)v);else throw new AssertionError("Unknown preference type");
        }edit.commit();context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();
    }
    private Object field(Object object,String name){try{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}catch(Exception e){throw new AssertionError(e);}}
    private void set(Object object,String name,Object value){try{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);f.set(object,value);}catch(Exception e){throw new AssertionError(e);}}
    private Object call(Object object,String name,Class<?>[] types,Object...args){try{Method m=object.getClass().getDeclaredMethod(name,types);m.setAccessible(true);return m.invoke(object,args);}catch(Exception e){throw new AssertionError(e);}}
    private View tagged(RookstrideActivity activity,String tag){return activity.findViewById(android.R.id.content).findViewWithTag(tag);}
    private ViewPager2 pager(RookstrideActivity activity){return (ViewPager2)tagged(activity,"quick-connection");}
    private void state(Gateway node,String next){Bundle b=new Bundle();b.putString("id",node.get("id"));b.putString("state",next);states.put(node.get("protocol").equals("xhttp")?"xray":node.get("protocol"),b);}
    private void idle(){InstrumentationRegistry.getInstrumentation().waitForIdleSync();}
    private List<View> descendants(View view){ArrayList<View> result=new ArrayList<>();result.add(view);if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++)result.addAll(descendants(((ViewGroup)view).getChildAt(i)));return result;}
    private long countText(View view,String value){return descendants(view).stream().filter(v->v instanceof TextView&&((TextView)v).getText().toString().equals(value)).count();}
    private static void wholeText(TextView text){assertNotNull(text.getLayout());assertTrue("Displayed text exceeds available lines",text.getLineCount()<=text.getMaxLines());for(int n=0;n<text.getLineCount();n++)assertEquals("Text was ellipsized",0,text.getLayout().getEllipsisCount(n));}

    private void wholeWords(TextView text){
        wholeText(text);String value=text.getText().toString();
        for(int line=0;line<text.getLineCount()-1;line++){int end=text.getLayout().getLineEnd(line);assertTrue("The action split a word between lines",end<=0||end>=value.length()||Character.isWhitespace(value.charAt(end-1))||Character.isWhitespace(value.charAt(end)));}
        int last=text.getLineCount()-1;assertTrue("The action clipped its final line",last>=0&&text.getLayout().getLineBottom(last)<=text.getHeight()-text.getCompoundPaddingTop()-text.getCompoundPaddingBottom());
        assertEquals("Text omitted its final characters",value.length(),text.getLayout().getLineEnd(last));
        int width=text.getWidth()-text.getCompoundPaddingLeft()-text.getCompoundPaddingRight();for(int line=0;line<text.getLineCount();line++)assertTrue("A full word is horizontally clipped",text.getLayout().getLineLeft(line)>=-1&&text.getLayout().getLineRight(line)<=width+1);
    }
    /** getGlobalVisibleRect uses the current window root, while injected touch
     * events and getLocationOnScreen use the screen. Dialog roots are offset. */
    private static boolean clippedOnScreen(View view,android.graphics.Rect result){
        if(!view.getGlobalVisibleRect(result))return false;int[] root=new int[2];view.getRootView().getLocationOnScreen(root);result.offset(root[0],root[1]);return true;
    }
    /** A long paragraph need not fit90% of a short viewport. Read every full
     * font ascent/descent envelope through real swipes; blank line leading is
     * not painted text. The short normal paragraph may already fit without one. */
    static androidx.test.espresso.ViewAction readEveryLineNaturally(){return new androidx.test.espresso.ViewAction(){
        @Override public org.hamcrest.Matcher<View> getConstraints(){return allOf(isAssignableFrom(TextView.class),withEffectiveVisibility(Visibility.VISIBLE));}
        @Override public String getDescription(){return "read every full paragraph line using natural scrolling";}
        @Override public void perform(androidx.test.espresso.UiController controller,View view){
            TextView text=(TextView)view;wholeText(text);assertTrue("The paragraph is empty",text.getText().length()>0&&text.getLineCount()>0);
            android.view.ViewParent parent=text.getParent();while(parent!=null&&!(parent instanceof android.widget.ScrollView))parent=parent.getParent();assertTrue("The paragraph has no readable scroll viewport",parent instanceof android.widget.ScrollView);android.widget.ScrollView scroll=(android.widget.ScrollView)parent;
            boolean[] read=new boolean[text.getLineCount()];int readCount=0;
            for(int step=0;step<48;step++){
                controller.loopMainThreadUntilIdle();assertEquals("Reading changed the paragraph layout",read.length,text.getLineCount());android.graphics.Rect viewport=new android.graphics.Rect();assertTrue("The paragraph viewport is hidden",clippedOnScreen(scroll,viewport));int[] xy=new int[2];text.getLocationOnScreen(xy);int originY=xy[1]+text.getTotalPaddingTop()-text.getScrollY();android.graphics.Rect visible=new android.graphics.Rect();boolean shown=clippedOnScreen(text,visible);android.graphics.Paint.FontMetricsInt metrics=text.getPaint().getFontMetricsInt();
                if(shown)for(int line=0;line<read.length;line++){
                    int baseline=originY+text.getLayout().getLineBaseline(line),top=baseline+metrics.ascent,bottom=baseline+metrics.descent;
                    if(!read[line]&&top>=Math.max(viewport.top,visible.top)&&bottom<=Math.min(viewport.bottom,visible.bottom)){
                        assertTrue("A paragraph line is horizontally clipped",xy[0]+text.getCompoundPaddingLeft()-text.getScrollX()+text.getLayout().getLineLeft(line)>=viewport.left-1&&xy[0]+text.getCompoundPaddingLeft()-text.getScrollX()+text.getLayout().getLineRight(line)<=viewport.right+1);read[line]=true;readCount++;
                    }
                }
                if(readCount==read.length){assertEquals("The final text was truncated",text.getText().length(),text.getLayout().getLineEnd(read.length-1));android.util.Log.i("RookParagraph","readAll lines="+read.length+" swipes="+step+" viewport="+viewport+" textVisible="+visible);return;}
                int next=0;while(read[next])next++;int baseline=originY+text.getLayout().getLineBaseline(next),top=baseline+metrics.ascent,bottom=baseline+metrics.descent;assertTrue("Even one text line cannot fit the visible viewport",bottom-top<=viewport.height());boolean forward=top>=viewport.top;
                int slop=android.view.ViewConfiguration.get(view.getContext()).getScaledTouchSlop(),inset=Math.max(Math.round(12*view.getResources().getDisplayMetrics().density),slop*2),travel=viewport.height()-2*inset;assertTrue("No usable pointer travel remains in the paragraph viewport",travel>slop*2);
                int needed=forward?Math.max(0,bottom-viewport.bottom):viewport.top-top,distance=Math.min(travel,Math.max(slop*2+1,needed+slop*2)),before=scroll.getScrollY();float x=viewport.left+Math.min(inset,viewport.width()/2f),from=forward?viewport.bottom-inset:viewport.top+inset,to=forward?from-distance:from+distance;
                new androidx.test.espresso.action.GeneralSwipeAction(androidx.test.espresso.action.Swipe.SLOW,v->new float[]{x,from},v->new float[]{x,to},androidx.test.espresso.action.Press.FINGER).perform(controller,scroll);controller.loopMainThreadForAtLeast(250);
                String geometry="line="+next+" glyph="+top+".."+bottom+" viewport="+viewport+" textVisible="+visible+" scroll="+before+"->"+scroll.getScrollY()+" swipe="+from+"->"+to;android.util.Log.i("RookParagraph",geometry);assertTrue("The natural paragraph swipe did not move in the required direction: "+geometry,forward?scroll.getScrollY()>before:scroll.getScrollY()<before);
            }
            fail("Not every complete paragraph line became readable after bounded natural scrolling");
        }
    };}

    @Test public void quickCardHasOnePrimaryActionAndWholeIdentityOnANeutralSurface()throws Exception{
        state(xhttp,"connected");
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(allOf(withTagValue(is((Object)"quick-protocol-name")),isDisplayed())).check(matches(withText(SingleProtocols.XHTTP.title)));
            screen.onActivity(activity->{
                View card=tagged(activity,"quick-card-"+xhttp.get("id"));assertNotNull(card);
                assertTrue(card.getBackground() instanceof GradientDrawable);assertEquals(Color.WHITE,((GradientDrawable)card.getBackground()).getColor().getDefaultColor());
                assertEquals(1,descendants(card).stream().filter(v->v instanceof Button).count());
                TextView title=card.findViewWithTag("quick-protocol-name"),address=card.findViewWithTag("quick-server-address");
                assertEquals(SingleProtocols.XHTTP.title,title.getText().toString());assertEquals(server.get("host"),address.getText().toString());wholeText(title);wholeText(address);
                Button action=card.findViewWithTag("quick-connection-control");assertEquals("Disconnect",action.getText().toString());assertEquals(1,action.getLineCount());
                ImageView rook=card.findViewWithTag("quick-rook");assertTrue("Rook should not displace the task",rook.getHeight()<=Math.round(48*context.getResources().getDisplayMetrics().density));
            });ScreenshotProof.save(context,"presentation-neutral-quick-card");
        }
    }

    @Test public void aNewActiveConnectionIsShownButLaterFavoriteBrowsingIsNotHijacked()throws Exception{
        state(awg,"connected");
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->assertEquals(0,pager(activity).getCurrentItem()));
            screen.onActivity(activity->{state(awg,"disconnected");state(xhttp,"connected");activity.stateChanged();});idle();
            onView(allOf(withTagValue(is((Object)"quick-protocol-name")),isDisplayed())).check(matches(withText(SingleProtocols.XHTTP.title)));
            onView(withTagValue(is((Object)"quick-connection"))).perform(swipeLeft());idle();
            screen.onActivity(activity->assertEquals(1,pager(activity).getCurrentItem()));
            screen.onActivity(RookstrideActivity::stateChanged);idle();
            screen.onActivity(activity->assertEquals("Same active ID must permit browsing another favorite",1,pager(activity).getCurrentItem()));
            onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("VPNs")).perform(click());
            onView(allOf(withTagValue(is((Object)"quick-protocol-name")),isDisplayed())).check(matches(withText(SingleProtocols.XHTTP.title)));
            ScreenshotProof.save(context,"presentation-active-quick-selection");
        }
    }

    @Test public void everyQuickStateKeepsReadableStatusAndAStableActionEnvelope()throws Exception{
        state(xhttp,"connected");
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(allOf(withTagValue(is((Object)"quick-connection-control")),isDescendantOfA(withTagValue(is((Object)("quick-card-"+xhttp.get("id"))))))).perform(scrollTo()).check(matches(isDisplayed()));
            final int[] baseline={0,0};screen.onActivity(activity->{int[] location=new int[2];tagged(activity,"quick-connection-control").getLocationOnScreen(location);baseline[0]=location[1];baseline[1]=pager(activity).getHeight();});
            String[][] values={{"connected","Connected"},{"checking","Checking web access…"},{"limited","VPN on · Check web access"},{"stopping","Disconnecting…"},{"disconnected","Disconnected"},{"connecting","Connecting…"},{"failed","Connection failed"}};
            for(String[] value:values){screen.onActivity(activity->{state(xhttp,value[0]);activity.stateChanged();});Thread.sleep(100);idle();
                onView(allOf(withTagValue(is((Object)"quick-connection-status")),isDisplayed())).check((view,failure)->{if(failure!=null)throw failure;TextView status=(TextView)view;assertEquals(value[1],status.getContentDescription());wholeText(status);int last=status.getLineCount()-1;assertEquals("Status text was silently cut",status.getText().length(),status.getLayout().getLineEnd(last));assertTrue("Status height clipped its final line",status.getLayout().getLineBottom(last)<=status.getHeight()-status.getPaddingTop()-status.getPaddingBottom());});
                screen.onActivity(activity->assertQuickActionEnvelope(activity,baseline,value[1]));
            }
            screen.onActivity(activity->call(activity,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},xhttp,false));Thread.sleep(100);idle();screen.onActivity(activity->assertQuickActionEnvelope(activity,baseline,"Connecting…"));
            screen.onActivity(activity->{state(xhttp,"connected");activity.stateChanged();call(activity,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},xhttp,true);});Thread.sleep(100);idle();screen.onActivity(activity->assertQuickActionEnvelope(activity,baseline,"Disconnecting…"));
            ScreenshotProof.save(context,"presentation-stable-quick-status-envelope");
        }
    }
    private void assertQuickActionEnvelope(RookstrideActivity activity,int[] baseline,String fullStatus){
        Button control=(Button)tagged(activity,"quick-connection-control");int[] location=new int[2];control.getLocationOnScreen(location);assertEquals("The quick action moved between states",baseline[0],location[1]);assertEquals("The quick pager changed height",baseline[1],pager(activity).getHeight());wholeText(control);assertEquals(1,control.getLineCount());assertTrue("Action text is hidden behind its spinner or padding",control.getLayout().getLineWidth(0)<=control.getWidth()-control.getCompoundPaddingLeft()-control.getCompoundPaddingRight()+1);assertTrue("The accessible action lost the full VPN state",control.getContentDescription().toString().contains(fullStatus));
    }

    @Test public void startingAndStoppingKeepOneLineAndTheSameCardHeight()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            final int[] height={0};screen.onActivity(activity->height[0]=pager(activity).getHeight());
            screen.onActivity(activity->call(activity,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},awg,false));idle();
            onView(allOf(withTagValue(is((Object)"quick-connection-control")),isDisplayed())).check(matches(withText("Starting"))).check((view,error)->{if(error!=null)throw error;assertEquals(1,((Button)view).getLineCount());});
            screen.onActivity(activity->assertEquals(height[0],pager(activity).getHeight()));ScreenshotProof.save(context,"presentation-starting-single-line");
            screen.onActivity(activity->{state(awg,"connected");activity.stateChanged();});idle();
            screen.onActivity(activity->call(activity,"beginConnectionTap",new Class<?>[]{Gateway.class,boolean.class},awg,true));idle();
            onView(allOf(withTagValue(is((Object)"quick-connection-control")),isDisplayed())).check(matches(withText("Stopping"))).check((view,error)->{if(error!=null)throw error;assertEquals(1,((Button)view).getLineCount());});
            screen.onActivity(activity->assertEquals(height[0],pager(activity).getHeight()));ScreenshotProof.save(context,"presentation-stopping-single-line");
        }
    }

    @Test public void importedAccessHasOneTitleOneConnectAndMeaningfulAccountContext()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Open "+imported.get("name"))).perform(scrollTo()).check((card,error)->{
                if(error!=null)throw error;assertEquals(1,countText(card,SingleProtocols.AWG.title));assertEquals(1,countText(card,"Shared connection · family-guest"));assertEquals(0,countText(card,"Details"));
                List<View> buttons=new ArrayList<>();for(View child:descendants(card))if(child instanceof Button)buttons.add(child);assertEquals(1,buttons.size());
                assertTrue("Imported action should not become another full-width card",buttons.get(0).getWidth()<card.getWidth()*.85f);
            });ScreenshotProof.save(context,"presentation-imported-connection-row");
        }
    }

    @Test public void legacyImportedQuickCardReadsLocalEndpointAndAccountWithoutDuplicatingProtocol()throws Exception{
        imported.set("protocol","openvpn");imported.set("name",SingleProtocols.OPENVPN.title);imported.set("host","");imported.set("vpnLogin","1");imported.vpnPassword="chosen secret";imported.data.put("rememberVpn",true);
        String config="client\ndev tun\nremote vpn.example.invalid 1194\nremote-cert-tls server\nverify-x509-name vpn.example.invalid name\nauth-user-pass\n<ca>\nfixture\n</ca>\n",wrapped=PasswordSignIn.openVpn(config,"1","chosen secret").toString();org.strongswan.android.rookstride.engine.NativeProfileStore profiles=new org.strongswan.android.rookstride.engine.NativeProfileStore(context);assertFalse(profiles.exists(imported.get("id")));profiles.save(imported.get("id"),"openvpn",imported.get("name"),wrapped);
        java.io.File ciphertext=new java.io.File(new java.io.File(context.getNoBackupFilesDir(),"vpn-profiles"),imported.get("id")+".enc");byte[] originalCiphertext=java.nio.file.Files.readAllBytes(ciphertext.toPath());vault.write(new ArrayList<>(Arrays.asList(server,awg,xhttp,imported)));context.getSharedPreferences("rookstride-ui",0).edit().putString("lastConnectedId",imported.get("id")).commit();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            long end=android.os.SystemClock.elapsedRealtime()+10000;Gateway saved=null;while(android.os.SystemClock.elapsedRealtime()<end){for(Gateway node:vault.read())if(node.get("id").equals(imported.get("id")))saved=node;if(saved!=null&&saved.get("host").equals("vpn.example.invalid"))break;Thread.sleep(100);}assertNotNull(saved);assertEquals("vpn.example.invalid",saved.get("host"));assertEquals(1194,saved.data.getInt("vpnPort"));assertEquals("1",saved.get("vpnLogin"));assertEquals("chosen secret",saved.vpnPassword);assertTrue(saved.data.optBoolean("clientOnly"));assertFalse(saved.data.optBoolean("adminAccess"));idle();
            onView(allOf(withTagValue(is((Object)"quick-server-address")),isDisplayed())).check(matches(withText("vpn.example.invalid")));screen.onActivity(activity->{View quick=tagged(activity,"quick-card-"+imported.get("id"));assertEquals(1,countText(quick,SingleProtocols.OPENVPN.title));assertEquals(1,countText(quick,"VPN user 1"));assertEquals(0,countText(quick,"Imported connection"));assertFalse((Boolean)field(activity,"busy"));});
            screen.recreate();idle();onView(allOf(withTagValue(is((Object)"quick-server-address")),isDisplayed())).check(matches(withText("vpn.example.invalid")));assertArrayEquals("Reading display metadata rewrote encrypted VPN access",originalCiphertext,java.nio.file.Files.readAllBytes(ciphertext.toPath()));assertEquals(wrapped,profiles.read(imported.get("id")).getString("content"));assertFalse(DeploymentService.active());ScreenshotProof.save(context,"presentation-imported-quick-metadata");
        }finally{profiles.remove(imported.get("id"));}
    }

    @Test public void explicitActionIdentityKeepsOnlyTheChosenShareLoadingAfterReorder()throws Exception{
        AtomicInteger requests=new AtomicInteger();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{
                call(activity,"openScreen",new Class<?>[]{String.class},"AppSettings");
                LinearLayout body=(LinearLayout)field(activity,"body");body.removeAllViews();
                Runnable redraw=()->{
                    requests.incrementAndGet();set(activity,"busy",true);body.removeAllViews();
                    factoryButton(activity,body,"share-user:fixture:instance:b","share-target-b",()->requests.addAndGet(100));
                    factoryButton(activity,body,"share-user:fixture:instance:a","share-target-a",()->requests.addAndGet(100));
                };
                factoryButton(activity,body,"share-user:fixture:instance:a","share-target-a",redraw);
                factoryButton(activity,body,"share-user:fixture:instance:b","share-target-b",()->requests.addAndGet(100));
            });
            onView(withTagValue(is((Object)"share-target-a"))).perform(click());
            screen.onActivity(activity->{
                Button a=(Button)tagged(activity,"share-target-a"),b=(Button)tagged(activity,"share-target-b");
                assertTrue(a.getCompoundDrawables()[0] instanceof LoadingArc);assertFalse(b.getCompoundDrawables()[0] instanceof LoadingArc);
                assertFalse(a.isEnabled());assertFalse(b.isEnabled());assertEquals(1,requests.get());
            });ScreenshotProof.save(context,"presentation-one-share-loading");
        }
    }
    private Button factoryButton(RookstrideActivity activity,LinearLayout body,String identity,String tag,Runnable action){
        Button button=(Button)call(activity,"fullButtonFor",new Class<?>[]{String.class,LinearLayout.class,String.class,boolean.class,Runnable.class},identity,body,"Share",false,action);button.setTag(tag);return button;
    }

    private androidx.test.espresso.ViewAction heldPointerRelease(){return new androidx.test.espresso.ViewAction(){
        public org.hamcrest.Matcher<View> getConstraints(){return allOf(isCompletelyDisplayed(),isClickable(),isEnabled());}
        public String getDescription(){return "hold a labelled destination for650ms and release once";}
        public void perform(androidx.test.espresso.UiController controller,View view){
            int[] xy=new int[2];view.getLocationOnScreen(xy);float x=xy[0]+view.getWidth()/2f,y=xy[1]+view.getHeight()/2f;long down=android.os.SystemClock.uptimeMillis();
            android.view.MotionEvent event=android.view.MotionEvent.obtain(down,down,android.view.MotionEvent.ACTION_DOWN,x,y,0);event.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            try{assertTrue("The real labelled hold DOWN was not injected",controller.injectMotionEvent(event));}catch(androidx.test.espresso.InjectEventSecurityException failure){throw new AssertionError(failure);}finally{event.recycle();}
            controller.loopMainThreadForAtLeast(650);event=android.view.MotionEvent.obtain(down,android.os.SystemClock.uptimeMillis(),android.view.MotionEvent.ACTION_UP,x,y,0);event.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            try{assertTrue("The real labelled hold UP was not injected",controller.injectMotionEvent(event));}catch(androidx.test.espresso.InjectEventSecurityException failure){throw new AssertionError(failure);}finally{event.recycle();}controller.loopMainThreadUntilIdle();
        }
    };}

    @Test public void allFiveDestinationsKeepWholeLabelsOrExplicitAccessibleIconTargets()throws Exception{
        String[] destinations={"Home","Servers","Routing","Stories","AppSettings"},labels={"VPNs","Servers","Split","Journal","App settings"};
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            for(int selected=0;selected<destinations.length;selected++){
                final int current=selected;onView(withTagValue(is((Object)("bottom-destination-"+destinations[selected])))).perform(click());
                screen.onActivity(activity->{
                    View nav=tagged(activity,"bottom-navigation");assertNotNull(nav);int visible=0;
                    for(int i=0;i<destinations.length;i++){
                        View target=tagged(activity,"bottom-destination-"+destinations[i]);TextView label=target.findViewWithTag("bottom-label");assertNotNull(label);assertEquals(labels[i],target.getContentDescription().toString());assertEquals(i==current,target.isSelected());
                        assertTrue("Navigation target must stay at least48dp",target.getWidth()>=Math.round(48*context.getResources().getDisplayMetrics().density)&&target.getHeight()>=Math.round(48*context.getResources().getDisplayMetrics().density));
                        if(label.getVisibility()==View.VISIBLE){visible++;wholeWords(label);assertNull("Visible destination words need no competing tooltip gesture",target.getTooltipText());assertFalse("Visible destination words must not consume a long hold",target.isLongClickable());}else{assertEquals("Only a deliberate icon fallback may hide a label",View.GONE,label.getVisibility());assertEquals(labels[i],target.getTooltipText().toString());assertTrue("The icon fallback retains its discoverable native tooltip",target.isLongClickable());}
                    }
                    assertTrue("Navigation must consistently show all labels or use all accessible icons",visible==0||visible==5);
                    if(visible==0){boolean wouldClip=false;for(int i=0;i<destinations.length;i++){View target=tagged(activity,"bottom-destination-"+destinations[i]);TextView label=target.findViewWithTag("bottom-label");wouldClip|=label.getPaint().measureText(label.getText().toString())>target.getWidth()-target.getPaddingLeft()-target.getPaddingRight();}assertTrue("Do not remove readable navigation labels unnecessarily",wouldClip);}
                });
            }
            final boolean[] labelled={false};screen.onActivity(activity->{View target=tagged(activity,"bottom-destination-Servers");labelled[0]=target.findViewWithTag("bottom-label").getVisibility()==View.VISIBLE;});
            if(labelled[0]){
                // One real650ms hold, no repeated tap or direct performClick.
                onView(withTagValue(is((Object)"bottom-destination-Servers"))).perform(heldPointerRelease());
                screen.onActivity(activity->{assertEquals("The first labelled hold/release must activate its destination","Servers",field(activity,"tab"));assertTrue(tagged(activity,"bottom-destination-Servers").isSelected());});
                ScreenshotProof.save(context,"presentation-held-navigation");
            }
            ScreenshotProof.save(context,"presentation-adaptive-bottom-navigation");
        }
    }

    @Test public void completedMaintenanceShowsOneHeadingSeparatedDetailAndVisibleDone()throws Exception{
        InstallationProgress completed=new InstallationProgress("helper-update",awg.get("id"),System.currentTimeMillis()-38000);completed.finish();
        context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",completed.json().toString()).commit();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"openScreen",new Class<?>[]{String.class},"Progress"));
            onView(withTagValue(is((Object)"completion-heading"))).perform(scrollTo()).check(matches(isCompletelyDisplayed())).check((view,error)->{if(error!=null)throw error;wholeWords((TextView)view);assertEquals("Maintenance complete",view.getContentDescription().toString());});onView(withText("Server checks completed")).check(doesNotExist());
            onView(withText("Done")).check(matches(isCompletelyDisplayed()));onView(withText("Server tools")).check(matches(isCompletelyDisplayed())).check((view,error)->{if(error!=null)throw error;wholeWords((TextView)view);});
            screen.onActivity(activity->{
                View breadcrumbs=tagged(activity,"breadcrumbs");assertNotNull(breadcrumbs);assertEquals(1,countText(breadcrumbs,"Server maintenance"));assertEquals(0,countText(breadcrumbs,"Installation"));
                View card=tagged(activity,"installation-complete");assertEquals("Show one visible full task meaning",1,descendants(card).stream().filter(v->v instanceof TextView&&v.isShown()&&((TextView)v).getText().toString().equals("Maintenance complete")).count());TextView heading=(TextView)tagged(activity,"completion-heading"),taskContext=(TextView)tagged(activity,"completion-heading-context");if(heading.getText().toString().equals("Complete")){assertTrue(taskContext.isShown());assertEquals("Maintenance complete",taskContext.getText().toString());wholeWords(taskContext);}else{assertEquals("Maintenance complete",heading.getText().toString());assertEquals(View.GONE,taskContext.getVisibility());}
                TextView elapsed=null,detail=null;for(View view:descendants(card))if(view instanceof TextView){String text=((TextView)view).getText().toString();if(text.startsWith("Elapsed"))elapsed=(TextView)view;if(text.equals(completed.phase))detail=(TextView)view;}
                assertNotNull(elapsed);assertNotNull(detail);int[] e={0,0},d={0,0};elapsed.getLocationOnScreen(e);detail.getLocationOnScreen(d);
                assertTrue("Separate result detail from optional timing",e[1]-d[1]-detail.getHeight()>=Math.round(12*context.getResources().getDisplayMetrics().density));
            });ScreenshotProof.save(context,"presentation-maintenance-completed");
        }
    }

    @Test public void maintenanceCategoriesRevealOnlyTheirOwnActionsAndRemainDiscoverable()throws Exception{
        Gateway pair=awg;pair.set("name","Two stations");pair.set("pairEngine","native-v2");pair.set("pairId","0123456789abcdef0123456789abcdef");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","awg");pair.data.put("pairReady",true);pair.exit=new Gateway();pair.exit.set("host","south.example.net");pair.exit.set("serverName","South station");vault.write(new ArrayList<>(Arrays.asList(pair)));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Servers")).perform(click());onView(withContentDescription("Manage North station")).perform(scrollTo(),click());onView(withText("Server maintenance")).perform(scrollTo(),click());
            String[] keys={"access","checks","route","cleanup"},names={"Access & administrators","Checks & updates","Double VPN & recovery","Remove or rebuild"};
            for(String key:keys)onView(withTagValue(is((Object)("maintenance-section-"+key)))).check(matches(withEffectiveVisibility(Visibility.GONE)));
            ScreenshotProof.save(context,"presentation-maintenance-index");
            for(int i=0;i<keys.length;i++){
                onView(withContentDescription("Expand "+names[i])).perform(scrollTo(),click());
                for(int j=0;j<keys.length;j++)onView(withTagValue(is((Object)("maintenance-section-"+keys[j])))).check(matches(withEffectiveVisibility(i==j?Visibility.VISIBLE:Visibility.GONE)));
            }
            screen.recreate();
            onView(withTagValue(is((Object)"maintenance-section-cleanup"))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));
            onView(withText("Advanced")).check(doesNotExist());onView(withText("Remove both VPN setups")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withContentDescription("Collapse Remove or rebuild")).perform(scrollTo(),click());onView(withTagValue(is((Object)"maintenance-section-cleanup"))).check(matches(withEffectiveVisibility(Visibility.GONE)));
            assertFalse(DeploymentService.active());ScreenshotProof.save(context,"presentation-maintenance-categories");
        }
    }

    @Test public void pendingMaintenanceHasADirectReviewWithoutAutomaticallyResumingIt()throws Exception{
        Gateway pair=awg;pair.set("name","Two stations");pair.set("pairEngine","native-v2");pair.set("pairId","0123456789abcdef0123456789abcdef");pair.set("pairEntryProtocol","awg");pair.set("pairExitProtocol","awg");pair.data.put("pairReady",true).put("engineUpdate",new JSONObject().put("state","prepared").put("group","awg"));pair.exit=new Gateway();pair.exit.set("host","south.example.net");vault.write(new ArrayList<>(Arrays.asList(pair)));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{Gateway live=((ArrayList<Gateway>)field(activity,"gateways")).get(0);call(activity,"openMaintenance",new Class<?>[]{Gateway.class},live);});
            onView(withText("A server change needs review")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Review change")).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());
            onView(withTagValue(is((Object)"maintenance-section-checks"))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));onView(withText("Resume VPN runtime update")).perform(scrollTo()).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
            screen.onActivity(activity->{try{Gateway live=((ArrayList<Gateway>)field(activity,"gateways")).get(0);live.data.remove("engineUpdate");live.data.put("entryMigration",new JSONObject().put("state","awaiting-endpoint-switch").put("new_address",true));set(activity,"maintenanceSection","");call(activity,"openMaintenance",new Class<?>[]{Gateway.class},live);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Review change")).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());onView(withTagValue(is((Object)"maintenance-section-route"))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)));onView(withText("Verify & finish entry replacement")).perform(scrollTo()).check(matches(isDisplayed()));assertFalse(DeploymentService.active());
            ScreenshotProof.save(context,"presentation-pending-operation-review");
        }
    }

    @Test public void suggestionsExplainTheirReasonWithoutHidingTheDefaultOrOtherChoices()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"addPair",new Class<?>[]{}));
            onView(withText(SingleProtocols.AWG.title)).check(matches(isChecked()));
            onView(allOf(withText("Suggested start"),isDescendantOfA(withTagValue(is((Object)"pair-choice-awg"))))).check(matches(isDisplayed()));
            onView(allOf(withText("Details"),isDescendantOfA(withTagValue(is((Object)"pair-choice-awg"))))).perform(scrollTo(),click());
            onView(withSubstring("Why suggested:")).perform(readEveryLineNaturally());onView(withText("Close")).perform(click());
            onView(withText(SingleProtocols.AWG.title)).check(matches(isChecked()));
            onView(allOf(withText("HTTPS alternative"),isDescendantOfA(withTagValue(is((Object)"pair-choice-trusttunnel"))))).perform(scrollTo()).check(matches(isDisplayed()));
            onView(allOf(withText("Details"),isDescendantOfA(withTagValue(is((Object)"pair-choice-trusttunnel"))))).perform(scrollTo(),click());
            onView(withSubstring("Why an alternative:")).perform(readEveryLineNaturally());onView(withText("Close")).perform(click());
            onView(withText(SingleProtocols.AWG.title)).check(matches(isChecked()));onView(withText(SingleProtocols.TRUSTTUNNEL.title)).check(matches(isNotChecked()));
            screen.onActivity(activity->{PairSetupState draft=(PairSetupState)field(activity,"pairDraft");assertEquals("Reading another protocol must not choose it","awg",draft.entry);});
            onView(withText(SingleProtocols.TRUSTTUNNEL.title)).perform(scrollTo(),click()).check(matches(isChecked()));onView(withText(SingleProtocols.AWG.title)).check(matches(isNotChecked()));
            ScreenshotProof.save(context,"presentation-protocol-suggestions");onView(withText("Cancel")).perform(click());assertFalse(DeploymentService.active());
        }
    }
}
