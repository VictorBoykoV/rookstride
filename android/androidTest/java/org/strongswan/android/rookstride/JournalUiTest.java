package org.strongswan.android.rookstride;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.ScrollView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.not;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;

/** Exact native Journal, saved identity and confirmed-user completion journeys. No live VPS. */
@RunWith(AndroidJUnit4.class)
public class JournalUiTest {
    private final Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
    private static Object field(Object a,String name)throws Exception{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(a);}
    private static void call(Object a,String name,Class<?>[] types,Object...args)throws Exception{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(a,args);}
    private static boolean hasWeb(View v){if(v instanceof WebView)return true;if(v instanceof ViewGroup)for(int i=0;i<((ViewGroup)v).getChildCount();i++)if(hasWeb(((ViewGroup)v).getChildAt(i)))return true;return false;}
    private java.util.ArrayList<Gateway> savedNodes;
    @org.junit.After public void cleanup()throws Exception{new Vault(context).write(savedNodes);}
    @org.junit.Before public void setup()throws Exception{savedNodes=new Vault(context).read();new Vault(context).write(new java.util.ArrayList<>());context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();}
    @Test public void journalIsNativeOfflineAndRetainsItsPageOnReselect()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Journal")).perform(click());onView(withText("Coming soon")).perform(scrollTo()).check(matches(isDisplayed()));
            final ScrollView[] page={null};screen.onActivity(a->{try{page[0]=(ScrollView)field(a,"pageScroll");assertFalse(hasWeb(a.getWindow().getDecorView()));}catch(Exception e){throw new AssertionError(e);}});
            for(int i=0;i<4;i++)onView(withContentDescription("Journal")).perform(click());
            screen.onActivity(a->{try{assertSame(page[0],field(a,"pageScroll"));}catch(Exception e){throw new AssertionError(e);}});ScreenshotProof.save(context,"journal-placeholder");
            screen.recreate();onView(withText("Coming soon")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Settings")).perform(click());onView(withText("Journal storage")).perform(scrollTo(),click());onView(withText("Done")).perform(click());
        }
    }
    @Test public void firstIdentityIsRememberedBeforeRetryAndChangedIdentityStops()throws Exception{
        Gateway node=new Gateway();node.set("host","identity-ui.example.net");String pin="SHA256:"+new String(new char[43]).replace('\0','A'),changed="SHA256:"+new String(new char[43]).replace('\0','B');ServerIdentityPins pins=new ServerIdentityPins(context);pins.forget(node);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            AtomicInteger retries=new AtomicInteger();screen.onActivity(a->{try{call(a,"trust",new Class<?>[]{Gateway.class,Ssh.HostTrust.class,Runnable.class},node,new Ssh.HostTrust(pin,false,node),(Runnable)()->{try{assertEquals(pin,new ServerIdentityPins(context).get(node));retries.incrementAndGet();}catch(Exception e){throw new AssertionError(e);}});}catch(Exception e){throw new AssertionError(e);}});
            assertEquals(1,retries.get());assertEquals(pin,pins.get(node));node.set("fingerprint","");
            screen.onActivity(a->{try{call(a,"trust",new Class<?>[]{Gateway.class,Ssh.HostTrust.class,Runnable.class},node,new Ssh.HostTrust(changed,false,node),(Runnable)retries::incrementAndGet);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Server identity changed")).check(matches(isDisplayed()));assertEquals(1,retries.get());assertEquals(pin,pins.get(node));onView(withText("Trust replacement")).check(matches(not(isEnabled())));onView(withText("Cancel")).perform(click());
        }finally{pins.forget(node);}
    }
    @Test public void newDraftCannotReplaceAnExistingServerIdentity()throws Exception{
        String pin="SHA256:"+new String(new char[43]).replace('\0','C'),changed="SHA256:"+new String(new char[43]).replace('\0','D');
        Gateway existing=new Gateway();existing.set("host","legacy-pin-ui.example.net");existing.set("fingerprint",pin);new Vault(context).write(new java.util.ArrayList<>(java.util.Arrays.asList(existing)));
        Gateway draft=new Gateway();draft.set("host",existing.get("host"));ServerIdentityPins pins=new ServerIdentityPins(context);pins.forget(draft);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            AtomicInteger retries=new AtomicInteger();assertEquals(pin,pins.get(draft));
            screen.onActivity(a->{try{call(a,"trust",new Class<?>[]{Gateway.class,Ssh.HostTrust.class,Runnable.class},draft,new Ssh.HostTrust(changed,false,draft),(Runnable)retries::incrementAndGet);}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Server identity changed")).check(matches(isDisplayed()));assertEquals(0,retries.get());assertEquals(pin,pins.get(draft));onView(withText("Trust replacement")).check(matches(not(isEnabled())));onView(withText("Cancel")).perform(click());
        }finally{pins.forget(draft);}
    }
    @Test public void newlyCreatedConnectionOffersSharingAcrossRecreation()throws Exception{
        Vault vault=new Vault(context);java.util.ArrayList<Gateway> original=vault.read();Gateway node=new Gateway();node.set("host","share-ui.example.net");node.set("protocol","awg");vault.write(new java.util.ArrayList<>(java.util.Arrays.asList(node)));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(a->{try{NewUserShareState state=(NewUserShareState)field(a,"newUserShare");state.created(node.get("id"),"laptop","");state.profile=new JSONObject().put("format","awg").put("name","rook-0123456789.conf").put("content","[Interface]\n# sample fixture");call(a,"restoreCreatedUserShare",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("Share connection")).check(matches(isDisplayed()));onView(withText("Share connection file")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Share configuration text")).perform(scrollTo()).check(matches(isDisplayed()));
            screen.recreate();onView(withText("Share connection")).check(matches(isDisplayed()));ScreenshotProof.save(context,"new-user-share");onView(withText("Done")).perform(click());
            screen.onActivity(a->{try{assertFalse(((NewUserShareState)field(a,"newUserShare")).pending);}catch(Exception e){throw new AssertionError(e);}});
        }finally{vault.write(original);}
    }
    @Test public void confirmedAccountWithMissingExportOffersOnlyReadRetry()throws Exception{
        Vault vault=new Vault(context);java.util.ArrayList<Gateway> original=vault.read();Gateway node=new Gateway();node.set("host","share-retry.example.net");vault.write(new java.util.ArrayList<>(java.util.Arrays.asList(node)));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(a->{try{NewUserShareState state=(NewUserShareState)field(a,"newUserShare");state.created(node.get("id"),"laptop","SamplePass12");call(a,"restoreCreatedUserShare",new Class<?>[]{});}catch(Exception e){throw new AssertionError(e);}});
            onView(withText("User created")).check(matches(isDisplayed()));onView(withText("Retry sharing")).check(matches(isDisplayed()));screen.recreate();onView(withText("Retry sharing")).check(matches(isDisplayed()));onView(withText("Later")).perform(click());
        }finally{vault.write(original);}
    }
}
