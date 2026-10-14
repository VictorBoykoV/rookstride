package org.strongswan.android.rookstride;

import android.content.Context;
import android.os.Build;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;

/** Real foreground service with a bounded transport fixture: no VPS mutation. */
@RunWith(AndroidJUnit4.class)
public class DeploymentNavigationTest {
    @org.junit.Before public void englishFixture(){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.forLanguageTags("en")));}
    @Test public void pairedHealthFinishesEightCheckpointRecipe()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        String oldProgress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
        Field engine=DeploymentService.class.getDeclaredField("engine"),current=DeploymentService.class.getDeclaredField("current");engine.setAccessible(true);current.setAccessible(true);Object previous=engine.get(null);
        CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        engine.set(null,(DeploymentService.Engine)(service,s)->{service.checkpoint(s,6,"Fixture: checking both gateway health reports");started.countDown();if(!finish.await(60,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("entry",new JSONObject().put("fixture",true)).put("exit",new JSONObject().put("fixture",true)).put("exit_ip","203.0.113.20");});
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            Gateway node=new Gateway();node.set("name","Two-server UI fixture");node.set("host","entry.example.net");node.exit=new Gateway();node.exit.set("host","exit.example.net");ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);
            activity.onActivity(a->DeploymentService.launch(a,node,nodes,"pair",new JSONObject(),false));
            assertTrue(started.await(15,TimeUnit.SECONDS));activity.recreate();
            onView(withText("Stories")).perform(click());assertTrue(DeploymentService.active());
            onView(withSubstring("Tap to view")).perform(click());onView(withText("Rook is on the route.")).check(matches(isDisplayed()));
            assertEquals(8,DeploymentService.current().progress.steps().length);assertEquals(6,DeploymentService.current().progress.completed);
            ScreenshotProof.save(context,"pair-progress-fixture");finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);
            assertEquals("complete",DeploymentService.current().progress.state);assertEquals(8,DeploymentService.current().progress.completed);
            assertTrue(node.data.getJSONObject("snapshot").getBoolean("fixture"));assertTrue(node.exit.data.getJSONObject("snapshot").getBoolean("fixture"));
        }finally{finish.countDown();engine.set(null,previous);current.set(null,null);vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();}
    }
    @Test public void serviceSurvivesStoriesGuideRecreationAndBackground()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        String oldProgress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
        if(Build.VERSION.SDK_INT>=33)InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("pm grant "+context.getPackageName()+" android.permission.POST_NOTIFICATIONS").close();
        Field engine=DeploymentService.class.getDeclaredField("engine"),current=DeploymentService.class.getDeclaredField("current");engine.setAccessible(true);current.setAccessible(true);Object previous=engine.get(null);
        CountDownLatch started=new CountDownLatch(1),advance=new CountDownLatch(1),finish=new CountDownLatch(1);
        engine.set(null,(DeploymentService.Engine)(service,s)->{service.checkpoint(s,2,"Fixture: preparing VPN and DNS");started.countDown();if(!advance.await(60,TimeUnit.SECONDS))throw new Exception("fixture timeout");service.checkpoint(s,3,"Fixture: adding management");if(!finish.await(60,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("services",new JSONObject());});
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            Gateway node=new Gateway();node.set("name","UI service fixture");node.set("host","vpn.example.net");ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);
            activity.onActivity(a->{DeploymentService.launch(a,node,nodes,"single",new JSONObject(),false);});
            assertTrue(started.await(15,TimeUnit.SECONDS));InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            // Add the shortcut to this initial screen, then browse while the worker is blocked.
            activity.recreate();onView(withText("Stories")).perform(click());onView(isAssignableFrom(android.webkit.WebView.class)).check(matches(isDisplayed()));
            onView(withText("Guide")).perform(click());onView(isAssignableFrom(android.webkit.WebView.class)).check(matches(isDisplayed()));
            onView(withSubstring("Tap to view")).perform(click());onView(withText("Rook is on the route.")).check(matches(isDisplayed()));
            ScreenshotProof.save(context,"progress-fixture");
            activity.recreate();assertTrue(DeploymentService.active());
            activity.moveToState(Lifecycle.State.CREATED);advance.countDown();Thread.sleep(400);assertTrue(DeploymentService.active());
            activity.moveToState(Lifecycle.State.RESUMED);onView(withSubstring("Fixture: adding management")).check(matches(isDisplayed()));
            finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);
            assertEquals("complete",DeploymentService.current().progress.state);assertEquals(5,DeploymentService.current().progress.completed);
        }finally{advance.countDown();finish.countDown();engine.set(null,previous);current.set(null,null);vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();}
    }
}
