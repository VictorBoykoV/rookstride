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
    @Test public void pairedHealthFinishesTenCheckpointRecipe()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        String oldProgress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
        Field engine=DeploymentService.class.getDeclaredField("engine"),current=DeploymentService.class.getDeclaredField("current");engine.setAccessible(true);current.setAccessible(true);Object previous=engine.get(null);
        CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        engine.set(null,(DeploymentService.Engine)(service,s)->{service.checkpoint(s,9,"Fixture: checking both gateway health reports");started.countDown();if(!finish.await(60,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("entry",new JSONObject().put("fixture",true)).put("exit",new JSONObject().put("fixture",true)).put("exit_ip","203.0.113.20");});
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            Gateway node=new Gateway();node.set("name","Two-server UI fixture");node.set("host","entry.example.net");node.exit=new Gateway();node.exit.set("host","exit.example.net");ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);
            activity.onActivity(a->DeploymentService.launch(a,node,nodes,"pair",new JSONObject(),false));
            assertTrue(started.await(15,TimeUnit.SECONDS));activity.recreate();
            onView(withContentDescription("Journal")).perform(click());assertTrue(DeploymentService.active());
            onView(withSubstring("View progress")).perform(click());onView(withText("Installing VPN")).check(matches(isDisplayed()));
            onView(withText(context.getString(org.strongswan.android.R.string.show_log))).check((view,error)->{if(error!=null)throw error;android.view.View hero=view.getRootView().findViewWithTag("installation-progress-card");assertNotNull(hero);int[] logPosition=new int[2],cardPosition=new int[2];view.getLocationOnScreen(logPosition);hero.getLocationOnScreen(cardPosition);assertTrue("Progress card touches the log button",cardPosition[1]-logPosition[1]-view.getHeight()>=Math.round(12*context.getResources().getDisplayMetrics().density)-1);}).check(matches(isEnabled())).perform(click());
            androidx.test.espresso.Espresso.pressBack();assertTrue(DeploymentService.active());
            assertEquals(10,DeploymentService.current().progress.steps().length);assertEquals(9,DeploymentService.current().progress.completed);
            ScreenshotProof.save(context,"pair-progress-fixture");finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);
            assertEquals("complete",DeploymentService.current().progress.state);assertEquals(10,DeploymentService.current().progress.completed);
            InstallationProgress completed=DeploymentService.current().progress;assertTrue(completed.finished>0);assertEquals(RookText.elapsed(context,completed,completed.finished),RookText.elapsed(context,completed,completed.finished+7_200_000));
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
            activity.recreate();onView(withContentDescription("Journal")).perform(click());onView(withText("Coming soon")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withContentDescription("App settings")).perform(click());onView(withText("Help & FAQ")).perform(scrollTo(),click());onView(withText("How do I connect?  +")).check(matches(isDisplayed()));
            onView(withSubstring("View progress")).perform(click());onView(withText("Installing VPN")).check(matches(isDisplayed()));
            ScreenshotProof.save(context,"progress-fixture");
            activity.recreate();assertTrue(DeploymentService.active());
            activity.moveToState(Lifecycle.State.CREATED);advance.countDown();Thread.sleep(400);assertTrue(DeploymentService.active());
            activity.moveToState(Lifecycle.State.RESUMED);onView(withSubstring("Fixture: adding management")).check(matches(isDisplayed()));
            finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);
            assertEquals("complete",DeploymentService.current().progress.state);assertEquals(5,DeploymentService.current().progress.completed);
        }finally{advance.countDown();finish.countDown();engine.set(null,previous);current.set(null,null);vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();}
    }
    @Test public void protocolSettingsUpdatesExistingPhoneProfilePort()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        String selected=context.getSharedPreferences("rookstride-ui",0).getString("selected",null);
        context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
        Gateway node=new Gateway();node.set("name","Client port fixture");node.set("host","vpn.example.net");node.set("admin","root");
        org.strongswan.android.data.VpnProfile profile=new org.strongswan.android.data.VpnProfile();profile.setName("Client port fixture");profile.setGateway("vpn.example.net");profile.setVpnType(org.strongswan.android.data.VpnType.IKEV2_EAP);profile.setUsername("example-user");
        org.strongswan.android.data.VpnProfileDataSource source=new org.strongswan.android.data.VpnProfileSource(context);source.open();source.insertProfile(profile);node.set("profileUuid",profile.getUUID().toString());node.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("strongswan-starter",true)));
        ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);vault.write(nodes);context.getSharedPreferences("rookstride-ui",0).edit().putString("selected",node.get("id")).commit();
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withContentDescription("Servers")).perform(click());
            onView(withContentDescription("Manage Client port fixture")).perform(scrollTo(),click());
            onView(withText("IKEv2")).perform(scrollTo(),click());
            onView(withText("Phone connection options")).perform(scrollTo(),click());
            onView(org.hamcrest.Matchers.allOf(isAssignableFrom(android.widget.EditText.class),withText("500"))).perform(scrollTo(),replaceText("4500"));
            androidx.test.espresso.Espresso.closeSoftKeyboard();
            onView(withText("Save")).perform(click());
            assertEquals(Integer.valueOf(4500),source.getVpnProfile(profile.getUUID().toString()).getPort());
            assertEquals(4500,vault.read().get(0).data.getInt("vpnPort"));
            onView(withContentDescription("VPNs")).perform(click());
            onView(withText("Add VPN")).perform(click());onView(withText("Set up a VPN")).perform(scrollTo(),click());onView(withText("Single-server VPN")).perform(click());onView(withText("IKEv2")).perform(scrollTo(),click());onView(withText("Connection options")).perform(scrollTo(),click());
            onView(org.hamcrest.Matchers.allOf(isAssignableFrom(android.widget.EditText.class),withText("500"))).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Cancel")).perform(click());
        }finally{source.deleteVpnProfile(profile);source.close();vault.write(original);context.getSharedPreferences("rookstride-ui",0).edit().putString("selected",selected).commit();}
    }
    @Test public void maintenanceSurvivesRecreationWithoutReplacingVpnUsers()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();String oldProgress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        Field engine=DeploymentService.class.getDeclaredField("engine"),current=DeploymentService.class.getDeclaredField("current");engine.setAccessible(true);current.setAccessible(true);Object previous=engine.get(null);CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        engine.set(null,(DeploymentService.Engine)(service,session)->{service.checkpoint(session,3,"Fixture: guarded replacement route verified");started.countDown();if(!finish.await(60,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("state","active");});
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            Gateway node=new Gateway();node.set("host","entry.example.net");node.set("name","Maintenance fixture");node.exit=new Gateway();node.exit.set("host","exit.example.net");node.data.put("snapshot",new JSONObject().put("retained_user","existing-client"));ArrayList<Gateway> nodes=new ArrayList<>(Arrays.asList(node));
            JSONObject configuration=new JSONObject().put("action","replace");activity.onActivity(a->DeploymentService.launch(a,node,nodes,"lifecycle-exit",configuration,false));assertTrue(started.await(15,TimeUnit.SECONDS));activity.recreate();onView(withContentDescription("Journal")).perform(click());assertTrue(DeploymentService.active());onView(withSubstring("View progress")).perform(click());onView(withText("Replacing exit server")).check(matches(isDisplayed()));assertEquals(4,DeploymentService.current().progress.steps().length);
            finish.countDown();for(int n=0;n<100&&DeploymentService.active();n++)Thread.sleep(100);assertEquals("complete",DeploymentService.current().progress.state);assertEquals("existing-client",node.data.getJSONObject("snapshot").getString("retained_user"));assertEquals("active",node.get("maintenanceStatus"));assertTrue(DeploymentService.current().progress.phase.contains("Verify actual client traffic"));
        }finally{finish.countDown();engine.set(null,previous);current.set(null,null);vault.write(original);context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();}
    }
}
