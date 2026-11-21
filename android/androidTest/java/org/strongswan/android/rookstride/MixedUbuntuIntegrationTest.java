package org.strongswan.android.rookstride;
import android.content.*;import android.os.SystemClock;import androidx.test.core.app.ActivityScenario;import androidx.test.platform.app.InstrumentationRegistry;import androidx.test.ext.junit.runners.AndroidJUnit4;import org.junit.Test;import org.junit.runner.RunWith;import org.json.*;import org.strongswan.android.ui.RookstrideActivity;import java.io.*;import java.nio.file.Files;import java.lang.reflect.*;import java.util.*;
import static org.junit.Assert.*;import static org.junit.Assume.*;import static org.hamcrest.Matchers.*;import static androidx.test.espresso.Espresso.*;import static androidx.test.espresso.action.ViewActions.*;import static androidx.test.espresso.matcher.ViewMatchers.*;import static androidx.test.espresso.assertion.ViewAssertions.*;
/** Opt-in owned disposable nodes. Real APK/service/SSH deployment; Linux traffic is a separate gate. */
@RunWith(AndroidJUnit4.class) public class MixedUbuntuIntegrationTest {
 /** Test fixture keys come from the disposable VM console; Android/JVM may negotiate different host algorithms. */
 static void verifyFixture(Gateway node)throws Exception{JSONArray pins=node.data.getJSONArray("pins");node.set("fingerprint","");try(Ssh ignored=new Ssh(node)){fail("Unpinned SSH key accepted");}catch(Ssh.HostTrust trust){boolean known=false;for(int i=0;i<pins.length();i++)if(pins.getString(i).equals(trust.fingerprint))known=true;assertTrue("Presented key is absent from the independently recorded fixture pins",known);node.set("fingerprint",trust.fingerprint);}}
 static Object value(Object a,String key)throws Exception{Field f=a.getClass().getDeclaredField(key);f.setAccessible(true);return f.get(a);}
 static void invoke(Object a,String name,Class<?>[] types,Object...args)throws Exception{Method m=a.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(a,args);}
 @Test public void signedAppDeploysMixedNodesAndShowsUserCreationProgress()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File fixture=new File(c.getFilesDir(),"mixed-ubuntu-integration.json");assumeTrue("No disposable pair fixture",fixture.isFile());JSONObject options=new JSONObject(new String(Files.readAllBytes(fixture.toPath()),"UTF-8"));assumeTrue(options.optBoolean("disposable"));Gateway node=new Gateway(options.getJSONObject("gateway"));assertTrue(node.isPair());assertEquals("native-v2",node.get("pairEngine"));
  ArrayList<Gateway> old=new Vault(c).read();String prior=c.getSharedPreferences("rookstride-deployment",0).getString("progress",null);Field current=DeploymentService.class.getDeclaredField("current");current.setAccessible(true);Object previous=current.get(null);assertFalse(DeploymentService.active());JSONObject result=new JSONObject();
  try{
   verifyFixture(node);verifyFixture(node.exit);
   JSONObject review=PairPreparationController.review(node,()->c.getAssets().open("gateway_bundle.zip"),()->c.getAssets().open("single_bundle.zip"));PairPreparationController.apply(node,review,()->c.getAssets().open("gateway_bundle.zip"),()->c.getAssets().open("single_bundle.zip"),phase->{});
   try(Ssh a=new Ssh(node);Ssh b=new Ssh(node.exit)){JSONObject x=a.probe(),y=b.probe();assertNotEquals(x.getString("version"),y.getString("version"));result.put("entry_ubuntu",x.getString("version")).put("exit_ubuntu",y.getString("version"));}
   ArrayList<Gateway> nodes=new ArrayList<>(Arrays.asList(node));new Vault(c).write(nodes);c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    screen.onActivity(a->{try{Field f=a.getClass().getDeclaredField("gateways");f.setAccessible(true);f.set(a,nodes);invoke(a,"runPair",new Class<?>[]{Gateway.class,boolean.class},node,true);}catch(Exception e){throw new AssertionError(e);}});
    long end=SystemClock.elapsedRealtime()+1800000;while(DeploymentService.current()==null&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);assertNotNull(DeploymentService.current());
    onView(withContentDescription("Journal")).perform(click());screen.recreate();
    while(DeploymentService.active()&&SystemClock.elapsedRealtime()<end)Thread.sleep(500);
    DeploymentService.Session session=DeploymentService.current();assertEquals(session.progress.phase,"complete",session.progress.state);assertEquals(10,session.progress.completed);assertTrue(session.result.getJSONObject("entry").optBoolean("monitoring_available"));result.put("app_service_deployed_both_nodes",true).put("journal_and_recreation_preserved_installation",true);
    screen.onActivity(a->{try{invoke(a,"openVpn",new Class<?>[]{Gateway.class},node);invoke(a,"openUsers",new Class<?>[]{Gateway.class},node);}catch(Exception e){throw new AssertionError(e);}});
    onView(withText("Add new user")).perform(scrollTo(),click());onView(isAssignableFrom(android.widget.EditText.class)).perform(replaceText("phone-ui-test"),androidx.test.espresso.action.ViewActions.closeSoftKeyboard());onView(withText("Create user")).perform(click()).check(matches(not(isEnabled())));
    screen.onActivity(a->{try{androidx.appcompat.app.AlertDialog d=(androidx.appcompat.app.AlertDialog)value(a,"newUserDialog");assertNotNull(d);assertTrue(d.isShowing());assertTrue(d.getButton(-1).getCompoundDrawables()[0] instanceof LoadingArc);}catch(Exception e){throw new AssertionError(e);}});
    long wait=SystemClock.elapsedRealtime()+45000;boolean[] shared={false};while(SystemClock.elapsedRealtime()<wait){screen.onActivity(a->{try{NewUserShareState share=(NewUserShareState)value(a,"newUserShare");shared[0]=share.profile!=null&&!share.loading;}catch(Exception e){throw new AssertionError(e);}});if(shared[0])break;Thread.sleep(100);}assertTrue("Created user sharing did not load",shared[0]);
    onView(withText("Share connection")).check(matches(isDisplayed()));onView(withText("Share connection file")).perform(scrollTo()).check(matches(isDisplayed()));ScreenshotProof.save(c,"mixed-ubuntu-new-user-share");onView(withText("Done")).perform(click());result.put("inline_user_progress_and_sharing",true);
    try(Ssh ssh=new Ssh(node);InputStream bundle=c.getAssets().open("single_bundle.zip")){ssh.single(bundle,new JSONObject().put("action","remove-user").put("protocol",node.get("protocol")).put("login","phone-ui-test"));}
    Files.write(new File(c.getFilesDir(),"mixed-ubuntu-result.json").toPath(),result.toString().getBytes("UTF-8"));
   }
  }finally{current.set(null,previous);new Vault(c).write(old);c.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",prior).commit();}
 }
}
