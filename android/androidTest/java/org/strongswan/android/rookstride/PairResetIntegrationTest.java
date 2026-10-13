package org.strongswan.android.rookstride;
import android.content.Context;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.strongswan.android.ui.RookstrideActivity;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.File;
import java.nio.file.Files;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;

/** Opt-in destructive check on two explicitly authorized test nodes. Exercises the actual phone UI. */
@RunWith(AndroidJUnit4.class)
public class PairResetIntegrationTest {
 private static void field(Object a,String name,Object value)throws Exception{Field f=a.getClass().getDeclaredField(name);f.setAccessible(true);f.set(a,value);}
 private static void call(Object a,String name)throws Exception{Method m=a.getClass().getDeclaredMethod(name);m.setAccessible(true);m.invoke(a);}
 private static void waitText(String text,int seconds)throws Exception{
  for(int i=0;i<seconds;i++){try{onView(withText(text)).check(matches(isDisplayed()));return;}catch(androidx.test.espresso.NoMatchingViewException|AssertionError e){Thread.sleep(1000);}}
  onView(withText(text)).check(matches(isDisplayed()));
 }
 @Test public void typedPhoneResetBothNodesAndSwapTheirRoles()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File f=new File(c.getFilesDir(),"pair-integration.json");assumeTrue(f.isFile());
  JSONObject fixture=new JSONObject(new String(Files.readAllBytes(f.toPath()),"UTF-8"));assertTrue(fixture.getBoolean("authorizeReset"));
  Gateway entry=new Gateway(fixture.getJSONObject("gateway"));
  Gateway exit=entry.exit;
  // The installer test verified/pinned the fixture keys; select the matching presented key again.
  Gateway direct=entry.sshRelay!=null?entry.exit:entry;
  for(Gateway n:new Gateway[]{direct,direct==entry?entry.exit:entry}){
   n.set("fingerprint","");try{new Ssh(n).close();fail();}catch(Ssh.HostTrust trust){org.json.JSONArray keys=fixture.getJSONArray(n==entry?"entryKeys":"exitKeys");boolean found=false;for(int i=0;i<keys.length();i++)if(keys.getString(i).equals(trust.fingerprint))found=true;assertTrue(found);n.set("fingerprint",trust.fingerprint);}
  }
  c.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();
  try(ActivityScenario<RookstrideActivity> scenario=ActivityScenario.launch(RookstrideActivity.class)){
   scenario.onActivity(a->{try{ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(entry);field(a,"gateways",nodes);field(a,"selected",entry);field(a,"demo",false);field(a,"tab","Gateways");call(a,"render");}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Reset both VPN nodes")).perform(scrollTo(),click());waitText("Reset both VPN nodes?",90);
   onView(isAssignableFrom(android.widget.EditText.class)).perform(scrollTo(),replaceText("DELETE PAIR"),closeSoftKeyboard());
   onView(withText("Delete pair data")).perform(click());waitText("Both nodes reset. Ubuntu and SSH retained.",180);
   onView(withText("Swap entry and exit")).perform(scrollTo(),click());
   scenario.onActivity(a->{try{Field selected=a.getClass().getDeclaredField("selected");selected.setAccessible(true);Gateway swapped=(Gateway)selected.get(a);assertEquals(entry.get("host"),swapped.exit.get("host"));assertTrue(swapped.get("pairPhase").contains("roles swapped"));}catch(Exception e){throw new AssertionError(e);}});
  }
  for(Gateway n:new Gateway[]{entry,exit})try(Ssh ssh=new Ssh(n)){JSONObject state=ssh.probe();assertFalse(state.getBoolean("pair_helper"));assertFalse(state.getBoolean("existing"));}
  Files.write(new File(c.getFilesDir(),"pair-reset-result.json").toPath(),"{\"phone_ui_typed_reset\":true,\"role_swap_control\":true}".getBytes("UTF-8"));
 }
}
