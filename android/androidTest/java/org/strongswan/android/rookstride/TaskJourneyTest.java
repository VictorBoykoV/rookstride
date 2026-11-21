package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;

/** The visible task hierarchy and real back stack, without contacting a VPS. */
@RunWith(AndroidJUnit4.class)
public class TaskJourneyTest {
    private boolean previousSaved;
    @org.junit.Before public void preserveStartState(){previousSaved=InstrumentationRegistry.getInstrumentation().getTargetContext().getSharedPreferences("rookstride-ui",0).getBoolean("hasSavedVpn",false);}
    @org.junit.After public void restoreStartState(){InstrumentationRegistry.getInstrumentation().getTargetContext().getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",previousSaved).commit();}
    private void editServer(RookstrideActivity activity,Gateway node){try{java.lang.reflect.Method method=RookstrideActivity.class.getDeclaredMethod("editGateway",Gateway.class);method.setAccessible(true);method.invoke(activity,node);}catch(Exception e){throw new AssertionError(e);}}
    private void readable(android.view.View view){
        if(view instanceof android.widget.TextView){android.widget.TextView text=(android.widget.TextView)view;android.text.Layout layout=text.getLayout();if(layout!=null&&view.isShown()){
            for(int line=0;line<layout.getLineCount();line++)org.junit.Assert.assertEquals("Clipped label: "+text.getText(),0,layout.getEllipsisCount(line));
            org.junit.Assert.assertTrue("Text height: "+text.getText(),layout.getHeight()<=text.getHeight()-text.getCompoundPaddingTop()-text.getCompoundPaddingBottom()+2);
        }}
        if(view instanceof android.view.ViewGroup){android.view.ViewGroup group=(android.view.ViewGroup)view;for(int i=0;i<group.getChildCount();i++)readable(group.getChildAt(i));}
    }
    @Test public void setupRevealsTopologyThenProtocolAndBackReturnsToParent()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Set up a VPN")).check(matches(isDisplayed()));
            onView(withText("Import a VPN")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Manage a server")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Double VPN")).check(doesNotExist());onView(withText("People")).check(doesNotExist());
            activity.onActivity(a->readable(a.findViewById(android.R.id.content)));
            ScreenshotProof.save(context,"home");
            onView(withText("Set up a VPN")).perform(scrollTo(),click());
            onView(withText("Single-server VPN")).check(matches(isDisplayed()));onView(withText("Double VPN")).check(matches(isDisplayed()));
            ScreenshotProof.save(context,"setup");
            onView(withText("Single-server VPN")).perform(click());
            for(String title:new String[]{"IKEv2","AmneziaWG 3.1","VLESS · REALITY (TCP)","OpenVPN"})onView(withText(title)).perform(scrollTo()).check(matches(isDisplayed()));
            activity.onActivity(a->readable(a.findViewById(android.R.id.content)));
            ScreenshotProof.save(context,"protocols");
            onView(withText("AmneziaWG 3.1")).perform(scrollTo(),click());
            onView(withText("Server address")).check(matches(isDisplayed()));
            onView(withText("Administrator login")).check(matches(isDisplayed()));
            onView(withText("VPN name")).check(matches(org.hamcrest.Matchers.not(isDisplayed())));
            onView(withText("SSH port")).check(matches(org.hamcrest.Matchers.not(isDisplayed())));
            onView(withText("VPN port")).check(matches(org.hamcrest.Matchers.not(isDisplayed())));
            onView(withText("Connection options")).perform(scrollTo(),click());
            onView(withHint("Automatic")).perform(scrollTo()).check(matches(isDisplayed())).check(matches(withText("")));
            onView(withText("Cancel")).perform(click());androidx.test.espresso.Espresso.pressBack();onView(withText("Single-server VPN")).check(matches(isDisplayed()));
            activity.recreate();onView(withText("Single-server VPN")).check(matches(isDisplayed()));androidx.test.espresso.Espresso.pressBack();onView(withText("Manage a server")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Import a VPN")).perform(scrollTo(),click());onView(withText("Choose the profile type")).check(matches(isDisplayed()));
            final Gateway server=new Gateway();server.set("protocol","xray");server.set("host","vpn.example.net");server.set("name","Port fixture");
            activity.onActivity(a->editServer(a,server));onView(withText("Connection options")).perform(scrollTo(),click());
            onView(org.hamcrest.Matchers.allOf(isAssignableFrom(android.widget.EditText.class),withText("443"))).perform(scrollTo()).check(matches(isEnabled()));onView(withText("Cancel")).perform(click());
            server.data.put("snapshot",new org.json.JSONObject().put("services",new org.json.JSONObject().put("protocol",false)));
            activity.onActivity(a->editServer(a,server));onView(withText("Connection options")).perform(scrollTo(),click());
            onView(org.hamcrest.Matchers.allOf(isAssignableFrom(android.widget.EditText.class),withText("443"))).perform(scrollTo()).check(matches(org.hamcrest.Matchers.not(isEnabled())));onView(withText("Cancel")).perform(click());
        }
    }
    private java.util.List<android.widget.EditText> visibleFields(android.view.View view){
        java.util.List<android.widget.EditText> fields=new java.util.ArrayList<>();
        if(view instanceof android.widget.EditText&&view.isShown())fields.add((android.widget.EditText)view);
        if(view instanceof android.view.ViewGroup){android.view.ViewGroup group=(android.view.ViewGroup)view;for(int i=0;i<group.getChildCount();i++)fields.addAll(visibleFields(group.getChildAt(i)));}return fields;
    }
    @Test public void eachSingleProtocolSavesWithOnlyServerAccess()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Vault vault=new Vault(context);java.util.ArrayList<Gateway> original=vault.read();
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            for(SingleProtocols protocol:SingleProtocols.values()){
                activity.onActivity(a->{try{
                    java.lang.reflect.Field chosen=RookstrideActivity.class.getDeclaredField("setupProtocol");chosen.setAccessible(true);chosen.set(a,protocol.id);editServer(a,null);
                    java.lang.reflect.Field editor=RookstrideActivity.class.getDeclaredField("editor");editor.setAccessible(true);androidx.appcompat.app.AlertDialog dialog=(androidx.appcompat.app.AlertDialog)editor.get(a);
                    java.util.List<android.widget.EditText> fields=visibleFields(dialog.getWindow().getDecorView());org.junit.Assert.assertEquals(3,fields.size());org.junit.Assert.assertEquals("root",fields.get(1).getText().toString());
                    fields.get(0).setText("vpn.example.net");fields.get(2).setText("fixture-only-password");dialog.getButton(android.content.DialogInterface.BUTTON_POSITIVE).performClick();
                    java.lang.reflect.Field selected=RookstrideActivity.class.getDeclaredField("selected");selected.setAccessible(true);Gateway node=(Gateway)selected.get(a);
                    org.junit.Assert.assertEquals("vpn.example.net",node.get("name"));org.junit.Assert.assertEquals("root",node.get("admin"));org.junit.Assert.assertEquals(22,node.port());org.junit.Assert.assertTrue(node.remember());org.junit.Assert.assertEquals("fixture-only-password",new Vault(a).read().get(new Vault(a).read().size()-1).sshPassword);org.junit.Assert.assertEquals(protocol.port,node.data.getInt("vpnPort"));org.junit.Assert.assertEquals(protocol!=SingleProtocols.IKEV2,node.data.getBoolean("vpnPortAuto"));
                }catch(Exception e){throw new AssertionError(e);}});
                onView(withText("First device name")).check(doesNotExist());onView(withText("REALITY server name")).check(doesNotExist());
            }
        }finally{vault.write(original);}
    }
}
