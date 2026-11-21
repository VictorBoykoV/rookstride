package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/** Local UI and retained-preview acceptance; no remote SSH or VPN traffic is exercised here. */
@RunWith(AndroidJUnit4.class)
public final class ConnectionCollectionUiTest {
    private Context context;private Vault vault;private ArrayList<Gateway> before;private Gateway server,awg,ike;private String progress;private Map<String,?> uiBefore;
    @Before public void fixture()throws Exception{
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();Assume.assumeFalse(DeploymentService.active());Assume.assumeFalse(ConnectionBundleImport.recoveryPending(context));
        vault=new Vault(context);before=vault.read();uiBefore=new HashMap<>(context.getSharedPreferences("rookstride-ui",0).getAll());progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
        server=new Gateway();server.set("host","family.example.invalid");server.set("name","Family server");server.set("serverName","Family server");server.set("protocol","");server.data.put("checkedAt",System.currentTimeMillis()).put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg").put("ikev2"))));
        awg=ServerProtocols.create(server,SingleProtocols.AWG);awg.set("vpnLogin","this-phone");awg.set("setupIntent","");ike=ServerProtocols.create(server,SingleProtocols.IKEV2);ike.set("setupIntent","");vault.write(new ArrayList<>(Arrays.asList(server,awg,ike)));
    }
    @After public void restore()throws Exception{if(vault!=null&&before!=null)vault.write(before);if(context!=null&&uiBefore!=null){SharedPreferences.Editor edit=context.getSharedPreferences("rookstride-ui",0).edit().clear();for(Map.Entry<String,?> entry:uiBefore.entrySet()){String k=entry.getKey();Object v=entry.getValue();if(v instanceof String)edit.putString(k,(String)v);else if(v instanceof Boolean)edit.putBoolean(k,(Boolean)v);else if(v instanceof Integer)edit.putInt(k,(Integer)v);else if(v instanceof Long)edit.putLong(k,(Long)v);else if(v instanceof Float)edit.putFloat(k,(Float)v);else if(v instanceof Set)edit.putStringSet(k,(Set<String>)v);}edit.commit();context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();}}
    private Object field(Object object,String name){try{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}catch(Exception e){throw new AssertionError(e);}}
    private void call(Object object,String name,Class<?>[] types,Object...args){try{Method m=object.getClass().getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(object,args);}catch(Exception e){throw new AssertionError(e);}}
    private ConnectionCollectionState state(RookstrideActivity activity){return (ConnectionCollectionState)field(activity,"collectionState");}
    private List<View> children(View view){ArrayList<View> result=new ArrayList<>();result.add(view);if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++)result.addAll(children(((ViewGroup)view).getChildAt(i)));return result;}

    @Test public void serverShareRequiresExplicitProtocolSelectionAndCancelDoesNotStartSsh()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"openServer",new Class<?>[]{Gateway.class},server));
            onView(withText("Share several connections")).perform(scrollTo(),click());
            onView(withText("Next")).check(matches(not(isEnabled())));
            onView(allOf(withText(SingleProtocols.AWG.title),isAssignableFrom(android.widget.CheckBox.class))).perform(click());
            onView(withText("Next")).check(matches(isEnabled()));
            screen.recreate();onView(withText("Next")).check(matches(isEnabled()));
            onView(withText("Cancel")).perform(click());
            screen.onActivity(activity->{assertFalse(state(activity).share.active());assertFalse((Boolean)field(activity,"busy"));});
        }
    }
    @Test public void existingAccountChoiceNeverPreselectsThisPhonesAmneziaKey()throws Exception{
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            JSONArray users=new JSONArray().put(new JSONObject().put("login","this-phone").put("person","Owner phone").put("device","Android")).put(new JSONObject().put("login","mina").put("person","Mina").put("device","Laptop"));
            screen.onActivity(activity->{ConnectionCollectionState.ShareDraft draft=state(activity).share;draft.serverId=server.get("id");draft.protocols.add("awg");draft.phase="users";draft.users=users;call(activity,"restoreCollectionUi",new Class<?>[]{});});
            onView(withText("Use VPN user")).check(matches(isCompletelyDisplayed())).check(matches(not(isEnabled())));
            onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));
            onView(allOf(withText("Owner phone · Android · this-phone"),isAssignableFrom(RadioButton.class))).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());
            onView(withText("This phone uses this key. Sharing it can interrupt simultaneous connections. A separate VPN user works better.")).perform(scrollTo()).check(matches(isDisplayed()));
            onView(withText("Use VPN user")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));
            onView(allOf(withText("Mina · Laptop · mina"),isAssignableFrom(RadioButton.class))).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());
            screen.onActivity(activity->assertEquals("mina",state(activity).share.login));
            screen.recreate();onView(withText("Use VPN user")).check(matches(isCompletelyDisplayed())).check(matches(isEnabled()));
            onView(withText("Cancel")).check(matches(isCompletelyDisplayed())).perform(click());screen.onActivity(activity->{assertFalse(state(activity).share.active());assertFalse((Boolean)field(activity,"busy"));});
        }
    }
    @Test public void importPreviewSurvivesRecreationAndShowsNoPasswordOrAdministratorAuthority()throws Exception{
        JSONObject profile=PasswordSignIn.withKnownPassword(PasswordSignIn.definition("ikev2","guest.example.invalid","mina","PRIVATE_TEST_SECRET",""),"mina","PRIVATE_TEST_SECRET");
        JSONObject entry=ConnectionExport.fromResponse(profile).pending().put("display_name","Mina’s guest VPN");ConnectionBundleImport.Preview preview=ConnectionBundleImport.preview(context,ConnectionBundle.pack(Collections.singletonList(entry)));
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{state(activity).preview=preview;state(activity).importReviewPending=true;call(activity,"restoreCollectionUi",new Class<?>[]{});});
            onView(withText("Import all")).check(matches(isDisplayed()));onView(withText(SingleProtocols.IKEV2.title+" · mina")).check(matches(isDisplayed()));onView(withText("guest.example.invalid:500")).check(matches(isDisplayed()));
            screen.recreate();onView(withText("Import all")).check(matches(isDisplayed()));
            screen.onActivity(activity->{AlertDialog dialog=(AlertDialog)field(activity,"collectionDialog");for(View v:children(dialog.getWindow().getDecorView()))if(v instanceof TextView)assertFalse(((TextView)v).getText().toString().contains("PRIVATE_TEST_SECRET"));assertTrue(state(activity).importReviewPending);});
            onView(withText("Cancel")).perform(click());screen.onActivity(activity->{assertNull(state(activity).preview);assertFalse(state(activity).importReviewPending);});
            assertEquals("No import commit happens before Import all",0,vault.read().stream().filter(n->n.get("host").equals("guest.example.invalid")).count());
        }
    }
    @Test public void oneCollectionShareUriPreservesAllBytesAboveTheSingleProfileLimit()throws Exception{
        String config="client\ndev tun\nremote vpn.example.invalid 1194\nremote-cert-tls server\n<ca>\nfixture\n</ca>\n<cert>\nfixture\n</cert>\n<key>\nfixture\n</key>\n";
        String pad="#"+String.join("",Collections.nCopies(280000,"x"))+"\n";List<JSONObject> profiles=new ArrayList<>();
        for(int i=0;i<2;i++)profiles.add(new JSONObject().put("format","openvpn").put("name","rookstride-fixture"+i+".ovpn").put("content",config+pad+"# device "+i+"\n"));
        String file=ConnectionBundle.pack(profiles);assertTrue(file.getBytes(StandardCharsets.UTF_8).length>512000);
        Uri uri=ProfileExportProvider.issue(context,"rookstride-connections.rookbundle",file);assertEquals(ConnectionBundle.MIME,context.getContentResolver().getType(uri));
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(InputStream input=context.getContentResolver().openInputStream(uri)){assertNotNull(input);byte[] buffer=new byte[8192];for(int n;(n=input.read(buffer))!=-1;)bytes.write(buffer,0,n);}
        assertEquals(file,new String(bytes.toByteArray(),StandardCharsets.UTF_8));assertEquals(2,ConnectionBundle.parse(new String(bytes.toByteArray(),StandardCharsets.UTF_8)).size());
        try{ProfileExportProvider.issue(context,"rookstride-connections.rookbundle","{\"role\":\"owner\"}");fail("An administrator-shaped payload became a connection share URI");}catch(IllegalArgumentException expected){}
    }
    @Test public void completedServerResultHasOnlyALocalSaveActionAndNeverReplaysTheEngine()throws Exception{
        Field current=DeploymentService.class.getDeclaredField("current"),engine=DeploymentService.class.getDeclaredField("engine"),pending=DeploymentService.Session.class.getDeclaredField("pendingCompletion");current.setAccessible(true);engine.setAccessible(true);pending.setAccessible(true);Object previous=current.get(null),previousEngine=engine.get(null);AtomicInteger remoteCalls=new AtomicInteger();
        DeploymentService.Session session=new DeploymentService.Session(server,vault.read(),"protocol",new JSONObject(),false,System.currentTimeMillis()-2000);session.result=new JSONObject().put("state","complete");session.progress.finish();JSONObject receipt=session.progress.json();long finished=session.progress.finished;String phase=session.progress.phase;pending.set(session,receipt);session.progress.state="needs-attention";session.progress.phase="The server finished. Save its result on this phone.";
        current.set(null,session);engine.set(null,(DeploymentService.Engine)(service,s)->{remoteCalls.incrementAndGet();throw new IOException("Unexpected engine execution in local-only UI test");});
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"openScreen",new Class<?>[]{String.class},"Progress"));
            onView(withText("Save result on this phone")).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Check and resume")).check(doesNotExist());onView(withText("Abandon setup")).check(doesNotExist());
            onView(withText("Save result on this phone")).perform(click());screen.onActivity(activity->{assertFalse(DeploymentService.needsLocalSave());assertEquals("complete",session.progress.state);assertEquals(finished,session.progress.finished);assertEquals(phase,session.progress.phase);assertEquals(0,remoteCalls.get());});
            assertEquals("complete",new JSONObject(context.getSharedPreferences("rookstride-deployment",0).getString("progress","{}")).getString("state"));
        }finally{current.set(null,previous);engine.set(null,previousEngine);}
    }
}
