package org.strongswan.android.rookstride;

import android.content.Context;
import android.graphics.Rect;
import android.util.TypedValue;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.typeText;
import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.isCompletelyDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withHint;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static androidx.test.espresso.matcher.ViewMatchers.withSubstring;
import static org.hamcrest.Matchers.allOf;
import static org.junit.Assert.*;

/** Local dialog interaction/geometry only. No server or VPN connection is made. */
@RunWith(AndroidJUnit4.class)
public final class DialogPresentationUiTest {
    private Context context;
    private Vault vault;
    private ArrayList<Gateway> previous;
    private String progress;
    private boolean hadSavedVpnPreference,savedVpnPreference;

    @Before public void isolateCatalog()throws Exception{
        context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        android.content.SharedPreferences ui=context.getSharedPreferences("rookstride-ui",0);
        hadSavedVpnPreference=ui.contains("hasSavedVpn");savedVpnPreference=ui.getBoolean("hasSavedVpn",false);
        vault=new Vault(context);previous=vault.read();vault.write(new ArrayList<>());
        progress=context.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        context.getSharedPreferences("rookstride-deployment",0).edit().remove("progress").commit();
    }
    @After public void restoreCatalog()throws Exception{
        vault.write(previous);
        context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",progress).commit();
        android.content.SharedPreferences.Editor ui=context.getSharedPreferences("rookstride-ui",0).edit();
        if(hadSavedVpnPreference)ui.putBoolean("hasSavedVpn",savedVpnPreference);else ui.remove("hasSavedVpn");
        assertTrue("Restore the original hasSavedVpn preference, including absence",ui.commit());
    }
    private void assertAction(Button button,String label){
        assertNotNull(button);assertEquals(label,button.getText().toString());
        CharSequence shown=button.getTransformationMethod()==null?button.getText():button.getTransformationMethod().getTransformation(button.getText(),button);
        assertEquals("Dialog actions must preserve sentence case",label,shown.toString());
        float expected=TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP,15,context.getResources().getDisplayMetrics());
        assertEquals("Action text follows the platform SP conversion",expected,button.getTextSize(),.6f);
        int target=Math.round(48*context.getResources().getDisplayMetrics().density);
        assertTrue("Action touch target height",button.getHeight()>=target);
        assertTrue("Action touch target width",button.getWidth()>=target);
    }
    private static Object field(Object target,String name){try{Field field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);}catch(Exception failure){throw new AssertionError(failure);}}
    private static void call(Object target,String name,Class<?>[] types,Object...args){try{Method method=target.getClass().getDeclaredMethod(name,types);method.setAccessible(true);method.invoke(target,args);}catch(Exception failure){throw new AssertionError(failure);}}
    private void fullDialogTitle(String expected){
        onView(allOf(withId(androidx.appcompat.R.id.alertTitle),withText(expected))).check(matches(isCompletelyDisplayed())).check((view,error)->{
            if(error!=null)throw error;TextView title=(TextView)view;assertNotNull(title.getLayout());int count=title.getLineCount();assertTrue("The native dialog title is empty",count>0);assertEquals("The native title omitted its ending",expected.length(),title.getLayout().getLineEnd(count-1));int width=title.getWidth()-title.getCompoundPaddingLeft()-title.getCompoundPaddingRight();
            for(int i=0;i<count;i++){assertEquals("The actual task title was ellipsized",0,title.getLayout().getEllipsisCount(i));assertTrue("Title glyphs exceed its width",title.getLayout().getLineLeft(i)>=-1&&title.getLayout().getLineRight(i)<=width+1);}
            assertTrue("The final title line was clipped",title.getLayout().getLineBottom(count-1)<=title.getHeight()-title.getCompoundPaddingTop()-title.getCompoundPaddingBottom());
        });
    }
    private void soleDismissal(String label){
        onView(allOf(withText(label),withId(android.R.id.button1))).check(matches(isCompletelyDisplayed())).check((view,error)->{if(error!=null)throw error;assertAction((Button)view,label);});
        onView(allOf(withId(android.R.id.button2),isDisplayed())).check(doesNotExist());onView(allOf(withId(android.R.id.button3),isDisplayed())).check(doesNotExist());
    }
    private void notSaved(Gateway target)throws Exception{for(Gateway saved:vault.read())assertFalse("Dismissing the product sheet persisted its local review fixture",target.get("id").equals(saved.get("id")));}
    private static void cleared(NewUserShareState state){assertFalse(state.pending);assertFalse(state.confirmed);assertTrue("The transient user password survived dismissal",state.password.isEmpty());assertTrue(state.login.isEmpty());assertTrue(state.nodeId.isEmpty());assertNull(state.profile);assertNull(state.snapshot);assertNull(state.scopedObject);}

    @Test public void confirmationPreservesNativeRolesAndOnlyRunsTheChosenAction()throws Exception{
        AtomicInteger updates=new AtomicInteger(),cancellations=new AtomicInteger();
        AtomicReference<AlertDialog> shown=new AtomicReference<>();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{
                AlertDialog dialog=RookDialogs.builder(activity).setTitle("Update management tools")
                    .setMessage("Update the management tools on both selected servers. Existing VPN users are kept.")
                    .setNegativeButton("Cancel",(d,w)->cancellations.incrementAndGet())
                    .setPositiveButton("Update",(d,w)->updates.incrementAndGet()).create();
                shown.set(dialog);dialog.show();
            });
            onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));
            onView(withText("Update")).check(matches(isCompletelyDisplayed()));
            screen.onActivity(activity->{
                Button cancel=shown.get().getButton(AlertDialog.BUTTON_NEGATIVE),update=shown.get().getButton(AlertDialog.BUTTON_POSITIVE);
                assertAction(cancel,"Cancel");assertAction(update,"Update");
                Rect c=new Rect(),u=new Rect();assertTrue(cancel.getGlobalVisibleRect(c));assertTrue(update.getGlobalVisibleRect(u));
                if(Math.abs(c.centerY()-u.centerY())<2&&activity.getResources().getConfiguration().getLayoutDirection()==View.LAYOUT_DIRECTION_LTR)
                    assertTrue("Native LTR positive action follows Cancel",c.right<=u.left);
            });
            ScreenshotProof.save(context,"dialog-update-semantics");
            onView(withText("Update")).perform(click());assertEquals(1,updates.get());assertEquals(0,cancellations.get());
        }
    }

    @Test public void informationHasOneTrailingCloseActionWithoutAnInventedMutation()throws Exception{
        AtomicInteger closes=new AtomicInteger();AtomicReference<AlertDialog> shown=new AtomicReference<>();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{AlertDialog dialog=RookDialogs.builder(activity).setTitle("Connection details")
                .setMessage("These details explain this VPN connection.").setPositiveButton("Close",(d,w)->closes.incrementAndGet()).create();shown.set(dialog);dialog.show();});
            onView(withText("Close")).check(matches(isCompletelyDisplayed()));
            screen.onActivity(activity->{
                assertAction(shown.get().getButton(AlertDialog.BUTTON_POSITIVE),"Close");
                for(int role:new int[]{AlertDialog.BUTTON_NEGATIVE,AlertDialog.BUTTON_NEUTRAL}){
                    Button action=shown.get().getButton(role);assertTrue(action==null||action.getVisibility()!=View.VISIBLE);
                }
            });
            ScreenshotProof.save(context,"dialog-information-close");
            onView(withText("Close")).perform(click());assertEquals(1,closes.get());
        }
    }

    @Test public void longFormKeepsCancelAndSaveVisibleWhileTheKeyboardIsOpen()throws Exception{
        AtomicInteger saves=new AtomicInteger();AtomicReference<AlertDialog> shown=new AtomicReference<>();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{
                LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
                EditText name=new EditText(activity);name.setSingleLine(true);name.setHint("Connection name");body.addView(name);
                for(int i=0;i<9;i++){TextView explanation=new TextView(activity);explanation.setTextSize(TypedValue.COMPLEX_UNIT_SP,15);explanation.setText("Optional connection information remains in this scrollable area.");explanation.setPadding(0,8,0,8);body.addView(explanation);}
                AlertDialog dialog=RookDialogs.builder(activity).setTitle("Edit connection name").setView(body)
                    .setNegativeButton("Cancel",null).setPositiveButton("Save",(d,w)->saves.incrementAndGet()).create();shown.set(dialog);dialog.show();
            });
            onView(withHint("Connection name")).perform(click(),typeText("Family"));
            onView(withText("Cancel")).check(matches(isCompletelyDisplayed()));onView(withText("Save")).check(matches(isCompletelyDisplayed()));
            screen.onActivity(activity->{assertNotNull(shown.get().getWindow().getDecorView().findViewWithTag(RookDialogs.BODY_TAG));assertAction(shown.get().getButton(AlertDialog.BUTTON_NEGATIVE),"Cancel");assertAction(shown.get().getButton(AlertDialog.BUTTON_POSITIVE),"Save");});
            ScreenshotProof.save(context,"dialog-keyboard-actions");
            onView(withText("Cancel")).perform(click());assertEquals(0,saves.get());
        }
    }

    @Test public void productRuntimeReviewsHaveOneTrailingCloseAndDoNotStartAnOperation()throws Exception{
        Gateway server=new Gateway();server.set("host","runtime-dialog.example.net");
        JSONObject review=new JSONObject().put("single",new JSONObject().put("groups",new JSONArray().put(new JSONObject().put("group","xray").put("title","Xray").put("supported",false).put("reason","No compatible installed runtime"))));
        JSONObject operation=new JSONObject().put("group","xray").put("state","prepared").put("single_status",new JSONObject().put("available",false).put("phase","Already current"));server.data.put("engineUpdate",operation);String original=operation.toString();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"reviewEngineUpdates",new Class<?>[]{Gateway.class,JSONObject.class},server,review));onView(withText("VPN runtime updates")).check(matches(isDisplayed()));soleDismissal("Close");onView(withText("Close")).perform(click());assertFalse(DeploymentService.active());
            screen.onActivity(activity->call(activity,"reviewEngineUpdateState",new Class<?>[]{Gateway.class},server));onView(withText("Review VPN runtime update")).check(matches(isDisplayed()));soleDismissal("Close");ScreenshotProof.save(context,"dialog-product-runtime-close");onView(withText("Close")).perform(click());assertEquals("Dismissal changed the reviewed operation",original,server.data.getJSONObject("engineUpdate").toString());assertFalse(DeploymentService.active());notSaved(server);
        }
    }

    @Test public void productShareDoneClearsTransientAccessAndBackKeepsTheSameCleanup()throws Exception{
        Gateway server=new Gateway();server.set("host","share-dialog.example.net");server.set("protocol","ikev2");vault.write(new ArrayList<>(Arrays.asList(server)));
        JSONObject profile=PasswordSignIn.withKnownPassword(new JSONObject().put("type","ikev2-eap").put("name","Dialog IKEv2").put("remote",new JSONObject().put("addr",server.get("host"))).put("local",new JSONObject().put("eap_id","reader")),"reader","DialogPass12");AtomicReference<NewUserShareState> state=new AtomicReference<>();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->{NewUserShareState pending=(NewUserShareState)field(activity,"newUserShare");state.set(pending);pending.created(server.get("id"),"reader","DialogPass12");pending.profile=profile;call(activity,"restoreCreatedUserShare",new Class<?>[]{});});
            onView(withText("Share connection")).check(matches(isDisplayed()));soleDismissal("Done");screen.recreate();soleDismissal("Done");assertTrue(state.get().pending);assertFalse(state.get().password.isEmpty());ScreenshotProof.save(context,"dialog-product-share-done");onView(withText("Done")).perform(click());cleared(state.get());Thread.sleep(1200);onView(withText("Share connection")).check(doesNotExist());screen.recreate();onView(withText("Share connection")).check(doesNotExist());
            screen.onActivity(activity->{NewUserShareState pending=(NewUserShareState)field(activity,"newUserShare");state.set(pending);pending.created(server.get("id"),"reader","DialogPass12");pending.profile=profile;call(activity,"restoreCreatedUserShare",new Class<?>[]{});});soleDismissal("Done");androidx.test.espresso.Espresso.pressBack();cleared(state.get());Thread.sleep(1200);onView(withText("Share connection")).check(doesNotExist());assertTrue("Dismissing sharing must not save its transient password",vault.read().get(0).vpnPassword.isEmpty());assertFalse(DeploymentService.active());
        }
    }

    @Test public void productInspectionUsesSoleCloseButKeepsTheAdoptionActionPositive()throws Exception{
        Gateway entry=new Gateway(),exit=new Gateway();entry.set("host","entry-dialog.example.net");exit.set("host","exit-dialog.example.net");JSONObject inspection=new JSONObject().put("deployment","dialog-inspection").put("read_only",false);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"reviewPairInventory",new Class<?>[]{Gateway.class,JSONObject.class,Gateway.class},entry,inspection,null));soleDismissal("Close");onView(withText("Close")).perform(click());
            screen.onActivity(activity->call(activity,"reviewPairInventory",new Class<?>[]{Gateway.class,JSONObject.class,Gateway.class},entry,inspection,exit));onView(allOf(withText("Close"),withId(android.R.id.button2))).check(matches(isCompletelyDisplayed()));onView(allOf(withText("Add existing Double VPN"),withId(android.R.id.button1))).check(matches(isCompletelyDisplayed()));onView(withText("Close")).perform(click());assertFalse(DeploymentService.active());notSaved(entry);assertNull(entry.exit);
        }
    }

    @Test public void productEnrollmentFailureUsesSoleCloseUnlessSafeResumeIsAvailable()throws Exception{
        JSONObject invitation=new JSONObject().put("fixture",true);Gateway draft=new Gateway();draft.privateKey="dialog-only-retained-key";
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"showAdminEnrollmentFailure",new Class<?>[]{JSONObject.class,Gateway.class,Exception.class},invitation,null,new IOException("dialog-only failure")));soleDismissal("Close");onView(withText("Close")).perform(click());
            screen.onActivity(activity->call(activity,"showAdminEnrollmentFailure",new Class<?>[]{JSONObject.class,Gateway.class,Exception.class},invitation,draft,new Ssh.SignInRejected(new IOException("dialog-only failure"))));onView(allOf(withText("Close"),withId(android.R.id.button2))).check(matches(isCompletelyDisplayed()));onView(allOf(withText("Continue setup"),withId(android.R.id.button1))).check(matches(isCompletelyDisplayed()));onView(withText("Close")).perform(click());
            screen.onActivity(activity->call(activity,"showAdminEnrollmentFailure",new Class<?>[]{JSONObject.class,Gateway.class,Exception.class},invitation,draft,new Ssh.HostTrust("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",true,draft)));soleDismissal("Close");onView(withText("Continue setup")).check(doesNotExist());onView(withText("Close")).perform(click());assertEquals("dialog-only-retained-key",draft.privateKey);assertFalse(DeploymentService.active());notSaved(draft);
        }
    }

    @Test public void productHelperReviewUsesCloseWhenCurrentAndCancelUpdateWhenAvailable()throws Exception{
        Gateway pair=new Gateway();pair.set("host","helper-entry-dialog.example.net");pair.exit=new Gateway();pair.exit.set("host","helper-exit-dialog.example.net");
        JSONObject current=new JSONObject().put("entry",new JSONObject().put("supported",true).put("available",false)).put("exit",new JSONObject().put("supported",true).put("available",false));String currentBefore=current.toString();
        JSONObject available=new JSONObject(current.toString());available.getJSONObject("entry").put("available",true);String availableBefore=available.toString();
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->call(activity,"reviewHelperUpdate",new Class<?>[]{Gateway.class,JSONObject.class},pair,current));fullDialogTitle("Update management tools");soleDismissal("Close");onView(withText("Close")).perform(click());assertEquals(currentBefore,current.toString());assertFalse(DeploymentService.active());
            screen.onActivity(activity->call(activity,"reviewHelperUpdate",new Class<?>[]{Gateway.class,JSONObject.class},pair,available));fullDialogTitle("Update management tools");onView(withSubstring("brief traffic interruption")).perform(PresentationFollowupUiTest.readEveryLineNaturally());onView(allOf(withText("Cancel"),withId(android.R.id.button2))).check(matches(isCompletelyDisplayed()));onView(allOf(withText("Update"),withId(android.R.id.button1))).check(matches(isCompletelyDisplayed()));ScreenshotProof.save(context,"dialog-product-helper-review-roles");onView(withText("Cancel")).perform(click());assertEquals(availableBefore,available.toString());assertFalse("Dismissing the review must not start a helper update",pair.data.has("helperUpdate"));assertFalse(DeploymentService.active());notSaved(pair);
        }
    }
}
