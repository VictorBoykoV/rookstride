package org.strongswan.android.rookstride;

import android.content.Context;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;

/** Signed release UI/resources, real locale recreation and service; no provider contact. */
@RunWith(AndroidJUnit4.class)
public class LocalizationTest {
    private Context context(){return InstrumentationRegistry.getInstrumentation().getTargetContext();}
    private void locale(String tag){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag)));InstrumentationRegistry.getInstrumentation().waitForIdleSync();}
    private void onboarded(){context().getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).commit();}
    private List<EditText> fields(View root){List<EditText> values=new ArrayList<>();if(root instanceof EditText)values.add((EditText)root);if(root instanceof ViewGroup)for(int i=0;i<((ViewGroup)root).getChildCount();i++)values.addAll(fields(((ViewGroup)root).getChildAt(i)));return values;}
    private int exactLabels(View view,String value){int count=view instanceof TextView&&((TextView)view).getText().toString().equals(value)?1:0;if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++)count+=exactLabels(((ViewGroup)view).getChildAt(i),value);return count;}
    private void readable(View view){
        if(view instanceof TextView && !(view instanceof EditText)){
            TextView text=(TextView)view;android.text.Layout layout=text.getLayout();
            if(layout!=null&&view.getVisibility()==View.VISIBLE){
                for(int line=0;line<layout.getLineCount();line++)assertEquals("Clipped label: "+text.getText(),0,layout.getEllipsisCount(line));
                assertTrue("Text height: "+text.getText(),layout.getHeight()<=text.getHeight()-text.getCompoundPaddingTop()-text.getCompoundPaddingBottom()+2);
            }
        }
        if(view instanceof ViewGroup)for(int i=0;i<((ViewGroup)view).getChildCount();i++)readable(((ViewGroup)view).getChildAt(i));
    }
    @Test public void fiveLanguagesKeepTechnicalInputsAndReadableNativeLayouts()throws Exception {
        onboarded();String previous=AppCompatDelegate.getApplicationLocales().toLanguageTags();
        try {
            for(String tag:new String[]{"en","ru","fa","ar","zh-Hans"}) {
                locale(tag);
                try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
                    activity.onActivity(a->{assertEquals(tag,RookText.tag(a));assertFalse(RookText.get(a,"start.connect_copy").isEmpty());
                        View root=a.findViewById(android.R.id.content);assertEquals(tag.equals("ar")||tag.equals("fa")?View.LAYOUT_DIRECTION_RTL:View.LAYOUT_DIRECTION_LTR,((ViewGroup)root).getChildAt(0).getLayoutDirection());
                        try{Method edit=RookstrideActivity.class.getDeclaredMethod("editGateway",Gateway.class);edit.setAccessible(true);edit.invoke(a,new Object[]{null});Field editor=RookstrideActivity.class.getDeclaredField("editor");editor.setAccessible(true);androidx.appcompat.app.AlertDialog dialog=(androidx.appcompat.app.AlertDialog)editor.get(a);
                            List<EditText> inputs=fields(dialog.getWindow().getDecorView());assertEquals(6,inputs.size());
                            inputs.get(1).setText("vpn.example.net");inputs.get(4).setText("Exact-ASCII-fixture-Password!");
                            for(EditText input:inputs.subList(1,inputs.size())){assertEquals(View.TEXT_DIRECTION_LTR,input.getTextDirection());assertEquals(View.LAYOUT_DIRECTION_LTR,input.getLayoutDirection());}
                            assertEquals("root",inputs.get(3).getText().toString());assertEquals("22",inputs.get(2).getText().toString());assertEquals("vpn.example.net",inputs.get(1).getText().toString());assertEquals("Exact-ASCII-fixture-Password!",inputs.get(4).getText().toString());
                            dialog.dismiss();
                        }catch(Exception e){throw new AssertionError(e);}
                        InstallationProgress p=new InstallationProgress("pair","fixture",System.currentTimeMillis());assertEquals(8,p.steps().length);assertTrue(RookText.summary(a,p).contains("0 / 8"));assertFalse(RookText.remaining(a,p).isEmpty());
                    });
                    activity.onActivity(a->{try{
                        Gateway sample=new Gateway();sample.set("name","Phone");sample.set("host","vpn.example.net");sample.data.put("snapshot",new JSONObject().put("users",new org.json.JSONArray().put(new JSONObject().put("login","Phone").put("person","Phone").put("device","Phone").put("kind","device"))));
                        Field chosen=RookstrideActivity.class.getDeclaredField("selected"),screen=RookstrideActivity.class.getDeclaredField("tab"),demo=RookstrideActivity.class.getDeclaredField("demo");chosen.setAccessible(true);screen.setAccessible(true);demo.setAccessible(true);chosen.set(a,sample);screen.set(a,"People");demo.setBoolean(a,true);
                        Method render=RookstrideActivity.class.getDeclaredMethod("render");render.setAccessible(true);render.invoke(a);
                        assertEquals("User-provided person, device label and login must not be translated",3,exactLabels(a.findViewById(android.R.id.content),"Phone"));
                    }catch(Exception e){throw new AssertionError(e);}});
                    ScreenshotProof.save(context(),"locale-"+tag);
                    activity.onActivity(a->readable(a.findViewById(android.R.id.content)));
                    activity.recreate();activity.onActivity(a->assertEquals(tag,RookText.tag(a)));
                }
            }
        }finally{locale(previous);}
    }
    @Test public void languageMenuRecreationKeepsTheSameInstallationSession()throws Exception {
        onboarded();locale("en");Context c=context();Vault vault=new Vault(c);ArrayList<Gateway> original=vault.read();String oldProgress=c.getSharedPreferences("rookstride-deployment",0).getString("progress",null);
        Field engine=DeploymentService.class.getDeclaredField("engine"),current=DeploymentService.class.getDeclaredField("current");engine.setAccessible(true);current.setAccessible(true);Object previous=engine.get(null);
        CountDownLatch started=new CountDownLatch(1),finish=new CountDownLatch(1);
        engine.set(null,(DeploymentService.Engine)(service,session)->{service.checkpoint(session,2,"Fixture: VPN installation running");started.countDown();if(!finish.await(90,TimeUnit.SECONDS))throw new Exception("fixture timeout");return new JSONObject().put("services",new JSONObject());});
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)) {
            Gateway node=new Gateway();node.set("host","vpn.example.net");node.set("name","Locale progress fixture");ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);
            activity.onActivity(a->DeploymentService.launch(a,node,nodes,"single",new JSONObject(),false));assertTrue(started.await(15,TimeUnit.SECONDS));activity.recreate();DeploymentService.Session same=DeploymentService.current();
            onView(withContentDescription("Change language")).perform(click());onView(withText("فارسی")).perform(click());InstrumentationRegistry.getInstrumentation().waitForIdleSync();
            activity.onActivity(a->{assertEquals("fa",RookText.tag(a));assertEquals("single",same.progress.kind);assertEquals("running",same.progress.state);});
            assertSame(same,DeploymentService.current());assertTrue(DeploymentService.active());
            activity.moveToState(Lifecycle.State.CREATED);activity.moveToState(Lifecycle.State.RESUMED);assertSame(same,DeploymentService.current());
            ScreenshotProof.save(c,"locale-fa-deployment");finish.countDown();for(int i=0;i<100&&DeploymentService.active();i++)Thread.sleep(100);assertEquals("complete",same.progress.state);assertEquals(5,same.progress.completed);
        } finally {finish.countDown();engine.set(null,previous);current.set(null,null);vault.write(original);c.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",oldProgress).commit();locale("en");}
    }
    @Test public void localizedGuidesAndPluralsAreBundledOffline()throws Exception {
        assertEquals("fa",RookText.firstSupported(Locale.FRENCH,Locale.forLanguageTag("fa")));
        assertEquals("en",RookText.firstSupported(Locale.forLanguageTag("he"),Locale.FRENCH));
        assertEquals("en",RookText.firstSupported(Locale.forLanguageTag("zh-Hant")));
        assertEquals("zh-Hans",RookText.firstSupported(Locale.forLanguageTag("zh-CN")));
        assertEquals("zh-Hans",RookText.firstSupported(Locale.forLanguageTag("zh-Hans-HK")));
        android.content.res.Configuration englishConfiguration=new android.content.res.Configuration(context().getResources().getConfiguration());englishConfiguration.setLocale(Locale.ENGLISH);
        Context english=context().createConfigurationContext(englishConfiguration);
        for(Map.Entry<String,Integer> entry:RookStrings.SOURCE.entrySet())assertEquals("Native text must preserve fragment whitespace and escapes",entry.getKey(),english.getString(entry.getValue()));
        if(android.os.Build.VERSION.SDK_INT>=33){
            android.app.LocaleManager manager=(android.app.LocaleManager)context().getSystemService(Context.LOCALE_SERVICE);
            android.os.LocaleList previous=manager.getApplicationLocales();
            onboarded();
            // Android may restart a cached app with no Activity when its framework locale changes.
            // Hold an Activity lifecycle without asking for screen focus or UI interaction.
            try(ActivityScenario<RookstrideActivity> active=ActivityScenario.launch(RookstrideActivity.class)){
                try{manager.setApplicationLocales(android.os.LocaleList.forLanguageTags("en"));manager.setApplicationLocales(android.os.LocaleList.forLanguageTags("fa"));Context translated=RookText.localized(context());assertEquals("fa",RookText.tag(translated));assertNotEquals("Language",RookText.get(translated,"language.label"));}
                finally{manager.setApplicationLocales(previous);}
            }
        }
        for(String tag:new String[]{"en","ru","fa","ar","zh-Hans"}) {
            try(java.io.InputStream input=context().getAssets().open("guide-"+tag+".html")){byte[] bytes=new byte[input.available()];assertEquals(bytes.length,input.read(bytes));String page=new String(bytes,java.nio.charset.StandardCharsets.UTF_8);assertTrue(page.contains("lang=\""+tag+"\""));assertTrue(page.contains("rookstride:full-guide"));assertFalse(page.contains("<script"));}
            android.content.res.Configuration config=new android.content.res.Configuration(context().getResources().getConfiguration());config.setLocale(java.util.Locale.forLanguageTag(tag));Context translated=context().createConfigurationContext(config);
            for(int remaining:new int[]{0,1,2,3,5,8}) {InstallationProgress p=new InstallationProgress("pair","fixture",0);p.completed=8-remaining;assertFalse(RookText.remaining(translated,p).isEmpty());}
        }
    }
}
