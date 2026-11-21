package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.BySelector;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import static org.junit.Assert.*;

/** Opt-in real app → Documents UI → official client import. Uses synthetic keys only. */
@RunWith(AndroidJUnit4.class)
public class ExternalClientImportTest {
    private UiObject2 waitFor(UiDevice device,BySelector selector){UiObject2 view=device.wait(Until.findObject(selector.enabled(true)),15000);assertNotNull("Missing external UI: "+selector,view);return view;}
    @Test public void officialAwgClientImportsTheActualBackendExport()throws Exception{
        Assume.assumeTrue("Explicit external-client fixture required",InstrumentationRegistry.getArguments().getString("external_awg","").equals("yes"));
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();context.getPackageManager().getPackageInfo("org.amnezia.awg",0);
        File file=new File(context.getExternalFilesDir(null),"awg-profile-fixture.json");JSONObject profile=new JSONObject(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
        String filename=profile.getString("name"),name=filename.substring(0,filename.length()-5);assertEquals("awg",profile.getString("format"));assertTrue(name.length()<=15);
        UiDevice device=UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            activity.onActivity(a->{try{java.lang.reflect.Method method=RookstrideActivity.class.getDeclaredMethod("exportProtocolProfile",JSONObject.class,boolean.class);method.setAccessible(true);method.invoke(a,profile,true);}catch(Exception e){throw new AssertionError(e);}});
            waitFor(device,By.res("android","button1")).click();
            waitFor(device,By.text(java.util.regex.Pattern.compile("Open AmneziaWG",java.util.regex.Pattern.CASE_INSENSITIVE))).click();
            waitFor(device,By.res("org.amnezia.awg","create_fab")).click();
            waitFor(device,By.text("Import from file or archive")).click();
            // Use the same Downloads provider the save dialog defaults to on this fixture.
            waitFor(device,By.desc("Show roots")).click();
            waitFor(device,By.text("Downloads")).click();
            waitFor(device,By.text(filename)).click();
            assertTrue("Official client did not import the profile",device.wait(Until.hasObject(By.pkg("org.amnezia.awg").text(name)),20000));
            device.takeScreenshot(new File(context.getExternalFilesDir(null),"ui-proof-awg-native-import.png"));
        }finally{file.delete();}
    }
}
