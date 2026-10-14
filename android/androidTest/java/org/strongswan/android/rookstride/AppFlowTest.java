package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class AppFlowTest {
    @org.junit.Before public void englishFixture(){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.forLanguageTags("en")));}
    @Test public void guideDemoPeopleAndConnectionsAreReachable() {
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        context.getSharedPreferences("rookstride-ui",Context.MODE_PRIVATE).edit().putBoolean("onboarded",true).commit();
        try(ActivityScenario<RookstrideActivity> a=ActivityScenario.launch(RookstrideActivity.class)) {
            onView(withText("Explore a sample gateway")).perform(scrollTo(),click());
            onView(withText("Sample data. No server is connected.")).check(matches(isDisplayed()));preview(context,"gateway");
            onView(withText("People")).perform(click());onView(withText("Alex")).check(matches(isDisplayed()));preview(context,"people");
            onView(withText("Sessions")).perform(click());onView(withText("Every connection.")).check(matches(isDisplayed()));preview(context,"sessions");
            onView(withText("Guide")).perform(click());onView(isAssignableFrom(android.webkit.WebView.class)).check(matches(isDisplayed()));
        }
    }
    private void preview(Context context,String name) {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        android.graphics.Bitmap bitmap=InstrumentationRegistry.getInstrumentation().getUiAutomation().takeScreenshot();
        if(bitmap!=null)try(java.io.FileOutputStream out=new java.io.FileOutputStream(new File(context.getFilesDir(),"preview-"+name+".png"))){bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out);}catch(java.io.IOException e){throw new AssertionError(e);}
    }
    @Test public void administratorSecretsAreEncryptedAtRest() throws Exception {
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        Vault v=new Vault(context);ArrayList<Gateway> original=v.read();
        try {
            Gateway g=new Gateway();g.data.put("remember",true);g.sshPassword="test-only-secret-never-plaintext";
            ArrayList<Gateway> list=new ArrayList<>();list.add(g);v.write(list);
            byte[] data=Files.readAllBytes(new File(context.getFilesDir(),"gateways.enc").toPath());
            assertFalse(new String(data,java.nio.charset.StandardCharsets.UTF_8).contains(g.sshPassword));
            assertEquals(g.sshPassword,v.read().get(0).sshPassword);
        }finally{v.write(original);}
    }
}
