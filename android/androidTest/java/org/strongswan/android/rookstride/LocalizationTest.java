package org.strongswan.android.rookstride;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.assertion.ViewAssertions.doesNotExist;

/** App language is deliberately English even after a previous translated installation. */
@RunWith(AndroidJUnit4.class)
public class LocalizationTest {
    @Test public void legacyLanguageAndRecreationReturnToEnglish()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        InstrumentationRegistry.getInstrumentation().runOnMainSync(()->AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("fa")));
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Set up a VPN")).check(matches(isDisplayed()));
            onView(withContentDescription("Change language")).check(doesNotExist());
            activity.onActivity(a->{assertEquals("en",RookText.tag(a));assertEquals("en",a.getResources().getConfiguration().getLocales().get(0).getLanguage());ViewGroup root=a.findViewById(android.R.id.content);assertEquals(View.LAYOUT_DIRECTION_LTR,root.getChildAt(0).getLayoutDirection());});
            activity.recreate();onView(withText("Set up a VPN")).check(matches(isDisplayed()));
            activity.onActivity(a->assertEquals("en",RookText.tag(a)));
            ScreenshotProof.save(context,"english-only");
        }
    }
    @Test public void appGuideAndLanguageSettingsAreEnglishOnly()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        try(java.io.InputStream input=context.getAssets().open("app-guide.html")){
            java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();byte[] buffer=new byte[1024];int n;while((n=input.read(buffer))!=-1)out.write(buffer,0,n);
            String page=new String(out.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);assertTrue(page.contains("lang=\"en\""));assertTrue(page.contains("Set up"));assertFalse(page.contains("<script"));
        }
        android.content.res.XmlResourceParser xml=context.getResources().getXml(org.strongswan.android.R.xml.rookstride_locales);int languages=0;
        for(int event=xml.getEventType();event!=org.xmlpull.v1.XmlPullParser.END_DOCUMENT;event=xml.next())if(event==org.xmlpull.v1.XmlPullParser.START_TAG&&xml.getName().equals("locale")){languages++;assertEquals("en",xml.getAttributeValue("http://schemas.android.com/apk/res/android","name"));}
        xml.close();assertEquals(1,languages);
    }
}
