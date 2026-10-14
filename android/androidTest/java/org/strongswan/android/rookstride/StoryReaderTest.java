package org.strongswan.android.rookstride;

import android.content.Context;
import android.webkit.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;

/** Real locked offline WebView; deterministic voice events, not an audible-device test. */
@RunWith(AndroidJUnit4.class)
public class StoryReaderTest {
    @org.junit.Before public void englishFixture(){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.forLanguageTags("en")));}
    static final class VoiceFixture {
        volatile String id="",spoken="";
        @JavascriptInterface public String voices(){return "[{\"name\":\"test-only-offline-voice\",\"lang\":\"en-US\",\"localService\":true}]";}
        @JavascriptInterface public void speak(String id,String text,String voice,float rate){this.id=id;spoken=text;}
        @JavascriptInterface public void stop(){id="";}
    }
    private String js(WebView view,String code)throws Exception{
        CountDownLatch done=new CountDownLatch(1);String[] out={null};InstrumentationRegistry.getInstrumentation().runOnMainSync(()->view.evaluateJavascript(code,value->{out[0]=value;done.countDown();}));assertTrue(done.await(10,TimeUnit.SECONDS));return out[0];
    }
    private void waitJs(WebView view,String code,String expected)throws Exception{for(int i=0;i<100;i++){if(expected.equals(js(view,code)))return;Thread.sleep(100);}assertEquals(expected,js(view,code));}
    @Test public void offlinePagesVoiceHighlightAndChapterStop()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();context.getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).remove("storyUrl").commit();
        try(ActivityScenario<RookstrideActivity> activity=ActivityScenario.launch(RookstrideActivity.class)){
            onView(withText("Stories")).perform(click());WebView[] web={null};activity.onActivity(a->{try{Field f=RookstrideActivity.class.getDeclaredField("storyView");f.setAccessible(true);web[0]=(WebView)f.get(a);}catch(Exception e){throw new RuntimeException(e);}});
            waitJs(web[0],"document.querySelectorAll('.world-card').length","5");
            VoiceFixture voice=new VoiceFixture();activity.onActivity(a->{web[0].removeJavascriptInterface("RookVoice");web[0].addJavascriptInterface(voice,"RookVoice");web[0].loadUrl("https://rookstride.invalid/stories/worlds/harbor/borrowed-light/");});
            waitJs(web[0],"document.querySelectorAll('.story-page').length","4");waitJs(web[0],"document.querySelector('[data-narrate]').disabled","false");
            js(web[0],"requestAnimationFrame(function(){requestAnimationFrame(function(){window.rookTestPaintReady=true;});});");waitJs(web[0],"window.rookTestPaintReady===true","true");Thread.sleep(500);
            ScreenshotProof.save(context,"offline-story");
            js(web[0],"document.querySelector('[data-narrate]').click()");
            for(int i=0;i<100&&voice.id.isEmpty();i++)Thread.sleep(50);assertFalse(voice.id.isEmpty());assertTrue(voice.spoken.contains("Rook"));
            String firstWord=voice.spoken.substring(0,voice.spoken.indexOf(' '));
            js(web[0],"window.rookNarrationEvent("+JSONObject.quote(voice.id)+",'boundary',0,"+firstWord.length()+")");assertEquals(JSONObject.quote(firstWord),js(web[0],"document.querySelector('.narration mark').textContent"));
            assertEquals("1",js(web[0],"document.querySelectorAll('.narrating').length"));
            for(int page=0;page<4;page++){
                String id=voice.id;assertFalse(id.isEmpty());js(web[0],"window.rookNarrationEvent("+JSONObject.quote(id)+",'end',0,0)");Thread.sleep(100);
            }
            assertEquals("false",js(web[0],"document.querySelector('.chapter-finished').hidden"));assertEquals("\"Page 4 / 4\"",js(web[0],"document.querySelector('[data-story-status]').textContent"));
            assertEquals("0",js(web[0],"document.querySelectorAll('.narrating').length"));assertTrue(js(web[0],"location.pathname").contains("borrowed-light"));
            js(web[0],"document.querySelector('[data-story-mode=chapter]').click()");assertEquals("\"chapter\"",js(web[0],"document.querySelector('[data-story-reader]').dataset.mode"));
            js(web[0],"document.querySelector('[data-story-mode=page]').click();document.querySelector('[data-story-prev]').click()");assertEquals("\"Page 3 / 4\"",js(web[0],"document.querySelector('[data-story-status]').textContent"));
            js(web[0],"document.querySelector('[data-story-next]').click()");assertEquals("false",js(web[0],"document.querySelector('.chapter-finished').hidden"));assertTrue(js(web[0],"location.pathname").contains("borrowed-light"));
            activity.onActivity(a->{assertFalse(web[0].getSettings().getAllowFileAccess());assertFalse(web[0].getSettings().getAllowContentAccess());assertTrue(web[0].getSettings().getBlockNetworkLoads());});
            onView(withText("Guide")).perform(click());onView(withText("Stories")).perform(click());
        }
    }
}
