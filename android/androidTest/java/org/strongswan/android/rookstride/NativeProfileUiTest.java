package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.Uri;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;

/** Opt-in fixture: real import/storage/removal UI without administrator credentials. */
@RunWith(AndroidJUnit4.class)
public class NativeProfileUiTest {
 @Test public void nativeImportsPersistEncryptedAndRemoveWithoutSsh()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();File input=new File(c.getFilesDir(),"native-engine-test.json");assumeTrue(input.isFile());JSONArray profiles=new JSONObject(new String(Files.readAllBytes(input.toPath()),"UTF-8")).getJSONArray("profiles");
  for(int i=0;i<profiles.length();i++){
   JSONObject p=profiles.getJSONObject(i);File imported=new File(c.getCacheDir(),"native-import-fixture");Files.write(imported.toPath(),p.getString("content").getBytes("UTF-8"));AtomicReference<Gateway> selected=new AtomicReference<>();
   try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
    screen.onActivity(a->{try{java.lang.reflect.Field protocol=RookstrideActivity.class.getDeclaredField("importProtocol");protocol.setAccessible(true);protocol.set(a,p.getString("protocol"));java.lang.reflect.Method method=RookstrideActivity.class.getDeclaredMethod("importProfile",Uri.class);method.setAccessible(true);method.invoke(a,Uri.fromFile(imported));java.lang.reflect.Field field=RookstrideActivity.class.getDeclaredField("selected");field.setAccessible(true);selected.set((Gateway)field.get(a));}catch(Exception e){throw new AssertionError(e);}});
    Gateway node=selected.get();assertNotNull(node);assertTrue(node.data.optBoolean("clientOnly"));assertEquals("",node.sshPassword);assertEquals("",node.privateKey);assertTrue(new NativeProfileStore(c).exists(node.get("id")));
    byte[] encrypted=Files.readAllBytes(new File(c.getNoBackupFilesDir(),"vpn-profiles/"+node.get("id")+".enc").toPath());assertFalse("Plaintext profile metadata on disk",new String(encrypted,"ISO-8859-1").contains("\"content\""));
    screen.recreate();assertTrue("Saved profile changed after recreation",p.getString("content").trim().equals(new NativeProfileStore(c).read(node.get("id")).getString("content")));
    onView(withText("Connect")).check(matches(isDisplayed()));onView(withText("Connection preferences")).perform(scrollTo(),click());onView(withText("Server access")).check(doesNotExist());onView(withText("View log")).check(matches(isDisplayed()));onView(withText("Remove VPN")).perform(click());onView(withText("Continue")).perform(click());
    assertFalse(new NativeProfileStore(c).exists(node.get("id")));for(Gateway saved:new Vault(c).read())assertNotEquals(node.get("id"),saved.get("id"));
   }finally{imported.delete();Gateway node=selected.get();if(node!=null){new NativeProfileStore(c).remove(node.get("id"));java.util.ArrayList<Gateway> saved=new Vault(c).read();saved.removeIf(n->n.get("id").equals(node.get("id")));new Vault(c).write(saved);}}
  }
 }
}
