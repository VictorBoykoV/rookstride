package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.Uri;
import android.provider.OpenableColumns;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.*;
import android.content.Intent;
import org.json.JSONObject;
import org.strongswan.android.ui.RookstrideActivity;
import androidx.test.core.app.ActivityScenario;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;

@RunWith(AndroidJUnit4.class)
public class ProfileExportTest {
    private JSONObject[] profiles()throws Exception{return new JSONObject[]{
        new JSONObject().put("format","awg").put("name","rook-0123456789.conf").put("content","[Interface]\nPrivateKey = synthetic-device-key\n\n[Peer]\nEndpoint = vpn.example.net:51820\n"),
        new JSONObject().put("format","openvpn").put("name","rookstride-phone.ovpn").put("content","client\n<cert>\nsynthetic-certificate\n</cert>\n<key>\nsynthetic-private-key\n</key>\n"),
        new JSONObject().put("format","xray").put("name","rookstride-phone.txt").put("content","vless://fixture@vpn.example.net:443?security=reality#Phone"),
        new JSONObject().put("type","ikev2-eap").put("name","Fixture").put("remote",new JSONObject().put("addr","vpn.example.net").put("cert","synthetic-ca")).put("local",new JSONObject().put("eap_id","phone"))
    };}
    private void menu(ActivityScenario<RookstrideActivity> screen,JSONObject profile){
        screen.onActivity(a->{try{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod("shareProtocolProfile",JSONObject.class);m.setAccessible(true);m.invoke(a,profile);}catch(Exception e){throw new AssertionError(e);}});
        if(profile.optString("type").equals("ikev2-eap"))onView(withText("File without password")).perform(click());
    }
    @Test public void allProtocolsShareExactTextOrReadOnlyFilesOnlyAfterExplicitChoice()throws Exception{
        android.app.Instrumentation instrumentation=InstrumentationRegistry.getInstrumentation();Context context=instrumentation.getTargetContext();
        AtomicReference<Intent> captured=new AtomicReference<>();
        android.app.Instrumentation.ActivityMonitor monitor=new android.app.Instrumentation.ActivityMonitor(){@Override public android.app.Instrumentation.ActivityResult onStartActivity(Intent intent){
            if(Intent.ACTION_CHOOSER.equals(intent.getAction())){captured.set(intent.getParcelableExtra(Intent.EXTRA_INTENT));return new android.app.Instrumentation.ActivityResult(0,null);}return null;
        }};instrumentation.addMonitor(monitor);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            for(JSONObject response:profiles()){
                ConnectionExport expected=ConnectionExport.fromResponse(response);menu(screen,response);assertNull(captured.get());
                for(String action:new String[]{"Share connection file","Share configuration text","Save connection file",expected.protocol.equals("xray")?"Copy link":"Copy configuration","Cancel"})onView(withText(action)).check(matches(isCompletelyDisplayed()));
                onView(withText("Share connection file")).perform(click());Intent file=captured.getAndSet(null);assertNotNull(file);assertEquals(Intent.ACTION_SEND,file.getAction());assertEquals(expected.mime(),file.getType());assertFalse(file.hasExtra(Intent.EXTRA_TEXT));
                assertTrue((file.getFlags()&Intent.FLAG_GRANT_READ_URI_PERMISSION)!=0);assertEquals(0,file.getFlags()&Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                Uri uri=file.getParcelableExtra(Intent.EXTRA_STREAM);assertNotNull(uri);assertEquals(uri,file.getClipData().getItemAt(0).getUri());
                try(InputStream input=context.getContentResolver().openInputStream(uri)){assertEquals(expected.content,new String(read(input),java.nio.charset.StandardCharsets.UTF_8));}
                assertFalse(new File(context.getCacheDir(),"exports/"+expected.name).exists());
                menu(screen,response);onView(withText("Share configuration text")).perform(click());Intent text=captured.getAndSet(null);assertEquals("text/plain",text.getType());assertEquals(expected.content,text.getStringExtra(Intent.EXTRA_TEXT));assertFalse(text.hasExtra(Intent.EXTRA_STREAM));assertNull(text.getClipData());
                menu(screen,response);onView(withText(expected.protocol.equals("xray")?"Copy link":"Copy configuration")).perform(click());
                screen.onActivity(a->{android.content.ClipData clip=((android.content.ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE)).getPrimaryClip();assertNotNull(clip);assertEquals(expected.content,clip.getItemAt(0).getText().toString());assertTrue(clip.getDescription().getExtras().getBoolean("android.content.extra.IS_SENSITIVE"));});
            }
        }finally{instrumentation.removeMonitor(monitor);instrumentation.runOnMainSync(()->((android.content.ClipboardManager)context.getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(android.content.ClipData.newPlainText("","")));}
    }
    private byte[] read(InputStream input)throws IOException{ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);return output.toByteArray();}
    @Test public void documentSavePreservesAllFourFormatsAndCancellationLeavesNoPendingSecret()throws Exception{
        android.app.Instrumentation instrumentation=InstrumentationRegistry.getInstrumentation();Context context=instrumentation.getTargetContext();AtomicReference<ConnectionExport> expected=new AtomicReference<>();AtomicReference<File> output=new AtomicReference<>();final boolean[] cancel={false};
        android.app.Instrumentation.ActivityMonitor monitor=new android.app.Instrumentation.ActivityMonitor(){@Override public android.app.Instrumentation.ActivityResult onStartActivity(Intent intent){
            if(!Intent.ACTION_CREATE_DOCUMENT.equals(intent.getAction()))return null;
            String suggested=intent.getStringExtra(Intent.EXTRA_TITLE);if(expected.get().protocol.equals("awg")){assertTrue(ProfileDocumentExport.amneziaName(suggested));assertTrue(suggested.matches("rook-[a-f0-9]{10}\\.conf"));}else assertEquals(expected.get().name,suggested);assertEquals(expected.get().mime(),intent.getType());assertFalse(intent.hasExtra(Intent.EXTRA_TEXT));assertFalse(intent.hasExtra(Intent.EXTRA_STREAM));
            if(cancel[0])return new android.app.Instrumentation.ActivityResult(0,null);
            File directory=new File(context.getCacheDir(),"exports");directory.mkdirs();File file=new File(directory,expected.get().name);output.set(file);
            return new android.app.Instrumentation.ActivityResult(android.app.Activity.RESULT_OK,new Intent().setData(androidx.core.content.FileProvider.getUriForFile(context,context.getPackageName()+".files",file)));
        }};instrumentation.addMonitor(monitor);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            for(JSONObject response:profiles()){
                expected.set(ConnectionExport.fromResponse(response));menu(screen,response);onView(withText("Save connection file")).perform(click());onView(withText("File saved")).check(matches(isDisplayed()));onView(withText("Done")).perform(click());
                File file=output.getAndSet(null);assertEquals(expected.get().content,new String(java.nio.file.Files.readAllBytes(file.toPath()),java.nio.charset.StandardCharsets.UTF_8));assertTrue(file.delete());
            }
            cancel[0]=true;menu(screen,profiles()[0]);expected.set(ConnectionExport.fromResponse(profiles()[0]));onView(withText("Save connection file")).perform(click());
            screen.onActivity(a->assertNull(new androidx.lifecycle.ViewModelProvider(a).get(ProfileExportState.class).take()));
        }finally{instrumentation.removeMonitor(monitor);if(output.get()!=null)output.get().delete();}
    }
    @Test public void repeatedAwgSaveWritesCompleteFilesEvenWhenProviderAddsCollisionSuffix()throws Exception{
        android.app.Instrumentation instrumentation=InstrumentationRegistry.getInstrumentation();Context context=instrumentation.getTargetContext();JSONObject response=profiles()[0];ConnectionExport export=ConnectionExport.fromResponse(response);
        File directory=new File(context.getCacheDir(),"exports");directory.mkdirs();String prefix="collision-"+java.util.UUID.randomUUID();File prior=new File(directory,prefix+".conf");java.nio.file.Files.write(prior.toPath(),"earlier-export-must-remain".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        java.util.ArrayList<File> created=new java.util.ArrayList<>();java.util.HashSet<String> suggestions=new java.util.HashSet<>();
        android.app.Instrumentation.ActivityMonitor monitor=new android.app.Instrumentation.ActivityMonitor(){@Override public android.app.Instrumentation.ActivityResult onStartActivity(Intent intent){
            if(!Intent.ACTION_CREATE_DOCUMENT.equals(intent.getAction()))return null;
            String name=intent.getStringExtra(Intent.EXTRA_TITLE);assertTrue(ProfileDocumentExport.amneziaName(name));assertTrue("Repeated Save reused its collision-prone default",suggestions.add(name));
            // FileProvider deliberately has no DocumentsContract rename support.
            // It models a provider's incompatible post-CREATE display name.
            File file=new File(directory,prefix+" ("+(created.size()+1)+").conf");created.add(file);try{assertTrue(file.createNewFile());}catch(IOException error){throw new AssertionError(error);}
            return new android.app.Instrumentation.ActivityResult(android.app.Activity.RESULT_OK,new Intent().setData(androidx.core.content.FileProvider.getUriForFile(context,context.getPackageName()+".files",file)));
        }};instrumentation.addMonitor(monitor);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            for(int attempt=0;attempt<2;attempt++){
                menu(screen,response);onView(withText("Save connection file")).perform(click());onView(withText("File saved")).check(matches(isDisplayed()));onView(withText("Done")).perform(click());
                assertEquals(export.content,new String(java.nio.file.Files.readAllBytes(created.get(attempt).toPath()),java.nio.charset.StandardCharsets.UTF_8));
                assertEquals("earlier-export-must-remain",new String(java.nio.file.Files.readAllBytes(prior.toPath()),java.nio.charset.StandardCharsets.UTF_8));
                onView(withText("Action needs attention")).check(androidx.test.espresso.assertion.ViewAssertions.doesNotExist());
            }
        }finally{instrumentation.removeMonitor(monitor);for(File file:created)file.delete();prior.delete();}
    }
    @Test public void pendingDocumentExportSurvivesRotationWithoutPersistingSecrets()throws Exception{
        org.json.JSONObject profile=new org.json.JSONObject().put("content","synthetic-export-secret");final ProfileExportState[] pending=new ProfileExportState[1];
        try(androidx.test.core.app.ActivityScenario<org.strongswan.android.ui.RookstrideActivity> activity=androidx.test.core.app.ActivityScenario.launch(org.strongswan.android.ui.RookstrideActivity.class)){
            activity.onActivity(a->{pending[0]=new androidx.lifecycle.ViewModelProvider(a).get(ProfileExportState.class);pending[0].set(profile);});
            activity.recreate();activity.onActivity(a->{ProfileExportState restored=new androidx.lifecycle.ViewModelProvider(a).get(ProfileExportState.class);assertSame(pending[0],restored);assertEquals("synthetic-export-secret",restored.take().optString("content"));assertNull(restored.take());});
        }
    }
    @Test public void workerProfilesUseJsonMimeAndReadOnlyMemoryGrants()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();String name="rookstride-phone.rookvpn",content="{\"protocol\":\"hysteria2\",\"password\":\"sample-profile-secret\"}";
        Uri uri=ProfileExportProvider.issue(context,name,content);
        assertEquals("application/json",context.getContentResolver().getType(uri));
        try(InputStream input=context.getContentResolver().openInputStream(uri)){assertEquals(content,new String(read(input),java.nio.charset.StandardCharsets.UTF_8));}
        assertFalse(new File(context.getCacheDir(),"exports/"+name).exists());
        try{context.getContentResolver().openFileDescriptor(uri,"w");fail("Write access must be rejected");}catch(FileNotFoundException expected){}
        java.lang.reflect.Method prune=ProfileExportProvider.class.getDeclaredMethod("prune",long.class);prune.setAccessible(true);prune.invoke(null,android.os.SystemClock.elapsedRealtime()+300001);
        try{context.getContentResolver().openInputStream(uri);fail("Expired worker profile must be rejected");}catch(FileNotFoundException expected){}
    }
    @Test public void privateProfilesAreReadOnlyTemporaryAndAbsentFromDisk()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();String name="rook-0123456789.conf",content="private-test-profile-material";
        Uri uri=ProfileExportProvider.issue(context,name,content);
        try(InputStream input=context.getContentResolver().openInputStream(uri)){
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] bytes=new byte[1024];int n;while((n=input.read(bytes))!=-1)out.write(bytes,0,n);assertEquals(content,out.toString("UTF-8"));
        }
        try(android.database.Cursor cursor=context.getContentResolver().query(uri,null,null,null,null)){assertTrue(cursor.moveToFirst());assertEquals(name,cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)));}
        assertFalse(new File(context.getCacheDir(),"exports/"+name).exists());
        try{context.getContentResolver().openFileDescriptor(uri,"w");fail("Write access must be rejected");}catch(FileNotFoundException expected){}
        java.lang.reflect.Method prune=ProfileExportProvider.class.getDeclaredMethod("prune",long.class);prune.setAccessible(true);prune.invoke(null,android.os.SystemClock.elapsedRealtime()+300001);
        try{context.getContentResolver().openInputStream(uri);fail("Expired profile must be rejected");}catch(FileNotFoundException expected){}
        android.content.pm.ProviderInfo provider=context.getPackageManager().getProviderInfo(new android.content.ComponentName(context,ProfileExportProvider.class),0);assertFalse(provider.exported);assertTrue(provider.grantUriPermissions);
    }
}
