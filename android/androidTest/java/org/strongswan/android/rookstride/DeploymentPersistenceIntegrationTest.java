package org.strongswan.android.rookstride;

import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Opt-in real local Vault failure/retry; no foreground service or server starts. */
@RunWith(AndroidJUnit4.class)
public final class DeploymentPersistenceIntegrationTest {
    @Test public void finalSaveFailureStaysAttentionAndRetriesLocallyWithoutRemoteReplay()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("deployment-local-save","allow_deployment_local_save");
        assertTrue(f.request.getBoolean("no_remote_access"));
        assertNull("No real coordinator may be replaced",DeploymentService.current());
        KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);assertTrue(keys.containsAlias("rookstride.gateway.v1"));
        Map<String,String> before=realFiles(f.context),aliases=aliases(keys);
        File parent=Files.createTempDirectory(f.context.getFilesDir().toPath(),"deployment-save-test-").toFile();
        File blocked=new File(parent,"store");Files.write(blocked.toPath(),new byte[]{1});
        String preferenceName="deployment-save-test-"+parent.getName();AtomicInteger starts=new AtomicInteger();
        Context local=new ContextWrapper(f.context){
            @Override public File getFilesDir(){return blocked;}
            @Override public SharedPreferences getSharedPreferences(String name,int mode){assertEquals("rookstride-deployment",name);return super.getSharedPreferences(preferenceName,mode);}
            @Override public ComponentName startForegroundService(Intent intent){starts.incrementAndGet();throw new AssertionError("Local save must never launch the remote worker");}
        };
        Field current=DeploymentService.class.getDeclaredField("current");current.setAccessible(true);
        JSONObject receipt=new JSONObject().put("action","deployment-local-save").put("no_remote_access",true);boolean passed=false;
        try{
            Gateway node=new Gateway();node.set("host","203.0.113.10");node.set("job","confirmed-job-sentinel");
            ArrayList<Gateway> nodes=new ArrayList<>();nodes.add(node);
            DeploymentService.Session session=new DeploymentService.Session(node,nodes,"protocol",new JSONObject(),false,System.currentTimeMillis()-1000);
            session.result=new JSONObject().put("state","complete").put("fixture",true);
            session.progress.finish();long originalFinished=session.progress.finished;String originalPhase=session.progress.phase;
            current.set(null,session);
            assertFalse("The inaccessible catalog must fail a real Vault write",DeploymentService.persistProgress(local,session));
            assertEquals("needs-attention",session.progress.state);assertNotNull(session.error);assertTrue(DeploymentService.needsLocalSave());
            JSONObject saved=new JSONObject(local.getSharedPreferences("rookstride-deployment",0).getString("progress","{}"));
            assertEquals("needs-attention",saved.getString("state"));assertFalse(saved.getString("phase").contains("server failed"));
            assertTrue(session.result.getBoolean("fixture"));assertEquals("confirmed-job-sentinel",node.get("job"));
            try{DeploymentService.retryLocalSave(local);fail("Retry succeeded before storage returned");}catch(IOException expected){}
            assertTrue(DeploymentService.needsLocalSave());assertEquals("needs-attention",session.progress.state);
            assertFalse("Abandon must preserve a confirmed unpublished result",DeploymentService.abandon(local,session.progress));
            DeploymentService.forget(local,node);assertSame(session,DeploymentService.current());
            Gateway unrelated=new Gateway();try{DeploymentService.launch(local,unrelated,nodes,"protocol",new JSONObject(),false);fail("Another remote job could start before saving");}catch(IllegalStateException expected){}
            assertEquals(0,starts.get());
            assertTrue(blocked.delete());assertTrue(blocked.mkdir());
            // Exercise the real coordinator with a real authenticated private
            // retry record: failed catalog publication must not clear it.
            Gateway retained=new Gateway(node.persisted());retained.set("job","");retained.set("protocol","xray");retained.set("fingerprint","SHA256:"+String.join("",Collections.nCopies(43,"A")));
            StandaloneInstallRetry.startRequest(local,retained,new JSONObject().put("action","start").put("protocol","xray").put("server",retained.get("host")).put("sshPort",22).put("login","phone"));
            File retryCipher=new File(blocked,"standalone-installs.enc");String retainedHash=PrivateAdministrationFixture.hash(retryCipher);
            // AtomicFile may legitimately rename/delete an empty base directory.
            // Deny parent writes while leaving the saved request readable instead.
            android.system.Os.chmod(blocked.getAbsolutePath(),0500);
            try{
                try{DeploymentService.retryLocalSave(local);fail("An unwritable catalog parent was published");}catch(IOException expected){}
                assertTrue(DeploymentService.needsLocalSave());assertSame(session,DeploymentService.current());assertEquals(retainedHash,PrivateAdministrationFixture.hash(retryCipher));assertTrue(StandaloneInstallRetry.has(local,retained));assertEquals(0,starts.get());
            }finally{android.system.Os.chmod(blocked.getAbsolutePath(),0700);}
            // Existing public launch API must intercept a stale retry locally,
            // even if its caller passes resume=false. No worker can be started.
            DeploymentService.launch(local,node,nodes,"protocol",new JSONObject(),false);
            assertEquals(0,starts.get());assertFalse(DeploymentService.needsLocalSave());assertSame(session,DeploymentService.current());
            assertEquals("complete",session.progress.state);assertEquals(originalFinished,session.progress.finished);assertEquals(originalPhase,session.progress.phase);assertNull(session.error);
            assertEquals("complete",new JSONObject(local.getSharedPreferences("rookstride-deployment",0).getString("progress","{}")).getString("state"));
            ArrayList<Gateway> savedNodes=new Vault(local).read();assertEquals(1,savedNodes.size());assertEquals("confirmed-job-sentinel",savedNodes.get(0).get("job"));
            assertTrue("Confirmed catalog publication clears retained retry secrets",new Vault(local,"standalone-installs.enc").read().isEmpty());
            receipt.put("final_failure_needs_attention",true).put("retry_failure_retained",true).put("durable_progress_matches_state",true).put("confirmed_result_retained",true).put("abandon_and_forget_guarded",true).put("remote_service_starts",starts.get()).put("local_retry_restored_completion",true);
            passed=true;
        }finally{
            if(blocked.isDirectory())android.system.Os.chmod(blocked.getAbsolutePath(),0700);
            current.set(null,null);local.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();f.context.deleteSharedPreferences(preferenceName);
            boolean removed=removeOwned(parent,f.context.getFilesDir());boolean unchanged=before.equals(realFiles(f.context)),sameAliases=aliases.equals(aliases(keys));
            receipt.put("passed",passed&&removed&&unchanged&&sameAliases).put("isolated_directory_removed",removed).put("real_ciphertexts_unchanged",unchanged).put("key_aliases_unchanged",sameAliases);
            f.receipt("deployment-local-save-result.json",receipt);
            assertTrue(removed);assertTrue(unchanged);assertTrue(sameAliases);
        }
    }
    @Test public void abandonCatalogFailurePreservesRetainedRequestAndAttention()throws Exception{
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("deployment-local-save","allow_deployment_local_save");assertTrue(f.request.getBoolean("no_remote_access"));assertNull(DeploymentService.current());
        KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);assertTrue(keys.containsAlias("rookstride.gateway.v1"));Map<String,String> before=realFiles(f.context),oldAliases=aliases(keys);
        File parent=Files.createTempDirectory(f.context.getFilesDir().toPath(),"deployment-save-test-").toFile(),store=new File(parent,"store");assertTrue(store.mkdir());String preferenceName="deployment-abandon-test-"+parent.getName();AtomicInteger starts=new AtomicInteger();
        Context local=new ContextWrapper(f.context){@Override public File getFilesDir(){return store;}@Override public SharedPreferences getSharedPreferences(String name,int mode){assertEquals("rookstride-deployment",name);return super.getSharedPreferences(preferenceName,mode);}@Override public ComponentName startForegroundService(Intent intent){starts.incrementAndGet();throw new AssertionError("Abandon cannot start a server worker");}};
        Field current=DeploymentService.class.getDeclaredField("current");current.setAccessible(true);JSONObject receipt=new JSONObject().put("action","deployment-local-abandon-failure").put("no_remote_access",true);boolean passed=false;
        try{
            Gateway node=new Gateway();node.set("host","203.0.113.10");node.set("protocol","xray");node.set("fingerprint","SHA256:"+String.join("",Collections.nCopies(43,"A")));ArrayList<Gateway> catalog=new ArrayList<>();catalog.add(node);new Vault(local).write(catalog);
            StandaloneInstallRetry.startRequest(local,node,new JSONObject().put("action","start").put("protocol","xray").put("server",node.get("host")).put("sshPort",22).put("login","phone"));
            DeploymentService.Session session=new DeploymentService.Session(node,catalog,"protocol",new JSONObject(),true,System.currentTimeMillis()-1000);session.progress.state="needs-attention";current.set(null,session);
            SharedPreferences prefs=local.getSharedPreferences("rookstride-deployment",0);assertTrue(prefs.edit().putString("progress",session.progress.json().toString()).commit());String progress=prefs.getString("progress","");File secret=new File(store,"standalone-installs.enc");String secretHash=PrivateAdministrationFixture.hash(secret);
            File actual=new File(store,"gateways.enc"),held=new File(store,"catalog-held");assertTrue(actual.renameTo(held));assertTrue(actual.mkdir());
            try{DeploymentService.abandon(local,session.progress);fail("Abandon cleared progress without an acknowledged catalog marker");}catch(Exception expected){assertNotNull(expected.getMessage());}
            assertSame(session,DeploymentService.current());assertEquals("needs-attention",session.progress.state);assertEquals(progress,prefs.getString("progress",""));assertEquals(secretHash,PrivateAdministrationFixture.hash(secret));assertTrue(StandaloneInstallRetry.has(local,node));assertFalse(node.data.optBoolean("setupAbandoned"));assertEquals(0,starts.get());
            assertTrue(actual.delete());assertTrue(held.renameTo(actual));assertFalse(new Vault(local).read().get(0).data.optBoolean("setupAbandoned"));receipt.put("catalog_failure_keeps_attention",true).put("retained_request_unchanged",true).put("remote_service_starts",0);passed=true;
        }finally{
            current.set(null,null);local.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();f.context.deleteSharedPreferences(preferenceName);boolean removed=removeOwned(parent,f.context.getFilesDir()),unchanged=before.equals(realFiles(f.context)),sameAliases=oldAliases.equals(aliases(keys));receipt.put("passed",passed&&removed&&unchanged&&sameAliases).put("isolated_directory_removed",removed).put("real_ciphertexts_unchanged",unchanged).put("key_aliases_unchanged",sameAliases);f.receipt("deployment-local-abandon-result.json",receipt);assertTrue(removed);assertTrue(unchanged);assertTrue(sameAliases);
        }
    }
    private static Map<String,String> aliases(KeyStore keys)throws Exception{Map<String,String> result=new TreeMap<>();for(String name:Collections.list(keys.aliases()))result.put(name,String.valueOf(keys.getCreationDate(name)));return result;}
    private static Map<String,String> realFiles(Context context)throws Exception{
        Map<String,String> result=new TreeMap<>();for(String name:new String[]{"gateways.enc","ssh-identities.enc","standalone-installs.enc"})for(String suffix:new String[]{"",".bak",".new"}){File file=new File(context.getFilesDir(),name+suffix);if(file.exists())result.put(name+suffix,PrivateAdministrationFixture.hash(file));}
        File nativeRoot=new File(context.getNoBackupFilesDir(),"vpn-profiles");if(nativeRoot.isDirectory())for(File file:nativeRoot.listFiles()){assertFalse(Files.isSymbolicLink(file.toPath()));if(file.isFile())result.put("native/"+file.getName(),PrivateAdministrationFixture.hash(file));}return result;
    }
    private static boolean removeOwned(File directory,File appFiles)throws Exception{if(!directory.getName().startsWith("deployment-save-test-")||!directory.getCanonicalFile().getParentFile().equals(appFiles.getCanonicalFile()))throw new IOException("Unexpected isolated cleanup scope");return remove(directory);}
    private static boolean remove(File file)throws IOException{if(Files.isSymbolicLink(file.toPath()))return file.delete();boolean ok=true;if(file.isDirectory()){File[] children=file.listFiles();if(children==null)return false;for(File child:children)ok=remove(child)&&ok;}return file.delete()&&ok;}
}
