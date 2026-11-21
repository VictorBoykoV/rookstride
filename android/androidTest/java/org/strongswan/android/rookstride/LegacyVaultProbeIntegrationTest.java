package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.ContextWrapper;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import static org.junit.Assert.*;

/** Bounded, opt-in diagnosis of the frozen legacy Vault, not a passing product
 * test. Only synthetic isolated files are written. Real phone stores are hashed
 * directly, never read through Vault; no network or key mutation is requested. */
@RunWith(AndroidJUnit4.class)
public final class LegacyVaultProbeIntegrationTest {
    private static final String ALIAS="rookstride.gateway.v1";
    private static final String RESULT="legacy-vault-probe-result.json";
    private static final int ITERATIONS=15,CONCURRENT_SIZE=70024;

    @Test public void diagnoseFrozenLegacyProviderAndAbsolutePathLocks()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("legacy-vault-probe","allow_legacy_vault_probe");
        assertTrue("Only local isolated diagnosis is authorized",f.request.getBoolean("no_remote_access"));
        // This method was removed by the envelope integration. Do not let a
        // modern Vault silently qualify a probe intended for the frozen app.
        Vault.class.getDeclaredMethod("key");
        KeyStore keys=store();SecretKey key=existingKey();
        Map<String,String> originalFiles=realFiles(f.context),originalAliases=aliases(keys);
        File owned=Files.createTempDirectory(f.context.getFilesDir().toPath(),"legacy-vault-probe-").toFile();
        android.system.Os.chmod(owned.getAbsolutePath(),0700);
        File isolated=new File(owned,"store");assertTrue(isolated.mkdir());android.system.Os.chmod(isolated.getAbsolutePath(),0700);
        JSONObject result=new JSONObject().put("action","legacy-vault-probe").put("diagnostic_only",true)
                .put("product_acceptance",false).put("no_remote_access",true).put("concurrent_operations_planned",60);
        boolean complete=false;ExecutorService pool=null;
        try {
            result.put("phase","resolve genuine Android storage aliases");
            String suffix=owned.getName()+"/store";
            File userPath=new File("/data/user/0/"+f.context.getPackageName()+"/files",suffix);
            File dataPath=new File("/data/data/"+f.context.getPackageName()+"/files",suffix);
            assertEquals("Both aliases must identify only the isolated store",isolated.getCanonicalFile(),userPath.getCanonicalFile());
            assertEquals("Both aliases must identify the same isolated store",isolated.getCanonicalFile(),dataPath.getCanonicalFile());
            assertTrue("Both aliases must already exist",userPath.isDirectory()&&dataPath.isDirectory());
            assertTrue("Aliases must be the same inode",Files.isSameFile(userPath.toPath(),dataPath.toPath()));
            android.system.StructStat userStat=android.system.Os.stat(userPath.getAbsolutePath()),dataStat=android.system.Os.stat(dataPath.getAbsolutePath());
            assertEquals(userStat.st_dev,dataStat.st_dev);assertEquals(userStat.st_ino,dataStat.st_ino);
            Context userContext=context(f.context,userPath),dataContext=context(f.context,dataPath);
            Vault userVault=new Vault(userContext),dataVault=new Vault(dataContext);
            Field lock=Vault.class.getDeclaredField("fileLock");lock.setAccessible(true);
            result.put("path_aliases",new JSONObject().put("user_absolute",userPath.getAbsolutePath()).put("data_absolute",dataPath.getAbsolutePath())
                    .put("canonical",userPath.getCanonicalPath()).put("same_inode",true).put("device",userStat.st_dev).put("inode",userStat.st_ino)
                    .put("lock_objects_same",lock.get(userVault)==lock.get(dataVault))
                    .put("user_lock_identity",System.identityHashCode(lock.get(userVault))).put("data_lock_identity",System.identityHashCode(lock.get(dataVault))));

            result.put("phase","sequential legacy Vault and in-memory provider probes");
            JSONArray sequential=new JSONArray(),memory=new JSONArray();
            for(int size:new int[]{31744,65536,70024,78082,250000}) {
                ArrayList<Gateway> wanted=rows(size,"sequential-"+size);byte[] plain=serialize(wanted);
                JSONObject observation=new JSONObject().put("plaintext_bytes",size);
                try {existingKey();userVault.write(wanted);observation.put("write_completed",true);}
                catch(Exception error){observation.put("write_completed",false).put("write_error",failure(error));}
                try {existingKey();ArrayList<Gateway> actual=userVault.read();observation.put("vault_read_completed",true).put("vault_round_trip_equal",Arrays.equals(plain,serialize(actual)));}
                catch(Exception error){observation.put("vault_read_completed",false).put("vault_read_error",failure(error));}
                File catalog=new File(userPath,"gateways.enc");
                if(catalog.isFile()) {
                    byte[] encoded=Files.readAllBytes(catalog.toPath());
                    try {observation.put("file_bytes",encoded.length).put("file_sha256",PrivateAdministrationFixture.hash(encoded))
                            .put("file_offset",decrypt(encoded,key,true,plain)).put("file_copied_payload",decrypt(encoded,key,false,plain));}
                    finally {Arrays.fill(encoded,(byte)0);}
                }
                sequential.put(observation);memory.put(inMemory(plain,key));Arrays.fill(plain,(byte)0);
            }
            result.put("sequential",sequential).put("in_memory",memory);

            result.put("phase","bounded concurrent legacy operations");
            // The seed need not authenticate for this diagnostic to continue:
            // provider failures and path-lock races are recorded, never hidden.
            JSONObject seed=new JSONObject();
            try {existingKey();userVault.write(rows(CONCURRENT_SIZE,"seed"));seed.put("write_completed",true);}
            catch(Exception error){seed.put("write_completed",false).put("error",failure(error));}
            result.put("concurrent_seed",seed);
            pool=Executors.newFixedThreadPool(4);CountDownLatch ready=new CountDownLatch(4),start=new CountDownLatch(1);
            List<Future<JSONObject>> tasks=new ArrayList<>();
            for(int worker=0;worker<4;worker++) {
                final int index=worker;final boolean writer=worker<2;
                final Vault vault=(worker%2==0)?userVault:dataVault;
                tasks.add(pool.submit(()->{
                    JSONObject observation=new JSONObject().put("worker",index).put("role",writer?"writer":"reader");
                    JSONArray errors=new JSONArray();int completed=0,attempted=0,authFailures=0,invalidRows=0;
                    ready.countDown();if(!start.await(10,TimeUnit.SECONDS))throw new IOException("Probe start deadline elapsed");
                    for(int i=0;i<ITERATIONS&&!Thread.currentThread().isInterrupted();i++) {
                        attempted++;
                        try {
                            existingKey();
                            if(writer)vault.write(rows(CONCURRENT_SIZE,"worker-"+index+"-"+i));
                            else {
                                ArrayList<Gateway> values=vault.read();
                                if(values.size()!=1||!"synthetic-vpn-secret".equals(values.get(0).vpnPassword)||serialize(values).length!=CONCURRENT_SIZE)invalidRows++;
                            }
                            completed++;
                        }catch(Exception error){if(authenticationFailure(error))authFailures++;errors.put(new JSONObject().put("iteration",i).put("failure",failure(error)));}
                    }
                    return observation.put("attempted",attempted).put("completed",completed).put("authentication_failures",authFailures)
                            .put("invalid_row_observations",invalidRows).put("errors",errors);
                }));
            }
            assertTrue("Probe workers did not become ready",ready.await(10,TimeUnit.SECONDS));start.countDown();
            JSONArray workers=new JSONArray();int attempted=0,completed=0,authFailures=0,errorCount=0,invalidRows=0;
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(90);
            for(Future<JSONObject> task:tasks) {
                JSONObject worker=task.get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);workers.put(worker);
                attempted+=worker.getInt("attempted");completed+=worker.getInt("completed");authFailures+=worker.getInt("authentication_failures");
                invalidRows+=worker.getInt("invalid_row_observations");errorCount+=worker.getJSONArray("errors").length();
            }
            result.put("workers",workers).put("concurrent_operations_attempted",attempted).put("concurrent_operations_completed",completed)
                    .put("concurrent_authentication_failures",authFailures).put("concurrent_errors",errorCount).put("concurrent_invalid_rows",invalidRows);
            assertEquals("Run only the reviewed bounded operation count",60,attempted);
            pool.shutdown();assertTrue("Probe workers did not stop",pool.awaitTermination(10,TimeUnit.SECONDS));pool=null;

            result.put("phase","final isolated ciphertext observations");
            JSONArray finalReads=new JSONArray();
            for(Vault vault:new Vault[]{userVault,dataVault}) {
                JSONObject item=new JSONObject();try {existingKey();ArrayList<Gateway> values=vault.read();item.put("read_completed",true).put("records",values.size())
                        .put("synthetic_record_valid",values.size()==1&&"synthetic-vpn-secret".equals(values.get(0).vpnPassword)&&serialize(values).length==CONCURRENT_SIZE);}
                catch(Exception error){item.put("read_completed",false).put("error",failure(error));}finalReads.put(item);
            }
            result.put("final_vault_reads",finalReads);
            File catalog=new File(userPath,"gateways.enc");
            if(catalog.isFile()) {byte[] encoded=Files.readAllBytes(catalog.toPath());try {result.put("final_file_bytes",encoded.length).put("final_file_offset",decrypt(encoded,key,true,null)).put("final_file_copied_payload",decrypt(encoded,key,false,null));}finally {Arrays.fill(encoded,(byte)0);}}
            complete=true;
        }catch(Exception|AssertionError failure) {result.put("probe_infrastructure_error",failure(failure));throw failure;}
        finally {
            boolean stopped=true;if(pool!=null){pool.shutdownNow();stopped=pool.awaitTermination(20,TimeUnit.SECONDS);}
            // Never remove a directory while diagnostic workers may still use it.
            boolean removed=stopped&&removeOwned(owned,f.context.getFilesDir());
            Map<String,String> afterFiles=realFiles(f.context),afterAliases=aliases(store());
            boolean sameFiles=originalFiles.equals(afterFiles),sameAliases=originalAliases.equals(afterAliases);
            result.put("probe_completed",complete).put("workers_stopped",stopped).put("isolated_directory_removed",removed)
                    .put("real_ciphertexts_unchanged",sameFiles).put("keystore_aliases_and_creation_dates_unchanged",sameAliases)
                    .put("real_files_before",new JSONObject(originalFiles)).put("real_files_after",new JSONObject(afterFiles))
                    .put("key_alias_count_before",originalAliases.size()).put("key_alias_count_after",afterAliases.size())
                    .put("interpretation","Observed failures are diagnostic data. Completion does not qualify legacy storage or establish the original corruption cause.");
            f.receipt(RESULT,result);
            assertTrue("Isolated workers did not stop",stopped);assertTrue("Only the isolated probe directory must be removed",removed);
            assertEquals("Real phone ciphertexts changed",originalFiles,afterFiles);assertEquals("Keystore alias metadata changed",originalAliases,afterAliases);
        }
    }

    private static Context context(Context original,File directory){return new ContextWrapper(original){@Override public File getFilesDir(){return directory;}};}
    private static KeyStore store()throws Exception {KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);return keys;}
    private static SecretKey existingKey()throws Exception {KeyStore keys=store();assertTrue("An existing alias is mandatory; never generate a probe key",keys.containsAlias(ALIAS));SecretKey key=(SecretKey)keys.getKey(ALIAS,null);assertNotNull("The existing key is unavailable",key);return key;}
    private static ArrayList<Gateway> rows(int size,String name)throws Exception {Gateway row=new Gateway();row.set("name",name);row.data.put("rememberVpn",true).put("payload","");row.vpnPassword="synthetic-vpn-secret";ArrayList<Gateway> rows=new ArrayList<>(Collections.singletonList(row));int overhead=serialize(rows).length;assertTrue(size>=overhead);char[] fill=new char[size-overhead];Arrays.fill(fill,'x');row.data.put("payload",new String(fill));assertEquals(size,serialize(rows).length);return rows;}
    private static byte[] serialize(ArrayList<Gateway> rows)throws Exception {JSONArray data=new JSONArray();for(Gateway row:rows)data.put(row.persisted());return data.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject inMemory(byte[] plain,SecretKey key)throws Exception {JSONObject result=new JSONObject().put("plaintext_bytes",plain.length);byte[] encoded=null;try {Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);result.put("provider",cipher.getProvider().getName());ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(cipher.getIV());out.write(cipher.doFinal(plain));encoded=out.toByteArray();result.put("encrypt_completed",true).put("encoded_bytes",encoded.length).put("offset",decrypt(encoded,key,true,plain)).put("copied_payload",decrypt(encoded,key,false,plain));}catch(Exception error){result.put("encrypt_completed",false).put("error",failure(error));}finally {if(encoded!=null)Arrays.fill(encoded,(byte)0);}return result;}
    private static JSONObject decrypt(byte[] encoded,SecretKey key,boolean offset,byte[] wanted)throws Exception {JSONObject result=new JSONObject();byte[] plain=null,payload=null;try {if(encoded.length<29)throw new IOException("Legacy ciphertext is too short");Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,Arrays.copyOfRange(encoded,0,12)));result.put("provider",cipher.getProvider().getName());if(offset)plain=cipher.doFinal(encoded,12,encoded.length-12);else {payload=Arrays.copyOfRange(encoded,12,encoded.length);plain=cipher.doFinal(payload);}result.put("authenticated",true).put("plaintext_bytes",plain.length);if(wanted!=null)result.put("plaintext_equal",Arrays.equals(wanted,plain));}catch(Exception error){result.put("authenticated",false).put("error",failure(error));}finally {if(plain!=null)Arrays.fill(plain,(byte)0);if(payload!=null)Arrays.fill(payload,(byte)0);}return result;}
    private static JSONObject failure(Throwable error)throws Exception {JSONObject result=new JSONObject().put("type",error.getClass().getName());if(error.getCause()!=null)result.put("cause_type",error.getCause().getClass().getName());return result;}
    private static boolean authenticationFailure(Throwable error){for(Throwable at=error;at!=null;at=at.getCause())if(at instanceof javax.crypto.AEADBadTagException)return true;return false;}
    private static Map<String,String> aliases(KeyStore keys)throws Exception {Map<String,String> result=new TreeMap<>();for(String name:Collections.list(keys.aliases())){java.util.Date created=keys.getCreationDate(name);result.put(name,created==null?"unknown":Long.toString(created.getTime()));}return result;}
    private static Map<String,String> realFiles(Context context)throws Exception {Map<String,String> result=new TreeMap<>();for(String name:new String[]{"gateways.enc","ssh-identities.enc"})for(String suffix:new String[]{"",".bak",".new"}){File file=new File(context.getFilesDir(),name+suffix);if(file.exists())result.put("files/"+name+suffix,PrivateAdministrationFixture.hash(file));}File nativeRoot=new File(context.getNoBackupFilesDir(),"vpn-profiles");if(nativeRoot.isDirectory()){File[] children=nativeRoot.listFiles();assertNotNull(children);for(File file:children){assertFalse("Do not follow native profile links",Files.isSymbolicLink(file.toPath()));if(file.isFile())result.put("native/"+file.getName(),PrivateAdministrationFixture.hash(file));}}return result;}
    private static boolean removeOwned(File owned,File appFiles)throws Exception {if(!owned.getName().startsWith("legacy-vault-probe-")||!owned.getCanonicalFile().getParentFile().equals(appFiles.getCanonicalFile()))throw new IOException("Unexpected probe cleanup scope");return removeTree(owned);}
    private static boolean removeTree(File file)throws Exception {if(Files.isSymbolicLink(file.toPath()))return file.delete();boolean okay=true;if(file.isDirectory()){File[] children=file.listFiles();if(children==null)return false;for(File child:children)okay=removeTree(child)&&okay;}return file.delete()&&okay;}
}
