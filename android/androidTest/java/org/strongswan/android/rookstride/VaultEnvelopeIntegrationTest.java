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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import static org.junit.Assert.*;

/** Opt-in actual Android Keystore/AtomicFile checks in a fresh isolated directory.
 * Real phone files are hashed directly, never opened through Vault or rewritten.
 * No server calls, alias generation, alias deletion or catalog recovery occur. */
@RunWith(AndroidJUnit4.class)
public final class VaultEnvelopeIntegrationTest {
    private static final String ALIAS="rookstride.gateway.v1",RESULT="vault-envelope-storage-result.json";
    private static final byte[] MAGIC="ROOKVLT2".getBytes(StandardCharsets.US_ASCII);
    private interface Checked {void run()throws Exception;}

    @Test public void actualKeystoreEnvelopeAndAtomicWritesPreserveOtherPhoneData()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("vault-envelope-storage","allow_vault_envelope_storage");
        assertTrue("Only local isolated storage checks are authorized",f.request.getBoolean("no_remote_access"));
        KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);
        assertTrue("Use the existing phone key; never generate one for this test",keys.containsAlias(ALIAS));
        SecretKey wrapping=(SecretKey)keys.getKey(ALIAS,null);assertNotNull(wrapping);
        Map<String,String> realFiles=realFiles(f.context),aliases=aliases(keys);
        File parent=Files.createTempDirectory(f.context.getFilesDir().toPath(),"vault-envelope-test-").toFile();
        android.system.Os.chmod(parent.getAbsolutePath(),0700);
        File isolated=new File(parent,"store");assertTrue(isolated.mkdir());android.system.Os.chmod(isolated.getAbsolutePath(),0700);
        Context local=context(f.context,isolated);JSONObject result=new JSONObject().put("action","vault-envelope-storage").put("no_remote_access",true);
        boolean complete=false;ExecutorService workers=null;
        try{
            // An existing ciphertext also makes Vault's missing-key guard refuse
            // generation if the prechecked alias unexpectedly becomes unavailable.
            byte[] seedPlain=serialize(rows(512,"seed")),seed=legacy(seedPlain,wrapping);
            assertArrayEquals(seedPlain,VaultCipher.decrypt("gateways.enc",seed,wrapping));
            Files.write(new File(isolated,"gateways.enc").toPath(),seed);
            Arrays.fill(seedPlain,(byte)0);Arrays.fill(seed,(byte)0);
            JSONArray sizes=new JSONArray();
            result.put("phase","bounded envelope round trips");
            for(int size:new int[]{31744,32768,65535,65536,65537,70024,78082,250000,VaultCipher.MAX_PLAINTEXT_BYTES}){
                ArrayList<Gateway> wanted=rows(size,"round-trip");
                new Vault(local).write(wanted);assertTrue("New writes need the versioned envelope",newFormat(new File(isolated,"gateways.enc")));
                ArrayList<Gateway> actual=new Vault(local).read();assertRows(wanted,actual);
                byte[] encoded=Files.readAllBytes(new File(isolated,"gateways.enc").toPath());
                assertEquals(size+96,encoded.length);
                assertArrayEquals(serialize(wanted),VaultCipher.decrypt("gateways.enc",encoded,wrapping));
                sizes.put(new JSONObject().put("plaintext_bytes",size).put("file_bytes",encoded.length));Arrays.fill(encoded,(byte)0);
            }
            result.put("round_trips",sizes);

            result.put("phase","authenticated legacy migration");
            ArrayList<Gateway> oldRows=rows(2048,"legacy");byte[] plain=serialize(oldRows),old=legacy(plain,wrapping);
            assertArrayEquals("Only write an already authenticated legacy fixture",plain,VaultCipher.decrypt("gateways.enc",old,wrapping));
            Files.write(new File(isolated,"gateways.enc").toPath(),old);assertRows(oldRows,new Vault(local).read());
            new Vault(local).write(oldRows);assertTrue(newFormat(new File(isolated,"gateways.enc")));assertRows(oldRows,new Vault(local).read());
            Arrays.fill(plain,(byte)0);Arrays.fill(old,(byte)0);result.put("legacy_authenticated_read_and_new_write",true);

            result.put("phase","oversize preservation");
            File catalog=new File(isolated,"gateways.enc");byte[] before=Files.readAllBytes(catalog.toPath());
            rejected(()->new Vault(local).write(rows(VaultCipher.MAX_PLAINTEXT_BYTES+1,"too-large")));
            assertArrayEquals("An oversized ordinary write replaced the valid catalog",before,Files.readAllBytes(catalog.toPath()));
            assertRows(oldRows,new Vault(local).read());assertFalse(new File(isolated,"gateways.enc.bak").exists());assertFalse(new File(isolated,"gateways.enc.new").exists());
            result.put("ordinary_oversize_write_preserves_file",true);

            result.put("phase","tamper and purpose rejection");
            byte[] bad=before.clone();bad[bad.length-1]^=1;Files.write(catalog.toPath(),bad);rejected(()->new Vault(local).read());
            assertArrayEquals("A failed read overwrote its evidence",bad,Files.readAllBytes(catalog.toPath()));Files.write(catalog.toPath(),before);
            File pins=new File(isolated,"ssh-identities.enc");Files.write(pins.toPath(),before);rejected(()->new Vault(local,"ssh-identities.enc").read());
            assertArrayEquals(before,Files.readAllBytes(pins.toPath()));
            ArrayList<Gateway> pinRows=rows(1024,"isolated-pins");new Vault(local,"ssh-identities.enc").write(pinRows);assertRows(pinRows,new Vault(local,"ssh-identities.enc").read());
            assertArrayEquals("Pin writes changed the separate catalog",before,Files.readAllBytes(catalog.toPath()));
            Arrays.fill(before,(byte)0);Arrays.fill(bad,(byte)0);result.put("tamper_rejected_without_rewrite",true).put("cross_purpose_envelope_rejected",true);

            result.put("phase","canonical alias and concurrent access");
            File alias=new File(parent,"alias");Files.createSymbolicLink(alias.toPath(),isolated.toPath());Context alternate=context(f.context,alias);
            Vault direct=new Vault(local),throughAlias=new Vault(alternate);Field lock=Vault.class.getDeclaredField("fileLock");lock.setAccessible(true);
            assertSame("Equivalent storage paths need the same process lock",lock.get(direct),lock.get(throughAlias));
            workers=Executors.newFixedThreadPool(3);final ExecutorService pool=workers;CountDownLatch ready=new CountDownLatch(3),start=new CountDownLatch(1);AtomicInteger writes=new AtomicInteger(),reads=new AtomicInteger();List<Future<?>> tasks=new ArrayList<>();
            for(int n=0;n<2;n++){final int worker=n;tasks.add(pool.submit(()->{ready.countDown();assertTrue(start.await(10,TimeUnit.SECONDS));for(int i=0;i<8;i++){new Vault(worker==0?local:alternate).write(rows(70024+worker,"worker-"+worker+"-"+i));writes.incrementAndGet();}return null;}));}
            tasks.add(pool.submit(()->{ready.countDown();assertTrue(start.await(10,TimeUnit.SECONDS));for(int i=0;i<25;i++){ArrayList<Gateway> values=new Vault(i%2==0?local:alternate).read();assertEquals(1,values.size());assertEquals("synthetic-vpn-secret",values.get(0).vpnPassword);assertTrue(values.get(0).get("name").equals("legacy")||values.get(0).get("name").startsWith("worker-"));reads.incrementAndGet();}return null;}));
            assertTrue(ready.await(10,TimeUnit.SECONDS));start.countDown();for(Future<?> task:tasks)task.get(90,TimeUnit.SECONDS);
            assertEquals(16,writes.get());assertEquals(25,reads.get());assertEquals(1,new Vault(local).read().size());
            result.put("canonical_alias_shared_lock",true).put("concurrent_writes",writes.get()).put("concurrent_reads",reads.get()).put("concurrent_authentication_failures",0);
            complete=true;
        }finally{
            if(workers!=null){workers.shutdownNow();assertTrue("Isolated storage workers did not stop",workers.awaitTermination(20,TimeUnit.SECONDS));}
            boolean removed=removeOwned(parent,f.context.getFilesDir());
            Map<String,String> afterFiles=realFiles(f.context),afterAliases=aliases(keys);
            boolean unchangedFiles=realFiles.equals(afterFiles),unchangedAliases=aliases.equals(afterAliases);
            result.put("passed",complete&&removed&&unchangedFiles&&unchangedAliases).put("test_directory_removed",removed).put("real_ciphertexts_unchanged",unchangedFiles).put("keystore_aliases_and_creation_dates_unchanged",unchangedAliases).put("real_files_before",new JSONObject(realFiles)).put("real_files_after",new JSONObject(afterFiles)).put("alias_count",aliases.size());
            f.receipt(RESULT,result);
            assertTrue("The exact isolated directory was not cleaned",removed);assertEquals("Real phone ciphertexts changed",realFiles,afterFiles);assertEquals("Keystore alias metadata changed",aliases,afterAliases);
        }
    }
    private static Context context(Context original,File directory){return new ContextWrapper(original){@Override public File getFilesDir(){return directory;}};}
    private static ArrayList<Gateway> rows(int size,String name)throws Exception {
        Gateway row=new Gateway();row.set("name",name);row.data.put("rememberVpn",true).put("payload","");row.vpnPassword="synthetic-vpn-secret";
        ArrayList<Gateway> result=new ArrayList<>(Collections.singletonList(row));int overhead=serialize(result).length;assertTrue(size>=overhead);
        char[] fill=new char[size-overhead];Arrays.fill(fill,'x');row.data.put("payload",new String(fill));assertEquals(size,serialize(result).length);return result;
    }
    private static byte[] serialize(ArrayList<Gateway> rows)throws Exception {JSONArray values=new JSONArray();for(Gateway row:rows)values.put(row.persisted());return values.toString().getBytes(StandardCharsets.UTF_8);}
    private static void assertRows(ArrayList<Gateway> expected,ArrayList<Gateway> actual)throws Exception {assertArrayEquals(serialize(expected),serialize(actual));assertEquals("synthetic-vpn-secret",actual.get(0).vpnPassword);}
    private static boolean newFormat(File path)throws Exception {byte[] encoded=Files.readAllBytes(path.toPath());try{return encoded.length>=96&&Arrays.equals(MAGIC,Arrays.copyOfRange(encoded,0,8));}finally{Arrays.fill(encoded,(byte)0);}}
    private static byte[] legacy(byte[] plaintext,SecretKey key)throws Exception {Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(cipher.getIV());out.write(cipher.doFinal(plaintext));return out.toByteArray();}
    private static void rejected(Checked action)throws Exception {try{action.run();fail("Invalid storage input was accepted");}catch(IOException|GeneralSecurityException expected){}}
    private static Map<String,String> aliases(KeyStore keys)throws Exception {Map<String,String> result=new TreeMap<>();for(String name:Collections.list(keys.aliases())){java.util.Date created=keys.getCreationDate(name);result.put(name,created==null?"unknown":Long.toString(created.getTime()));}return result;}
    private static Map<String,String> realFiles(Context context)throws Exception {
        Map<String,String> result=new TreeMap<>();for(String name:new String[]{"gateways.enc","ssh-identities.enc"})for(String suffix:new String[]{"",".bak",".new"}){File path=new File(context.getFilesDir(),name+suffix);if(path.exists())result.put("files/"+name+suffix,PrivateAdministrationFixture.hash(path));}
        File nativeRoot=new File(context.getNoBackupFilesDir(),"vpn-profiles");if(nativeRoot.isDirectory())for(File path:nativeRoot.listFiles()){assertFalse("Native profile snapshot must not follow links",Files.isSymbolicLink(path.toPath()));if(path.isFile())result.put("native/"+path.getName(),PrivateAdministrationFixture.hash(path));}return result;
    }
    private static boolean removeOwned(File directory,File appFiles)throws Exception {
        if(!directory.getName().startsWith("vault-envelope-test-")||!directory.getCanonicalFile().getParentFile().equals(appFiles.getCanonicalFile()))throw new IOException("Unexpected isolated cleanup scope");return removeTree(directory);
    }
    private static boolean removeTree(File file)throws Exception {
        if(Files.isSymbolicLink(file.toPath()))return file.delete();
        boolean ok=true;if(file.isDirectory()){File[] children=file.listFiles();if(children==null)return false;for(File child:children)ok=removeTree(child)&&ok;}return file.delete()&&ok;
    }
}
