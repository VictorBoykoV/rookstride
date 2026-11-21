package org.strongswan.android.rookstride;

import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Build;
import android.util.AtomicFile;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.jcraft.jsch.SocketFactory;
import org.strongswan.android.rookstride.engine.AdminSocketFactory;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

/** Opt-in real Keystore/AtomicFile local checks. The fault deliberately skips
 * finishWrite; it is not an organic platform I/O or power-loss reproduction. */
@RunWith(AndroidJUnit4.class)
public final class AndroidCommitIntegrationTest {
    private static final String ALIAS="rookstride.gateway.v1",RESULT="android-commit-storage-result.json";
    private static final String[] PURPOSES={"gateways.enc","ssh-identities.enc","standalone-installs.enc"};
    private static final class NoFinish extends AtomicFile {
        final File base;int finishes,rollbacks;FileOutputStream pending;Map<String,String> atFinish;Exception captureError;
        NoFinish(File path){super(path);base=path;}
        @Override public void finishWrite(FileOutputStream stream){finishes++;pending=stream;try{atFinish=slots(base);}catch(Exception error){captureError=error;}/* no super: preserve the real platform's uncommitted files */}
        @Override public void failWrite(FileOutputStream stream){rollbacks++;super.failWrite(stream);}
        void closeOwnedStream()throws IOException{if(pending!=null){pending.close();pending=null;}}
    }
    @Test public void acknowledgedWritesAndSkippedFinishPreserveRealPhoneState()throws Exception{
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("android-commit-storage","allow_android_commit_storage");assertTrue(f.request.getBoolean("no_remote_access"));assertEquals(f.request.getInt("expected_sdk"),Build.VERSION.SDK_INT);assertTrue("This gate explicitly qualifies the two inspected AtomicFile versions",Build.VERSION.SDK_INT==26||Build.VERSION.SDK_INT==36);assertEquals(f.request.getString("expected_test_apk_sha256"),f.binary.getString("test_apk_sha256"));assertFalse("Preserve an earlier receipt rather than overwrite it",f.file(RESULT).exists());
        KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);assertTrue("Never generate or replace a real phone key for this gate",keys.containsAlias(ALIAS));SecretKey wrapping=(SecretKey)keys.getKey(ALIAS,null);assertNotNull(wrapping);Map<String,String> oldAliases=aliases(keys),before=realFiles(f.context,null);
        Cipher challenge=Cipher.getInstance("AES/GCM/NoPadding");challenge.init(Cipher.ENCRYPT_MODE,wrapping);byte[] iv=challenge.getIV(),proof=challenge.doFinal("isolated commit key identity".getBytes(StandardCharsets.UTF_8));
        File parent=Files.createTempDirectory(f.context.getFilesDir().getCanonicalFile().toPath(),"vault-commit-test-").toFile();android.system.Os.chmod(parent.getAbsolutePath(),0700);AtomicInteger sockets=new AtomicInteger(),serviceStarts=new AtomicInteger();List<NoFinish> faults=new ArrayList<>();
        SocketFactory previous=Ssh.socketFactory;assertTrue("Preserve the real default SSH policy",previous==null||previous instanceof AdminSocketFactory);SocketFactory deny=new SocketFactory(){public Socket createSocket(String host,int port)throws IOException{sockets.incrementAndGet();throw new IOException("Local storage gate forbids SSH");}public InputStream getInputStream(Socket socket)throws IOException{throw new IOException("Local storage gate forbids SSH streams");}public OutputStream getOutputStream(Socket socket)throws IOException{throw new IOException("Local storage gate forbids SSH streams");}};Ssh.socketFactory=deny;
        JSONObject receipt=new JSONObject().put("action","android-commit-storage").put("sdk",Build.VERSION.SDK_INT).put("fault","finishWrite deliberately skipped on real AtomicFile").put("organic_platform_failure_reproduced",false).put("power_loss_test",false).put("no_remote_access",true).put("isolated_evidence_directory",parent.getName());boolean passed=false;JSONArray ordinary=new JSONArray(),simulated=new JSONArray();
        try{
            for(String purpose:PURPOSES){
                File directory=directory(parent,"normal-"+purpose);Context local=local(f.context,directory,serviceStarts);File base=new File(directory,purpose);ArrayList<Gateway> old=rows("old"),next=rows("committed");seed(base,purpose,old,wrapping);
                new Vault(local,purpose).write(next);assertEquals("A normal acknowledgement leaves only its exact base",Collections.singleton(purpose),slots(base).keySet());assertRows(next,direct(base,purpose,wrapping));assertRows(next,new Vault(local,purpose).read());ordinary.put(new JSONObject().put("purpose",purpose).put("acknowledged",true).put("raw_base_matches_requested_rows",true).put("slots",new JSONObject(slots(base))));
            }
            for(String purpose:PURPOSES){
                File directory=directory(parent,"skipped-finish-"+purpose);Context local=local(f.context,directory,serviceStarts);File base=new File(directory,purpose);ArrayList<Gateway> old=rows("old"),next=rows("uncommitted");seed(base,purpose,old,wrapping);String oldHash=PrivateAdministrationFixture.hash(base);NoFinish fault=new NoFinish(base);faults.add(fault);File canonicalBase=base.getCanonicalFile();boolean rejected=false;
                try{new Vault(local,purpose,path->{assertEquals("The factory must receive only the canonical isolated base",canonicalBase,path);return fault;}).write(next);}catch(IOException expected){rejected=true;}
                assertEquals("The write must actually reach the simulated finish boundary",1,fault.finishes);assertNull(fault.captureError);assertNotNull(fault.atFinish);assertTrue("Vault must not acknowledge an uncommitted write",rejected);assertEquals("No failWrite rollback may alter evidence after finish was called",0,fault.rollbacks);Map<String,String> preserved=slots(base);assertEquals("The post-finish rejection changed the actual platform files",fault.atFinish,preserved);
                File oldSlot,newSlot;
                if(Build.VERSION.SDK_INT==26){assertEquals(new TreeSet<>(Arrays.asList(purpose,purpose+".bak")),preserved.keySet());oldSlot=new File(directory,purpose+".bak");newSlot=base;}
                else{assertEquals(new TreeSet<>(Arrays.asList(purpose,purpose+".new")),preserved.keySet());oldSlot=base;newSlot=new File(directory,purpose+".new");}
                assertEquals("The exact previous ciphertext was retained",oldHash,PrivateAdministrationFixture.hash(oldSlot));assertRows(old,direct(oldSlot,purpose,wrapping));assertRows(next,direct(newSlot,purpose,wrapping));boolean closedByVault;try{closedByVault=!fault.pending.getFD().valid();}catch(IOException closed){closedByVault=true;}assertTrue("Vault must close its owned FD before returning a post-finish failure",closedByVault);fault.closeOwnedStream();assertEquals("Closing only the test FD changed evidence",preserved,slots(base));simulated.put(new JSONObject().put("purpose",purpose).put("caller_received_ioexception",true).put("finish_calls",fault.finishes).put("post_finish_failWrite_calls",fault.rollbacks).put("write_stream_closed_before_return",true).put("old_ciphertext_retained",true).put("new_ciphertext_retained",true).put("slots",new JSONObject(preserved)));
            }
            assertEquals(0,sockets.get());assertEquals(0,serviceStarts.get());passed=true;
        }finally{
            boolean closed=true;for(NoFinish fault:faults)try{fault.closeOwnedStream();}catch(IOException error){closed=false;}
            assertSame("Do not overwrite a concurrently changed SSH policy",deny,Ssh.socketFactory);Ssh.socketFactory=previous;
            Map<String,String> after=realFiles(f.context,parent),newAliases=aliases(keys);boolean filesUnchanged=before.equals(after),aliasesUnchanged=oldAliases.equals(newAliases);SecretKey same=(SecretKey)keys.getKey(ALIAS,null);Cipher verify=Cipher.getInstance("AES/GCM/NoPadding");verify.init(Cipher.DECRYPT_MODE,same,new javax.crypto.spec.GCMParameterSpec(128,iv));boolean keyUnchanged=Arrays.equals("isolated commit key identity".getBytes(StandardCharsets.UTF_8),verify.doFinal(proof));Arrays.fill(iv,(byte)0);Arrays.fill(proof,(byte)0);
            receipt.put("normal_purposes",ordinary).put("simulated_no_finish",simulated).put("passed",passed&&closed&&filesUnchanged&&aliasesUnchanged&&keyUnchanged&&sockets.get()==0&&serviceStarts.get()==0).put("isolated_evidence_retained",parent.isDirectory()).put("test_streams_closed",closed).put("original_phone_files_unchanged",filesUnchanged).put("keystore_aliases_and_dates_unchanged",aliasesUnchanged).put("existing_key_challenge_unchanged",keyUnchanged).put("ssh_socket_attempts",sockets.get()).put("foreground_service_starts",serviceStarts.get()).put("real_files_before",new JSONObject(before)).put("real_files_after",new JSONObject(after));f.receipt(RESULT,receipt);
            assertTrue("The test did not close its own streams",closed);assertEquals("A pre-existing Rookstride file changed",before,after);assertEquals("Real key aliases changed",oldAliases,newAliases);assertTrue("The existing wrapping key changed",keyUnchanged);assertEquals(0,sockets.get());assertEquals(0,serviceStarts.get());
        }
    }
    private static Context local(Context context,File directory,AtomicInteger starts){return new ContextWrapper(context){@Override public File getFilesDir(){return directory;}@Override public ComponentName startForegroundService(Intent intent){starts.incrementAndGet();throw new AssertionError("A local storage gate cannot launch a worker");}};}
    private static File directory(File parent,String name)throws Exception{File child=new File(parent,name);assertTrue(child.mkdir());android.system.Os.chmod(child.getAbsolutePath(),0700);return child;}
    private static ArrayList<Gateway> rows(String value)throws Exception{Gateway row=new Gateway();row.set("name",value);row.data.put("testPayload",value);return new ArrayList<>(Collections.singletonList(row));}
    private static byte[] serialize(ArrayList<Gateway> rows)throws Exception{JSONArray json=new JSONArray();for(Gateway row:rows)json.put(row.persisted());return json.toString().getBytes(StandardCharsets.UTF_8);}
    private static void seed(File base,String purpose,ArrayList<Gateway> rows,SecretKey key)throws Exception{byte[] plain=serialize(rows),encoded=VaultCipher.encrypt(purpose,plain,key);try(FileOutputStream out=new FileOutputStream(base)){out.write(encoded);out.getFD().sync();}finally{Arrays.fill(plain,(byte)0);Arrays.fill(encoded,(byte)0);}}
    private static ArrayList<Gateway> direct(File slot,String purpose,SecretKey key)throws Exception{byte[] raw=Files.readAllBytes(slot.toPath()),plain=null;try{plain=VaultCipher.decrypt(purpose,raw,key);JSONArray a=new JSONArray(new String(plain,StandardCharsets.UTF_8));ArrayList<Gateway> rows=new ArrayList<>();for(int i=0;i<a.length();i++)rows.add(new Gateway(a.getJSONObject(i)));return rows;}finally{Arrays.fill(raw,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}}
    private static void assertRows(ArrayList<Gateway> expected,ArrayList<Gateway> actual)throws Exception{assertArrayEquals(serialize(expected),serialize(actual));}
    private static Map<String,String> slots(File base)throws Exception{Map<String,String> values=new TreeMap<>();for(String suffix:new String[]{"",".bak",".new"}){File file=new File(base.getPath()+suffix);assertFalse("Never follow a slot link",Files.isSymbolicLink(file.toPath()));if(file.exists()){assertTrue(file.isFile());values.put(file.getName(),PrivateAdministrationFixture.hash(file));}}return values;}
    private static Map<String,String> aliases(KeyStore keys)throws Exception{Map<String,String> values=new TreeMap<>();for(String alias:Collections.list(keys.aliases()))values.put(alias,String.valueOf(keys.getCreationDate(alias)));return values;}
    private static Map<String,String> realFiles(Context context,File excluded)throws Exception{Map<String,String> values=new TreeMap<>();File data=context.getFilesDir().getCanonicalFile().getParentFile();for(String name:new String[]{"files","shared_prefs","no_backup","databases"})walk(data,new File(data,name),excluded,values);return values;}
    private static void walk(File data,File path,File excluded,Map<String,String> values)throws Exception{if(excluded!=null&&path.equals(excluded))return;assertFalse("Snapshot must not follow links",Files.isSymbolicLink(path.toPath()));if(!path.exists())return;if(path.isDirectory()){File[] files=path.listFiles();assertNotNull(files);for(File file:files)walk(data,file,excluded,values);}else{assertTrue(path.isFile());values.put(data.toPath().relativize(path.toPath()).toString(),PrivateAdministrationFixture.hash(path));}}
}
