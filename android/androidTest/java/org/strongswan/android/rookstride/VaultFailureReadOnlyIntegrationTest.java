package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import static org.junit.Assert.*;

/** Explicit forensic read. Never calls Vault.read(), AtomicFile, a remote
 * controller, a key generator, an alias deletion or a ciphertext writer. */
@RunWith(AndroidJUnit4.class)
public final class VaultFailureReadOnlyIntegrationTest {
 private static final String ALIAS="rookstride.gateway.v1";
 private static byte[] read(File file,File root)throws Exception{
  assertFalse("Do not follow a diagnostic input symlink",Files.isSymbolicLink(file.toPath()));
  assertTrue("Diagnostic input must remain in the app directory",file.getCanonicalPath().startsWith(root.getCanonicalPath()+File.separator));
  assertTrue("Preserve the actual ciphertext first",file.isFile());assertTrue("Bound the forensic read",file.length()>=29&&file.length()<=2*1024*1024);
  return Files.readAllBytes(file.toPath());
 }
 private static void createPrivate(File target,byte[] value)throws Exception{
  assertFalse("Never overwrite earlier forensic evidence",target.exists());
  Files.write(target.toPath(),value,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);android.system.Os.chmod(target.getAbsolutePath(),0600);
 }
 private static JSONObject context(Context context)throws Exception{return new JSONObject().put("package",context.getPackageName()).put("files_absolute",context.getFilesDir().getAbsolutePath()).put("files_canonical",context.getFilesDir().getCanonicalPath()).put("classloader",loader(context.getClassLoader()));}
 private static JSONObject loader(ClassLoader loader)throws Exception{return new JSONObject().put("type",loader==null?"bootstrap":loader.getClass().getName()).put("identity",loader==null?0:System.identityHashCode(loader));}
 private static JSONObject failure(Throwable error)throws Exception{JSONObject value=new JSONObject().put("type",error.getClass().getName());if(error.getCause()!=null)value.put("cause_type",error.getCause().getClass().getName());return value;}
 private static JSONObject decrypt(byte[] file,SecretKey key,boolean offset,File recover)throws Exception{
  JSONObject result=new JSONObject().put("mode",offset?"offset_doFinal":"copied_payload_doFinal");byte[] plaintext=null,payload=null;
  try{
   Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,Arrays.copyOfRange(file,0,12)));result.put("provider",cipher.getProvider().getName());
   if(offset)plaintext=cipher.doFinal(file,12,file.length-12);else{payload=Arrays.copyOfRange(file,12,file.length);plaintext=cipher.doFinal(payload);}
   result.put("authenticated",true).put("plaintext_bytes",plaintext.length).put("plaintext_sha256",PrivateAdministrationFixture.hash(plaintext));
   try{
    JSONArray array=new JSONArray(new String(plaintext,StandardCharsets.UTF_8));result.put("json_array",true).put("records",array.length());
    if(recover!=null){createPrivate(recover,plaintext);result.put("recovery_file",recover.getName()).put("recovery_sha256",PrivateAdministrationFixture.hash(plaintext));}
   }catch(JSONException invalid){result.put("json_array",false).put("json_error_type",invalid.getClass().getName());}
  }catch(Exception error){if(result.optBoolean("authenticated"))result.put("post_decrypt_error",failure(error));else result.put("authenticated",false).put("error",failure(error));}
  finally{if(plaintext!=null)Arrays.fill(plaintext,(byte)0);if(payload!=null)Arrays.fill(payload,(byte)0);}
  return result;
 }
 @Test public void compareExistingCiphertextsWithoutChangingKeysOrCatalog()throws Exception{
  PrivateAdministrationFixture f=PrivateAdministrationFixture.load("vault-read-only-diagnosis","allow_vault_diagnosis");
  assertTrue("Only this local diagnosis is authorized",f.request.getBoolean("no_remote_access"));
  String operation=f.request.getString("operation");assertTrue("Use an exact recorded operation",InputRules.job(operation));
  File root=f.context.getFilesDir(),receipt=f.file("vault-read-only-diagnosis-result.json"),recovery=f.file("vault-diagnosis-recovered-catalog-private.json");assertFalse("Keep the prior receipt",receipt.exists());
  boolean save=f.request.optBoolean("save_decrypted_catalog_for_recovery");if(save)assertFalse("Keep the prior recovery file",recovery.exists());
  LinkedHashMap<String,File> inputs=new LinkedHashMap<>();inputs.put("current_catalog",f.file("gateways.enc"));inputs.put("ssh_pins",f.file("ssh-identities.enc"));inputs.put("pre_operation_catalog",f.file("entry-reconcile-backup-"+operation+"/gateways.enc"));
  LinkedHashMap<String,byte[]> originals=new LinkedHashMap<>();for(Map.Entry<String,File> item:inputs.entrySet())originals.put(item.getKey(),read(item.getValue(),root));
  JSONObject result=new JSONObject().put("binary",new JSONObject(f.binary.toString())).put("action","vault-read-only-diagnosis").put("operation",operation).put("no_remote_access",true)
   .put("uid",android.os.Process.myUid()).put("pid",android.os.Process.myPid()).put("thread_id",Thread.currentThread().getId()).put("target_context",context(f.context)).put("application_context",context(f.context.getApplicationContext())).put("vault_classloader",loader(Vault.class.getClassLoader())).put("test_classloader",loader(getClass().getClassLoader()));
  JSONArray locks=new JSONArray();Field field=Vault.class.getDeclaredField("FILE_LOCKS");field.setAccessible(true);Map<?,?> map=(Map<?,?>)field.get(null);for(Map.Entry<?,?> item:map.entrySet()){String path=String.valueOf(item.getKey());locks.put(new JSONObject().put("absolute_key",path).put("canonical_key",new File(path).getCanonicalPath()).put("lock_identity",System.identityHashCode(item.getValue())));}result.put("file_lock_keys",locks).put("lock_observation_scope","Current diagnosis process only; a restarted process has no prior static lock history");
  KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);boolean exists=store.containsAlias(ALIAS);result.put("alias_exists",exists);Date created=exists?store.getCreationDate(ALIAS):null;result.put("alias_creation_ms",created==null?JSONObject.NULL:created.getTime());
  SecretKey key=null;try{if(exists)key=(SecretKey)store.getKey(ALIAS,null);}catch(Exception error){result.put("key_lookup_error",failure(error));}
  JSONArray files=new JSONArray();for(Map.Entry<String,byte[]> item:originals.entrySet()){
   byte[] data=item.getValue();JSONObject observation=new JSONObject().put("input",item.getKey()).put("bytes",data.length).put("sha256",PrivateAdministrationFixture.hash(data)).put("iv_sha256",PrivateAdministrationFixture.hash(Arrays.copyOfRange(data,0,12)));
   if(key!=null){observation.put("offset",decrypt(data,key,true,null));observation.put("copied_payload",decrypt(data,key,false,save&&item.getKey().equals("current_catalog")?recovery:null));}
   files.put(observation);
  }
  result.put("files",files);for(Map.Entry<String,File> item:inputs.entrySet())assertArrayEquals("Diagnosis changed a captured ciphertext",originals.get(item.getKey()),read(item.getValue(),root));
  result.put("input_ciphertexts_unchanged",true).put("alias_still_exists",store.containsAlias(ALIAS)).put("keystore_mutated",false).put("vault_or_atomicfile_reads",false);
  createPrivate(receipt,result.toString(2).getBytes(StandardCharsets.UTF_8));for(byte[] value:originals.values())Arrays.fill(value,(byte)0);
 }
}
