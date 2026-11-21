package org.strongswan.android.rookstride;
import org.junit.Test;import org.junit.runner.RunWith;import androidx.test.ext.junit.runners.AndroidJUnit4;import androidx.test.platform.app.InstrumentationRegistry;
import org.strongswan.android.rookstride.engine.*;import android.content.Context;import java.nio.file.Files;import java.io.File;import java.util.UUID;import static org.junit.Assert.*;
@RunWith(AndroidJUnit4.class)
public class ProfileStorageTest {
 private String profile(int padding){return "client\ndev tun\nproto tcp-client\nremote vpn.example.net 1194\nremote-cert-tls server\nverify-x509-name vpn.example.net name\nauth-user-pass\n<ca>\nfixture\n</ca>\n# "+new String(new char[padding]).replace('\0','x')+"\n";}
 @Test public void smallAndLargeEncryptedProfilesRoundTripAndTamperingIsRejected()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();NativeProfileStore store=new NativeProfileStore(c);
  for(int size:new int[]{32,32768,65536,250000,450000}){String id=UUID.randomUUID().toString();try{String content=profile(size);store.save(id,"openvpn","Synthetic storage test",content);assertEquals(content,store.read(id).getString("content"));File file=new File(c.getNoBackupFilesDir(),"vpn-profiles/"+id+".enc");byte[] data=Files.readAllBytes(file.toPath());assertEquals("ROOKVPN2",new String(data,0,8,"US-ASCII"));data[data.length-1]^=1;Files.write(file.toPath(),data);try{store.read(id);fail("Tampered encrypted connection accepted");}catch(NativeProfileStore.StorageException expected){assertFalse(expected.getMessage().contains(content));}}finally{store.remove(id);}}
 }
 @Test public void legacySmallProfileRemainsReadableWithTheOriginalKeystoreKey()throws Exception{
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();NativeProfileStore store=new NativeProfileStore(c);String id=UUID.randomUUID().toString();try{store.save(id,"openvpn","Seed",profile(32));java.lang.reflect.Method key=NativeProfileStore.class.getDeclaredMethod("key",boolean.class);key.setAccessible(true);javax.crypto.SecretKey secret=(javax.crypto.SecretKey)key.invoke(store,false);javax.crypto.Cipher cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,secret);byte[] iv=cipher.getIV();byte[] text=new org.json.JSONObject().put("protocol","openvpn").put("name","Legacy").put("content",profile(32)).toString().getBytes("UTF-8");java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();bytes.write(iv);bytes.write(cipher.doFinal(text));Files.write(new File(c.getNoBackupFilesDir(),"vpn-profiles/"+id+".enc").toPath(),bytes.toByteArray());assertEquals(profile(32),store.read(id).getString("content"));}finally{store.remove(id);}
 }
}
