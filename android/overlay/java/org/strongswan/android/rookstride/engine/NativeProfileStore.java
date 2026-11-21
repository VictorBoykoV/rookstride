package org.strongswan.android.rookstride.engine;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

/** Connection keys are separate from saved SSH access and always encrypted. */
public final class NativeProfileStore {
    private static final String ALIAS="rookstride.native-profile.v1";
    private final Context context;
    public NativeProfileStore(Context context){this.context=context;}
    private AtomicFile file(String id)throws IOException{
        if(!id.matches("[a-fA-F0-9-]{36}"))throw new IOException("Invalid VPN identifier");
        File folder=new File(context.getNoBackupFilesDir(),"vpn-profiles");if(!folder.exists()&&!folder.mkdirs())throw new IOException("Cannot save VPN profile");
        return new AtomicFile(new File(folder,id+".enc"));
    }
    public static final class StorageException extends IOException { StorageException(String message,Throwable cause){super(message,cause);} }
    private SecretKey key(boolean create)throws Exception{
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);
        if(!ks.containsAlias(ALIAS)&&!create)throw new StorageException("The phone’s saved VPN key is unavailable. Add this VPN again.",null);
        if(!ks.containsAlias(ALIAS)){KeyGenerator g=KeyGenerator.getInstance("AES","AndroidKeyStore");g.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes("GCM").setEncryptionPaddings("NoPadding").setKeySize(256).build());g.generateKey();}
        return (SecretKey)ks.getKey(ALIAS,null);
    }
    public void save(String id,String protocol,String name,String content)throws Exception{
        NativeProfiles.validate(protocol,content);
        byte[] bytes=new JSONObject().put("protocol",protocol).put("name",name).put("content",content).toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted;try{encrypted=ProfileCipher.encrypt(id,bytes,key(true));}finally{java.util.Arrays.fill(bytes,(byte)0);}
        AtomicFile f=file(id);FileOutputStream out=f.startWrite();
        try{out.write(encrypted);f.finishWrite(out);}catch(Exception e){f.failWrite(out);throw e;}finally{java.util.Arrays.fill(bytes,(byte)0);}
    }
    public JSONObject read(String id)throws Exception{
        byte[] bytes=file(id).readFully();if(bytes.length<29||bytes.length>1024*1024)throw new IOException("Invalid saved VPN profile");
        byte[] text;try{text=ProfileCipher.decrypt(id,bytes,key(false));}catch(java.security.GeneralSecurityException e){throw new StorageException("Saved VPN access could not be verified. Edit the sign-in details or retrieve the connection again.",e);}
        try{return new JSONObject(new String(text,StandardCharsets.UTF_8));}finally{java.util.Arrays.fill(text,(byte)0);}
    }
    public boolean exists(String id){try{return file(id).getBaseFile().isFile();}catch(IOException e){return false;}}
    public void remove(String id)throws IOException{file(id).delete();}
}
