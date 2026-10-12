package org.strongswan.android.rookstride;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import org.json.JSONArray;
import java.io.*;
import java.security.KeyStore;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Administrator secrets are encrypted with a key held by Android Keystore. */
public final class Vault {
    private final AtomicFile file;
    private static final String ALIAS="rookstride.gateway.v1";
    public Vault(Context context) { file=new AtomicFile(new File(context.getFilesDir(),"gateways.enc")); }
    private SecretKey key() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build());
            generator.generateKey();
        }
        return (SecretKey)store.getKey(ALIAS,null);
    }
    public ArrayList<Gateway> read() throws Exception {
        ArrayList<Gateway> nodes=new ArrayList<>();
        if (!file.getBaseFile().exists()) return nodes;
        byte[] bytes=file.readFully();
        if (bytes.length<29 || bytes.length>2*1024*1024) throw new IOException("Saved gateway data is invalid");
        byte[] iv=java.util.Arrays.copyOfRange(bytes,0,12);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,iv));
        String text=new String(cipher.doFinal(bytes,12,bytes.length-12),java.nio.charset.StandardCharsets.UTF_8);
        JSONArray values=new JSONArray(text);
        for(int i=0;i<values.length();i++) nodes.add(new Gateway(values.getJSONObject(i)));
        return nodes;
    }
    public void write(ArrayList<Gateway> nodes) throws Exception {
        JSONArray values=new JSONArray(); for(Gateway n:nodes) values.put(n.persisted());
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,key());
        FileOutputStream stream=file.startWrite();
        try {
            stream.write(cipher.getIV()); stream.write(cipher.doFinal(values.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            file.finishWrite(stream);
        } catch(Exception e) { file.failWrite(stream); throw e; }
    }
}
