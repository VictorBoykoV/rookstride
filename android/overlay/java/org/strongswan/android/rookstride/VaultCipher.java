package org.strongswan.android.rookstride;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Catalog envelope. The existing Keystore key wraps only a fresh 32-byte key;
 * the bounded catalog uses software GCM. No files, aliases or keys are created here. */
public final class VaultCipher {
    public static final int MAX_FILE_BYTES=2*1024*1024;
    public static final int MAX_BYTES=MAX_FILE_BYTES;
    public static final int HEADER_BYTES=80;
    public static final int MAX_PLAINTEXT_BYTES=MAX_FILE_BYTES-HEADER_BYTES-16;
    private static final byte[] MAGIC="ROOKVLT2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VAULT_PREFIX="ROOKVLT".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PROFILE_MAGIC="ROOKVPN2".getBytes(StandardCharsets.US_ASCII);
    private VaultCipher(){}

    private static byte[] aad(String purpose)throws IOException {
        if(!"gateways.enc".equals(purpose)&&!"ssh-identities.enc".equals(purpose)&&!"standalone-installs.enc".equals(purpose))
            throw new IOException("Unknown saved-data purpose");
        return ("ROOKVLT2:"+purpose).getBytes(StandardCharsets.US_ASCII);
    }
    private static Cipher decryptor(SecretKey key,byte[] nonce)throws GeneralSecurityException {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,nonce));
        return cipher;
    }
    private static boolean startsWith(byte[] value,byte[] prefix){
        if(value.length<prefix.length)return false;
        for(int i=0;i<prefix.length;i++)if(value[i]!=prefix[i])return false;
        return true;
    }

    /** The returned complete envelope must be verified before beginning an atomic write. */
    public static byte[] encrypt(String purpose,byte[] plaintext,SecretKey wrapping)
            throws GeneralSecurityException,IOException {
        byte[] associated=aad(purpose);
        if(plaintext==null||plaintext.length==0||plaintext.length>MAX_PLAINTEXT_BYTES)
            throw new IOException("Saved data is empty or too large");
        byte[] secret=new byte[32],nonce=new byte[12];
        SecureRandom random=new SecureRandom();random.nextBytes(secret);random.nextBytes(nonce);
        try{
            Cipher wrap=Cipher.getInstance("AES/GCM/NoPadding");
            wrap.init(Cipher.ENCRYPT_MODE,wrapping);
            byte[] iv=wrap.getIV();
            if(iv==null||iv.length!=12)throw new GeneralSecurityException("Unexpected saved-key nonce");
            wrap.updateAAD(associated);
            byte[] wrapped=wrap.doFinal(secret);
            if(wrapped.length!=48)throw new GeneralSecurityException("Unexpected wrapped-key size");
            ByteArrayOutputStream result=new ByteArrayOutputStream(HEADER_BYTES+plaintext.length+16);
            result.write(MAGIC);result.write(iv);result.write(wrapped);result.write(nonce);
            byte[] header=result.toByteArray();
            // SecretKeySpec is an in-memory AES key, not an Android Keystore key.
            Cipher payload=Cipher.getInstance("AES/GCM/NoPadding");
            payload.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(secret,"AES"),new GCMParameterSpec(128,nonce));
            payload.updateAAD(associated);payload.updateAAD(header);
            result.write(payload.doFinal(plaintext));
            byte[] encoded=result.toByteArray();
            if(encoded.length>MAX_FILE_BYTES)throw new IOException("Saved data is too large");
            return encoded;
        }finally{Arrays.fill(secret,(byte)0);}
    }

    /** Legacy files are authenticated normally; damaged data is never returned. */
    public static byte[] decrypt(String purpose,byte[] encoded,SecretKey wrapping)
            throws GeneralSecurityException,IOException {
        byte[] associated=aad(purpose);
        if(encoded==null||encoded.length<29||encoded.length>MAX_FILE_BYTES)
            throw new IOException("Invalid saved data size");
        if(!startsWith(encoded,MAGIC)){
            if("standalone-installs.enc".equals(purpose))throw new IOException("Unsupported saved data format");
            if(startsWith(encoded,VAULT_PREFIX)||startsWith(encoded,PROFILE_MAGIC))
                throw new IOException("Unsupported saved data format");
            // Keep old files readable without using a nonzero hardware input offset.
            return decryptor(wrapping,Arrays.copyOfRange(encoded,0,12))
                    .doFinal(Arrays.copyOfRange(encoded,12,encoded.length));
        }
        if(encoded.length<HEADER_BYTES+17)throw new IOException("Incomplete saved data");
        Cipher unwrap=decryptor(wrapping,Arrays.copyOfRange(encoded,8,20));
        unwrap.updateAAD(associated);
        byte[] secret=unwrap.doFinal(Arrays.copyOfRange(encoded,20,68));
        try{
            if(secret.length!=32)throw new GeneralSecurityException("Invalid saved-data key");
            Cipher payload=decryptor(new SecretKeySpec(secret,"AES"),Arrays.copyOfRange(encoded,68,80));
            payload.updateAAD(associated);payload.updateAAD(Arrays.copyOfRange(encoded,0,HEADER_BYTES));
            return payload.doFinal(Arrays.copyOfRange(encoded,HEADER_BYTES,encoded.length));
        }finally{Arrays.fill(secret,(byte)0);}
    }
}
