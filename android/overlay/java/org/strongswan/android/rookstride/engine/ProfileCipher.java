package org.strongswan.android.rookstride.engine;

import javax.crypto.Cipher;import javax.crypto.SecretKey;import javax.crypto.spec.GCMParameterSpec;import javax.crypto.spec.SecretKeySpec;
import java.io.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.Arrays;

/** Versioned envelope: Keystore wraps a 32-byte random key; software GCM handles
 * the bounded profile. Large CA bundles never enter hardware/IPC cipher streams.
 * Header and profile ID are authenticated. Legacy Keystore-GCM files stay readable. */
public final class ProfileCipher {
 private static final byte[] MAGIC="ROOKVPN2".getBytes(StandardCharsets.US_ASCII);
 private static final int HEADER=80,MAX=1024*1024;
 private static byte[] aad(String id){return ("ROOKVPN2:"+id).getBytes(StandardCharsets.US_ASCII);}
 private static Cipher cipher(int mode,SecretKey key,byte[] iv)throws GeneralSecurityException{
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(mode,key,new GCMParameterSpec(128,iv));return c;
 }
 public static byte[] encrypt(String id,byte[] plaintext,SecretKey wrapping)throws GeneralSecurityException,IOException{
  if(plaintext.length==0||plaintext.length>MAX-HEADER-16)throw new IOException("VPN profile is too large");
  byte[] secret=new byte[32],nonce=new byte[12];SecureRandom random=new SecureRandom();random.nextBytes(secret);random.nextBytes(nonce);
  try{
   Cipher wrap=Cipher.getInstance("AES/GCM/NoPadding");wrap.init(Cipher.ENCRYPT_MODE,wrapping);byte[] iv=wrap.getIV();wrap.updateAAD(aad(id));byte[] wrapped=wrap.doFinal(secret);if(iv.length!=12||wrapped.length!=48)throw new GeneralSecurityException("Unexpected key wrapping format");
   ByteArrayOutputStream header=new ByteArrayOutputStream();header.write(MAGIC);header.write(iv);header.write(wrapped);header.write(nonce);byte[] prefix=header.toByteArray();
   Cipher payload=cipher(Cipher.ENCRYPT_MODE,new SecretKeySpec(secret,"AES"),nonce);payload.updateAAD(aad(id));payload.updateAAD(prefix);header.write(payload.doFinal(plaintext));return header.toByteArray();
  }finally{Arrays.fill(secret,(byte)0);}
 }
 public static byte[] decrypt(String id,byte[] file,SecretKey wrapping)throws GeneralSecurityException,IOException{
  if(file.length<29||file.length>MAX)throw new IOException("Invalid saved VPN profile");
  if(!Arrays.equals(MAGIC,Arrays.copyOfRange(file,0,8))){
   // Separate ciphertext avoids old hardware-provider offset/chunk interactions.
   return cipher(Cipher.DECRYPT_MODE,wrapping,Arrays.copyOfRange(file,0,12)).doFinal(Arrays.copyOfRange(file,12,file.length));
  }
  if(file.length<HEADER+16)throw new IOException("Incomplete saved VPN profile");
  Cipher wrap=cipher(Cipher.DECRYPT_MODE,wrapping,Arrays.copyOfRange(file,8,20));wrap.updateAAD(aad(id));byte[] secret=wrap.doFinal(Arrays.copyOfRange(file,20,68));
  try{
   if(secret.length!=32)throw new GeneralSecurityException("Invalid profile key");Cipher payload=cipher(Cipher.DECRYPT_MODE,new SecretKeySpec(secret,"AES"),Arrays.copyOfRange(file,68,80));payload.updateAAD(aad(id));payload.updateAAD(Arrays.copyOfRange(file,0,HEADER));return payload.doFinal(Arrays.copyOfRange(file,HEADER,file.length));
  }finally{Arrays.fill(secret,(byte)0);}
 }
}
