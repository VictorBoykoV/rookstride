package org.strongswan.android.rookstride;
import org.junit.Test;import static org.junit.Assert.*;import org.strongswan.android.rookstride.engine.ProfileCipher;
import javax.crypto.*;import javax.crypto.spec.*;import java.util.*;import java.security.*;
public class ProfileCipherTest {
 SecretKey key(){byte[] k=new byte[32];new SecureRandom().nextBytes(k);return new SecretKeySpec(k,"AES");}
 @Test public void smallAndLargeProfilesRoundTripWithFreshFileKeys()throws Exception{
  SecretKey k=key();for(int size:new int[]{64,32768,65536,250000,500000}){byte[] plain=new byte[size];new SecureRandom().nextBytes(plain);byte[] one=ProfileCipher.encrypt("profile-a",plain,k),two=ProfileCipher.encrypt("profile-a",plain,k);assertFalse(Arrays.equals(one,two));assertArrayEquals(plain,ProfileCipher.decrypt("profile-a",one,k));}
 }
 @Test public void allHeaderSectionsCiphertextDifferentIdentityAndWrongKeyAreRejected()throws Exception{
  SecretKey k=key();byte[] encrypted=ProfileCipher.encrypt("profile-a",new byte[1000],k);
  for(int offset:new int[]{0,8,20,68,80,encrypted.length-1}){byte[] bad=encrypted.clone();bad[offset]^=1;try{ProfileCipher.decrypt("profile-a",bad,k);fail("Tampered authenticated data accepted");}catch(GeneralSecurityException|java.io.IOException expected){}}
  try{ProfileCipher.decrypt("profile-b",encrypted,k);fail();}catch(GeneralSecurityException expected){}
  try{ProfileCipher.decrypt("profile-a",encrypted,key());fail();}catch(GeneralSecurityException expected){}
 }
 @Test public void legacyFilesRemainReadableWithoutChangingTheWrappingKey()throws Exception{
  SecretKey k=key();byte[] plain="legacy private profile".getBytes("UTF-8");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,k);java.io.ByteArrayOutputStream data=new java.io.ByteArrayOutputStream();data.write(c.getIV());data.write(c.doFinal(plain));assertArrayEquals(plain,ProfileCipher.decrypt("legacy-id",data.toByteArray(),k));
 }
}
