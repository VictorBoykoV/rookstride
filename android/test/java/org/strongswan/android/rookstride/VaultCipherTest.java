package org.strongswan.android.rookstride;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class VaultCipherTest {
    private SecretKey key(){return new SecretKeySpec(bytes(32),"AES");}
    private byte[] bytes(int size){byte[] value=new byte[size];new SecureRandom().nextBytes(value);return value;}
    private interface Attempt {void run()throws Exception;}
    private void reject(Attempt attempt)throws Exception{
        try{attempt.run();fail("Invalid authenticated data accepted");}
        catch(GeneralSecurityException|IOException expected){}
    }
    private byte[] legacy(byte[] plain,SecretKey key)throws Exception{
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);
        ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(cipher.getIV());out.write(cipher.doFinal(plain));return out.toByteArray();
    }

    @Test public void exactIncidentAndBoundarySizesRoundTripForBothPurposes()throws Exception{
        SecretKey key=key();
        for(String purpose:new String[]{"gateways.enc","ssh-identities.enc"})
            for(int size:new int[]{1,2,293,32767,32768,32769,65535,65536,65537,70024,78082,250000,VaultCipher.MAX_PLAINTEXT_BYTES}){
                byte[] plain=bytes(size),original=plain.clone();
                byte[] encrypted=VaultCipher.encrypt(purpose,plain,key);
                assertArrayEquals(original,plain);
                assertEquals(VaultCipher.HEADER_BYTES+size+16,encrypted.length);
                assertTrue(encrypted.length<=VaultCipher.MAX_FILE_BYTES);
                assertArrayEquals(plain,VaultCipher.decrypt(purpose,encrypted,key));
            }
    }
    @Test public void repeatedWritesUseDifferentDataKeysAndNonces()throws Exception{
        SecretKey key=key();byte[] plain=bytes(70024);
        byte[] first=VaultCipher.encrypt("gateways.enc",plain,key),second=VaultCipher.encrypt("gateways.enc",plain,key);
        assertFalse(Arrays.equals(first,second));
        assertFalse(Arrays.equals(Arrays.copyOfRange(first,8,20),Arrays.copyOfRange(second,8,20)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(first,20,68),Arrays.copyOfRange(second,20,68)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(first,68,80),Arrays.copyOfRange(second,68,80)));
        assertArrayEquals(plain,VaultCipher.decrypt("gateways.enc",first,key));
        assertArrayEquals(plain,VaultCipher.decrypt("gateways.enc",second,key));
    }
    @Test public void everyEnvelopeRegionAndAuthenticationTagAreAuthenticated()throws Exception{
        SecretKey key=key();byte[] good=VaultCipher.encrypt("gateways.enc",bytes(70024),key);
        for(int offset:new int[]{0,7,8,19,20,43,67,68,79,80,65536,good.length-17,good.length-1}){
            byte[] bad=good.clone();bad[offset]^=1;reject(()->VaultCipher.decrypt("gateways.enc",bad,key));
        }
    }
    @Test public void oneWrappingAliasCannotSwapNewCatalogAndPinFiles()throws Exception{
        SecretKey key=key();byte[] plain="[{\"name\":\"fixture\"}]".getBytes(StandardCharsets.UTF_8);
        byte[] catalog=VaultCipher.encrypt("gateways.enc",plain,key),pins=VaultCipher.encrypt("ssh-identities.enc",plain,key);
        reject(()->VaultCipher.decrypt("ssh-identities.enc",catalog,key));
        reject(()->VaultCipher.decrypt("gateways.enc",pins,key));
        assertArrayEquals(plain,VaultCipher.decrypt("gateways.enc",catalog,key));
        assertArrayEquals(plain,VaultCipher.decrypt("ssh-identities.enc",pins,key));
    }
    @Test public void wrongWrappingKeyNeverReturnsPlaintext()throws Exception{
        byte[] good=VaultCipher.encrypt("gateways.enc",bytes(78082),key());
        reject(()->VaultCipher.decrypt("gateways.enc",good,key()));
    }
    @Test public void allTruncationBoundariesAndAppendedBytesAreRejected()throws Exception{
        SecretKey key=key();byte[] good=VaultCipher.encrypt("gateways.enc",bytes(293),key);
        for(int size:new int[]{0,1,7,8,12,20,29,67,68,79,80,95,96,97,good.length-1}){
            byte[] bad=Arrays.copyOf(good,size);reject(()->VaultCipher.decrypt("gateways.enc",bad,key));
        }
        byte[] appended=Arrays.copyOf(good,good.length+1);reject(()->VaultCipher.decrypt("gateways.enc",appended,key));
    }
    @Test public void invalidSizesAreRejectedBeforeEncryptionOrDecryption()throws Exception{
        SecretKey key=key();
        reject(()->VaultCipher.encrypt("gateways.enc",null,key));
        reject(()->VaultCipher.encrypt("gateways.enc",new byte[0],key));
        reject(()->VaultCipher.encrypt("gateways.enc",new byte[VaultCipher.MAX_PLAINTEXT_BYTES+1],key));
        reject(()->VaultCipher.decrypt("gateways.enc",null,key));
        reject(()->VaultCipher.decrypt("gateways.enc",new byte[VaultCipher.MAX_FILE_BYTES+1],key));
    }
    @Test public void unknownPurposeAndRecognizedOtherFormatsAreRejected()throws Exception{
        SecretKey key=key();byte[] good=VaultCipher.encrypt("gateways.enc",bytes(128),key);
        for(String purpose:new String[]{"","../gateways.enc","profile-id","gateways.enc\u0000", "GATEWAYS.ENC"}){
            reject(()->VaultCipher.encrypt(purpose,new byte[]{1},key));reject(()->VaultCipher.decrypt(purpose,good,key));
        }
        for(String magic:new String[]{"ROOKVPN2","ROOKVLT1","ROOKVLT3"}){
            byte[] bad=good.clone();System.arraycopy(magic.getBytes(StandardCharsets.US_ASCII),0,bad,0,8);
            reject(()->VaultCipher.decrypt("gateways.enc",bad,key));
        }
    }
    @Test public void authenticatedLegacyFilesStayReadableWithTheSameAlias()throws Exception{
        SecretKey key=key();
        for(int size:new int[]{2,293,32768,65536,70024,78082,250000}){
            byte[] plain=bytes(size),old=legacy(plain,key);
            assertArrayEquals(plain,VaultCipher.decrypt("gateways.enc",old,key));
            // Old files had no filename binding; this documents compatibility only.
            assertArrayEquals(plain,VaultCipher.decrypt("ssh-identities.enc",old,key));
            byte[] migrated=VaultCipher.encrypt("gateways.enc",VaultCipher.decrypt("gateways.enc",old,key),key);
            assertArrayEquals(plain,VaultCipher.decrypt("gateways.enc",migrated,key));
        }
    }
    @Test public void corruptedLegacyFilesFailAuthenticationWithoutFallback()throws Exception{
        SecretKey key=key();byte[] old=legacy(bytes(70024),key);
        for(int offset:new int[]{0,11,12,65536,old.length-1}){
            byte[] bad=old.clone();bad[offset]^=1;reject(()->VaultCipher.decrypt("gateways.enc",bad,key));
        }
        reject(()->VaultCipher.decrypt("gateways.enc",old,key()));
    }
    @Test public void standaloneRetryPurposeIsAuthenticatedAndCannotReadOrReplaceOtherVaults()throws Exception{
        SecretKey key=key();byte[] plain="[{\"id\":\"actual-owner\",\"request\":{\"password\":\"private fixture\"}}]".getBytes(StandardCharsets.UTF_8),retry=VaultCipher.encrypt("standalone-installs.enc",plain,key);assertArrayEquals(plain,VaultCipher.decrypt("standalone-installs.enc",retry,key));
        for(String other:new String[]{"gateways.enc","ssh-identities.enc"}){reject(()->VaultCipher.decrypt(other,retry,key));byte[] file=VaultCipher.encrypt(other,plain,key);reject(()->VaultCipher.decrypt("standalone-installs.enc",file,key));}
        reject(()->VaultCipher.decrypt("standalone-installs.enc",legacy(plain,key),key));
    }

}
