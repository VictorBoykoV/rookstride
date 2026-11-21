package org.strongswan.android.rookstride;

import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import static org.junit.Assert.*;

public class ConnectionCollectionDecodeTest {
    @Test public void readsExactUtf8IncludingMultibyteCharactersAcrossBufferBoundaries()throws Exception{
        char[] prefix=new char[8191];Arrays.fill(prefix,'x');String text=new String(prefix)+"😀 Mina’s VPN";
        assertEquals(text,ConnectionCollectionState.decode(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))));
    }
    @Test public void theFourMiBLimitIsInBytesAndRejectsTheFirstExtraByte()throws Exception{
        byte[] exact=new byte[ConnectionBundle.MAX_BYTES];Arrays.fill(exact,(byte)' ');assertEquals(exact.length,ConnectionCollectionState.decode(new ByteArrayInputStream(exact)).length());
        try{ConnectionCollectionState.decode(new ByteArrayInputStream(Arrays.copyOf(exact,exact.length+1)));fail("Oversized file accepted");}catch(IOException expected){assertNotNull(expected.getMessage());}
    }
    @Test public void malformedAndTruncatedUtf8AreRejectedInsteadOfReplacingCharacters()throws Exception{
        for(byte[] invalid:new byte[][]{{(byte)0xc3,0x28},{(byte)0xf0,(byte)0x9f,(byte)0x98},{(byte)0xc0,(byte)0xaf}})try{ConnectionCollectionState.decode(new ByteArrayInputStream(invalid));fail("Malformed UTF-8 accepted");}catch(IOException expected){}
    }
}
