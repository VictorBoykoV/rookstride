package org.strongswan.android.rookstride;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.*;
import static org.junit.Assert.*;

/** Real temporary-file acknowledgement/refusal checks; no Android or Keystore. */
public final class VaultCommitTest {
    @Rule public TemporaryFolder temporary=new TemporaryFolder();
    private byte[] ciphertext(){byte[] value=new byte[8197];for(int i=0;i<value.length;i++)value[i]=(byte)(i^(i>>>8));return value;}
    private Path base()throws IOException{return temporary.newFolder().toPath().resolve("gateways.enc");}
    private Map<String,String> evidence(Path root)throws IOException{
        Map<String,String> value=new TreeMap<>();try(java.util.stream.Stream<Path> paths=Files.walk(root)){
            for(Iterator<Path> i=paths.iterator();i.hasNext();){Path path=i.next();String key=root.relativize(path).toString();
                if(Files.isSymbolicLink(path))value.put(key,"link:"+Files.readSymbolicLink(path));
                else if(Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))value.put(key,"directory");
                else value.put(key,Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
            }
        }return value;
    }
    private void refusedUnchanged(Path path,byte[] expected,int limit)throws Exception{
        Map<String,String> before=evidence(path.getParent());
        try{VaultCommit.verify(path.toFile(),expected,limit);fail("Uncertain ciphertext was acknowledged");}catch(IOException expectedFailure){assertNotNull(expectedFailure.getMessage());}
        assertEquals("Acknowledgement must never recover/delete/rewrite evidence",before,evidence(path.getParent()));
    }
    @Test public void exactBoundedCiphertextIsAcknowledgedWithoutChangingAnyFile()throws Exception{
        Path path=base();byte[] expected=ciphertext();Files.write(path,expected);Map<String,String> before=evidence(path.getParent());VaultCommit.verify(path.toFile(),expected,expected.length);assertEquals(before,evidence(path.getParent()));
    }
    @Test public void absentBaseDoesNotCreateOrRecoverOne()throws Exception{
        Path path=base();refusedUnchanged(path,ciphertext(),10000);Files.write(path.resolveSibling("gateways.enc.bak"),ciphertext());refusedUnchanged(path,ciphertext(),10000);assertFalse(Files.exists(path));
    }
    @Test public void sameSizeChangedCiphertextIsRefused()throws Exception{
        Path path=base();byte[] expected=ciphertext(),changed=expected.clone();changed[4096]^=1;Files.write(path,changed);refusedUnchanged(path,expected,10000);
    }
    @Test public void truncatedAndAppendedFilesCannotPassSizeOrReadBounds()throws Exception{
        Path path=base();byte[] expected=ciphertext();for(int size:new int[]{0,expected.length-1,expected.length+1,32768}){Files.write(path,Arrays.copyOf(expected,size));refusedUnchanged(path,expected,10000);}
    }
    @Test public void callerLimitCannotBeBypassedByMatchingOversizedBytes()throws Exception{
        Path path=base();byte[] expected=ciphertext();Files.write(path,expected);refusedUnchanged(path,expected,4096);
    }
    @Test public void backupAndNewSidecarsNeverGetDeletedOrRecovered()throws Exception{
        for(String suffix:new String[]{".bak",".new"}){Path path=base();byte[] expected=ciphertext();Files.write(path,expected);Files.write(path.resolveSibling(path.getFileName()+suffix),new byte[]{7,8,9});refusedUnchanged(path,expected,10000);}
    }
    @Test public void danglingAndLiveSidecarLinksAlsoPreventAcknowledgement()throws Exception{
        for(String suffix:new String[]{".bak",".new"})for(boolean live:new boolean[]{false,true}){Path path=base();byte[] expected=ciphertext();Files.write(path,expected);Path target=path.resolveSibling("held");if(live)Files.write(target,new byte[]{5});Files.createSymbolicLink(path.resolveSibling(path.getFileName()+suffix),target);refusedUnchanged(path,expected,10000);}
    }
    @Test public void linkedBaseCannotBorrowMatchingTargetBytes()throws Exception{
        Path path=base(),target=path.resolveSibling("held");byte[] expected=ciphertext();Files.write(target,expected);Files.createSymbolicLink(path,target);refusedUnchanged(path,expected,10000);
    }
    @Test public void aDirectoryAtTheBaseIsNotAnAcknowledgedFile()throws Exception{
        Path path=base();Files.createDirectory(path);refusedUnchanged(path,new byte[0],10000);
    }
}
