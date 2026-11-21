package org.strongswan.android.rookstride;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Objects;

/** Direct encrypted-file acknowledgement. Never invokes AtomicFile recovery. */
final class VaultCommit {
    private VaultCommit(){}
    private static void need(boolean valid)throws IOException {
        if(!valid)throw new IOException("Saved phone storage commit could not be verified. Existing files were preserved.");
    }
    private static void noSidecars(Path base)throws IOException {
        for(String suffix:new String[]{".bak",".new"})need(!Files.exists(base.resolveSibling(base.getFileName()+suffix),LinkOption.NOFOLLOW_LINKS));
    }
    static void verify(File base,byte[] expected,int limit)throws IOException {
        need(base!=null&&expected!=null&&limit>=0&&expected.length<=limit);
        Path path=base.toPath();noSidecars(path);
        BasicFileAttributes before=Files.readAttributes(path,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        need(before.isRegularFile()&&!before.isSymbolicLink()&&before.size()==expected.length);
        byte[] buffer=new byte[4096];int total=0,difference=0;
        try(SeekableByteChannel channel=Files.newByteChannel(path,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS);InputStream in=Channels.newInputStream(channel)){
            int count;while((count=in.read(buffer))!=-1){
                need(count>0&&count<=expected.length-total);
                for(int i=0;i<count;i++)difference|=buffer[i]^expected[total+i];total+=count;
            }
        }finally{Arrays.fill(buffer,(byte)0);}
        need(total==expected.length&&difference==0);
        BasicFileAttributes after=Files.readAttributes(path,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        need(after.isRegularFile()&&!after.isSymbolicLink()&&after.size()==expected.length&&Objects.equals(before.fileKey(),after.fileKey()));
        noSidecars(path);
    }
}
