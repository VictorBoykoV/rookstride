package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.ContextWrapper;
import android.util.AtomicFile;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.*;
import org.junit.*;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

/** Real Android Keystore encryption and AtomicFile races in an isolated folder.
 * Never changes the actual phone catalog or deletes its shared Keystore alias. */
@RunWith(AndroidJUnit4.class)
public final class VaultConcurrencyTest {
    private File directory;
    private Context context;
    private ExecutorService workers;
    @Before public void setup() throws Exception {
        Context original=InstrumentationRegistry.getInstrumentation().getTargetContext();
        directory=Files.createTempDirectory(original.getCacheDir().toPath(),"vault-concurrency-").toFile();
        context=new ContextWrapper(original){@Override public File getFilesDir(){return directory;}};
        workers=Executors.newFixedThreadPool(3);
        new Vault(context).write(rows("previous"));
    }
    @After public void cleanup() throws Exception {
        workers.shutdownNow();assertTrue("Vault workers did not finish",workers.awaitTermination(20,TimeUnit.SECONDS));
        for(File path:directory.listFiles())assertTrue(path.delete());assertTrue(directory.delete());
    }
    private static ArrayList<Gateway> rows(String value)throws Exception {
        Gateway node=new Gateway();node.set("name",value);node.data.put("remember",true);node.vpnPassword="private test password";
        return new ArrayList<>(Arrays.asList(node));
    }
    private String stored()throws Exception {
        ArrayList<Gateway> values=new Vault(context).read();assertEquals(1,values.size());
        assertEquals("private test password",values.get(0).vpnPassword);return values.get(0).get("name");
    }
    private static void blocked(Future<?> task)throws Exception {
        try{task.get(250,TimeUnit.MILLISECONDS);fail("Concurrent access escaped the in-progress atomic write");}
        catch(TimeoutException expected){/* A separate Vault instance must wait. */}
    }
    private PausedFile pause(Vault vault,boolean fail)throws Exception {
        PausedFile atomic=new PausedFile(new File(directory,"gateways.enc"),fail);
        Field field=Vault.class.getDeclaredField("file");field.setAccessible(true);field.set(vault,atomic);return atomic;
    }
    private static final class PausedFile extends AtomicFile {
        final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        final boolean fail;
        PausedFile(File path,boolean fail){super(path);this.fail=fail;}
        @Override public FileOutputStream startWrite()throws IOException {
            FileOutputStream original=super.startWrite();entered.countDown();
            try{if(!release.await(15,TimeUnit.SECONDS))throw new IOException("Test did not release the paused write");}
            catch(InterruptedException e){Thread.currentThread().interrupt();super.failWrite(original);throw new IOException(e);}
            if(!fail)return original;
            // Wrap the same real descriptor so failWrite() handles the actual
            // interrupted AtomicFile on both backup and newer staging variants.
            return new FileOutputStream(original.getFD()) {
                final FileOutputStream retained=original;
                @Override public void write(byte[] bytes)throws IOException{throw new IOException("Injected write failure");}
                @Override public void write(byte[] bytes,int offset,int count)throws IOException{throw new IOException("Injected write failure");}
            };
        }
    }
    @Test public void separateReaderWaitsUntilCommitAndSeesNewRecord()throws Exception {
        Vault writer=new Vault(context);PausedFile atomic=pause(writer,false);
        Future<?> write=workers.submit(()->{writer.write(rows("committed"));return null;});
        assertTrue(atomic.entered.await(10,TimeUnit.SECONDS));CountDownLatch started=new CountDownLatch(1);
        Future<String> read=workers.submit(()->{started.countDown();return stored();});
        try{assertTrue(started.await(10,TimeUnit.SECONDS));blocked(read);}finally{atomic.release.countDown();}
        write.get(15,TimeUnit.SECONDS);assertEquals("committed",read.get(15,TimeUnit.SECONDS));assertEquals("committed",stored());
    }
    @Test public void separateReaderWaitsForRollbackAndKeepsOldRecord()throws Exception {
        Vault writer=new Vault(context);PausedFile atomic=pause(writer,true);
        Future<?> write=workers.submit(()->{writer.write(rows("must not persist"));return null;});
        assertTrue(atomic.entered.await(10,TimeUnit.SECONDS));CountDownLatch started=new CountDownLatch(1);
        Future<String> read=workers.submit(()->{started.countDown();return stored();});
        try{assertTrue(started.await(10,TimeUnit.SECONDS));blocked(read);}finally{atomic.release.countDown();}
        try{write.get(15,TimeUnit.SECONDS);fail("Injected write should fail");}catch(ExecutionException expected){assertTrue(expected.getCause() instanceof IOException);}
        assertEquals("previous",read.get(15,TimeUnit.SECONDS));assertEquals("previous",stored());
    }
    @Test public void differentVaultWritersSerializeTheirCompleteAtomicWrites()throws Exception {
        Vault first=new Vault(context),second=new Vault(context);PausedFile atomic=pause(first,false);
        Future<?> one=workers.submit(()->{first.write(rows("first"));return null;});
        assertTrue(atomic.entered.await(10,TimeUnit.SECONDS));CountDownLatch started=new CountDownLatch(1);
        Future<?> two=workers.submit(()->{started.countDown();second.write(rows("second"));return null;});
        try{assertTrue(started.await(10,TimeUnit.SECONDS));blocked(two);}finally{atomic.release.countDown();}
        one.get(15,TimeUnit.SECONDS);two.get(15,TimeUnit.SECONDS);assertEquals("second",stored());
    }
    @Test public void backupOnlyCrashRecoversInsteadOfReturningAnEmptyCatalog()throws Exception {
        File base=new File(directory,"gateways.enc"),backup=new File(directory,"gateways.enc.bak");
        assertTrue(base.renameTo(backup));assertFalse(base.exists());assertEquals("previous",stored());assertTrue(base.isFile());
    }
    @Test public void corruptStoreDoesNotBecomeEmptyButAbsentStoreDoes()throws Exception {
        File base=new File(directory,"gateways.enc");Files.write(base.toPath(),new byte[]{1,2,3});
        try{new Vault(context).read();fail("Corrupt encrypted state must surface");}catch(IOException expected){}
        assertTrue(base.delete());assertTrue(new Vault(context).read().isEmpty());
    }
}
