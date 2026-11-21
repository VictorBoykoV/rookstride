package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.ContextWrapper;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

/** Opt-in real JNI/filesystem publication in isolated app-owned directories.
 * No live trust alias, SQL profile, catalog, Keystore or server is changed. */
@RunWith(AndroidJUnit4.class)
public final class CertificatePublicationTest {
    private static final class Scope implements AutoCloseable {
        final Context original,context;final File parent,files,staging;final Map<String,String> before;
        Scope()throws Exception{
            assumeTrue("Run local storage acceptance explicitly","true".equals(InstrumentationRegistry.getArguments().getString("rookstride_bundle_storage_test")));
            assumeFalse(DeploymentService.active());original=InstrumentationRegistry.getInstrumentation().getTargetContext();before=realFiles(original);
            parent=Files.createTempDirectory(original.getCacheDir().toPath(),"certificate-publication-test-").toFile();Os.chmod(parent.getPath(),0700);files=new File(parent,"files");staging=new File(parent,"no_backup");assertTrue(files.mkdir());assertTrue(staging.mkdir());Os.chmod(files.getPath(),0700);Os.chmod(staging.getPath(),0700);
            context=new ContextWrapper(original){@Override public Context getApplicationContext(){return this;}@Override public File getFilesDir(){return files;}@Override public File getNoBackupFilesDir(){return staging;}};
        }
        void write(File file,byte[] bytes)throws Exception{Files.write(file.toPath(),bytes);Os.chmod(file.getPath(),0600);}
        @Override public void close()throws Exception{assertEquals(original.getCacheDir().getCanonicalFile(),parent.getCanonicalFile().getParentFile());assertTrue(parent.getName().startsWith("certificate-publication-test-"));assertTrue(remove(parent));assertEquals("Real phone files changed during isolated publication",before,realFiles(original));}
    }
    private static ConnectionBundleImport.Asset asset(X509Certificate certificate)throws Exception{return new ConnectionBundleImport.Asset(UUID.randomUUID().toString(),"ikev2",new org.strongswan.android.security.LocalCertificateStore().getCertificateAlias(certificate),hash(certificate.getEncoded()),true,UUID.randomUUID().toString());}
    private static String hash(byte[] bytes)throws Exception{return ConnectionBundleImport.hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void rejected(Checked action)throws Exception{try{action.run();fail("Unsafe publication was accepted");}catch(IOException expected){}}
    private interface Checked{void run()throws Exception;}
    private static boolean remove(File file)throws Exception{if(Files.isSymbolicLink(file.toPath()))return file.delete();boolean ok=true;if(file.isDirectory()){File[] children=file.listFiles();if(children==null)return false;for(File child:children)ok=remove(child)&&ok;}return file.delete()&&ok;}
    private static Map<String,String> realFiles(Context context)throws Exception{
        Map<String,String> result=new TreeMap<>();File[] files=context.getFilesDir().listFiles();if(files!=null)for(File file:files)if(file.isFile()&&(file.getName().startsWith("certificate-")||file.getName().startsWith("gateways.enc")||file.getName().startsWith("ssh-identities.enc")))result.put("files/"+file.getName(),hash(Files.readAllBytes(file.toPath())));
        File[] nativeFiles=new File(context.getNoBackupFilesDir(),"vpn-profiles").listFiles();if(nativeFiles!=null)for(File file:nativeFiles)if(file.isFile())result.put("native/"+file.getName(),hash(Files.readAllBytes(file.toPath())));return result;
    }
    @Test public void nativeNoReplacePreservesSameDifferentAndSymlinkAliases()throws Exception{
        X509Certificate certificate=ConnectionBundleStorageTest.certificate();byte[] encoded=certificate.getEncoded();
        for(int variant=0;variant<3;variant++)try(Scope scope=new Scope()){
            CertificatePublication publication=new CertificatePublication(scope.context);ConnectionBundleImport.Asset asset=asset(certificate);File target=publication.target(asset);byte[] existing=encoded.clone();if(variant==1)existing[existing.length-1]^=1;
            File underlying=new File(scope.files,"foreign.der");if(variant==2){scope.write(underlying,existing);Files.createSymbolicLink(target.toPath(),underlying.toPath());}else scope.write(target,existing);
            long inode=Os.lstat(target.getPath()).st_ino;
            if(variant==0)publication.stage(asset,certificate);else rejected(()->publication.stage(asset,certificate));
            publication.cleanup(asset,false);assertEquals(inode,Os.lstat(target.getPath()).st_ino);assertArrayEquals(existing,Files.readAllBytes((variant==2?underlying:target).toPath()));if(variant==2)assertTrue(Files.isSymbolicLink(target.toPath()));assertFalse(publication.proofFile(asset).exists());
        }
    }
    @Test public void durableProofPrecedesPublicationAndSourceOnlyCrashIsRecoverable()throws Exception{
        try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);AtomicInteger calls=new AtomicInteger();
            CertificatePublication publication=new CertificatePublication(scope.context,(source,target)->{calls.incrementAndGet();File proof=new File(source.getParentFile(),asset.id+".ownership.json");JSONObject value=new JSONObject(new String(Files.readAllBytes(proof.toPath()),StandardCharsets.UTF_8));StructStat stat=Os.lstat(source.getPath());assertEquals(asset.operation,value.getString("operation"));assertEquals(asset.certificateHash,value.getString("sha256"));assertEquals(stat.st_dev,value.getLong("dev"));assertEquals(stat.st_ino,value.getLong("inode"));assertFalse(target.exists());throw new IOException("Fixture interruption before publication");});
            rejected(()->publication.stage(asset,certificate));assertEquals(1,calls.get());assertTrue(publication.temporary(asset).isFile());assertTrue(publication.proofFile(asset).isFile());
            new CertificatePublication(scope.context).cleanup(asset,false);assertFalse(publication.target(asset).exists());assertFalse(publication.temporary(asset).exists());assertFalse(publication.proofFile(asset).exists());
        }
    }
    @Test public void publishedBeforeSqlCrashRecoversUsingPrivateInodeProof()throws Exception{
        try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);
            CertificatePublication publication=new CertificatePublication(scope.context,(source,target)->{assertEquals(0,CertificatePublication.publishNative(source,target));throw new IOException("Fixture crash after publication before SQL");});
            rejected(()->publication.stage(asset,certificate));assertFalse(publication.temporary(asset).exists());assertTrue(publication.target(asset).isFile());assertTrue(publication.proofFile(asset).isFile());
            new CertificatePublication(scope.context).cleanup(asset,false);assertFalse(publication.target(asset).exists());assertFalse(publication.proofFile(asset).exists());
        }
    }
    @Test public void foreignReplacementAndProofMismatchNeverAuthorizeAliasDeletion()throws Exception{
        for(int variant=0;variant<3;variant++)try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);CertificatePublication publication=new CertificatePublication(scope.context);publication.stage(asset,certificate);File target=publication.target(asset);byte[] expected=certificate.getEncoded();File proof=publication.proofFile(asset);
            if(variant==0){expected[expected.length-1]^=1;scope.write(target,expected);}else{JSONObject value=new JSONObject(new String(Files.readAllBytes(proof.toPath()),StandardCharsets.UTF_8));if(variant==1)value.put("inode",value.getLong("inode")+1);else value.put("operation",UUID.randomUUID().toString());scope.write(proof,value.toString().getBytes(StandardCharsets.UTF_8));}
            if(variant==2){byte[] before=Files.readAllBytes(proof.toPath());rejected(()->new CertificatePublication(scope.context).cleanup(asset,false));assertArrayEquals(before,Files.readAllBytes(proof.toPath()));}else publication.cleanup(asset,false);
            assertArrayEquals(expected,Files.readAllBytes(target.toPath()));
        }
    }
    @Test public void committedReferencesRetainTrustAfterPrivateProofIsReleased()throws Exception{
        try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);CertificatePublication publication=new CertificatePublication(scope.context);publication.stage(asset,certificate);long inode=Os.lstat(publication.target(asset).getPath()).st_ino;
            publication.cleanup(asset,true);assertFalse(publication.proofFile(asset).exists());assertEquals(inode,Os.lstat(publication.target(asset).getPath()).st_ino);assertArrayEquals(certificate.getEncoded(),Files.readAllBytes(publication.target(asset).toPath()));
            new CertificatePublication(scope.context).cleanup(asset,false);assertTrue("Released ownership must not be reacquired from equal certificate bytes",publication.target(asset).exists());
        }
    }
    @Test public void unsupportedPublicationFailsClosedWithoutAnyOverwriteFallback()throws Exception{
        for(int error:new int[]{OsConstants.ENOSYS,OsConstants.EOPNOTSUPP,OsConstants.EXDEV})try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);AtomicInteger calls=new AtomicInteger();CertificatePublication publication=new CertificatePublication(scope.context,(source,target)->{calls.incrementAndGet();return error;});
            rejected(()->publication.stage(asset,certificate));assertEquals(1,calls.get());assertFalse(publication.target(asset).exists());publication.cleanup(asset,false);assertFalse(publication.temporary(asset).exists());assertFalse(publication.proofFile(asset).exists());
        }
    }
    @Test public void sameAliasPublisherRacePreservesTheOtherWritersExactInode()throws Exception{
        for(boolean same:new boolean[]{true,false})try(Scope scope=new Scope()){
            X509Certificate certificate=ConnectionBundleStorageTest.certificate();ConnectionBundleImport.Asset asset=asset(certificate);byte[] foreign=certificate.getEncoded();if(!same)foreign[foreign.length-1]^=1;long[] foreignInode={0};
            CertificatePublication publication=new CertificatePublication(scope.context,(source,target)->{scope.write(target,foreign);foreignInode[0]=Os.lstat(target.getPath()).st_ino;return CertificatePublication.publishNative(source,target);});
            if(same)publication.stage(asset,certificate);else rejected(()->publication.stage(asset,certificate));publication.cleanup(asset,false);assertEquals(foreignInode[0],Os.lstat(publication.target(asset).getPath()).st_ino);assertArrayEquals(foreign,Files.readAllBytes(publication.target(asset).toPath()));
        }
    }
}
