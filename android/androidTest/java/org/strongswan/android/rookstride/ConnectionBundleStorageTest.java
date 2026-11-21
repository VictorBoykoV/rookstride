package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.ContextWrapper;
import android.util.AtomicFile;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.data.*;
import org.strongswan.android.security.LocalCertificateStore;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

/** Explicit local-storage opt-in: no server, network, VPN connection or catalog commit. */
@RunWith(AndroidJUnit4.class)
public final class ConnectionBundleStorageTest {
    private static final String CERTIFICATE="MIIC/DCCAeSgAwIBAgIJAIOTpz77hJqnMA0GCSqGSIb3DQEBCwUAMDMxMTAvBgNVBAMMKFJvb2tzdHJpZGUgc3ludGhldGljIHVuaXQtdGVzdCBhdXRob3JpdHkwHhcNMjYxMTAzMjEyNTQ3WhcNMzYxMDMxMjEyNTQ3WjAzMTEwLwYDVQQDDChSb29rc3RyaWRlIHN5bnRoZXRpYyB1bml0LXRlc3QgYXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuY7vEIV3lPYYPX0Ds1FFMsqKh351afpz2EfGmgcZzDvCwv0khi8aZU/2KvUxD3z2Pg45Erq4qQ0ZKfxGnEhj+aHeaJnz0gb/qSGQP7c5VUxUyOG3QgEdhpcHPnSQahESVTI4ZVqwd1bDEYIjYTQY15BtKmBncbi485Vvw5c4Vj2MsZa9v1FKu8/lYUcU3J335VR/DcR+Z5dyt+IY095khmhdglrbVMH/MI+XthYy+NLRFHoae8g2ykuFPYr/u7Ca0/MFpBHyQnAcmUisvFadY8FJzcQxQPhnpwboeyptm7qOdsaFDrupoF9FQWNqSrIhsD5JxpP3CjXlbkyww1W3WwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAcGYDDGlA2pUUSUd1maoSY8polTxv3AtkYtLQVrAmdEMFQIbELlwUijhULHWa7sdz01arBMqZqI78qrmdjppmA+Z8pfWiJ7sXOsd96+3aY42UtXdFQVtSz2qyzlnAV6eW5imK8xEHQ5DREucPWPjQwzjhkwlnA1qzOU6x9u/sudcC2RtfP113llQM/8MITGaFiswpT9IM/0R1bbLdxyE+fTpN/8DtqELqBnl5CkCJI7pwaEgssIrsEAkVFoaozbSyYQprg7voOIhYCw6wbqeM+Xq8V1tSUkdpJxdiUn+36VawrARd1GXGexT7XZBX/Kg92mCls0kPdvDCyo1O6hya2";
    private Context context()throws Exception {
        assumeTrue("Run this local storage acceptance explicitly", "true".equals(InstrumentationRegistry.getArguments().getString("rookstride_bundle_storage_test")));
        assumeFalse("Finish the existing foreground operation first",DeploymentService.active());
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();new Vault(context).read();
        assumeTrue("A previous import needs its own recovery first",new ConnectionBundleAndroidStore(context).journal()==null);
        return context;
    }
    static X509Certificate certificate()throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CERTIFICATE)));}
    private JSONObject ike(String login,byte[] cert)throws Exception {
        JSONObject profile=PasswordSignIn.withKnownPassword(PasswordSignIn.definition("ikev2","vpn.example.invalid",login,"chosen-local-test",""),login,"chosen-local-test");profile.getJSONObject("remote").put("cert",Base64.getEncoder().encodeToString(cert));
        return ConnectionExport.fromResponse(profile).pending().put("display_name",login+"’s test connection");
    }
    private JSONObject awg()throws Exception {
        byte[] key=new byte[32];Arrays.fill(key,(byte)1);String a=Base64.getEncoder().encodeToString(key);Arrays.fill(key,(byte)2);String b=Base64.getEncoder().encodeToString(key);
        String config="[Interface]\nPrivateKey = "+a+"\nAddress = 10.80.0.2/32\nDNS = 10.80.0.1\n\n[Peer]\nPublicKey = "+b+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.invalid:51820\n";
        return new JSONObject().put("format","awg").put("name","rookstride-local.conf").put("content",config);
    }
    private static String hash(byte[] bytes)throws Exception{return ConnectionBundleImport.hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static byte[] optional(File file)throws Exception{return file.isFile()?Files.readAllBytes(file.toPath()):null;}
    private static Map<String,String> nativeFiles(Context context)throws Exception {
        Map<String,String> result=new TreeMap<>();File directory=new File(context.getNoBackupFilesDir(),"vpn-profiles");File[] files=directory.listFiles();if(files!=null)for(File file:files)if(file.isFile())result.put(file.getName(),hash(Files.readAllBytes(file.toPath())));return result;
    }
    private static Map<String,String> sqlProfiles()throws Exception {
        Map<String,String> result=new TreeMap<>();VpnProfileDataSource source=new VpnProfileSqlDataSource().open();try{for(VpnProfile p:source.getAllVpnProfiles()){
            JSONObject values=new JSONObject();Method[] methods=VpnProfile.class.getMethods();Arrays.sort(methods,Comparator.comparing(Method::getName));
            for(Method method:methods)if((method.getName().startsWith("get")||method.getName().startsWith("is"))&&method.getParameterTypes().length==0&&!method.getName().equals("getClass")&&!method.getName().equals("getDataSource"))values.put(method.getName(),String.valueOf(method.invoke(p)));
            result.put(p.getUUID().toString(),hash(values.toString().getBytes(StandardCharsets.UTF_8)));
        }}finally{source.close();}return result;
    }
    private static Map<String,String> certificates()throws Exception {Map<String,String> result=new TreeMap<>();LocalCertificateStore store=new LocalCertificateStore();for(String alias:store.aliases()){X509Certificate certificate=store.getCertificate(alias);result.put(alias,certificate==null?"unreadable":hash(certificate.getEncoded()));}return result;}
    private static Set<String> keys()throws Exception {KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);return new HashSet<>(Collections.list(keys.aliases()));}
    private static void removeFixtureCertificate(Context context,LocalCertificateStore trust,String alias,X509Certificate fixture)throws Exception {
        VpnProfileDataSource source=new VpnProfileSqlDataSource().open();try{for(VpnProfile profile:source.getAllVpnProfiles())if(alias.equals(profile.getCertificateAlias()))throw new IOException("Fixture trust is still referenced; preserve it for review");}finally{source.close();}
        source=new VpnProfileSource(context).open();try{for(VpnProfile profile:source.getAllVpnProfiles())if(alias.equals(profile.getCertificateAlias()))throw new IOException("Fixture trust is still referenced; preserve it for review");}finally{source.close();}
        X509Certificate actual=trust.getCertificate(alias);if(actual!=null&&Arrays.equals(actual.getEncoded(),fixture.getEncoded()))trust.deleteCertificate(alias);
    }
    private static final class Snapshot {
        final byte[] catalog,pins;final Map<String,String> nativeProfiles,sql,certificates;final Set<String> keys;
        Snapshot(Context context)throws Exception{catalog=optional(new File(context.getFilesDir(),"gateways.enc"));pins=optional(new File(context.getFilesDir(),"ssh-identities.enc"));nativeProfiles=nativeFiles(context);sql=sqlProfiles();certificates=certificates();keys=keys();}
        void unchanged(Context context)throws Exception{assertArrayEquals("The existing catalog ciphertext changed",catalog,optional(new File(context.getFilesDir(),"gateways.enc")));assertArrayEquals("SSH trust changed",pins,optional(new File(context.getFilesDir(),"ssh-identities.enc")));assertEquals(nativeProfiles,nativeFiles(context));assertEquals(sql,sqlProfiles());assertEquals(certificates,certificates());assertTrue("An existing Keystore alias disappeared",keys().containsAll(keys));}
    }
    /** Actual Android stores, with only the final catalog-append boundary refused. */
    private static final class BeforeCommit implements ConnectionBundleImport.Store {
        final ConnectionBundleAndroidStore actual;int commits,stages;Exception firstFailure;String firstFailureBoundary="";
        private interface Checked<T>{T run()throws Exception;}
        private <T>T observed(String boundary,Checked<T> call)throws Exception{try{return call.run();}catch(Exception failure){if(firstFailure==null){firstFailure=failure;firstFailureBoundary=boundary;}throw failure;}}
        BeforeCommit(Context context){actual=new ConnectionBundleAndroidStore(context);}
        public ArrayList<Gateway> catalog()throws Exception{return observed("catalog read",()->actual.catalog());}
        public boolean matches(Gateway node,JSONObject profile)throws Exception{return observed("existing connection match",()->actual.matches(node,profile));}
        public ConnectionBundleImport.Asset describe(Gateway node,JSONObject profile)throws Exception{return observed("describe "+profile.optString("format"),()->actual.describe(node,profile));}
        public void stage(Gateway node,JSONObject profile,ConnectionBundleImport.Asset plan)throws Exception{int index=++stages;observed("stage "+index+" "+plan.protocol,()->{actual.stage(node,profile,plan);return null;});}
        public ArrayList<Gateway> append(List<Gateway> nodes)throws Exception{commits++;throw new IOException("Injected refusal before catalog commit");}
        public JSONObject journal()throws Exception{return observed("journal read",()->actual.journal());}
        public void journal(JSONObject value)throws Exception{observed("journal write",()->{actual.journal(value);return null;});}
        public void clearJournal()throws Exception{observed("journal clear",()->{actual.clearJournal();return null;});}
        public void cleanup(ConnectionBundleImport.Asset asset,List<Gateway> references)throws Exception{observed("asset cleanup "+asset.protocol,()->{actual.cleanup(asset,references);return null;});}
        public void finishCleanup(List<ConnectionBundleImport.Asset> assets,List<Gateway> references)throws Exception{observed("shared certificate cleanup",()->{actual.finishCleanup(assets,references);return null;});}
    }
    private void rejected(BeforeCommit store,String file)throws Exception {
        try{ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,file));fail("The deliberately refused commit succeeded");}
        catch(IOException expected){if(store.commits!=1){AssertionError failure=new AssertionError("The injected final commit was not reached exactly once (commits="+store.commits+"); first failing local boundary: "+(store.firstFailureBoundary.isEmpty()?"preview/import before a store exception":store.firstFailureBoundary));failure.initCause(store.firstFailure==null?expected:store.firstFailure);if(store.firstFailure!=null&&store.firstFailure!=expected)failure.addSuppressed(expected);throw failure;}}
        assertNull("Staged local import cleanup needs attention",store.journal());
    }
    @Test public void actualNativeSqlAndSharedPrivateCertificateRollbackPreservesExistingAccess()throws Exception {
        Context context=context();LocalCertificateStore trust=new LocalCertificateStore();String alias=trust.getCertificateAlias(certificate());assumeFalse("Do not remove an existing copy of this test certificate",trust.containsAlias(alias));Snapshot before=new Snapshot(context);BeforeCommit store=new BeforeCommit(context);
        try{rejected(store,ConnectionBundle.pack(Arrays.asList(ike("bundle_mina",certificate().getEncoded()),ike("bundle_navid",certificate().getEncoded()),awg())));before.unchanged(context);assertFalse(trust.containsAlias(alias));}
        finally{if(store.journal()!=null)ConnectionBundleImport.recover(store);}
    }
    @Test public void reusedCertificateIsNeverRewrittenOrRemovedByRollback()throws Exception {
        Context context=context();LocalCertificateStore trust=new LocalCertificateStore();X509Certificate certificate=certificate();String alias=trust.getCertificateAlias(certificate);assumeFalse("Keep an existing certificate outside this fixture",trust.containsAlias(alias));Snapshot original=new Snapshot(context);assertTrue(trust.addCertificate(certificate));Snapshot withFixture=new Snapshot(context);BeforeCommit store=new BeforeCommit(context);
        try{rejected(store,ConnectionBundle.pack(Collections.singletonList(ike("bundle_reuse",certificate.getEncoded()))));withFixture.unchanged(context);}
        finally{if(store.journal()!=null)ConnectionBundleImport.recover(store);removeFixtureCertificate(context,trust,alias,certificate);original.unchanged(context);}
    }
    @Test public void differentCertificateWithTheSamePublicKeyIsRejectedBeforeStaging()throws Exception {
        Context context=context();LocalCertificateStore trust=new LocalCertificateStore();X509Certificate certificate=certificate();String alias=trust.getCertificateAlias(certificate);assumeFalse("Keep an existing certificate outside this fixture",trust.containsAlias(alias));Snapshot original=new Snapshot(context);assertTrue(trust.addCertificate(certificate));Snapshot withFixture=new Snapshot(context);BeforeCommit store=new BeforeCommit(context);byte[] different=certificate.getEncoded();different[different.length-1]^=1;
        try{String file=ConnectionBundle.pack(Collections.singletonList(ike("bundle_conflict",different)));try{ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,file));fail("Conflicting certificate was accepted");}catch(IOException expected){}assertEquals(0,store.commits);assertNull(store.journal());withFixture.unchanged(context);}
        finally{if(store.journal()!=null)ConnectionBundleImport.recover(store);removeFixtureCertificate(context,trust,alias,certificate);original.unchanged(context);}
    }
    @Test public void realEncryptedAppendMergesConcurrentClientsAndRejectsAuthorityInAnIsolatedCatalog()throws Exception {
        Context original=context();File directory=Files.createTempDirectory(original.getCacheDir().toPath(),"bundle-vault-").toFile();Context isolated=new ContextWrapper(original){@Override public File getFilesDir(){return directory;}};ExecutorService workers=Executors.newFixedThreadPool(2);
        try{
            Gateway owner=new Gateway();owner.set("name","Unrelated owner fixture");owner.data.put("remember",true);owner.sshPassword="local test owner secret";new Vault(isolated).write(new ArrayList<>(Collections.singletonList(owner)));
            Gateway one=ConnectionBundleImport.client(ike("append_one",certificate().getEncoded()),UUID.randomUUID().toString()),two=ConnectionBundleImport.client(ike("append_two",certificate().getEncoded()),UUID.randomUUID().toString());CountDownLatch start=new CountDownLatch(1);
            Future<?> first=workers.submit(()->{start.await();new Vault(isolated).appendClientRecords(Collections.singletonList(one));return null;});Future<?> second=workers.submit(()->{start.await();new Vault(isolated).appendClientRecords(Collections.singletonList(two));return null;});start.countDown();first.get(20,TimeUnit.SECONDS);second.get(20,TimeUnit.SECONDS);
            ArrayList<Gateway> saved=new Vault(isolated).read();assertEquals(3,saved.size());assertEquals(owner.get("id"),saved.get(0).get("id"));assertEquals(owner.sshPassword,saved.get(0).sshPassword);Set<String> ids=new HashSet<>();for(Gateway node:saved)ids.add(node.get("id"));assertTrue(ids.contains(one.get("id")));assertTrue(ids.contains(two.get("id")));
            byte[] ciphertext=Files.readAllBytes(new File(directory,"gateways.enc").toPath());Gateway malicious=ConnectionBundleImport.client(ike("not_admin",certificate().getEncoded()),UUID.randomUUID().toString());malicious.privateKey="not ordinary VPN access";
            try{new Vault(isolated).appendClientRecords(Collections.singletonList(malicious));fail("Administrator material entered an ordinary import");}catch(IOException expected){}assertArrayEquals(ciphertext,Files.readAllBytes(new File(directory,"gateways.enc").toPath()));
            try{new Vault(isolated).appendClientRecords(Collections.singletonList(one));fail("An existing record was replaced");}catch(IOException expected){}assertArrayEquals(ciphertext,Files.readAllBytes(new File(directory,"gateways.enc").toPath()));
        }finally{workers.shutdownNow();assertTrue(workers.awaitTermination(20,TimeUnit.SECONDS));File[] files=directory.listFiles();if(files!=null)for(File file:files)assertTrue(file.delete());assertTrue(directory.delete());}
    }
    /** The stream and backup/new-file behavior are Android AtomicFile, not a JVM model. */
    private static final class PausedAtomicFile extends AtomicFile {
        final CountDownLatch writing=new CountDownLatch(1),release=new CountDownLatch(1);final boolean refuseCommit;
        PausedAtomicFile(File file,boolean refuseCommit){super(file);this.refuseCommit=refuseCommit;}
        @Override public FileOutputStream startWrite()throws IOException {
            FileOutputStream out=super.startWrite();writing.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new IOException("Test writer scheduling timed out");return out;}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();super.failWrite(out);throw new IOException("Test writer interrupted");}
            catch(IOException failure){super.failWrite(out);throw failure;}
        }
        @Override public void finishWrite(FileOutputStream out){if(refuseCommit)throw new IllegalStateException("Injected failure before AtomicFile commit");super.finishWrite(out);}
    }
    private static JSONObject journalFixture(String protocol)throws Exception {
        String operation=UUID.randomUUID().toString();ConnectionBundleImport.Asset asset=new ConnectionBundleImport.Asset(UUID.randomUUID().toString(),protocol,"","",false,operation);
        return new JSONObject().put("schema",1).put("kind","rookstride-local-import").put("operation",operation).put("assets",new JSONArray().put(asset.json()));
    }
    private void atomicJournalRace(boolean failedCommit,boolean clearReader)throws Exception {
        assumeTrue("Run this local storage acceptance explicitly","true".equals(InstrumentationRegistry.getArguments().getString("rookstride_bundle_storage_test")));
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();File directory=Files.createTempDirectory(context.getCacheDir().toPath(),"bundle-journal-").toFile(),target=new File(directory,"import.json");ExecutorService workers=Executors.newFixedThreadPool(2);
        PausedAtomicFile paused=new PausedAtomicFile(target,failedCommit);JSONObject before=journalFixture("awg"),after=journalFixture("ikev2");ConnectionImportJournal baseline=new ConnectionImportJournal(new AtomicFile(target));baseline.write(before);
        try{
            Future<?> write=workers.submit(()->{new ConnectionImportJournal(paused).write(after);return null;});assertTrue("Real AtomicFile write did not begin",paused.writing.await(10,TimeUnit.SECONDS));CountDownLatch readerStarted=new CountDownLatch(1);
            Future<JSONObject> read=workers.submit(()->{readerStarted.countDown();ConnectionImportJournal separateInstance=new ConnectionImportJournal(new AtomicFile(target));if(clearReader){separateInstance.clear();return null;}return separateInstance.read();});assertTrue(readerStarted.await(10,TimeUnit.SECONDS));
            try{read.get(200,TimeUnit.MILLISECONDS);fail("A second AtomicFile instance touched the journal during its write");}catch(TimeoutException correctlyBlocked){}
            paused.release.countDown();if(failedCommit){try{write.get(10,TimeUnit.SECONDS);fail("Injected failed commit succeeded");}catch(ExecutionException expected){assertTrue(expected.getCause() instanceof IllegalStateException);}}else write.get(10,TimeUnit.SECONDS);
            JSONObject observed=read.get(10,TimeUnit.SECONDS);if(clearReader){assertNull(observed);assertNull(baseline.read());}else assertEquals((failedCommit?before:after).getString("operation"),observed.getString("operation"));
            assertFalse("AtomicFile backup was left behind",new File(target.getPath()+".bak").exists());assertFalse("AtomicFile new file was left behind",new File(target.getPath()+".new").exists());
        }finally{paused.release.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(20,TimeUnit.SECONDS));baseline.clear();File[] files=directory.listFiles();if(files!=null)for(File file:files)assertTrue(file.delete());assertTrue(directory.delete());}
    }
    @Test public void actualAtomicFileReaderWaitsForAnotherInstancesCompletedJournalWrite()throws Exception{atomicJournalRace(false,false);}
    @Test public void actualAtomicFileReaderWaitsForRollbackAndKeepsPreviousJournal()throws Exception{atomicJournalRace(true,false);}
    @Test public void actualAtomicFileClearWaitsForAnotherInstancesJournalWrite()throws Exception{atomicJournalRace(false,true);}
    @Test public void actualJournalFastCheckRecognizesNativeOnlyRecoveryAndRejectsCorruptEvidence()throws Exception{
        assumeTrue("Run this local storage acceptance explicitly","true".equals(InstrumentationRegistry.getArguments().getString("rookstride_bundle_storage_test")));
        Context original=InstrumentationRegistry.getInstrumentation().getTargetContext();File directory=Files.createTempDirectory(original.getCacheDir().toPath(),"bundle-journal-check-").toFile();Context isolated=new ContextWrapper(original){@Override public Context getApplicationContext(){return this;}@Override public File getNoBackupFilesDir(){return directory;}};ConnectionImportJournal journal=new ConnectionImportJournal(isolated);
        try{
            assertFalse(ConnectionBundleImport.recoveryPending(isolated));journal.write(journalFixture("awg"));assertTrue(ConnectionBundleImport.recoveryPending(isolated));assertTrue("Native-only recovery must not be mistaken for no recovery",ConnectionBundleImport.pendingIkeProfileIds(isolated).isEmpty());journal.clear();assertFalse(ConnectionBundleImport.recoveryPending(isolated));
            File target=new File(directory,"connection-import.json");byte[] corrupt="{\"schema\":1,\"kind\":\"not-an-import\"}".getBytes(StandardCharsets.UTF_8);Files.write(target.toPath(),corrupt);
            try{ConnectionBundleImport.recoveryPending(isolated);fail("Corrupt recovery evidence was accepted as a healthy startup");}catch(IOException expected){}catch(JSONException expected){}
            assertArrayEquals("Invalid evidence must be preserved for recovery",corrupt,Files.readAllBytes(target.toPath()));
        }finally{journal.clear();assertTrue(directory.delete());}
    }
}
