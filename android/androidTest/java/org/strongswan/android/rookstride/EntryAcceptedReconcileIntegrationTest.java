package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import org.strongswan.android.rookstride.engine.NativeProfiles;
import org.strongswan.android.rookstride.engine.NativeVpn;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import static org.junit.Assert.*;

/** Lost-reply reconciliation of an ALREADY ACCEPTED disposable entry migration.
 * Uses the real foreground coordinator and native engine, never a stage action or
 * private Activity handler. Run before the retired entry/journal is removed. */
@RunWith(AndroidJUnit4.class)
public class EntryAcceptedReconcileIntegrationTest {
    private static final PairController.Progress QUIET=phase->{};
    private static final String RESULT="entry-accepted-reconcile-result.json";

    @Test public void acceptedReplyReconcilesOwnerCacheAndKeepsImportedAccess()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("entry-accepted-reconcile","allow_entry_accept_reconcile");
        assertTrue("Review the canonical-catalog handoff explicitly",f.request.getBoolean("leave_reconciled_catalog"));
        assertTrue("Authorize the updated native client probe explicitly",f.request.getBoolean("allow_updated_client_traffic"));
        String assetHash=assetHash(f.context,"gateway_bundle.zip"),installedBundle=f.request.getString("expected_installed_bundle");
        assertEquals(f.request.getString("expected_gateway_zip_sha256"),assetHash);
        assertTrue(installedBundle.matches("[a-f0-9]{64}"));
        String appBundle=sourceBundleDigest(f.context);boolean crossEpoch=!appBundle.equals(installedBundle);
        if(crossEpoch)assertTrue("Review cross-version resume explicitly before using a different app helper",f.request.optBoolean("allow_accepted_operation_bundle_migration"));
        Context context=f.context;
        assertNull("Grant VPN consent on this disposable emulator first",VpnService.prepare(context));
        ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
        NetworkCapabilities network=cm.getNetworkCapabilities(cm.getActiveNetwork());
        assertTrue("Disconnect the existing VPN before this acceptance test",network==null||!network.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
        for(String protocol:new String[]{"awg","xray","openvpn","hysteria2"})
            assertFalse("An existing native connection must be stopped first",NativeVpn.isActive(NativeVpn.status(context,protocol).state));

        Gateway stale=f.acceptedEntryPair(),accepted=new Gateway(copy(f.request.getJSONObject("accepted_pair")));
        JSONObject operation=stale.data.getJSONObject("entryMigration"),acceptedOperation=accepted.data.getJSONObject("lastEntryMigration");
        String operationId=operation.getString("operation"),ownerId=f.request.getString("owner_catalog_id");
        assertFalse("Capture the actual stale physical administrator cache for this acceptance",stale.get("adminServerId").isEmpty());
        assertFalse("The lost-reply checkpoint must precede local authority reconciliation",operation.has("authorityReconciliation"));
        assertTrue(InputRules.job(operationId));
        assertEquals("awaiting-endpoint-switch",operation.getString("state"));
        assertTrue(operation.getBoolean("new_address"));
        assertEquals("accepted",acceptedOperation.getString("state"));
        assertEquals(operationId,acceptedOperation.getString("operation"));
        assertEquals(operationId,f.request.getJSONObject("accepted_result").getString("operation"));
        assertEquals("accepted",f.request.getJSONObject("accepted_result").getString("state"));
        assertEquals(stale.get("pairId"),accepted.get("pairId"));
        assertEquals(stale.get("pairId"),operation.getString("deployment"));
        assertEquals(operation.getInt("expected_revision")+1,accepted.data.getInt("deploymentRevision"));
        Gateway previous=new Gateway(copy(operation.getJSONObject("previous"))),candidate=new Gateway(copy(operation.getJSONObject("candidate")));
        assertTrue("This fixture must contain an actual endpoint change",!previous.get("host").equals(candidate.get("host")));
        assertTrue("The stale record must still address the retired entry",stale.get("host").equals(previous.get("host")));
        assertTrue("The receipt must identify the reviewed candidate",accepted.get("host").equals(candidate.get("host"))&&accepted.get("fingerprint").equals(candidate.get("fingerprint")));
        assertTrue("The exit must be unchanged by entry replacement",sameEndpoint(stale.exit,accepted.exit));
        assertEquals("awg",stale.get("protocol"));
        String oldContent=f.request.getJSONObject("old_profile").getString("content");
        String updatedContent=operation.getJSONObject("updated_profile").getString("content");
        NativeProfiles.validate("awg",oldContent);NativeProfiles.validate("awg",updatedContent);
        assertTrue("The stale profile is not the captured retired endpoint",awgEndpoint(oldContent,previous.get("host")));
        assertTrue("The replacement profile does not address the candidate",awgEndpoint(updatedContent,candidate.get("host")));
        assertFalse("An address-changing migration must update the native connection",oldContent.equals(updatedContent));
        assertTrue("Accepted and staged client material disagree",updatedContent.equals(acceptedOperation.getJSONObject("updated_profile").getString("content")));

        // Check the installed epoch through fixed, read-only SSH before executing
        // even the current app's observational bundled helpers. No helper is upgraded.
        verifyInstalledEpoch(previous,accepted.exit,stale.get("pairId"),"entry",installedBundle);
        verifyInstalledEpoch(candidate,accepted.exit,stale.get("pairId"),"entry",installedBundle);
        verifyInstalledEpoch(accepted.exit,candidate,stale.get("pairId"),"exit",installedBundle);
        RuntimeComponents.install(context);
        JSONObject initialStatus=status(f,previous,operation);
        assertAccepted(initialStatus,operation);
        verifyCanonical(f,accepted,operation);
        JSONObject beforeServers=identityReceipts(f,previous,candidate,accepted.exit);

        Vault vault=new Vault(context);if(f.request.optBoolean("allow_verified_catalog_recovery"))recoverVerifiedCatalogForFixture(f,vault);ArrayList<Gateway> original=vault.read();
        Gateway originalOwner=find(original,ownerId),imported=find(original,f.request.getString("preserved_client_id"));
        assertTrue("The owner catalog record belongs to another deployment",originalOwner.get("pairId").equals(stale.get("pairId")));
        assertTrue("The preserved record must be independently imported access",imported.data.optBoolean("clientOnly"));
        assertFalse(ownerId.equals(imported.get("id")));
        String importedRecord=canonical(imported.persisted());
        NativeProfileStore store=new NativeProfileStore(context);
        File importedFile=profileFile(context,imported.get("id")),ownerFile=profileFile(context,ownerId);
        byte[] importedBytes=Files.readAllBytes(importedFile.toPath()),ownerBytes=ownerFile.isFile()?Files.readAllBytes(ownerFile.toPath()):null;
        byte[] pinBytes=optionalBytes(new File(context.getFilesDir(),"ssh-identities.enc"));
        JSONObject importedProfile=store.read(imported.get("id"));
        String attempt=f.request.optString("reconcile_attempt","");assertTrue("Use a bounded private attempt label",attempt.isEmpty()||attempt.matches("[a-z0-9-]{1,24}"));File backup=new File(context.getFilesDir(),"entry-reconcile-backup-"+operationId+(attempt.isEmpty()?"":"-"+attempt));
        assertTrue("Keep the existing attempt backup; do not replay this fixture",backup.mkdir());
        backup(context,backup,"gateways.enc");backup(context,backup,"ssh-identities.enc");
        if(ownerBytes!=null)PrivateAdministrationFixture.atomic(new File(backup,"owner-profile.enc"),ownerBytes);
        JSONArray originalCatalog=new JSONArray();for(Gateway node:original)originalCatalog.put(node.persisted());
        PrivateAdministrationFixture.atomic(new File(backup,"catalog-private.json"),originalCatalog.toString().getBytes(StandardCharsets.UTF_8));
        f.receipt("entry-accepted-reconcile-progress.json",new JSONObject().put("phase","accepted server receipt verified; phone backup saved").put("operation",operationId));

        Gateway client=new Gateway();client.set("protocol","awg");client.set("name","Reviewed replacement entry probe");
        boolean launched=false,completed=false;
        ArrayList<Gateway> working=new ArrayList<>();
        stale.set("id",ownerId);stale.data.put("nativeProfile",true).put("connectionCheckedAt",1L);
        for(Gateway node:original)working.add(node.get("id").equals(ownerId)?stale:new Gateway(copy(node.persisted())));
        try {
            store.save(ownerId,"awg",stale.get("name"),oldContent);
            vault.write(working);
            assertTrue("The stale cache was not seeded",store.exists(ownerId));
            assertTrue(store.read(ownerId).getString("content").equals(oldContent));
            try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)) {
                // The service owns this same catalog through durable completion. No engine seam is replaced.
                JSONObject resumeConfig=new JSONObject().put("action","finish");
                screen.onActivity(activity->DeploymentService.launch(activity,stale,working,"lifecycle-entry",resumeConfig,true,candidate));
                launched=true;
                DeploymentService.Session result=awaitService(stale,Math.min(20,Math.max(3,f.request.optInt("timeout_minutes",10))));
                if(result.error!=null)throw new AssertionError("Accepted entry reconciliation needs attention; keep the private checkpoint",result.error);
                assertEquals("complete",result.progress.state);assertEquals("accepted",result.result.getString("state"));
                assertEquals(operationId,result.result.getString("operation"));
                completed=true;
                ArrayList<Gateway> saved=vault.read();Gateway owner=find(saved,ownerId);
                assertTrue("The owner still addresses the retired entry",owner.get("host").equals(candidate.get("host"))&&owner.get("vpnServer").equals(candidate.get("host")));
                assertTrue("The candidate's pinned SSH identity was not retained",owner.get("fingerprint").equals(candidate.get("fingerprint"))&&owner.get("machine").equals(candidate.get("machine")));
                assertTrue("Saved administrator access was lost",owner.sshPassword.equals(candidate.sshPassword)&&owner.privateKey.equals(candidate.privateKey));
                assertEquals(operation.getInt("expected_revision")+1,owner.data.getInt("deploymentRevision"));
                assertFalse(owner.data.has("entryMigration"));assertEquals(operationId,owner.data.getJSONObject("lastEntryMigration").getString("operation"));
                for(Iterator<String> keys=owner.data.keys();keys.hasNext();){String key=keys.next();assertFalse("Old physical administrator cache survived acceptance: "+key,key.startsWith("admin")&&!key.equals("admin"));}
                assertFalse("Old topology inventory survived acceptance",owner.data.has("deploymentInventory"));
                JSONObject authority=owner.data.getJSONObject("lastEntryMigration").getJSONObject("authorityReconciliation");
                assertEquals(operationId,authority.getString("operation"));assertEquals("accepted",authority.getString("state"));
                assertTrue("Authority reconciliation belongs to another physical server",authority.getString("machine").equals(candidate.get("machine"))&&authority.getString("fingerprint").equals(candidate.get("fingerprint")));
                assertEquals(candidate.get("admin"),owner.get("admin"));
                assertFalse("Retired owner native cache survived acceptance",store.exists(ownerId));
                assertFalse(owner.data.has("nativeProfile"));assertFalse(owner.data.has("profileUuid"));assertFalse(owner.data.has("connectionCheckedAt"));
                assertTrue("Entry replacement changed the exit management identity",sameEndpoint(owner.exit,accepted.exit));
                unchangedOthers(original,saved,ownerId);
                assertTrue("Imported connection metadata changed",importedRecord.equals(canonical(find(saved,imported.get("id")).persisted())));
                assertArrayEquals("Imported encrypted connection changed",importedBytes,Files.readAllBytes(importedFile.toPath()));
                assertTrue("Imported connection contents changed",canonical(importedProfile).equals(canonical(store.read(imported.get("id")))));
                assertArrayEquals("Unrelated SSH identity aliases changed",pinBytes,optionalBytes(new File(context.getFilesDir(),"ssh-identities.enc")));
                assertAccepted(status(f,previous,operation),operation);verifyCanonical(f,owner,operation);
                assertTrue("Reconciliation altered server users or private identity",canonical(beforeServers).equals(canonical(identityReceipts(f,previous,candidate,accepted.exit))));
                f.receipt("entry-accepted-reconcile-progress.json",new JSONObject().put("phase","canonical owner reconciled; checking updated native client").put("operation",operationId));
                store.save(client.get("id"),"awg",client.get("name"),updatedContent);
                screen.onActivity(activity->NativeVpn.start(activity,"awg",client.get("id")));
                NativePairIntegrationTest.connected(context,client);
                JSONObject traffic=NativePairIntegrationTest.probe(context,false,f.request.optString("canaryUrl"));
                NativePairIntegrationTest.verifyTraffic(traffic,operation.getString("expected_exit_ip"),f.request.optString("canaryToken"));
                assertArrayEquals(importedBytes,Files.readAllBytes(importedFile.toPath()));
                f.receipt(RESULT,new JSONObject().put("operation",operationId).put("already_accepted_receipt_replayed",true)
                    .put("installed_journal_bundle",installedBundle).put("resuming_app_gateway_zip_sha256",assetHash).put("resuming_app_bundle",appBundle)
                    .put("explicit_reviewed_cross_epoch_resume",crossEpoch).put("installed_helper_updated",false)
                    .put("foreground_service_reconciled_canonical_owner",true).put("retired_owner_cache_invalidated",true)
                    .put("old_physical_administrator_cache_retired",true).put("authority_reconciliation_checkpoint_persisted",true)
                    .put("imported_client_ciphertext_unchanged",true).put("ssh_aliases_unchanged",true)
                    .put("server_users_and_identity_unchanged",true).put("separate_app_updated_client_https_exit_dns_ipv6",true)
                    .put("ipv6_positive_underlay_qualification",false).put("canonical_catalog_handed_off",true));
                f.receipt("entry-accepted-reconciled-owner-private.json",new JSONObject().put("gateway",owner.persisted()));
            }
        } finally {
            NativeVpn.disconnect(context,"awg");
            long off=SystemClock.elapsedRealtime()+15000;
            while(NativeVpn.status(context,"awg").active(client.get("id"))&&SystemClock.elapsedRealtime()<off)Thread.sleep(100);
            store.remove(client.get("id"));
            if(!launched){vault.write(original);if(ownerBytes==null)store.remove(ownerId);else PrivateAdministrationFixture.atomic(ownerFile,ownerBytes);}
            // Never overwrite a running coordinator or restore a retired endpoint after a real acceptance.
            // The operator receives the canonical catalog; a failed resumed job retains its durable checkpoint.
            if(completed&&!DeploymentService.active())DeploymentService.forget(context,stale);
        }
    }

    /** Explicit disposable-fixture recovery, after the actual accepted server
     * journal/identities were verified above. Never a product startup fallback. */
    private static void recoverVerifiedCatalogForFixture(PrivateAdministrationFixture f,Vault vault)throws Exception {
        assertTrue("Authorize this known corrupted emulator baseline only",f.request.getBoolean("disposable"));
        String operation=f.request.getJSONObject("pair").getJSONObject("entryMigration").getString("operation");assertTrue(InputRules.job(operation));
        File current=f.file("gateways.enc"),known=f.file("entry-reconcile-backup-"+operation+"/gateways.enc"),receipt=f.file("verified-catalog-recovery-"+operation+".json");
        assertFalse("Keep the existing recovery receipt; inspect before resuming",receipt.exists());
        byte[] damaged=Files.readAllBytes(current.toPath()),backup=Files.readAllBytes(known.toPath()),clear=null;
        try{
            assertEquals("The captured failed catalog differs",f.request.getString("failed_catalog_sha256"),PrivateAdministrationFixture.hash(damaged));
            assertEquals("The independently authenticated backup differs",f.request.getString("verified_catalog_backup_sha256"),PrivateAdministrationFixture.hash(backup));
            assertTrue(damaged.length<=VaultCipher.MAX_BYTES&&backup.length<=VaultCipher.MAX_BYTES);
            java.security.KeyStore keys=java.security.KeyStore.getInstance("AndroidKeyStore");keys.load(null);assertTrue(keys.containsAlias("rookstride.gateway.v1"));
            javax.crypto.SecretKey key=(javax.crypto.SecretKey)keys.getKey("rookstride.gateway.v1",null);
            try{VaultCipher.decrypt("gateways.enc",damaged,key);fail("The declared failed ciphertext unexpectedly authenticated");}catch(javax.crypto.AEADBadTagException expected){}
            clear=VaultCipher.decrypt("gateways.enc",backup,key);JSONArray values=new JSONArray(new String(clear,StandardCharsets.UTF_8));ArrayList<Gateway> restored=new ArrayList<>();for(int i=0;i<values.length();i++)restored.add(new Gateway(values.getJSONObject(i)));
            Gateway owner=find(restored,f.request.getString("owner_catalog_id"));assertEquals(f.request.getJSONObject("pair").getString("pairId"),owner.get("pairId"));
            vault.write(restored);assertEquals(restored.size(),vault.read().size());byte[] sealed=Files.readAllBytes(current.toPath());assertEquals("ROOKVLT2",new String(sealed,0,8,StandardCharsets.US_ASCII));
            f.receipt(receipt.getName(),new JSONObject().put("verified_backup_authenticated",true).put("failed_ciphertext_preserved_in_host_evidence",true).put("remote_accepted_journal_verified_before_local_recovery",true).put("new_envelope_read_back",true).put("restored_records",restored.size()).put("source_backup_sha256",PrivateAdministrationFixture.hash(backup)).put("new_ciphertext_sha256",PrivateAdministrationFixture.hash(sealed)));
        }finally{java.util.Arrays.fill(damaged,(byte)0);java.util.Arrays.fill(backup,(byte)0);if(clear!=null)java.util.Arrays.fill(clear,(byte)0);}
    }
    private static DeploymentService.Session awaitService(Gateway node,int minutes)throws Exception {
        long until=SystemClock.elapsedRealtime()+minutes*60_000L;
        while(SystemClock.elapsedRealtime()<until){DeploymentService.Session session=DeploymentService.current();
            if(session!=null&&session.node==node&&!session.progress.state.equals("running"))return session;
            Thread.sleep(250);
        }
        throw new AssertionError("The exact resumed operation is still pending; preserve its checkpoint and do not stage another migration");
    }
    private static String assetHash(Context context,String name)throws Exception {
        java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
        try(InputStream in=context.getAssets().open(name)){byte[] buffer=new byte[65536];int read;while((read=in.read(buffer))!=-1)digest.update(buffer,0,read);}
        StringBuilder value=new StringBuilder();for(byte b:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();
    }
    private static String sourceBundleDigest(Context context)throws Exception {
        // Same canonical path/content order as pair.source_digest, independent of ZIP timestamps.
        java.util.TreeMap<String,byte[]> entries=new java.util.TreeMap<>();long total=0;
        try(java.util.zip.ZipInputStream zip=new java.util.zip.ZipInputStream(context.getAssets().open("gateway_bundle.zip"))){
            java.util.zip.ZipEntry entry;while((entry=zip.getNextEntry())!=null){String name=entry.getName();
                if(entry.isDirectory()||name.contains("/__pycache__/")||name.endsWith(".pyc")||!(name.startsWith("server/")||name.startsWith("twohop/")||name.startsWith("gateway/")||name.startsWith("single/")))continue;
                assertFalse("Unexpected duplicate packaged path",entries.containsKey(name));
                java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();byte[] buffer=new byte[65536];int read;
                while((read=zip.read(buffer))!=-1){total+=read;assertTrue("Unexpected gateway source size",total<=128L*1024*1024);out.write(buffer,0,read);}entries.put(name,out.toByteArray());
            }
        }
        assertTrue("Missing packaged lifecycle source",entries.containsKey("server/entry_migration.py"));
        java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
        for(String folder:new String[]{"server/","twohop/","gateway/","single/"})for(java.util.Map.Entry<String,byte[]> entry:entries.entrySet())if(entry.getKey().startsWith(folder)){digest.update(entry.getKey().getBytes(StandardCharsets.UTF_8));digest.update(entry.getValue());}
        StringBuilder value=new StringBuilder();for(byte b:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();
    }
    private static void verifyInstalledEpoch(Gateway node,Gateway relay,String deployment,String role,String expected)throws Exception {
        String code="import json; m=json.load(open('/etc/rookstride-pair/manifest.json')); print(json.dumps({'bundle':m['bundle'],'deployment':m['plan']['pair'],'role':m['plan']['role']}))";
        try(Ssh ssh=PairSsh.connectNode(node,relay,QUIET)){
            String prefix=ssh.execute("id -u",null).trim().equals("0")?"":"sudo -n ";
            JSONObject installed=new JSONObject(ssh.execute(prefix+"python3 -c "+InputRules.quote(code),null));
            assertEquals("The installed helper epoch was not reviewed",expected,installed.getString("bundle"));
            assertEquals(deployment,installed.getString("deployment"));assertEquals(role,installed.getString("role"));
        }
    }
    private static JSONObject status(PrivateAdministrationFixture f,Gateway old,JSONObject op)throws Exception {
        try(Ssh ssh=PairSsh.connectNode(old,old.exit,QUIET);InputStream bundle=f.context.getAssets().open("gateway_bundle.zip")){
            return ssh.entryMigration(bundle,new JSONObject().put("action","status").put("deployment",op.getString("deployment")).put("operation",op.getString("operation")));
        }
    }
    private static void assertAccepted(JSONObject status,JSONObject operation)throws Exception {
        assertEquals("accepted",status.getString("state"));assertEquals(operation.getString("operation"),status.getString("operation"));
        assertEquals(operation.getString("deployment"),status.getString("deployment"));assertEquals(operation.getInt("expected_revision"),status.getInt("expected_revision"));
        assertTrue(status.getBoolean("client_update_required"));assertTrue(status.getString("endpoint").equals(operation.getJSONObject("candidate").getString("host")));
    }
    private static void verifyCanonical(PrivateAdministrationFixture f,Gateway pair,JSONObject operation)throws Exception {
        JSONObject live=LifecycleController.inspect(pair,()->f.context.getAssets().open("gateway_bundle.zip"),QUIET);
        assertFalse("Current topology must pass ownership inspection",live.getBoolean("read_only"));
        assertEquals(operation.getInt("expected_revision")+1,live.getInt("revision"));
        assertEquals(live.getInt("revision"),live.getJSONObject("exit").getInt("revision"));
        assertTrue("The live canonical endpoint differs from the accepted candidate",live.getJSONObject("entry").getJSONObject("plan").getString("server").equals(pair.get("vpnServer")));
        assertTrue("The candidate physical server differs",live.getJSONObject("probes").getJSONObject("entry").getString("machine").equals(pair.get("machine")));
    }
    private static JSONObject identityReceipts(PrivateAdministrationFixture f,Gateway old,Gateway candidate,Gateway exit)throws Exception {
        JSONObject receipt=new JSONObject();Gateway[] nodes={old,candidate,exit};String[] roles={"retired","candidate","exit"};
        for(int i=0;i<nodes.length;i++)try(Ssh ssh=PairSsh.connectNode(nodes[i],i==2?candidate:exit,QUIET);InputStream bundle=f.context.getAssets().open("gateway_bundle.zip")){
            JSONObject snapshot=ssh.recovery(bundle,new JSONObject().put("action","export"));
            receipt.put(roles[i],new JSONObject().put("state_sha256",PrivateAdministrationFixture.hash(canonical(snapshot.getJSONObject("state"))))
                .put("identity_sha256",PrivateAdministrationFixture.hash(canonical(snapshot.get("identity_files")))));
        }return receipt;
    }
    private static void unchangedOthers(ArrayList<Gateway> before,ArrayList<Gateway> after,String owner)throws Exception {
        assertEquals(before.size(),after.size());for(Gateway node:before)if(!node.get("id").equals(owner))
            assertTrue("An unrelated catalog record or SSH alias changed",canonical(node.persisted()).equals(canonical(find(after,node.get("id")).persisted())));
    }
    private static Gateway find(ArrayList<Gateway> nodes,String id){for(Gateway node:nodes)if(node.get("id").equals(id))return node;throw new AssertionError("The explicitly selected phone record is missing");}
    private static boolean sameEndpoint(Gateway a,Gateway b){return a!=null&&b!=null&&ServerIdentityPins.sameEndpoint(a,b)&&a.get("fingerprint").equals(b.get("fingerprint"))&&a.get("machine").equals(b.get("machine"));}
    private static boolean awgEndpoint(String content,String host){return java.util.regex.Pattern.compile("(?m)^Endpoint\\s*=\\s*"+java.util.regex.Pattern.quote(host)+":[0-9]+\\s*$").matcher(content).find();}
    private static File profileFile(Context context,String id){assertTrue("Invalid private profile identifier",id.matches("[a-fA-F0-9-]{36}"));return new File(new File(context.getNoBackupFilesDir(),"vpn-profiles"),id+".enc");}
    private static byte[] optionalBytes(File file)throws Exception{return file.isFile()?Files.readAllBytes(file.toPath()):null;}
    private static void backup(Context context,File directory,String name)throws Exception{File from=new File(context.getFilesDir(),name);if(from.isFile())PrivateAdministrationFixture.atomic(new File(directory,name),Files.readAllBytes(from.toPath()));}
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    private static String canonical(Object value)throws Exception {
        if(value instanceof JSONObject){JSONObject object=(JSONObject)value;ArrayList<String> names=new ArrayList<>();Iterator<String> keys=object.keys();while(keys.hasNext())names.add(keys.next());Collections.sort(names);StringBuilder out=new StringBuilder("{");for(String key:names){if(out.length()>1)out.append(',');out.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray array=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<array.length();i++){if(i>0)out.append(',');out.append(canonical(array.get(i)));}return out.append(']').toString();}
        if(value==null||value==JSONObject.NULL)return "null";
        if(value instanceof String)return JSONObject.quote((String)value);
        if(value instanceof Number||value instanceof Boolean)return value.toString();
        throw new IllegalArgumentException("Unsupported JSON value");
    }
}
