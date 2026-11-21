package org.strongswan.android.rookstride;

import android.content.Intent;
import android.os.SystemClock;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import org.strongswan.android.rookstride.engine.AdminSocketFactory;
import org.json.*;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.RunWith;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Separately authorized original and fresh sole-relay invocations. No fixture or opt-in means no network calls.
 * The real foreground service/controller runs; only a post-save observer pauses it. */
@RunWith(AndroidJUnit4.class)
public final class PairedOsRestoreIntegrationTest {
    private static final String META="privatePairedRestoreTest",ARCHIVE="paired-restore-private.rookrecovery",RESULT="paired-restore-checks-result.json";
    private static final PairController.Progress QUIET=phase->{};
    private static final class ReviewedPause extends IOException {ReviewedPause(){super("Provider acceptance paused after the first verified server; resume the same recorded jobs.");}}


    /** Test transport failure only; SSH forwarding, host trust and root authentication stay real. */
    private SoleRelayProof soleRelay;
    /** Observation only: every production source method delegates unchanged. */
    private static final class ArtifactRouteObservation implements ArtifactBridge.Source {
        final ArtifactBridge.Source original;final AtomicInteger phoneTransports=new AtomicInteger();
        ArtifactRouteObservation(ArtifactBridge.Source original){this.original=original;}
        public PublicArtifactCatalog catalog()throws Exception{return original.catalog();}
        public InputStream openBundle()throws Exception{return original.openBundle();}
        public File cacheDirectory()throws Exception{return original.cacheDirectory();}
        public ArtifactDownloader.Transport transport()throws Exception{phoneTransports.incrementAndGet();return original.transport();}
    }
    @Rule public final TestRule soleRelayCleanup=(base,description)->new Statement(){
        @Override public void evaluate()throws Throwable{
            try{base.evaluate();if(soleRelay!=null)soleRelay.success();}
            finally{if(soleRelay!=null)soleRelay.close();}
        }
    };
    private final class SoleRelayProof {
        final PrivateAdministrationFixture fixture;final String action,entryHost,exitHost;final int entryPort,exitPort;
        final AtomicInteger blockedExit=new AtomicInteger(),realEntry=new AtomicInteger(),otherDirect=new AtomicInteger();
        final com.jcraft.jsch.SocketFactory factory,previous;String operation="";
        final ArtifactBridge.Source previousArtifacts;final ArtifactRouteObservation artifactObservation;
        SoleRelayProof(PrivateAdministrationFixture f,String action)throws Exception{
            fixture=f;this.action=action;
            assertTrue("Sole-relay acceptance is limited to fresh preparation and recorded continuations",Arrays.asList("paired-sole-relay-prepare-pause","paired-sole-relay-recover-first","paired-sole-relay-resume","paired-sole-relay-resume-restore","paired-sole-relay-completed-resume").contains(action));
            assertFalse("This gate must not reinterpret a previous application's OS job",f.request.optBoolean("allow_recorded_job_apk_migration"));
            assertEquals("Bind the actual reviewed test package",f.request.getString("expected_test_apk_sha256"),f.binary.getString("test_apk_sha256"));
            Gateway selected=f.pair();entryHost=selected.get("host");exitHost=selected.exit.get("host");entryPort=selected.port();exitPort=selected.exit.port();
            assertFalse("Fixture endpoints must differ",entryHost.equals(exitHost));
            assertEquals("Review Automatic management before this test; do not silently override a route","auto",selected.get("sshRoute"));
            previous=Ssh.socketFactory;assertTrue("Another SSH socket fixture is active",previous==null||previous instanceof AdminSocketFactory);OsWipeNetwork.requireDirect(f.context);
            factory=new com.jcraft.jsch.SocketFactory(){
                public java.net.Socket createSocket(String host,int port)throws IOException{
                    if(exitHost.equals(host)&&exitPort==port){blockedExit.incrementAndGet();throw new java.net.ConnectException("Reviewed direct exit path is unavailable");}
                    boolean entry=entryHost.equals(host)&&entryPort==port;if(!entry)otherDirect.incrementAndGet();
                    if(previous!=null){java.net.Socket socket=previous.createSocket(host,port);if(entry)realEntry.incrementAndGet();return socket;}
                    java.net.Socket socket=new java.net.Socket();try{socket.connect(new java.net.InetSocketAddress(host,port),12000);if(entry)realEntry.incrementAndGet();return socket;}catch(IOException e){try{socket.close();}catch(IOException ignored){}throw e;}
                }
                public InputStream getInputStream(java.net.Socket socket)throws IOException{return previous==null?socket.getInputStream():previous.getInputStream(socket);}
                public OutputStream getOutputStream(java.net.Socket socket)throws IOException{return previous==null?socket.getOutputStream():previous.getOutputStream(socket);}
            };
            Object observe=f.request.opt("observe_artifact_routes");assertTrue("Artifact observation must be an explicit boolean",observe==null||observe instanceof Boolean);
            previousArtifacts=Ssh.artifactSource;
            if(Boolean.TRUE.equals(observe)){
                assertNotNull("The actual app artifact source is required",previousArtifacts);
                assertFalse("Another artifact observer is still active",previousArtifacts instanceof ArtifactRouteObservation);
                artifactObservation=new ArtifactRouteObservation(previousArtifacts);
            }else artifactObservation=null;
            Ssh.socketFactory=factory;if(artifactObservation!=null)Ssh.artifactSource=artifactObservation;
        }
        JSONObject identity()throws Exception{return new JSONObject().put("schema",1).put("scenario","direct-exit-unreachable").put("apk_sha256",fixture.binary.getString("apk_sha256")).put("test_apk_sha256",fixture.binary.getString("test_apk_sha256")).put("entry_host",entryHost).put("entry_port",entryPort).put("exit_host",exitHost).put("exit_port",exitPort).put("observe_artifact_routes",artifactObservation!=null);}
        void metadata(JSONObject metadata)throws Exception{
            JSONObject bound=metadata.getJSONObject("sole_relay_test"),expected=identity();
            for(String key:new String[]{"schema","scenario","apk_sha256","test_apk_sha256","entry_host","entry_port","exit_host","exit_port"})assertEquals("Sole-relay fixture identity changed",expected.get(key),bound.get(key));
            assertEquals("Continue with the same reviewed artifact observation",expected.optBoolean("observe_artifact_routes"),bound.optBoolean("observe_artifact_routes"));
            review(null,metadata.getJSONObject("reviewed"));
        }
        void review(Gateway pair,JSONObject plan)throws Exception{
            assertSame("The exit-path fault was removed before the durable phase",factory,Ssh.socketFactory);
            if(artifactObservation!=null)assertSame("The artifact observer changed during this phase",artifactObservation,Ssh.artifactSource);
            assertEquals("exit-via-entry",plan.getString("route"));assertEquals(2,plan.getJSONArray("order").length());assertEquals("exit",plan.getJSONArray("order").getString(0));assertEquals("entry",plan.getJSONArray("order").getString(1));
            if(!operation.isEmpty())assertEquals("A different erase operation was substituted",operation,plan.getString("operation"));operation=plan.getString("operation");
            if(pair!=null){assertEquals("auto",pair.get("sshRoute"));assertEquals("exit-via-entry",pair.get("resolvedSshRoute"));assertEquals(entryHost,pair.get("host"));assertEquals(entryPort,pair.port());assertEquals(exitHost,pair.exit.get("host"));assertEquals(exitPort,pair.exit.port());}
        }
        void success()throws Exception{
            assertFalse("The sole-relay phase has not stopped",DeploymentService.active());
            Gateway saved=fixture.savedPair(new Vault(fixture.context).read());JSONObject meta=saved.data.getJSONObject(META);metadata(meta);
            JSONObject plan=saved.data.optJSONObject("pairedOsOperation");if(plan==null)plan=saved.data.getJSONObject("lastPairedOsOperation");review(saved,plan);
            assertTrue("No direct-exit failure was exercised",blockedExit.get()>0);assertTrue("No real entry SSH socket was opened",realEntry.get()>0);assertEquals("An unexpected direct SSH endpoint was used",0,otherDirect.get());
            fixture.receipt("sole-relay-"+operation+"-"+action+"-"+System.currentTimeMillis()+"-private.json",new JSONObject().put("operation",operation).put("route",plan.getString("route")).put("order",plan.getJSONArray("order")).put("phase",plan.getString("phase")).put("blocked_direct_exit_sockets",blockedExit.get()).put("real_entry_sockets",realEntry.get()).put("unexpected_direct_sockets",otherDirect.get()).put("underlying_vpn_disabled",true).put("existing_owner_aliases_checked",meta.getJSONObject("aliases").length()).put("host_trust_and_root_authentication_unmodified",true).put("simulated_phone_path_failure_only",true).put("artifact_routes_observed",artifactObservation!=null).put("phone_https_transport_requests",artifactObservation==null?JSONObject.NULL:artifactObservation.phoneTransports.get()).put("peer_origin_proven_by_counter_alone",false));
            if(artifactObservation!=null)assertEquals("This peer-route gate used phone HTTPS; retain the receipt and inspect cache/source evidence",0,artifactObservation.phoneTransports.get());
        }
        void close()throws Exception{
            long deadline=SystemClock.elapsedRealtime()+20000;
            while(DeploymentService.active()&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
            // Do not reopen the direct path underneath a still-running destructive worker.
            assertFalse("Worker remains active; retain the fault and resume its recorded jobs after review",DeploymentService.active());
            assertSame("Another test replaced the sole-relay fault",factory,Ssh.socketFactory);
            if(artifactObservation!=null){assertSame("Another test replaced the artifact observer",artifactObservation,Ssh.artifactSource);Ssh.artifactSource=previousArtifacts;}
            Ssh.socketFactory=previous;
        }
    }

    @Test public void captureReviewAndPauseAfterOnlyTheFirstServerIsVerified()throws Exception {prepareAndPause(false);}
    @Test public void completedCycleCanBeRebuiltAgainOnlyAfterUnchangedClientProof()throws Exception {prepareAndPause(true);}
    private void prepareAndPause(boolean repeat)throws Exception {
        PrivateAdministrationFixture f=fixture(repeat?"paired-repeat-prepare-pause":"paired-prepare-pause");Gateway pair=f.pair();
        assertTrue("This wipe also erases coexisting VPNs; only the selected pair returns",f.request.optBoolean("acknowledge_pair_only_restore"));
        assertFalse("Resume the recorded operation instead",pair.data.has("pairedOsOperation"));
        ArrayList<Gateway> nodes=new Vault(f.context).read();
        String previousProfile="",previousOperation="";
        if(soleRelay!=null){
            assertFalse("A sole-relay cycle is fresh, never the historical repeat action",repeat);
            Gateway saved=f.savedPair(nodes);assertFalse("Resume the recorded operation instead",saved.data.has("pairedOsOperation"));
            for(String role:new String[]{"entry","exit"}){Gateway selected=part(pair,role),actual=part(saved,role);assertEquals(selected.get("id"),actual.get("id"));assertTrue(ServerIdentityPins.sameEndpoint(selected,actual));assertEquals(selected.get("fingerprint"),actual.get("fingerprint"));}
            assertEquals("Review Automatic management on the actual saved pair","auto",saved.get("sshRoute"));pair=saved;
            assertTrue("Keep the actual saved pre-wipe profile",new NativeProfileStore(f.context).exists(pair.get("id")));
        }else if(repeat){
            assertTrue("A fresh second cycle needs separate authorization",f.request.optBoolean("allow_paired_os_repeat"));assertTrue("Complete independent unchanged-client proof before another cycle",f.request.optBoolean("previous_cycle_client_traffic_verified"));
            Gateway saved=f.savedPair(nodes);JSONObject prior=metadata(f,saved);assertTrue(prior.has("completed_boots"));assertEquals("restored",saved.data.getJSONObject("lastPairedOsOperation").getString("phase"));assertFalse(saved.data.has("pairedOsOperation"));
            previousOperation=saved.data.getJSONObject("lastPairedOsOperation").getString("operation");assertEquals(f.request.getString("previous_cycle_operation"),previousOperation);previousProfile=prior.getString("profile_sha256");assertEquals(f.request.getString("previous_profile_sha256"),previousProfile);
            JSONObject phoneProof=new JSONObject(new String(Files.readAllBytes(f.file("paired-native-traffic-result.json").toPath()),java.nio.charset.StandardCharsets.UTF_8));assertTrue(phoneProof.getBoolean("live_client_traffic_tested"));assertEquals(previousOperation,phoneProof.getString("operation"));assertEquals(previousProfile,phoneProof.getString("original_profile_sha256"));
            for(Gateway record:nodes){assertFalse("A separate imported profile is outside this repeat fixture",record.data.optBoolean("clientOnly"));assertTrue("An unrelated server is outside this repeat fixture",ServerIdentityPins.sameEndpoint(record,pair)||ServerIdentityPins.sameEndpoint(record,pair.exit));}
            assertEquals(pair.get("fingerprint"),saved.get("fingerprint"));assertEquals(pair.exit.get("fingerprint"),saved.exit.get("fingerprint"));pair=saved;
            PrivateAdministrationFixture.atomic(f.file("previous-cycle-private.rookrecovery"),Files.readAllBytes(f.file(ARCHIVE).toPath()));
        }else assertTrue("Use a dedicated cleared app: old server records must not be mixed into this provider fixture",nodes.isEmpty());
        for(Gateway node:new Gateway[]{pair,pair.exit}){assertFalse("OS replacement requires the real root password",node.sshPassword.isEmpty());assertTrue("Do not use an SSH key passphrase as the root password",node.privateKey.isEmpty());node.data.put("remember",true).put("saveAccessChosen",true);new ServerIdentityPins(f.context).remember(node,node.get("fingerprint"));}
        JSONObject aliases=new JSONObject();
        if(soleRelay==null)for(String role:new String[]{"entry","exit"}){Gateway node=part(pair,role);String oldId=f.request.getString(role.equals("entry")?"entry_admin_server_id":"exit_admin_server_id");assertFalse(oldId.isEmpty());node.set("adminServerId",oldId);node.set("adminDeploymentId",pair.get("pairId"));node.data.put("adminEnabled",true).put("adminSnapshot",new JSONObject().put("fixture_cache",true));Gateway alias=PairNodes.copy(node);PairNodes.clearConnection(alias);alias.set("id",UUID.randomUUID().toString());alias.set("name",role+" owner control alias");nodes.add(alias);aliases.put(role,new JSONObject().put("id",alias.get("id")).put("old_server_id",oldId).put("old_deployment_id",node.get("adminDeploymentId")));}
        OsWipeNetwork.requireDirect(f.context);
        JSONObject baseline=inspect(pair,true);
        // Bind fixture aliases to fresh authenticated observations; an old phone
        // checkpoint may itself predate a previous OS replacement.
        for(String role:new String[]{"entry","exit"}){String machine=baseline.getJSONObject(role).getString("machine");assertTrue(machine.matches("[0-9a-f]{64}"));part(pair,role).set("machine",machine);JSONObject record=aliases.optJSONObject(role);if(record!=null){record.put("old_machine",machine);PairNodes.find(nodes,record.getString("id")).set("machine",machine);}}
        String profile=exportProfile(f,pair);NativeProfileStore profiles=new NativeProfileStore(f.context);
        if(profiles.exists(pair.get("id")))assertTrue("The existing saved profile differs from this fixture user",profile.equals(profiles.read(pair.get("id")).getString("content")));
        else profiles.save(pair.get("id"),"awg",pair.get("name"),profile);
        if(repeat)assertEquals("A repeated cycle must retain the exact original phone profile",previousProfile,PrivateAdministrationFixture.hash(profile));
        JSONObject archive=OwnerRecovery.capture(pair,()->f.context.getAssets().open("gateway_bundle.zip"),QUIET);char[] password=f.request.getString("recovery_password").toCharArray();byte[] encrypted;
        try{encrypted=OwnerRecovery.encrypt(archive,password);}finally{Arrays.fill(password,'\0');}
        if(soleRelay!=null&&f.file(ARCHIVE).isFile()){
            String prior=PrivateAdministrationFixture.hash(f.file(ARCHIVE));File retained=f.file("paired-restore-before-sole-relay-"+prior+".rookrecovery");
            if(!retained.exists())Files.copy(f.file(ARCHIVE).toPath(),retained.toPath());assertEquals("Preserve the previous encrypted archive",prior,PrivateAdministrationFixture.hash(retained));
        }
        try{PrivateAdministrationFixture.atomic(f.file(ARCHIVE),encrypted);}finally{Arrays.fill(encrypted,(byte)0);}
        archive=decrypt(f,pair);rejectDamagedArchivesBeforeErase(pair,archive);assertFalse(OwnerRecovery.rehearse(pair,archive,()->f.context.getAssets().open("gateway_bundle.zip"),QUIET).getBoolean("live_restore_tested"));
        String entryVersion=f.request.getString("entry_version"),exitVersion=f.request.getString("exit_version");assertTrue(Arrays.asList("22.04","26.04").contains(entryVersion));assertTrue(Arrays.asList("22.04","26.04").contains(exitVersion));assertFalse("Use independently selected mixed versions",entryVersion.equals(exitVersion));
        JSONObject plan=PairedOsReinstall.prepareRestore(pair,entryVersion,exitVersion,true,archive,()->f.context.getAssets().open("reinstall_bundle.zip"),()->f.context.getAssets().open("gateway_bundle.zip"),QUIET);
        if(soleRelay!=null)soleRelay.review(pair,plan);
        for(String role:new String[]{"entry","exit"})assertFalse("A fresh planned SSH identity is required",plan.getJSONObject("plans").getJSONObject(role).getString("fingerprint").equals(baseline.getJSONObject(role).getString("fingerprint")));
        JSONObject meta=new JSONObject().put("binary",f.binary).put("baseline",baseline).put("reviewed",plan).put("profile_sha256",PrivateAdministrationFixture.hash(profile)).put("login",pair.get("vpnLogin")).put("profile_uuid",pair.get("profileUuid")).put("aliases",aliases).put("previous_cycle_operation",previousOperation);
        if(soleRelay!=null)meta.put("sole_relay_test",soleRelay.identity());
        pair.data.put(META,meta);String pairRecordId=pair.get("id");nodes.removeIf(node->node.get("id").equals(pairRecordId));nodes.add(pair);new Vault(f.context).write(nodes);
        pauseAndVerify(f,pair,nodes,plan,meta,false,archive);
    }

    @Test public void interruptedFirstServerResumesItsExistingJobAndPausesBeforeTheSecondErase()throws Exception{
        PrivateAdministrationFixture f=fixture("paired-recover-first");ArrayList<Gateway> nodes=new Vault(f.context).read();Gateway pair=f.savedPair(nodes);JSONObject meta=metadata(f,pair),plan=pair.data.getJSONObject("pairedOsOperation");
        assertEquals("This action is only for the interrupted first job",0,plan.getJSONArray("verified").length());assertFalse(meta.optBoolean("paused_after_verified"));assertSameJobs(meta.getJSONObject("reviewed"),plan);
        pauseAndVerify(f,pair,nodes,plan,meta,true,decrypt(f,pair));
    }

    private void pauseAndVerify(PrivateAdministrationFixture f,Gateway pair,ArrayList<Gateway> nodes,JSONObject plan,JSONObject meta,boolean resume,JSONObject archive)throws Exception{
        JSONObject baseline=meta.getJSONObject("baseline");
        AtomicBoolean paused=new AtomicBoolean();DeploymentService.CheckpointObserver previous=DeploymentService.checkpointObserver;
        try{
            assertNull("Another checkpoint observer is active",previous);
            DeploymentService.checkpointObserver=session->{f.checkpoint(session.node);JSONObject operation=session.node.data.optJSONObject("pairedOsOperation");if(session.node.get("id").equals(pair.get("id"))&&operation!=null&&operation.getJSONArray("verified").length()==1&&operation.getString("phase").equals("verified-"+operation.getJSONArray("order").getString(0))){paused.set(true);throw new ReviewedPause();}};
            DeploymentService.Session stopped=runService(f,pair,nodes,plan,resume,archive,true);if(!paused.get())throw new AssertionError("The exact durable checkpoint was not reached; resume the recorded jobs",stopped.error);assertTrue("An unexpected failure interrupted the job",stopped.error instanceof ReviewedPause);assertEquals("needs-attention",stopped.progress.state);
        }finally{DeploymentService.checkpointObserver=previous;}
        nodes=new Vault(f.context).read();Gateway saved=f.savedPair(nodes);JSONObject operation=saved.data.getJSONObject("pairedOsOperation");assertSameJobs(meta.getJSONObject("reviewed"),operation);
        assertEquals(1,operation.getJSONArray("verified").length());String first=operation.getJSONArray("order").getString(0),second=operation.getJSONArray("order").getString(1);JSONObject actual=inspect(saved,false);
        verifyReturned(f,saved,first,operation,actual);assertEquals("Untouched server machine identity changed",baseline.getJSONObject(second).getString("machine"),actual.getJSONObject(second).getString("machine"));assertEquals("The second server rebooted before explicit resume",baseline.getJSONObject(second).getString("boot_id"),actual.getJSONObject(second).getString("boot_id"));
        assertEquals(baseline.getJSONObject(second).getString("version"),actual.getJSONObject(second).getString("version"));assertEquals(baseline.getJSONObject(second).getString("fingerprint"),part(saved,second).get("fingerprint"));assertTrue("The second disk's canary disappeared",actual.getJSONObject(second).getBoolean("canary"));JSONObject secondRecorded=part(saved,second).data.optJSONObject("osReinstall");assertTrue("The second erase was started",secondRecorded==null||!secondRecorded.optString("job").equals(operation.getJSONObject("plans").getJSONObject(second).getString("job")));
        verifyAlias(f,saved,nodes,first,true);verifyAlias(f,saved,nodes,second,false);
        saved.data.getJSONObject(META).put("paused_first",first).put("first_return_boot",actual.getJSONObject(first).getString("boot_id")).put("paused_after_verified",true);new Vault(f.context).write(nodes);f.checkpoint(saved);
        f.receipt(RESULT,new JSONObject().put("phase","paused-after-first-verified").put("first_role",first).put("second_disk_unchanged",true).put("checkpoint_saved_before_pause",true).put("first_alias_pin_and_admin_identity_advanced",meta.getJSONObject("aliases").has(first)).put("first_owner_and_alias_machine_verified",meta.getJSONObject("aliases").has(first)).put("second_alias_unchanged",meta.getJSONObject("aliases").has(second)).put("archive_encrypted_and_rehearsed",true).put("invalid_archives_rejected_before_erase",true).put("operation_started_binary",meta.getJSONObject("binary")).put("profile_sha256",meta.getString("profile_sha256")));
    }

    @Test public void resumeTheSameJobsAndRestoreTheUnchangedSavedProfile()throws Exception {
        PrivateAdministrationFixture f=fixture("paired-resume");ArrayList<Gateway> nodes=new Vault(f.context).read();Gateway pair=f.savedPair(nodes);JSONObject meta=metadata(f,pair),operation=pair.data.getJSONObject("pairedOsOperation");
        assertTrue("Run the explicit first-node pause before this action",meta.getBoolean("paused_after_verified"));assertEquals(1,operation.getJSONArray("verified").length());assertSameJobs(meta.getJSONObject("reviewed"),operation);
        DeploymentService.CheckpointObserver previous=DeploymentService.checkpointObserver;try{assertNull(previous);DeploymentService.checkpointObserver=session->f.checkpoint(session.node);DeploymentService.Session done=runService(f,pair,nodes,operation,true,decrypt(f,pair),true);requireComplete(done);}finally{DeploymentService.checkpointObserver=previous;}
        nodes=new Vault(f.context).read();pair=f.savedPair(nodes);verifyRestored(f,pair);
        JSONObject current=inspect(pair,false);assertEquals("The verified first node was wiped again on resume",meta.getString("first_return_boot"),current.getJSONObject(meta.getString("paused_first")).getString("boot_id"));
        pair.data.getJSONObject(META).put("completed_boots",current);new Vault(f.context).write(nodes);f.checkpoint(pair);
        f.receipt(RESULT,new JSONObject().put("phase","restored").put("same_recorded_jobs",true).put("entry_version",meta.getJSONObject("reviewed").getJSONObject("plans").getJSONObject("entry").getString("version")).put("exit_version",meta.getJSONObject("reviewed").getJSONObject("plans").getJSONObject("exit").getString("version")).put("planned_pins_verified",true).put("owner_and_alias_machine_identities_verified",meta.getJSONObject("aliases").length()==2).put("saved_profile_unchanged",true).put("operation_started_binary",meta.getJSONObject("binary")).put("profile_sha256",meta.getString("profile_sha256")).put("administrator_grants_restored",false).put("live_client_traffic_tested",false));
    }

    /** Recovery after both disks returned but VPN bootstrap/filtering failed.
     * This action cannot prepare new jobs or return to either disk's erase path. */
    @Test public void bothVerifiedServersResumeOnlyTheRecordedVpnRestoration()throws Exception {
        PrivateAdministrationFixture f=fixture("paired-resume-restore");ArrayList<Gateway> nodes=new Vault(f.context).read();Gateway pair=f.savedPair(nodes);JSONObject meta=metadata(f,pair),operation=pair.data.getJSONObject("pairedOsOperation"),reviewed=meta.getJSONObject("reviewed");
        assertEquals("Only the originally recorded app may resume this restoration",f.binary.getString("apk_sha256"),meta.getJSONObject("binary").getString("apk_sha256"));
        assertEquals("This action is only for interrupted VPN restoration","restoring-vpn",operation.getString("phase"));assertEquals("restore",operation.getString("mode"));assertEquals(pair.get("pairId"),operation.getString("deployment"));assertSameJobs(reviewed,operation);
        JSONArray verified=operation.getJSONArray("verified"),order=operation.getJSONArray("order");assertEquals("Both OS returns must already be durably verified",2,verified.length());assertEquals(2,order.length());Set<String> roles=new HashSet<>();for(int i=0;i<2;i++){assertEquals("Verified-node order changed",order.getString(i),verified.getString(i));roles.add(verified.getString(i));}assertEquals(new HashSet<>(Arrays.asList("entry","exit")),roles);
        assertTrue("The original first-node pause proof is required",meta.getBoolean("paused_after_verified"));String first=meta.getString("paused_first");assertEquals(order.getString(0),first);
        assertEquals("OS completion did not retain the reviewed revision",operation.getInt("expected_revision")+1,pair.data.getInt("deploymentRevision"));
        JSONObject archive=decrypt(f,pair);String archiveHash=PrivateAdministrationFixture.hash(f.file(ARCHIVE));assertEquals("The retained archive differs from the reviewed recovery package",operation.getString("recovery_digest"),PrivateAdministrationFixture.hash(archive.toString()));
        final String operationId=operation.getString("operation"),entryJob=operation.getJSONObject("plans").getJSONObject("entry").getString("job"),exitJob=operation.getJSONObject("plans").getJSONObject("exit").getString("job");
        JSONObject before=inspect(pair,false);
        for(String role:new String[]{"entry","exit"}){
            JSONObject planned=operation.getJSONObject("plans").getJSONObject(role);assertEquals("The complete reviewed OS plan changed",PrivateAdministrationFixture.hash(reviewed.getJSONObject("plans").getJSONObject(role).toString()),PrivateAdministrationFixture.hash(planned.toString()));
            verifyReturned(f,pair,role,operation,before);verifyAlias(f,pair,nodes,role,true);JSONObject baseline=meta.getJSONObject("baseline").getJSONObject(role),returned=before.getJSONObject(role);assertNotEquals("The reviewed OS replacement did not reboot the server",baseline.getString("boot_id"),returned.getString("boot_id"));assertNotEquals("The replacement did not use its newly planned SSH identity",baseline.getString("fingerprint"),planned.getString("fingerprint"));assertEquals(planned.getString("version"),returned.getString("version"));assertNotEquals("This mixed-version fixture must change the selected Ubuntu version",baseline.getString("version"),returned.getString("version"));
            assertEquals(planned.getString("job"),part(pair,role).data.getJSONObject("osReinstall").getString("job"));
        }
        assertEquals("The originally verified first node rebooted before restoration-only resume",meta.getString("first_return_boot"),before.getJSONObject(first).getString("boot_id"));
        f.receipt("paired-restore-stage-before.json",new JSONObject().put("phase","restoring-vpn").put("operation",operationId).put("entry_job",entryJob).put("exit_job",exitJob).put("both_os_returns_verified",true).put("observed",before).put("archive_sha256",archiveHash).put("operation_started_binary",meta.getJSONObject("binary")));
        AtomicInteger checkpoints=new AtomicInteger(),rejectedOsCheckpoints=new AtomicInteger();DeploymentService.CheckpointObserver previous=DeploymentService.checkpointObserver;
        try{
            assertNull("Another checkpoint observer is active",previous);
            DeploymentService.checkpointObserver=session->{
                // Production saves reinstalling-* immediately before invoking
                // OsReinstall.run. Refuse that checkpoint in this restore-only
                // action while retaining the actual foreground controller.
                try{
                    assertEquals(pair.get("id"),session.node.get("id"));assertTrue(session.resume);assertEquals("paired-restore",session.progress.kind);JSONObject current=session.node.data.getJSONObject("pairedOsOperation");assertEquals(operationId,current.getString("operation"));assertEquals(entryJob,current.getJSONObject("plans").getJSONObject("entry").getString("job"));assertEquals(exitJob,current.getJSONObject("plans").getJSONObject("exit").getString("job"));assertEquals(2,current.getJSONArray("verified").length());
                    for(int i=0;i<2;i++)assertEquals(order.getString(i),current.getJSONArray("verified").getString(i));assertTrue("Restoration-only resume tried to return to OS replacement",Arrays.asList("restoring-vpn","restored").contains(current.getString("phase")));
                    for(String role:new String[]{"entry","exit"}){Gateway returned=part(session.node,role);assertEquals("complete",returned.get("osReinstallState"));assertEquals(before.getJSONObject(role).getString("machine"),returned.get("machine"));assertEquals(current.getJSONObject("plans").getJSONObject(role).getString("fingerprint"),returned.get("fingerprint"));}
                }catch(AssertionError|JSONException unsafe){rejectedOsCheckpoints.incrementAndGet();throw new IOException("Restoration-only acceptance stopped an unexpected OS/job checkpoint before a reinstall command",unsafe);}
                checkpoints.incrementAndGet();f.checkpoint(session.node);
            };
            DeploymentService.Session done=runService(f,pair,nodes,operation,true,archive,true);requireComplete(done);
        }finally{DeploymentService.checkpointObserver=previous;}
        assertEquals("A disk-replacement checkpoint was reached",0,rejectedOsCheckpoints.get());assertTrue("The restored controller did not save its VPN checkpoints",checkpoints.get()>0);assertEquals("The encrypted recovery archive changed during resume",archiveHash,PrivateAdministrationFixture.hash(f.file(ARCHIVE)));
        nodes=new Vault(f.context).read();Gateway saved=f.savedPair(nodes);verifyRestored(f,saved);JSONObject completed=saved.data.getJSONObject("lastPairedOsOperation"),after=inspect(saved,false);assertSameJobs(reviewed,completed);assertEquals(operationId,completed.getString("operation"));
        for(String role:new String[]{"entry","exit"}){assertEquals("Restoration-only resume rebooted a verified node",before.getJSONObject(role).getString("boot_id"),after.getJSONObject(role).getString("boot_id"));assertEquals("Restoration-only resume changed its completed OS job",before.getJSONObject(role).getString("result_job"),after.getJSONObject(role).getString("result_job"));assertEquals("Restoration-only resume changed the OS machine",before.getJSONObject(role).getString("machine"),after.getJSONObject(role).getString("machine"));assertEquals(before.getJSONObject(role).getString("version"),after.getJSONObject(role).getString("version"));}
        assertEquals("The original first-return boot proof changed",meta.getString("first_return_boot"),after.getJSONObject(first).getString("boot_id"));saved.data.getJSONObject(META).put("completed_boots",after);new Vault(f.context).write(nodes);f.checkpoint(saved);
        f.receipt(RESULT,new JSONObject().put("phase","restored").put("restoration_only_resume",true).put("operation",operationId).put("entry_job",entryJob).put("exit_job",exitJob).put("same_recorded_jobs",true).put("both_os_returns_verified_before_resume",true).put("no_second_erase",true).put("no_server_reboot",true).put("boots_jobs_and_machines_unchanged",true).put("before",before).put("after",after).put("original_first_return_boot_preserved",true).put("planned_pins_verified",true).put("owner_and_alias_machine_identities_verified",meta.getJSONObject("aliases").length()==2).put("saved_profile_unchanged",true).put("archive_sha256",archiveHash).put("restore_checkpoints",checkpoints.get()).put("operation_started_binary",meta.getJSONObject("binary")).put("profile_sha256",meta.getString("profile_sha256")).put("administrator_grants_restored",false).put("live_client_traffic_tested",false));
    }

    @Test public void completedResumeCannotStartAnotherErase()throws Exception {
        PrivateAdministrationFixture f=fixture("paired-completed-resume");ArrayList<Gateway> nodes=new Vault(f.context).read();Gateway pair=f.savedPair(nodes);JSONObject meta=metadata(f,pair),receipt=pair.data.getJSONObject("lastPairedOsOperation");
        assertEquals("restored",receipt.getString("phase"));assertTrue("Complete the restore action first",meta.has("completed_boots"));JSONObject before=inspect(pair,false);
        // Reconstitute the identical final checkpoint, as a crash before UI retirement would.
        pair.data.put("pairedOsOperation",new JSONObject(receipt.toString()));new Vault(f.context).write(nodes);
        AtomicInteger saves=new AtomicInteger();DeploymentService.CheckpointObserver previous=DeploymentService.checkpointObserver;
        try{assertNull(previous);DeploymentService.checkpointObserver=session->saves.incrementAndGet();requireComplete(runService(f,pair,nodes,receipt,true,decrypt(f,pair),false));}finally{DeploymentService.checkpointObserver=previous;}
        assertEquals("A completed controller must not execute another erase checkpoint",0,saves.get());pair=f.savedPair(new Vault(f.context).read());JSONObject after=inspect(pair,false);
        for(String role:new String[]{"entry","exit"}){assertEquals("Completed resume rebooted a server",before.getJSONObject(role).getString("boot_id"),after.getJSONObject(role).getString("boot_id"));assertEquals("Completed resume changed the OS job",before.getJSONObject(role).getString("result_job"),after.getJSONObject(role).getString("result_job"));}
        verifyRestored(f,pair);f.checkpoint(pair);f.receipt(RESULT,new JSONObject().put("phase","completed-resume-verified").put("same_recorded_jobs",true).put("no_second_erase",true).put("no_server_reboot",true).put("saved_profile_unchanged",true).put("operation_started_binary",meta.getJSONObject("binary")).put("profile_sha256",meta.getString("profile_sha256")).put("live_client_traffic_tested",false));
    }

    private void rejectDamagedArchivesBeforeErase(Gateway pair,JSONObject original)throws Exception{for(int variant=0;variant<2;variant++){JSONObject damaged=new JSONObject(original.toString());if(variant==0)damaged.getJSONObject("nodes").getJSONObject("entry").remove("initial_user");else damaged.getJSONObject("nodes").getJSONObject("exit").getJSONObject("plan").put("exit_host","unexpected.example.net");PairController.Bundle unopened=()->{throw new AssertionError("An incompatible archive opened a remote adapter");};try{PairedOsReinstall.runRestore(pair,new JSONObject().put("mode","restore"),false,damaged,unopened,unopened,QUIET,()->{throw new AssertionError("An incompatible archive persisted an erase checkpoint");},()->{throw new AssertionError("An incompatible archive reached disk erase");});fail("An incompatible archive passed validation");}catch(IOException expected){}assertFalse(pair.data.has("pairedOsOperation"));}}
    private PrivateAdministrationFixture fixture(String action)throws Exception{
        String requested=InstrumentationRegistry.getArguments().getString("rookstride_private_major_action",""),soleAction=action.replace("paired-","paired-sole-relay-");
        boolean sole=requested.equals(soleAction);PrivateAdministrationFixture f=PrivateAdministrationFixture.load(sole?soleAction:action,"allow_paired_os_restore");
        if(sole){assertTrue("The new sole-relay action requires separate consent",f.request.getBoolean("allow_sole_relay_os_test"));assertNull(soleRelay);soleRelay=new SoleRelayProof(f,soleAction);}
        else assertFalse("The original actions do not activate a different access-path test",f.request.optBoolean("allow_sole_relay_os_test"));return f;
    }
    private JSONObject metadata(PrivateAdministrationFixture f,Gateway pair)throws Exception{JSONObject value=pair.data.getJSONObject(META);f.verifyRecordedBinary(value);if(value.has("sole_relay_test"))assertNotNull("Continue this reviewed operation with its sole-relay test enabled",soleRelay);if(soleRelay!=null)soleRelay.metadata(value);return value;}
    private JSONObject decrypt(PrivateAdministrationFixture f,Gateway pair)throws Exception{char[] key=f.request.getString("recovery_password").toCharArray();byte[] envelope=Files.readAllBytes(f.file(ARCHIVE).toPath());try{return OwnerRecovery.decrypt(envelope,key,pair.get("pairId"));}finally{Arrays.fill(key,'\0');Arrays.fill(envelope,(byte)0);}}
    private Gateway part(Gateway pair,String role){return role.equals("entry")?pair:pair.exit;}
    private JSONObject inspect(Gateway pair,boolean createCanary)throws Exception{
        JSONObject result=new JSONObject();try(PairSsh sessions=PairSsh.connect(pair,QUIET)){for(String role:new String[]{"entry","exit"}){Ssh ssh=role.equals("entry")?sessions.entry:sessions.exit;
            if(createCanary)ssh.execute("mkdir -p /srv/rook-major-restore-erase-canary && printf 'disposable paired restore fixture' > /srv/rook-major-restore-erase-canary/check",null);
            JSONObject probe=ssh.probe();String raw=ssh.execute("if test -f /etc/rookstride-reinstall-result.json; then cat /etc/rookstride-reinstall-result.json; else printf '{}'; fi",null);
            result.put(role,new JSONObject().put("os",probe.getString("os")).put("version",probe.getString("version")).put("machine",probe.getString("machine")).put("fingerprint",part(pair,role).get("fingerprint")).put("boot_id",ssh.execute("cat /proc/sys/kernel/random/boot_id",null)).put("canary",ssh.execute("if test -e /srv/rook-major-restore-erase-canary/check; then printf present; else printf erased; fi",null).equals("present")).put("result_job",new JSONObject(raw).optString("job")));
        }}return result;
    }
    private String exportProfile(PrivateAdministrationFixture f,Gateway pair)throws Exception{try(PairSsh sessions=PairSsh.connect(pair,QUIET);InputStream bundle=f.context.getAssets().open("single_bundle.zip")){return sessions.entry.single(bundle,new JSONObject().put("action","profile").put("protocol","awg").put("login",pair.get("vpnLogin"))).getString("content");}}
    private void assertSameJobs(JSONObject expected,JSONObject actual)throws Exception{assertEquals(expected.getString("operation"),actual.getString("operation"));for(String role:new String[]{"entry","exit"})assertEquals("A new OS job replaced the reviewed job",expected.getJSONObject("plans").getJSONObject(role).getString("job"),actual.getJSONObject("plans").getJSONObject(role).getString("job"));}
    private void verifyReturned(PrivateAdministrationFixture f,Gateway pair,String role,JSONObject operation,JSONObject actual)throws Exception{Gateway node=part(pair,role);JSONObject plan=operation.getJSONObject("plans").getJSONObject(role),state=actual.getJSONObject(role);assertEquals("complete",node.get("osReinstallState"));assertEquals("Returned machine identity was not durably refreshed",state.getString("machine"),node.get("machine"));assertTrue(node.get("machine").matches("[0-9a-f]{64}"));assertEquals("ubuntu",state.getString("os"));assertEquals(plan.getString("version"),state.getString("version"));assertEquals(plan.getString("job"),state.getString("result_job"));assertEquals(plan.getString("fingerprint"),node.get("fingerprint"));assertEquals(node.get("fingerprint"),new ServerIdentityPins(f.context).get(node));assertFalse("The reviewed disk was not erased",state.getBoolean("canary"));}
    private void verifyRestored(PrivateAdministrationFixture f,Gateway pair)throws Exception{JSONObject meta=metadata(f,pair),receipt=pair.data.getJSONObject("lastPairedOsOperation"),actual=inspect(pair,false);assertSameJobs(meta.getJSONObject("reviewed"),receipt);assertEquals("restored",receipt.getString("phase"));assertFalse(pair.data.has("pairedOsOperation"));assertTrue(pair.data.getBoolean("pairReady"));for(String role:new String[]{"entry","exit"}){verifyReturned(f,pair,role,receipt,actual);verifyAlias(f,pair,new Vault(f.context).read(),role,true);}assertEquals(meta.getString("login"),pair.get("vpnLogin"));assertEquals(meta.getString("profile_uuid"),pair.get("profileUuid"));String saved=new NativeProfileStore(f.context).read(pair.get("id")).getString("content");assertEquals(meta.getString("profile_sha256"),PrivateAdministrationFixture.hash(saved));assertTrue("Restored export changed the original saved AWG profile",saved.equals(exportProfile(f,pair)));}
    private void verifyAlias(PrivateAdministrationFixture f,Gateway pair,ArrayList<Gateway> nodes,String role,boolean replaced)throws Exception{JSONObject aliases=pair.data.getJSONObject(META).getJSONObject("aliases");if(!aliases.has(role)){assertNotNull("Only the fresh sole-relay test omits synthetic control aliases",soleRelay);return;}JSONObject recorded=aliases.getJSONObject(role);Gateway alias=null;for(Gateway node:nodes)if(node.get("id").equals(recorded.getString("id")))alias=node;assertNotNull("Owner alias disappeared",alias);Gateway owner=part(pair,role);assertEquals(owner.get("fingerprint"),alias.get("fingerprint"));assertEquals(owner.get("fingerprint"),new ServerIdentityPins(f.context).get(alias));assertEquals("root",alias.get("admin"));assertTrue("Root SSH access was lost",owner.sshPassword.equals(alias.sshPassword));if(replaced){assertEquals("Owner alias kept an erased OS machine identity",owner.get("machine"),alias.get("machine"));assertFalse("Old physical administration identity survived OS replacement",recorded.getString("old_server_id").equals(owner.get("adminServerId")));assertEquals(owner.get("adminServerId"),alias.get("adminServerId"));assertFalse(recorded.getString("old_deployment_id").equals(alias.get("adminDeploymentId")));assertFalse(alias.data.has("adminSnapshot"));assertFalse(alias.data.optBoolean("adminEnabled"));}else{assertEquals("Untouched alias machine changed",recorded.getString("old_machine"),alias.get("machine"));assertEquals(recorded.getString("old_machine"),owner.get("machine"));assertEquals(recorded.getString("old_server_id"),alias.get("adminServerId"));assertTrue(alias.data.optBoolean("adminEnabled"));assertTrue(alias.data.has("adminSnapshot"));}}
    private void requireComplete(DeploymentService.Session session){if(session.error!=null)throw new AssertionError("Recorded paired restore needs attention; retain private device logs",session.error);assertEquals("complete",session.progress.state);assertEquals("restored",session.result.optString("state"));}
    private DeploymentService.Session runService(PrivateAdministrationFixture f,Gateway pair,ArrayList<Gateway> nodes,JSONObject plan,boolean resume,JSONObject archive,boolean navigate)throws Exception{
        if(soleRelay!=null)soleRelay.review(pair,plan);
        try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
            screen.onActivity(activity->DeploymentService.launchRecovery(activity,pair,nodes,plan,resume,archive));long deadline=SystemClock.elapsedRealtime()+Math.min(270,Math.max(30,f.request.optInt("timeout_minutes",250)))*60_000L;boolean moved=false;
            while(SystemClock.elapsedRealtime()<deadline){DeploymentService.Session session=DeploymentService.current();if(session!=null&&session.node.get("id").equals(pair.get("id"))){
                if(navigate&&!moved&&session.progress.completed>=1){screen.onActivity(activity->{try{java.lang.reflect.Method open=RookstrideActivity.class.getDeclaredMethod("openScreen",String.class);open.setAccessible(true);open.invoke(activity,"Stories");}catch(Exception e){throw new AssertionError(e);}});screen.recreate();moved=true;}
                if(!session.progress.state.equals("running"))return session;
            }Thread.sleep(2000);}
            InstrumentationRegistry.getInstrumentation().runOnMainSync(()->f.context.stopService(new Intent(f.context,DeploymentService.class)));
            throw new AssertionError("Polling timed out; retain the recorded jobs and resume, never prepare a new wipe");
        }
    }
}
