package org.strongswan.android.rookstride;

import java.io.IOException;
import java.net.NoRouteToHostException;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

/** Local connection-order/trust tests; these do not claim real SSH qualification. */
public class PairSshNodeTest {
    private static final String PIN="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private Gateway node(String host)throws Exception {
        Gateway node=new Gateway();node.set("host",host);node.set("admin","root");node.set("fingerprint",PIN);
        node.data.put("port",2222);node.sshPassword="fixture-"+host;return node;
    }
    private Ssh.Unreachable offline(Gateway node){return new Ssh.Unreachable(new NoRouteToHostException("local fixture"),node,false);}
    private PairController.TrustNeeded trust(Gateway node,boolean changed){return new PairController.TrustNeeded(node,new Ssh.HostTrust(PIN,changed,node));}
    @Test public void directSuccessDoesNotTouchRelayOrMutateCanonicalNodes()throws Exception {
        Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");candidate.sshRelay=entry;
        String before=candidate.data.toString();AtomicInteger calls=new AtomicInteger();
        String result=PairSsh.connectNode(candidate,entry,p->{fail("Unexpected relay progress");},attempt->{
            calls.incrementAndGet();assertNotSame(candidate,attempt);assertNull(attempt.sshRelay);assertEquals(candidate.get("id"),attempt.get("id"));assertEquals(candidate.sshPassword,attempt.sshPassword);return "direct";
        });
        assertEquals("direct",result);assertEquals(1,calls.get());assertSame(entry,candidate.sshRelay);assertEquals(before,candidate.data.toString());
    }
    @Test public void onlyUnreachableRetriesOnceThroughSuppliedPinnedMember()throws Exception {
        Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");AtomicInteger calls=new AtomicInteger(),progress=new AtomicInteger();
        assertEquals("relay",PairSsh.connectNode(candidate,entry,p->progress.incrementAndGet(),attempt->{
            if(calls.getAndIncrement()==0){assertNull(attempt.sshRelay);throw offline(attempt);}
            assertNotNull(attempt.sshRelay);assertNull(attempt.sshRelay.sshRelay);assertNotSame(entry,attempt.sshRelay);
            assertEquals(entry.get("id"),attempt.sshRelay.get("id"));assertEquals(entry.get("fingerprint"),attempt.sshRelay.get("fingerprint"));
            assertEquals(entry.sshPassword,attempt.sshRelay.sshPassword);assertEquals(candidate.sshPassword,attempt.sshPassword);return "relay";
        }));
        assertEquals(2,calls.get());assertEquals(1,progress.get());assertNull(candidate.sshRelay);assertNull(entry.sshRelay);
    }
    @Test public void directKeyAuthenticationAndHandshakeErrorsNeverFallBack()throws Exception {
        for(int kind=0;kind<4;kind++){
            Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");AtomicInteger calls=new AtomicInteger();final int selected=kind;
            try {PairSsh.connectNode(candidate,entry,p->fail("Unexpected relay"),attempt->{calls.incrementAndGet();if(selected<2)throw trust(attempt,selected==1);if(selected==2)throw new Ssh.SignInRejected(new IOException("local fixture"),attempt);throw new Ssh.HandshakeFailure(new IOException("local fixture"));});fail("Accepted failed connection");}
            catch(PairController.TrustNeeded expected){assertTrue(selected<2);assertSame(candidate,expected.node);assertSame(candidate,expected.issue.node);assertEquals(selected==1,expected.issue.changed);assertEquals(PIN,expected.issue.fingerprint);}
            catch(Ssh.SignInRejected expected){assertEquals(2,selected);}
            catch(Ssh.HandshakeFailure expected){assertEquals(3,selected);}
            assertEquals(1,calls.get());
        }
    }
    @Test public void candidateFirstUsePinsOriginalDraftThenNextAttemptSucceeds()throws Exception {
        Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");candidate.set("fingerprint","");String id=candidate.get("id");AtomicInteger calls=new AtomicInteger();
        PairSsh.NodeOpener<String> opener=attempt->{calls.incrementAndGet();if(attempt.sshRelay==null)throw offline(attempt);if(attempt.get("fingerprint").isEmpty())throw trust(attempt,false);assertEquals(PIN,attempt.get("fingerprint"));return "ready";};
        try{PairSsh.connectNode(candidate,entry,p->{},opener);fail("Unpinned candidate accepted");}catch(PairController.TrustNeeded expected){assertSame(candidate,expected.node);assertSame(candidate,expected.issue.node);assertFalse(expected.issue.changed);assertEquals("",candidate.get("fingerprint"));expected.node.set("fingerprint",expected.issue.fingerprint);}
        assertEquals("ready",PairSsh.connectNode(candidate,entry,p->{},opener));assertEquals(4,calls.get());assertEquals(id,candidate.get("id"));assertEquals(PIN,entry.get("fingerprint"));
    }
    @Test public void relayTrustFailureMapsToCanonicalRelayAndDoesNotChangeCandidatePin()throws Exception {
        Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");entry.set("fingerprint","SHA256:old-relay");AtomicInteger calls=new AtomicInteger();
        try{PairSsh.connectNode(candidate,entry,p->{},attempt->{calls.incrementAndGet();if(attempt.sshRelay==null)throw offline(attempt);throw trust(attempt.sshRelay,true);});fail("Changed relay accepted");}
        catch(PairController.TrustNeeded expected){assertSame(entry,expected.node);assertSame(entry,expected.issue.node);assertTrue(expected.issue.changed);assertEquals("SHA256:old-relay",entry.get("fingerprint"));assertEquals(PIN,candidate.get("fingerprint"));}
        assertEquals(2,calls.get());
    }
    @Test public void forwardedCandidateChangedKeyAndBadAuthenticationDoNotTryAnotherRoute()throws Exception {
        for(boolean changedKey:new boolean[]{true,false}){
            Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");AtomicInteger calls=new AtomicInteger();
            try{PairSsh.connectNode(candidate,entry,p->{},attempt->{calls.incrementAndGet();if(attempt.sshRelay==null)throw offline(attempt);if(changedKey)throw trust(attempt,true);throw new Ssh.SignInRejected(new IOException("local fixture"),attempt);});fail("Failed authentication accepted");}
            catch(PairController.TrustNeeded expected){assertTrue(changedKey);assertSame(candidate,expected.node);assertTrue(expected.issue.changed);}
            catch(Ssh.SignInRejected expected){assertFalse(changedKey);}
            assertEquals(2,calls.get());
        }
    }
    @Test public void unexpectedTrustIdentityCannotPinCandidateOrRelay()throws Exception {
        for(int field=0;field<4;field++){
            Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");final int changed=field;
            try{PairSsh.connectNode(candidate,entry,p->fail("Unexpected relay"),attempt->{Gateway foreign=PairNodes.copy(attempt);if(changed==0)foreign.set("id","different");if(changed==1)foreign.set("host","other.example.net");if(changed==2)foreign.data.put("port",2223);if(changed==3)foreign.set("admin","other-admin");throw trust(foreign,true);});fail("Foreign trust accepted");}
            catch(IOException expected){assertTrue(expected.getCause() instanceof PairController.TrustNeeded);}
            assertEquals(PIN,candidate.get("fingerprint"));assertEquals(PIN,entry.get("fingerprint"));
        }
    }
    @Test public void absentRelayPreservesOriginalUnreachableFailure()throws Exception {
        Gateway candidate=node("candidate.example.net");Ssh.Unreachable failure=offline(candidate);AtomicInteger calls=new AtomicInteger();
        try{PairSsh.connectNode(candidate,null,p->fail("Unexpected relay"),attempt->{calls.incrementAndGet();throw failure;});fail();}catch(Ssh.Unreachable expected){assertSame(failure,expected);}assertEquals(1,calls.get());
    }
    @Test public void persistedLifecycleCandidateRetainsIdsPinsAndConsentWithoutRelayObject()throws Exception {
        Gateway entry=node("entry.example.net"),candidate=node("candidate.example.net");entry.exit=node("old-exit.example.net");entry.set("pairId",PairController.newId());entry.set("pairEntryProtocol","awg");entry.set("pairExitProtocol","hysteria2");entry.set("pairEngine","native-v2");
        candidate.set("machine","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");candidate.data.put("remember",true);String id=candidate.get("id");
        JSONObject snapshot=LifecycleSnapshots.copy(candidate);assertFalse(snapshot.has("sshRelay"));Gateway reopened=new Gateway(snapshot);assertEquals(id,reopened.get("id"));assertEquals(PIN,reopened.get("fingerprint"));assertEquals(candidate.sshPassword,reopened.sshPassword);assertEquals(candidate.get("machine"),reopened.get("machine"));
        // This is the existing lifecycle draft/cutover representation: auto pair
        // members, never a serialized relay object or fabricated catalog record.
        entry.exit=reopened;entry.set("exitEndpoint",reopened.get("host"));entry.set("sshRoute","auto");entry.set("resolvedSshRoute","");entry.configureRelay();Gateway loaded=new Gateway(entry.persisted());
        assertEquals(id,loaded.exit.get("id"));assertEquals("auto",loaded.get("sshRoute"));assertNull(loaded.exit.sshRelay);assertEquals("candidate.example.net",PairController.request(loaded,"exit").getString("exit_host"));
        AtomicInteger calls=new AtomicInteger();assertEquals("relay",PairSsh.connectNode(loaded.exit,loaded,p->{},attempt->{calls.incrementAndGet();if(attempt.sshRelay==null)throw offline(attempt);assertEquals(loaded.get("id"),attempt.sshRelay.get("id"));return "relay";}));assertEquals(2,calls.get());
    }
    @Test public void noRememberSnapshotNeverExportsAdministratorSecrets()throws Exception {
        Gateway candidate=node("candidate.example.net"),entry=node("entry.example.net");candidate.privateKey="fixture-private-key";candidate.sshRelay=entry;
        JSONObject value=LifecycleSnapshots.copy(candidate);assertFalse(value.has("sshPassword"));assertFalse(value.has("privateKey"));assertFalse(value.has("sshRelay"));assertFalse(value.toString().contains("fixture-"));assertEquals(candidate.get("id"),value.getString("id"));
    }
}
