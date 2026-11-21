package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;
import java.net.SocketTimeoutException;

public class ConnectionDiagnosisTest {
    @Test public void identifiesAuthenticatedRelayWithoutCallingItBadPassword()throws Exception{
        Gateway target=new Gateway(),relay=new Gateway();target.set("host","exit.example");relay.set("host","entry.example");target.sshRelay=relay;
        Exception e=new Ssh.Unreachable(new SocketTimeoutException("private raw detail"),target,true);
        assertEquals("ssh_relay_destination_unreachable",ConnectionDiagnosis.code(e));
        assertTrue(ConnectionDiagnosis.detail(e).contains("entry.example"));assertTrue(ConnectionDiagnosis.detail(e).contains("exit.example"));
        assertFalse(ConnectionDiagnosis.detail(e).contains("password"));
        String exported=ConnectionDiagnosis.supportReport(e).toString();
        assertFalse(exported.contains("example"));assertFalse(exported.contains("private raw detail"));
    }
    @Test public void relayLoginFailureIsAttributedToRelay()throws Exception{
        Gateway relay=new Gateway();relay.set("host","entry.example");
        Exception e=new Ssh.SignInRejected(new Exception("secret"),relay);
        assertEquals("ssh_sign_in_rejected",ConnectionDiagnosis.code(new Exception("wrapper",e)));
        assertTrue(ConnectionDiagnosis.detail(e).contains("entry.example"));assertFalse(ConnectionDiagnosis.supportReport(e).toString().contains("secret"));
    }
    @Test public void changedKeyRemainsSeparateFromNetworkFailure()throws Exception{
        assertEquals("ssh_identity_changed",ConnectionDiagnosis.code(new Ssh.HostTrust("SHA256:test",true)));
        assertEquals("ssh_server_unreachable",ConnectionDiagnosis.code(new Ssh.Unreachable(new SocketTimeoutException())));
    }
}
