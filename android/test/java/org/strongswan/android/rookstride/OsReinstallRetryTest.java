package org.strongswan.android.rookstride;

import com.jcraft.jsch.JSchException;
import java.io.IOException;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class OsReinstallRetryTest {
    private static final long WINDOW=300_000_000_000L;
    private Exception[] temporaryFailures(){return new Exception[]{
        new Ssh.HandshakeFailure(new JSchException("negotiation interrupted")),
        new Ssh.SignInRejected(new JSchException("administrator access starting")),
        new JSchException("SSH channel starting")
    };}

    @Test public void originalSignInAndHandshakeFailuresNeverWaitBeforeReboot(){
        for(Exception error:temporaryFailures())for(long elapsed:new long[]{0,10_000_000_000L,WINDOW-1})
            assertFalse(OsReinstall.mayWaitForAdministratorAccess(false,error,elapsed));
    }

    @Test public void onlyTypedTemporaryFailuresMayWaitDuringTheRebootWindow(){
        for(Exception error:temporaryFailures())for(long elapsed:new long[]{0,10_000_000_000L,WINDOW-1})
            assertTrue(OsReinstall.mayWaitForAdministratorAccess(true,error,elapsed));
    }

    @Test public void exactFiveMinutesExpiredAndInvalidElapsedTimeRefuseRetry(){
        for(Exception error:temporaryFailures())for(long elapsed:new long[]{-1,WINDOW,WINDOW+1,Long.MAX_VALUE})
            assertFalse(OsReinstall.mayWaitForAdministratorAccess(true,error,elapsed));
    }

    @Test public void identityFailuresNeverEnterTheAdministratorWaitPolicy(){
        for(Exception error:new Exception[]{new Ssh.HostTrust("SHA256:unexpected",true),new Ssh.HostTrust("SHA256:unreviewed",false)})
            for(boolean rebooting:new boolean[]{false,true})assertFalse(OsReinstall.mayWaitForAdministratorAccess(rebooting,error,0));
    }

    @Test public void ordinaryOsFailuresAndWrappedTemporaryCausesAreNotRetried(){
        Exception[] failures={new IOException("Installer reported failure"),new IOException("Returned OS differs"),
            new IOException("Command failed",new JSchException("nested transport cause")),
            new IOException("Command failed",new Ssh.HandshakeFailure(new JSchException("nested handshake cause"))),
            new InterruptedException("Coordinator stopped"),new IllegalStateException("Unexpected state"),null};
        for(Exception error:failures)for(boolean rebooting:new boolean[]{false,true})
            assertFalse(OsReinstall.mayWaitForAdministratorAccess(rebooting,error,0));
    }

    @Test public void verifiedOsReturnPersistsTheObservedMachineWithThePlannedSshIdentity()throws Exception{
        Gateway node=new Gateway();node.set("machine","a".repeat(64));node.set("fingerprint","SHA256:old");node.set("admin","previous-admin");node.privateKey="old-private-key";node.sshPassword="retained administrator password";node.set("osReinstallState","rebooting");
        JSONObject plan=new JSONObject().put("version","26.04").put("fingerprint","SHA256:reviewed-future");
        OsReinstall.recordVerifiedOsReturn(node,plan,new JSONObject().put("os","ubuntu").put("version","26.04").put("machine","b".repeat(64)));
        Gateway restored=new Gateway(node.persisted());assertEquals("b".repeat(64),restored.get("machine"));assertEquals("SHA256:reviewed-future",restored.get("fingerprint"));assertEquals("ecdsa-sha2-nistp256",restored.get("sshKeyType"));assertEquals("root",restored.get("admin"));assertEquals("complete",restored.get("osReinstallState"));assertEquals("",node.privateKey);assertEquals("retained administrator password",node.sshPassword);
    }

    @Test public void wrongOrMissingReturnedOsIdentityCannotAdvanceTheSavedReceipt()throws Exception{
        JSONObject plan=new JSONObject().put("version","24.04").put("fingerprint","SHA256:reviewed-future");
        JSONObject[] rejected={new JSONObject().put("os","debian").put("version","24.04").put("machine","b".repeat(64)),new JSONObject().put("os","ubuntu").put("version","22.04").put("machine","b".repeat(64)),new JSONObject().put("os","ubuntu").put("version","24.04"),new JSONObject().put("os","ubuntu").put("version","24.04").put("machine","unverified")};
        for(JSONObject actual:rejected){Gateway node=new Gateway();node.set("machine","a".repeat(64));node.set("fingerprint","SHA256:old");node.set("osReinstallState","rebooting");node.privateKey="keep-existing-key";String before=node.persisted().toString();try{OsReinstall.recordVerifiedOsReturn(node,plan,actual);fail("Unverified return must not advance the receipt");}catch(IOException expected){}assertEquals(before,node.persisted().toString());assertEquals("keep-existing-key",node.privateKey);}
    }
}
