package org.strongswan.android.rookstride;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.json.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;

/** Exact signed app enrollment/revocation. Requires an already enabled owner module;
 * creates only its named management invitation/device, never ordinary VPN users. */
@RunWith(AndroidJUnit4.class)
public final class ScopedAccessIntegrationTest {
    @Test public void signedAppEnrollsAndRevokesItsOwnScopedDevice()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("scoped-enroll-revoke","allow_scoped_access");Gateway pair=f.pair();String serverId=f.request.getString("entry_admin_server_id");JSONArray checks=new JSONArray();
        try(PairSsh sessions=PairSsh.connect(pair,phase->{})){
            Ssh owner=sessions.entry;JSONObject capabilities=call(owner,"capabilities");assertEquals("owner",capabilities.getString("role"));JSONObject object=object(capabilities,serverId,pair.get("pairId"));
            String before=profile(f,owner,pair);JSONObject scope=new JSONObject().put("kind","protocol").put("id",object.getString("id")).put("users","own");Gateway device=null;JSONObject invitation=null;
            try{
                invitation=AdminAccessController.request(owner,new JSONObject().put("operation","invitations.create").put("role","viewer").put("scope",scope).put("name","Signed APK acceptance phone").put("ttl_seconds",600).put("expected_revision",capabilities.getLong("revision"))).getJSONObject("invitation");
                invitation=AdminAccess.parseInvitation(invitation.toString());device=AdminAccessController.deviceDraft(invitation);String key=device.privateKey;assertFalse("The recipient must generate a separate key",key.equals(invitation.getJSONObject("bootstrap").getString("private_key")));
                ArrayList<Gateway> rows=new Vault(f.context).read();rows.add(device);new Vault(f.context).write(rows);new ServerIdentityPins(f.context).remember(device,device.get("fingerprint"));
                Gateway persisted=find(new Vault(f.context).read(),device.get("id"));assertTrue("The own key was not saved before enrollment",key.equals(persisted.privateKey));assertTrue(persisted.data.has("adminEnrollment"));assertFalse("The own key was stored as plaintext",new String(Files.readAllBytes(f.file("gateways.enc").toPath()),StandardCharsets.ISO_8859_1).contains(key));checks.put("own-device-key-encrypted-before-enrollment");
                device=persisted;device=AdminAccessController.accept(invitation,device);saveDevice(f,device);assertFalse(device.data.has("adminEnrollment"));assertTrue(key.equals(device.privateKey));String id=device.get("adminDeviceId");
                device=AdminAccessController.accept(invitation,device);saveDevice(f,device);assertEquals("Own enrollment resume changed device identity",id,device.get("adminDeviceId"));checks.put("controller-enrollment-and-own-key-resume");
                try{AdminAccessController.accept(invitation,AdminAccessController.deviceDraft(invitation));fail("A second device replayed the used invitation");}catch(IOException expected){call(owner,"capabilities");}checks.put("second-device-replay-denied");
                try(Ssh delegated=new Ssh(device)){
                    JSONObject actual=call(delegated,"capabilities");assertEquals("viewer",actual.getString("role"));assertEquals(scope.getString("id"),actual.getJSONObject("scope").getString("id"));assertEquals("own",actual.getJSONObject("scope").getString("users"));assertFalse(contains(actual.getJSONArray("capabilities"),"users.create"));
                    String forced=delegated.execute("id",new JSONObject().put("schema",1).put("operation","capabilities").toString());assertEquals("viewer",Ssh.response(forced).getString("role"));checks.put("pinned-restricted-device-and-forced-dispatcher");
                    grant(owner,device,scope,"user_manager");assertEquals("Role change did not affect the existing SSH session","user_manager",call(delegated,"capabilities").getString("role"));grant(owner,device,scope,"viewer");assertEquals("viewer",call(delegated,"capabilities").getString("role"));checks.put("role-changes-effective-on-open-session");
                    revoke(owner,"devices.revoke","device_id",device.get("adminDeviceId"));
                    try{call(delegated,"capabilities");fail("Revoked open session retained authority");}catch(IOException|com.jcraft.jsch.JSchException denied){assertTrue("Expected a revocation denial or closed SSH session",revocationDenial(denied));}
                    call(owner,"capabilities");assertTrue("Owner metadata did not confirm device revocation",deviceRevoked(call(owner,"access.list"),device.get("adminDeviceId")));checks.put("revocation-effective-on-open-session");
                }
                try(Ssh ignored=new Ssh(device)){fail("A revoked device established a new SSH session");}catch(Ssh.SignInRejected expected){call(owner,"capabilities");}checks.put("revoked-new-ssh-authentication-denied");
                assertTrue("Ordinary VPN identity changed",before.equals(profile(f,owner,pair)));checks.put("ordinary-vpn-profile-unchanged");String audit=call(owner,"audit.read").toString();assertFalse(audit.contains(key));assertFalse(audit.contains(invitation.getJSONObject("bootstrap").getString("private_key")));if(!pair.sshPassword.isEmpty())assertFalse(audit.contains(pair.sshPassword));checks.put("audit-contains-no-admin-secrets");
            }finally{
                // A server claim can commit before its reply arrives. Resolve it
                // through owner metadata before retiring the only saved device key.
                if(invitation!=null)retireOwnEnrollment(f,owner,invitation,device);
            }
        }
        f.receipt("scoped-access-checks-result.json",new JSONObject().put("suite","exact-apk-scoped-enrollment-revocation").put("passed",checks).put("count",checks.length()).put("ordinary_vpn_users_mutated",false));
    }
    private JSONObject call(Ssh ssh,String operation)throws Exception{return AdminAccessController.request(ssh,new JSONObject().put("operation",operation));}
    private JSONObject object(JSONObject caps,String server,String deployment)throws Exception{JSONArray objects=caps.getJSONArray("objects");for(int i=0;i<objects.length();i++){JSONObject object=objects.getJSONObject(i);if(object.getString("server_id").equals(server)&&object.getString("deployment_id").equals(deployment)&&object.getString("protocol").equals("awg"))return object;}throw new AssertionError("The exact reviewed entry AWG object is absent from owner capabilities");}
    private boolean contains(JSONArray values,String value){for(int i=0;i<values.length();i++)if(value.equals(values.optString(i)))return true;return false;}
    private Gateway find(ArrayList<Gateway> rows,String id){for(Gateway node:rows)if(node.get("id").equals(id))return node;throw new AssertionError("The encrypted own-device draft was not saved");}
    private void saveDevice(PrivateAdministrationFixture f,Gateway device)throws Exception{ArrayList<Gateway> rows=new Vault(f.context).read();rows.removeIf(node->node.get("id").equals(device.get("id")));rows.add(device);new Vault(f.context).write(rows);}
    private void grant(Ssh owner,Gateway device,JSONObject scope,String role)throws Exception{AdminAccessController.request(owner,new JSONObject().put("operation","grants.update").put("grant_id",device.get("adminGrantId")).put("role",role).put("scope",scope).put("expected_revision",call(owner,"capabilities").getLong("revision")));}
    private void revoke(Ssh owner,String operation,String key,String value)throws Exception{AdminAccessController.request(owner,new JSONObject().put("operation",operation).put(key,value).put("expected_revision",call(owner,"capabilities").getLong("revision")));}
    private boolean revocationDenial(Exception failure){for(Throwable cause=failure;cause!=null;cause=cause.getCause()){String message=cause.getMessage()==null?"":cause.getMessage().toLowerCase(Locale.ROOT);if(message.contains("revoked")||message.contains("no longer has access")||message.contains("session is down")||message.contains("session is closed")||message.contains("channel is not opened")||message.contains("channel is closed")||message.contains("socket is closed")||message.contains("connection reset")||message.contains("broken pipe"))return true;}return false;}
    private JSONObject record(JSONArray values,String id)throws Exception{for(int i=0;i<values.length();i++){JSONObject value=values.getJSONObject(i);if(id.equals(value.optString("id")))return value;}return null;}
    private boolean deviceRevoked(JSONObject access,String id)throws Exception{JSONObject device=record(access.getJSONArray("devices"),id);return device!=null&&device.optBoolean("revoked");}
    private String expectedDeviceId(Gateway device)throws Exception{String[] key=device.get("adminPublicKey").trim().split("\\s+");if(key.length<2)throw new IOException("The saved device public key is missing");return "dev-"+PrivateAdministrationFixture.hash(key[0]+" "+key[1]).substring(0,32);}
    private void retireOwnEnrollment(PrivateAdministrationFixture f,Ssh owner,JSONObject invitation,Gateway device)throws Exception{
        try{
            String invitationId=invitation.getString("invitation_id");revoke(owner,"invitations.revoke","invitation_id",invitationId);
            JSONObject access=call(owner,"access.list"),record=record(access.getJSONArray("invitations"),invitationId);
            if(record==null||!record.optBoolean("revoked"))throw new IOException("Owner metadata could not confirm invitation retirement");
            String claimed=record.isNull("claimed_device")?"":record.optString("claimed_device","");
            if(!claimed.isEmpty()){
                if(device==null||!device.get("adminInvitationId").equals(invitationId)||!claimed.equals(expectedDeviceId(device)))throw new IOException("Owner metadata did not identify this test's device claim");
                if(!deviceRevoked(access,claimed))revoke(owner,"devices.revoke","device_id",claimed);
                if(!deviceRevoked(call(owner,"access.list"),claimed))throw new IOException("Owner metadata could not confirm claimed device retirement");
            }else if(device!=null&&!device.get("adminDeviceId").isEmpty())throw new IOException("Owner enrollment metadata is incomplete; retain the saved device");
            if(device!=null){String localId=device.get("id");ArrayList<Gateway> rows=new Vault(f.context).read();rows.removeIf(node->node.get("id").equals(localId));new Vault(f.context).write(rows);new ServerIdentityPins(f.context).forgetIfUnreferenced(device,rows);}
        }catch(Exception failure){if(device!=null)try{saveDevice(f,device);}catch(Exception preserve){failure.addSuppressed(preserve);}throw new IOException("Administrative cleanup could not be verified; retain this phone's saved device for owner reconciliation",failure);}
    }
    private String profile(PrivateAdministrationFixture f,Ssh owner,Gateway pair)throws Exception{try(InputStream bundle=f.context.getAssets().open("single_bundle.zip")){return owner.single(bundle,new JSONObject().put("action","profile").put("protocol","awg").put("login",pair.get("vpnLogin"))).getString("content");}}
}
