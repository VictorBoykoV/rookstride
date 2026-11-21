package org.strongswan.android.rookstride;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ServerAccessTest {
    @Test public void explicitRelaySurvivesASeparateProtocolRecordAndRejectsForeignMembers()throws Exception{
        Gateway pair=node("awg"),exit=node("awg");pair.set("host","entry.example.test");exit.set("host","exit.example.test");pair.exit=exit;
        Gateway entryAlias=node("openvpn"),exitAlias=node("openvpn"),other=node("openvpn");entryAlias.set("host",pair.get("host"));exitAlias.set("host",exit.get("host"));other.set("host","other.example.test");
        pair.set("sshRoute","entry-via-exit");assertTrue(AdminConnection.explicitRelay(entryAlias,pair));assertFalse(AdminConnection.explicitRelay(exitAlias,pair));assertFalse(AdminConnection.explicitRelay(other,pair));
        pair.set("sshRoute","exit-via-entry");assertTrue(AdminConnection.explicitRelay(exitAlias,pair));assertFalse(AdminConnection.explicitRelay(entryAlias,pair));assertFalse(AdminConnection.explicitRelay(other,pair));
        exitAlias.set("fingerprint","changed-pin");assertFalse(AdminConnection.explicitRelay(exitAlias,pair));
        for(String route:new String[]{"","auto","direct","unknown"}){pair.set("sshRoute",route);assertFalse(AdminConnection.explicitRelay(entryAlias,pair));assertFalse(AdminConnection.explicitRelay(exitAlias,pair));}
        assertFalse(AdminConnection.explicitRelay(entryAlias,null));assertFalse(AdminConnection.explicitRelay(entryAlias,exit));
    }
    private Gateway node(String protocol)throws Exception{Gateway g=new Gateway();g.set("host","vpn.example.net");g.set("admin","root");g.set("fingerprint","fixture-pin");g.set("protocol",protocol);return g;}
    @Test public void savedAdministratorAccessIsSharedAcrossProtocolsWithoutVpnPasswords()throws Exception{
        Gateway a=node("awg"),b=node("xray");a.sshPassword="fixture-admin";a.vpnPassword="fixture-vpn";
        ServerAccess.remember(Arrays.asList(a,b),a,true);
        assertEquals(a.sshPassword,b.persisted().getString("sshPassword"));assertEquals("",b.vpnPassword);
        b.sshPassword="";b.set("fingerprint","");assertTrue(ServerAccess.reuse(Arrays.asList(a,b),b));assertTrue(b.remember());assertEquals(a.get("fingerprint"),b.get("fingerprint"));
    }
    @Test public void importedOtherAccountsAndChangedPinsCannotBorrowSecrets()throws Exception{
        Gateway source=node("awg");source.sshPassword="fixture-admin";
        for(String kind:new String[]{"imported","different-admin","changed-pin","other-host"}){
            Gateway target=node("xray");if(kind.equals("imported"))target.data.put("clientOnly",true);else if(kind.equals("different-admin"))target.set("admin","another-admin");else if(kind.equals("changed-pin"))target.set("fingerprint","changed");else target.set("host","other.example.net");
            assertFalse(ServerAccess.reuse(Arrays.asList(source,target),target));ServerAccess.remember(Arrays.asList(source,target),source,true);assertEquals("",target.sshPassword);
        }
    }
    @Test public void optingOutRemovesPersistedSshCopiesAndPreservesDeviceCredentials()throws Exception{
        Gateway a=node("awg"),b=node("ikev2");a.privateKey="fixture-key";a.sshPassword="fixture-passphrase";b.vpnPassword="fixture-vpn";b.data.put("rememberVpn",true);
        ServerAccess.remember(Arrays.asList(a,b),a,true);assertEquals(a.privateKey,b.persisted().getString("privateKey"));
        ServerAccess.remember(Arrays.asList(a,b),a,false);assertFalse(a.persisted().has("privateKey"));assertFalse(b.persisted().has("sshPassword"));assertEquals("fixture-vpn",b.persisted().getString("vpnPassword"));
    }
    @Test public void legacyUnsetSavingIsEnabledButConsciousOptOutSurvivesDefaults()throws Exception{
        Gateway old=node("awg");old.data.put("remember",false);assertTrue(ServerAccess.shouldRemember(old,true));assertTrue(ServerAccess.shouldRemember(null,true));
        old.data.put("saveAccessChosen",true);assertFalse(ServerAccess.shouldRemember(old,true));assertFalse(ServerAccess.shouldRemember(null,false));
        old.data.put("remember",true);assertTrue(ServerAccess.shouldRemember(old,false));
    }
    @Test public void pairExitAccessIsReusedAndExplicitOptOutIsNotLost()throws Exception{
        Gateway pair=node("awg"),exit=node("ikev2"),target=node("xray");pair.set("host","entry.example.net");pair.exit=exit;exit.sshPassword="fixture-exit";exit.data.put("remember",true);exit.data.put("saveAccessChosen",true);
        target.data.put("remember",false);target.data.put("saveAccessChosen",true);assertTrue(ServerAccess.reuse(Arrays.asList(pair,target),target));assertEquals("fixture-exit",target.sshPassword);assertFalse(target.persisted().has("sshPassword"));
        ServerAccess.remember(Arrays.asList(pair,target),target,true);assertTrue(exit.remember());assertEquals("fixture-exit",exit.persisted().getString("sshPassword"));
    }
}
