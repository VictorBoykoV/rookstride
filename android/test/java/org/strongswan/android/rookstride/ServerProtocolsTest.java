package org.strongswan.android.rookstride;
import org.junit.Test;
import org.json.*;
import java.util.*;
import static org.junit.Assert.*;

public class ServerProtocolsTest {
    @Test public void renamingUpdatesPhysicalAliasesAndPersistsWithoutChangingConnectionsOrAccess()throws Exception{
        Gateway ike=server("ikev2"),awg=ServerProtocols.create(ike,SingleProtocols.AWG),alias=server("xray"),changed=server("openvpn"),imported=server("awg");
        ike.set("name","Original VPN");ike.set("profileUuid","retained-profile");ike.sshPassword="fixture-admin";ike.data.put("remember",true);alias.set("host","alias.example.net");changed.set("fingerprint","different");imported.data.put("clientOnly",true);
        List<Gateway> nodes=Arrays.asList(ike,awg,alias,changed,imported);ServerProtocols.rename(nodes,awg,"  North bridge  ");
        for(Gateway node:Arrays.asList(ike,awg,alias))assertEquals("North bridge",ServerProtocols.name(new Gateway(node.persisted())));
        assertEquals("",changed.get("serverName"));assertEquals("",imported.get("serverName"));assertEquals("Original VPN",ike.get("name"));assertEquals("retained-profile",ike.get("profileUuid"));assertEquals("fixture-admin",ike.sshPassword);assertEquals("pinned-identity",ike.get("fingerprint"));
    }
    @Test public void renamingEitherPairNodeKeepsTheOtherServerAndLogicalVpnIndependent()throws Exception{
        Gateway entry=server("awg");entry.set("name","My Double VPN");entry.set("pairId","retained-route");entry.exit=server("openvpn");entry.exit.set("host","exit.example.net");entry.exit.set("machine","other-machine");entry.exit.set("fingerprint","other-pin");entry.exit.set("name","My Double VPN Exit");
        List<Gateway> nodes=Arrays.asList(entry);ServerProtocols.rename(nodes,entry,"First bridge");ServerProtocols.rename(nodes,entry.exit,"Far bridge");Gateway saved=new Gateway(entry.persisted());
        assertEquals("First bridge",ServerProtocols.name(saved));assertEquals("Far bridge",ServerProtocols.name(saved.exit));assertEquals("My Double VPN",saved.get("name"));assertEquals("My Double VPN Exit",saved.exit.get("name"));assertEquals("retained-route",saved.get("pairId"));assertEquals("exit.example.net",saved.exit.get("host"));
        for(String invalid:Arrays.asList("   ","line\nbreak",String.join("",Collections.nCopies(81,"a")))){try{ServerProtocols.rename(nodes,entry,invalid);fail("Invalid label saved");}catch(IllegalArgumentException expected){}assertEquals("First bridge",entry.get("serverName"));}
    }
    private Gateway server(String protocol)throws Exception{Gateway g=new Gateway();g.set("host","vpn.example.net");g.set("admin","root");g.set("protocol",protocol);g.set("fingerprint","pinned-identity");g.set("machine","machine-hash");return g;}
    @Test public void homeGroupsManagedServersButNeverMergesImportedOrChangedIdentities()throws Exception{
        Gateway ike=server("ikev2"),awg=ServerProtocols.create(ike,SingleProtocols.AWG),foreign=server("xray");foreign.set("fingerprint","other-identity");Gateway imported=server("awg");imported.data.put("clientOnly",true);
        assertEquals(Arrays.asList(ike,foreign,imported),ServerProtocols.servers(Arrays.asList(ike,awg,foreign,imported)));
        assertEquals(Arrays.asList(SingleProtocols.AWG,SingleProtocols.IKEV2),ServerProtocols.ordered(new HashSet<>(Arrays.asList("ikev2","awg")),true));
        assertEquals(Arrays.asList(SingleProtocols.HYSTERIA2,SingleProtocols.NAIVE,SingleProtocols.OPENVPN,SingleProtocols.OUTLINE,SingleProtocols.SHADOWSOCKS,SingleProtocols.TRUSTTUNNEL,SingleProtocols.XRAY,SingleProtocols.XHTTP),ServerProtocols.ordered(new HashSet<>(Arrays.asList("ikev2","awg")),false));
    }
    @Test public void reusesEachProtocolsRecordRatherThanDuplicatingIt()throws Exception{
        Gateway ike=server("ikev2"),awg=ServerProtocols.create(ike,SingleProtocols.AWG);List<Gateway> nodes=Arrays.asList(ike,awg);
        assertSame(awg,ServerProtocols.find(nodes,ike,"awg"));assertSame(ike,ServerProtocols.find(nodes,awg,"ikev2"));assertNull(ServerProtocols.find(nodes,ike,"xray"));
    }
    @Test public void legacyIkeProfilesRemainReusableButEmptyManagedServersDoNotBecomeConnections()throws Exception{
        Gateway legacy=server("");List<Gateway> nodes=Arrays.asList(legacy);
        assertNull(ServerProtocols.find(nodes,legacy,"ikev2"));
        legacy.set("profileUuid","legacy-profile-id");assertSame(legacy,ServerProtocols.find(nodes,legacy,"ikev2"));
        legacy.set("profileUuid","");legacy.data.put("snapshot",new JSONObject().put("services",new JSONObject().put("strongswan-starter",true)));
        assertSame(legacy,ServerProtocols.find(nodes,legacy,"ikev2"));assertNull(ServerProtocols.find(nodes,legacy,"awg"));
    }
    @Test public void changedPinsImportedProfilesAndPairsNeverShareAdministratorIdentity()throws Exception{
        Gateway a=server("ikev2"),b=server("awg");b.set("fingerprint","changed");assertFalse(ServerProtocols.sameServer(a,b));
        b=server("awg");b.data.put("clientOnly",true);assertFalse(ServerProtocols.sameServer(a,b));b.data.remove("clientOnly");b.exit=new Gateway();assertFalse(ServerProtocols.sameServer(a,b));
    }
    @Test public void aliasesNeedBothPinnedIdentityAndMachineMetadata()throws Exception{
        Gateway a=server("ikev2"),b=server("awg");b.set("host","alias.example.net");assertTrue(ServerProtocols.sameServer(a,b));b.set("machine","");assertFalse(ServerProtocols.sameServer(a,b));
    }
    @Test public void newProtocolKeepsOptInSshButDoesNotInheritVpnSecretsOrOldProfile()throws Exception{
        Gateway a=server("ikev2");a.sshPassword="fixture-admin";a.vpnPassword="fixture-vpn";a.set("profileUuid","old-uuid");
        Gateway b=ServerProtocols.create(a,SingleProtocols.OPENVPN);assertEquals(a.sshPassword,b.sshPassword);assertEquals("",b.vpnPassword);assertEquals("",b.get("profileUuid"));assertFalse(b.persisted().has("sshPassword"));assertTrue(b.data.getBoolean("vpnPortAuto"));
        a.data.put("remember",true);assertEquals(a.sshPassword,ServerProtocols.create(a,SingleProtocols.XRAY).persisted().getString("sshPassword"));
    }
    @Test public void freshInventoryOverridesOldStatusAndReplacementKeysInvalidateTheCache()throws Exception{
        Gateway node=server("awg");node.data.put("snapshot",new JSONObject().put("services",new JSONObject()));node.data.put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray())));
        assertTrue(ServerProtocols.installed(Arrays.asList(node),node).isEmpty());assertFalse(ServerProtocols.changedInstance(node,"new"));node.set("serverInstance","old");assertTrue(ServerProtocols.changedInstance(node,"new"));assertFalse(ServerProtocols.changedInstance(node,"old"));assertFalse(ServerProtocols.changedInstance(node,""));
    }
    @Test public void installedListCombinesOwnedInventoryAndSavedStatus()throws Exception{
        Gateway a=server("ikev2");a.data.put("probe",new JSONObject().put("gateway",true).put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg").put("xray").put("unknown"))));
        assertEquals(new LinkedHashSet<>(Arrays.asList("ikev2","awg","xray")),ServerProtocols.installed(Arrays.asList(a),a));
    }
    @Test public void successfulDeploymentUpdatesSiblingInventoryWithoutHidingTheNewProtocol()throws Exception{
        Gateway a=server("ikev2");a.data.put("probe",new JSONObject().put("inventory",new JSONObject().put("installed_protocols",new JSONArray())));Gateway b=ServerProtocols.create(a,SingleProtocols.XRAY);List<Gateway> nodes=Arrays.asList(a,b);
        ServerProtocols.recordInstalled(nodes,b,"new-instance");assertEquals(Collections.singleton("xray"),ServerProtocols.installed(nodes,a));assertEquals("new-instance",a.data.getJSONObject("probe").getJSONObject("inventory").getJSONObject("installed_instances").getString("xray"));
        ServerProtocols.recordInstalled(nodes,a,"");assertEquals(new HashSet<>(Arrays.asList("ikev2","xray")),ServerProtocols.installed(nodes,b));
    }
    @Test public void selectiveRemovalClearsEverySiblingInventoryWithoutLosingOtherProtocols()throws Exception{
        Gateway ike=server("ikev2"),awg=ServerProtocols.create(ike,SingleProtocols.AWG);List<Gateway> nodes=Arrays.asList(ike,awg);
        for(Gateway g:nodes)g.data.put("probe",new JSONObject().put("gateway",true).put("inventory",new JSONObject().put("installed_protocols",new JSONArray().put("awg").put("xray")).put("installed_instances",new JSONObject().put("awg","old-key-generation").put("xray","keep-generation"))));
        ServerProtocols.recordRemoved(nodes,awg);assertEquals(new HashSet<>(Arrays.asList("ikev2","xray")),ServerProtocols.installed(nodes,ike));
        for(Gateway g:nodes){JSONObject instances=g.data.getJSONObject("probe").getJSONObject("inventory").getJSONObject("installed_instances");assertFalse(instances.has("awg"));assertEquals("keep-generation",instances.getString("xray"));}
        ServerProtocols.recordInstalled(nodes,awg,"fresh-generation");assertTrue(ServerProtocols.installed(nodes,ike).contains("awg"));
        ServerProtocols.recordRemoved(nodes,ike);assertEquals(new HashSet<>(Arrays.asList("awg","xray")),ServerProtocols.installed(nodes,awg));
    }
    @Test public void verifiedCertificateHostnamesSurviveProtocolRecreationWithoutLeakingAcrossServers()throws Exception{Gateway a=server("ikev2"),b=ServerProtocols.create(a,SingleProtocols.AWG),other=server("openvpn");other.set("host","other.example.net");other.set("machine","other-machine");other.set("fingerprint","other-pin");JSONObject report=new JSONObject().put("certificate",new JSONObject().put("trust","public").put("aliases",new JSONArray().put("vpn.family-domain.org")));ServerProtocols.rememberIkeCertificateNames(Arrays.asList(a,b,other),a,report);assertFalse(other.data.has("ikeCertificateAliases"));assertEquals("vpn.family-domain.org",b.data.getJSONArray("ikeCertificateAliases").getString(0));Gateway reinstall=ServerProtocols.create(b,SingleProtocols.IKEV2);assertEquals(a.data.getJSONArray("ikeCertificateAliases").toString(),reinstall.data.getJSONArray("ikeCertificateAliases").toString());reinstall.data.getJSONArray("ikeCertificateAliases").put("separate.family-domain.org");assertEquals(1,a.data.getJSONArray("ikeCertificateAliases").length());}
    @Test public void malformedOrPrivateCertificateNamesAreNotRemembered()throws Exception{Gateway a=server("ikev2");for(JSONObject cert:Arrays.asList(new JSONObject().put("trust","pinned").put("aliases",new JSONArray().put("vpn.family-domain.org")),new JSONObject().put("trust","public").put("aliases",new JSONArray().put("name;command"))))ServerProtocols.rememberIkeCertificateNames(Arrays.asList(a),a,new JSONObject().put("certificate",cert));assertFalse(a.data.has("ikeCertificateAliases"));}

    @Test public void publicTrustMigrationRequiresTheExactPrecedingPrivateIdentity()throws Exception{Gateway a=server("ikev2");String old=String.join("",Collections.nCopies(64,"1")),instance="public-"+String.join("",Collections.nCopies(32,"2"));a.set("serverInstance",old);JSONObject status=new JSONObject().put("certificate",new JSONObject().put("trust","public").put("previous_instance",old));assertTrue(ServerProtocols.publicCertificateMigration(a,status,instance));status.getJSONObject("certificate").put("previous_instance",String.join("",Collections.nCopies(64,"3")));assertFalse(ServerProtocols.publicCertificateMigration(a,status,instance));status.getJSONObject("certificate").put("previous_instance",old);a.data.put("clientOnly",true);assertFalse(ServerProtocols.publicCertificateMigration(a,status,instance));}

    @Test public void separateOpenVpnRetainsOnlyPhysicalAccessAndExactPairOwnership()throws Exception{
        Gateway pair=server("awg");pair.exit=server("awg");pair.exit.set("host","exit.example.net");pair.set("pairEntryProtocol","awg");pair.set("pairEngine","native-v2");pair.set("pairId",String.join("",Collections.nCopies(32,"a")));pair.set("profileUuid","pair-profile");pair.vpnPassword="pair-vpn-secret";pair.sshPassword="administrator-secret";
        Gateway separate=ServerProtocols.createCoexistingOpenVpn(pair);assertFalse(separate.isPair());assertNotEquals(pair.get("id"),separate.get("id"));assertEquals("openvpn",separate.get("protocol"));assertEquals(pair.get("pairId"),separate.get("coexistPair"));assertEquals("",separate.get("profileUuid"));assertEquals("",separate.vpnPassword);assertEquals(pair.sshPassword,separate.sshPassword);assertEquals(pair.get("fingerprint"),separate.get("fingerprint"));
        ServerProtocols.rememberCoexistence(separate,"foreign");assertEquals("",separate.get("coexistPair"));ServerProtocols.rememberConnection(Arrays.asList(separate),separate,new JSONObject().put("coexist_pair",pair.get("pairId")).put("port",1194));assertEquals(pair.get("pairId"),separate.get("coexistPair"));PairNodes.clearConnection(separate);assertEquals("",separate.get("coexistPair"));
        pair.set("pairEntryProtocol","xray");try{ServerProtocols.createCoexistingOpenVpn(pair);fail("Unsupported coexistence was offered");}catch(IllegalArgumentException expected){}
    }

}
