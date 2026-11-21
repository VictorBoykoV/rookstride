package org.strongswan.android.rookstride;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class PairModelTest {
    @Test public void phonePasswordIsNeverPartOfTheExitBootstrap()throws Exception{Gateway a=pair();a.set("pairEntryProtocol","ikev2");a.set("pairExitProtocol","ikev2");a.set("vpnLogin","phone-user");a.vpnPassword="phone-pass123";JSONObject entry=PairController.bootstrapRequest(a,"entry"),exit=PairController.bootstrapRequest(a,"exit");assertEquals("phone-pass123",entry.getString("password"));assertEquals("phone-user",entry.getString("login"));assertFalse(exit.has("password"));assertFalse(exit.has("login"));assertFalse(exit.toString().contains("phone-pass123"));}
    @Test public void nativeRouteChoicesSurviveStorageAndPhysicalRoleSwap()throws Exception{Gateway a=pair();a.set("pairEntryProtocol","awg");a.set("pairExitProtocol","ikev2");a.set("protocol","awg");a.exit.set("protocol","ikev2");a.data.put("vpnPort",51820);a.data.put("tunnelPort",500);Gateway loaded=new Gateway(a.persisted());assertEquals("awg",PairController.request(loaded,"entry").getString("entry_protocol"));assertEquals("ikev2",PairController.request(loaded,"exit").getString("exit_protocol"));Gateway swapped=loaded.swapped();assertEquals("awg",swapped.get("protocol"));assertEquals("ikev2",swapped.exit.get("protocol"));assertEquals(51820,PairController.request(swapped,"entry").getInt("vpn_port"));assertEquals(500,PairController.request(swapped,"exit").getInt("tunnel_port"));}
    @Test public void savedVpnAccessDoesNotRememberAdministratorSecrets() throws Exception {
        Gateway node=new Gateway();node.sshPassword="administrator-fixture";node.privateKey="key-fixture";node.vpnPassword="vpn-fixture";
        assertFalse(node.persisted().has("vpnPassword"));node.data.put("rememberVpn",true);
        Gateway loaded=new Gateway(node.persisted());assertEquals("vpn-fixture",loaded.vpnPassword);assertEquals("",loaded.sshPassword);assertEquals("",loaded.privateKey);assertFalse(loaded.remember());
        node.data.put("rememberVpn",false);assertFalse(node.persisted().has("vpnPassword"));
    }
    @Test public void relayPinsAndCredentialsRemainOnTheirOwnNodeAfterSwap() throws Exception {
        Gateway a=pair();a.set("name","My pair");a.set("sshRoute","entry-via-exit");a.configureRelay();
        a.set("fingerprint","SHA256:entry");a.exit.set("fingerprint","SHA256:exit");a.data.put("remember",true);a.exit.data.put("remember",true);a.sshPassword="entry-password";a.exit.sshPassword="exit-password";
        Gateway b=new Gateway(a.persisted());assertSame(b.exit,b.sshRelay);assertNull(b.exit.sshRelay);
        Gateway swapped=b.swapped();assertEquals("exit.example.net",swapped.get("host"));assertEquals("SHA256:exit",swapped.get("fingerprint"));assertSame(swapped,swapped.exit.sshRelay);assertNull(swapped.sshRelay);
        Gateway loaded=new Gateway(swapped.persisted());assertNull(loaded.exit.exit);assertEquals("exit-password",loaded.sshPassword);assertEquals("entry-password",loaded.exit.sshPassword);
    }
    private Gateway pair() throws Exception {
        Gateway a=new Gateway();a.exit=new Gateway();a.set("pairId",PairController.newId());a.set("host","entry.example.net");a.exit.set("host","exit.example.net");return a;
    }
    @Test public void entryAndExitCredentialsHaveIndependentConsent() throws Exception {
        Gateway a=pair();a.sshPassword="entry-secret";a.exit.sshPassword="exit-secret";
        assertFalse(a.persisted().toString().contains("-secret"));
        a.data.put("remember",true);
        assertEquals("entry-secret",a.persisted().getString("sshPassword"));
        assertFalse(a.persisted().getJSONObject("pairExit").has("sshPassword"));
        a.data.put("remember",false);a.exit.data.put("remember",true);
        assertFalse(a.persisted().has("sshPassword"));assertEquals("exit-secret",a.persisted().getJSONObject("pairExit").getString("sshPassword"));
    }
    @Test public void savedModelRoundTripRestoresBothNodePinsAndPorts() throws Exception {
        Gateway a=pair();a.data.put("port",2222);a.exit.data.put("port",2200);a.set("fingerprint","SHA256:entry");a.exit.set("fingerprint","SHA256:exit");
        Gateway b=new Gateway(a.persisted());assertTrue(b.isPair());assertEquals(2222,b.port());assertEquals(2200,b.exit.port());assertEquals("SHA256:exit",b.exit.get("fingerprint"));
    }
    @Test public void managementEndpointCanDifferFromBackhaulAndVpnEndpoint() throws Exception {
        Gateway a=pair();a.set("vpnServer","vpn.example.net");a.set("exitEndpoint","tunnel.example.net");a.data.put("vpnPort",15500);
        JSONObject r=PairController.request(a,"entry");assertEquals("vpn.example.net",r.getString("server"));assertEquals("tunnel.example.net",r.getString("exit_host"));assertEquals(15500,r.getInt("vpn_port"));
        assertFalse(r.toString().contains("sshPassword"));
    }
    @Test public void unsafeEndpointAndMissingPairOwnershipAreRejected() throws Exception {
        Gateway a=pair();a.set("exitEndpoint","host; id");try{PairController.request(a,"entry");fail();}catch(java.io.IOException expected){}
        a.set("exitEndpoint","");a.set("pairId","../other");try{PairController.request(a,"entry");fail();}catch(java.io.IOException expected){}
    }
    @Test public void installerDigestMatchesServerOrderingAndContent() throws Exception {
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
        try(java.util.zip.ZipOutputStream zip=new java.util.zip.ZipOutputStream(out)) {
            for(String[] file:new String[][]{{"server/rookstride/a.py","nested"},{"server/rookstride-service","sibling"},{"gateway/c.sh","private"},{"twohop/b.sh","blocked"},{"server/a.py","owned"}}){zip.putNextEntry(new java.util.zip.ZipEntry(file[0]));zip.write(file[1].getBytes("UTF-8"));zip.closeEntry();}
        }
        java.security.MessageDigest expected=java.security.MessageDigest.getInstance("SHA-256");expected.update("server/a.pyownedserver/rookstride-servicesiblingserver/rookstride/a.pynestedtwohop/b.shblockedgateway/c.shprivate".getBytes("UTF-8"));
        StringBuilder hex=new StringBuilder();for(byte b:expected.digest())hex.append(String.format("%02x",b&255));
        assertEquals(hex.toString(),PairController.bundleDigest(()->new java.io.ByteArrayInputStream(out.toByteArray())));
    }
    @Test public void completeBundledInstallerMatchesPythonDigest() throws Exception {
        java.io.File folder=new java.io.File("src/main/assets");
        String expected=new String(java.nio.file.Files.readAllBytes(new java.io.File(folder,"gateway_bundle.sha256").toPath()),"UTF-8").trim();
        assertEquals(expected,PairController.bundleDigest(()->new java.io.FileInputStream(new java.io.File(folder,"gateway_bundle.zip"))));
    }
}
