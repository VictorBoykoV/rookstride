package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class ConnectionExportTest {
    @Test public void nativeExportPreservesOnlyClientContentAndItsExtension()throws Exception{
        for(String[] p:new String[][]{{"awg","rook-0123456789.conf","[Interface]\nPrivateKey = fixture\n\n[Peer]\nEndpoint = vpn.example.net:51820\n"},
                {"openvpn","rookstride-phone.ovpn","client\n<key>\nfixture\n</key>\n"},
                {"xray","rookstride-phone.txt","vless://fixture@vpn.example.net:443?security=reality#Phone"},
                {"xhttp","rookstride-phone.txt","vless://fixture@vpn.example.net:443?security=reality&type=xhttp#Phone"},
                {"hysteria2","rookstride-phone.rookvpn","{\"protocol\":\"hysteria2\"}"},
                {"outline","rookstride-phone.rookvpn","{\"protocol\":\"outline\"}"},
                {"shadowsocks","rookstride-phone.rookvpn","{\"protocol\":\"shadowsocks\"}"},
                {"trusttunnel","rookstride-phone.rookvpn","{\"protocol\":\"trusttunnel\"}"},
                {"naive","rookstride-phone.rookvpn","{\"protocol\":\"naive\"}"}}){
            JSONObject response=new JSONObject().put("format",p[0]).put("name",p[1]).put("content",p[2]).put("administrator_password","must-not-export");
            ConnectionExport export=ConnectionExport.fromResponse(response);
            assertEquals(p[2],export.content);assertEquals(p[1],export.name);
            assertEquals(export.content,ConnectionExport.fromResponse(export.pending()).content);
            assertFalse(export.pending().toString().contains("must-not-export"));
        }
    }
    @Test public void ikeExportIsStrongSwanJsonWithPinnedCertificateAndNoInventedPassword()throws Exception{
        JSONObject response=new JSONObject().put("type","ikev2-eap").put("name","VPN").put("remote",new JSONObject().put("addr","vpn.example.net").put("cert","fixture-ca"))
                .put("local",new JSONObject().put("eap_id","phone"));
        ConnectionExport export=ConnectionExport.fromResponse(response);
        assertEquals("rookstride-phone.sswan",export.name);assertEquals("application/vnd.strongswan.profile",export.mime());
        JSONObject actual=new JSONObject(export.content);assertEquals("phone",actual.getJSONObject("local").getString("eap_id"));
        assertEquals("fixture-ca",actual.getJSONObject("remote").getString("cert"));assertFalse(actual.getJSONObject("local").has("password"));
    }
    @Test public void newlyCreatedIkeAccountRetainsItsChosenSharedSecret()throws Exception{
        JSONObject response=new JSONObject().put("type","ikev2-eap").put("remote",new JSONObject().put("addr","vpn.example.net").put("cert","fixture-ca"))
                .put("local",new JSONObject().put("eap_id","phone").put("shared_secret","SamplePass12"));
        JSONObject shared=new JSONObject(ConnectionExport.fromResponse(response).content);
        assertEquals("SamplePass12",shared.getJSONObject("local").getString("shared_secret"));
        assertEquals("fixture-ca",shared.getJSONObject("remote").getString("cert"));
    }
    @Test public void ikeFilenameIsSafeWithoutChangingAnAcceptedLogin()throws Exception{
        JSONObject response=new JSONObject().put("type","ikev2-eap").put("local",new JSONObject().put("eap_id","mina.reader@example"));
        ConnectionExport shared=ConnectionExport.fromResponse(response);
        assertEquals("rookstride-mina_reader_example.sswan",shared.name);
        assertEquals("mina.reader@example",new JSONObject(shared.content).getJSONObject("local").getString("eap_id"));
    }
    @Test public void savedAmneziaWgKeepsItsNativeFormatAndShortTunnelName()throws Exception{
        JSONObject stored=new JSONObject().put("protocol","awg").put("name","A long display name stays inside Rookstride").put("content","[Interface]\nPrivateKey = fixture\n");
        ConnectionExport export=ConnectionExport.fromStored("b74ab96c-a1db-4f4a-b10c-a784c92c5c21",stored);
        assertTrue(export.name.matches("rook-[0-9a-f]{10}\\.conf"));assertEquals(15,export.name.length()-5);assertEquals(stored.getString("content"),export.content);
        assertFalse(export.content.startsWith("vpn://"));
    }
    @Test public void unsafeNamesUnknownFormatsAndMismatchedExtensionsAreRejected()throws Exception{
        for(String[] p:new String[][]{{"unknown","rookstride-phone.txt"},{"awg","../../private.conf"},{"awg","rookstride-phone.txt"},{"xray","rookstride-phone.ovpn"}}){
            try{ConnectionExport.fromResponse(new JSONObject().put("format",p[0]).put("name",p[1]).put("content","fixture"));fail("Unexpected export accepted");}catch(java.io.IOException|IllegalArgumentException expected){}
        }
        for(String content:new String[]{"",new String(new char[512001]).replace('\0','x')}){
            try{ConnectionExport.fromResponse(new JSONObject().put("format","xray").put("name","rookstride-phone.txt").put("content",content));fail("Unbounded export accepted");}catch(java.io.IOException expected){}
        }
    }
}
