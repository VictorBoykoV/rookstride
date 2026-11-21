package org.strongswan.android.rookstride;

import org.json.*;
import org.junit.Test;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

public class ConnectionBundleTest {
    private interface Checked {void run()throws Exception;}
    private void rejects(Checked action)throws Exception {try{action.run();fail("Invalid collection accepted");}catch(IOException expected){assertNotNull(expected.getMessage());assertNull("Rejected payload must not survive in an exception cause",expected.getCause());}}
    private String roots()throws Exception{try(java.io.InputStream in=getClass().getResourceAsStream("/password-test-root.txt");java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream()){byte[] bytes=new byte[4096];for(int n;(n=in.read(bytes))!=-1;)out.write(bytes,0,n);return new String(out.toByteArray(),StandardCharsets.US_ASCII);}}
    private JSONObject envelope(String format,String content)throws Exception {return new JSONObject().put("format",format).put("name","rookstride-family"+(format.equals("ikev2")?".sswan":format.equals("awg")?".conf":format.equals("openvpn")?".ovpn":format.equals("xray")||format.equals("xhttp")?".txt":".rookvpn")).put("content",content);}
    private JSONObject ike(String user,String password)throws Exception {return envelope("ikev2",PasswordSignIn.withKnownPassword(PasswordSignIn.definition("ikev2","vpn.example.net",user,password,""),user,password).toString());}
    private String vless(String user){return "vless://"+user+"@vpn.example.net:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=www.example.net&sid=abcd&flow=xtls-rprx-vision#Family";}
    private JSONObject xray()throws Exception{return envelope("xray",vless("b74ab96c-a1db-4f4a-b10c-a784c92c5c21"));}
    private String awg(){byte[] privateKey=new byte[32],publicKey=new byte[32];Arrays.fill(privateKey,(byte)1);Arrays.fill(publicKey,(byte)2);return "[Interface]\nPrivateKey = "+Base64.getEncoder().encodeToString(privateKey)+"\nAddress = 10.80.0.2/32\nDNS = 10.80.0.1\n\n[Peer]\nPublicKey = "+Base64.getEncoder().encodeToString(publicKey)+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51820\nPersistentKeepalive = 25\n";}
    private String json(List<JSONObject> entries)throws Exception {JSONArray array=new JSONArray();for(JSONObject entry:entries)array.put(entry);return new JSONObject().put("schema",1).put("kind",ConnectionBundle.KIND).put("connections",array).toString();}

    @Test public void mixedTenMethodRoundTripPreservesExactClientBytesAndChosenPasswords()throws Exception {
        List<JSONObject> original=new ArrayList<>();original.add(ike("mina","  Chosen family secret!  "));original.add(envelope("awg",awg()));original.add(xray());
        original.add(envelope("xhttp",xray().getString("content").replace("type=tcp","type=xhttp").replace("flow=xtls-rprx-vision","flow=&path=%2F"+String.join("",Collections.nCopies(48,"a"))+"&mode=auto")));
        for(String protocol:new String[]{"openvpn","hysteria2","trusttunnel","naive"})original.add(envelope(protocol,PasswordSignIn.definition(protocol,"vpn.example.net","family.user","1",roots()).toString()));
        for(String protocol:new String[]{"outline","shadowsocks"})original.add(envelope(protocol,new JSONObject().put("schema",1).put("protocol",protocol).put("server","vpn.example.net").put("port",443).put("server_name","vpn.example.net").put("login","family").put("password","example-password").put("certificate",roots()).put("method","chacha20-ietf-poly1305").put("path","/"+String.join("",Collections.nCopies(48,"a"))).toString()));
        List<JSONObject> parsed=ConnectionBundle.parse(ConnectionBundle.pack(original));assertEquals(10,parsed.size());
        for(int i=0;i<original.size();i++){assertEquals(original.get(i).getString("format"),parsed.get(i).getString("format"));assertEquals(original.get(i).getString("content"),parsed.get(i).getString("content"));assertEquals(3,parsed.get(i).length());}
        assertEquals("  Chosen family secret!  ",new JSONObject(parsed.get(0).getString("content")).getJSONObject("local").getString("shared_secret"));
        assertEquals("1",new JSONObject(parsed.get(4).getString("content")).getString("password"));
    }
    @Test public void sourceAndParsedValuesAreIndependentAndNeverAcquireAdministratorData()throws Exception {
        JSONObject source=ike("navid","letters-only");String file=ConnectionBundle.pack(Collections.singletonList(source));source.put("content","changed");
        List<JSONObject> first=ConnectionBundle.parse(file);assertFalse(first.get(0).getString("content").equals("changed"));first.get(0).put("content","recipient change");
        assertTrue(ConnectionBundle.parse(file).get(0).getString("content").contains("letters-only"));assertFalse(file.contains("sshPassword"));assertFalse(file.contains("adminAccess"));
    }
    @Test public void privateIkeTrustIsRetainedAlongsideItsChosenPassword()throws Exception {
        byte[] certificate=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(roots().getBytes(StandardCharsets.US_ASCII))).getEncoded();
        JSONObject profile=new JSONObject(ike("family","chosen secret").getString("content"));String encoded=Base64.getEncoder().encodeToString(certificate);profile.getJSONObject("remote").put("cert",encoded);
        JSONObject actual=new JSONObject(ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(envelope("ikev2",profile.toString())))).get(0).getString("content"));
        assertEquals(encoded,actual.getJSONObject("remote").getString("cert"));assertEquals("chosen secret",actual.getJSONObject("local").getString("shared_secret"));
    }
    @Test public void differentUsersOnTheSameEndpointAndProtocolRemainSeparate()throws Exception {
        List<JSONObject> parsed=ConnectionBundle.parse(ConnectionBundle.pack(Arrays.asList(ike("mina","one"),ike("navid","two"))));assertEquals(2,parsed.size());
        assertEquals("mina",new JSONObject(parsed.get(0).getString("content")).getJSONObject("local").getString("eap_id"));
        assertEquals("navid",new JSONObject(parsed.get(1).getString("content")).getJSONObject("local").getString("eap_id"));
    }
    @Test public void exactDuplicateClientAccessIsRejectedEvenWithDifferentFilenames()throws Exception {
        JSONObject a=xray(),b=new JSONObject(a.toString()).put("name","rookstride-another.txt");rejects(()->ConnectionBundle.pack(Arrays.asList(a,b)));rejects(()->ConnectionBundle.parse(json(Arrays.asList(a,b))));
    }
    @Test public void collectionCountIsBoundedOnBothWriteAndRead()throws Exception {
        rejects(()->ConnectionBundle.pack(Collections.emptyList()));rejects(()->ConnectionBundle.parse(json(Collections.emptyList())));
        List<JSONObject> entries=new ArrayList<>();for(int i=0;i<17;i++)entries.add(ike("user"+i,"chosen"));
        rejects(()->ConnectionBundle.pack(entries));rejects(()->ConnectionBundle.parse(json(entries)));assertEquals(16,ConnectionBundle.parse(ConnectionBundle.pack(entries.subList(0,16))).size());
    }
    @Test public void individualAndTotalUtf8ByteLimitsAreEnforced()throws Exception {
        rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("xray",String.join("",Collections.nCopies(512001,"x"))))));
        rejects(()->ConnectionBundle.parse(String.join("",Collections.nCopies(ConnectionBundle.MAX_BYTES+1," "))));
        List<JSONObject> entries=new ArrayList<>();String padding="#"+String.join("",Collections.nCopies(300000,"x"))+"\n";
        String base="client\ndev tun\nremote vpn.example.net 1194\nremote-cert-tls server\n<ca>\nfixture\n</ca>\n<cert>\nfixture\n</cert>\n<key>\nfixture\n</key>\n";
        for(int i=0;i<16;i++)entries.add(envelope("openvpn",base+padding+"# distinct client "+i+"\n"));
        rejects(()->ConnectionBundle.pack(entries));
    }
    @Test public void administratorRecoveryAndUnknownOuterOptionsAreNotConnectionCollections()throws Exception {
        for(String kind:new String[]{"rookstride-administrator","rookstride-recovery","unknown"}){JSONObject root=new JSONObject(json(Collections.singletonList(xray()))).put("kind",kind);rejects(()->ConnectionBundle.parse(root.toString()));}
        JSONObject root=new JSONObject(json(Collections.singletonList(xray()))).put("sshPassword","not-client-data");rejects(()->ConnectionBundle.parse(root.toString()));
        JSONObject entry=xray().put("adminAccess",true);rejects(()->ConnectionBundle.pack(Collections.singletonList(entry)));
        rejects(()->ConnectionBundle.parse("{\"schema\":1,\"role\":\"owner\",\"invitation\":{}}"));
    }
    @Test public void versionsKindsAndEnvelopeTypesMustBeExact()throws Exception {
        String valid=json(Collections.singletonList(xray()));for(Object version:new Object[]{2,"1",true,JSONObject.NULL}){JSONObject root=new JSONObject(valid).put("schema",version);rejects(()->ConnectionBundle.parse(root.toString()));}
        rejects(()->ConnectionBundle.parse(valid.replace("\"schema\":1","\"schema\":1.0")));
        rejects(()->ConnectionBundle.parse(new JSONObject(valid).put("connections",new JSONObject()).toString()));
        rejects(()->ConnectionBundle.parse(new JSONObject(valid).put("connections",new JSONArray().put("not an envelope")).toString()));
        rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("unknown","sample"))));
        rejects(()->ConnectionBundle.pack(Collections.singletonList(xray().put("content",new JSONArray().put("sample")))));
    }
    @Test public void duplicateFieldsIncludingEscapedKeysAndTrailingDataAreRejected()throws Exception {
        String valid=json(Collections.singletonList(xray()));
        for(String malformed:new String[]{valid+" {}",valid.replace("\"schema\":1","\"schema\":1,\"schema\":1"),valid.replace("\"kind\":", "\"k\\u0069nd\":\"rookstride-connections\",\"kind\":"),valid.replace("\"schema\":1","\"schema\":01"),valid.replace("\"schema\"","schema"),valid.replace("{","{/*comment*/"),valid.substring(0,valid.length()-1)+",}",valid.replace("\"kind\"","'kind'"),"["+valid+"]"})rejects(()->ConnectionBundle.parse(malformed));
    }
    @Test public void badLastEntryRejectsTheWholeCollectionWithoutChangingEarlierObjects()throws Exception {
        JSONObject first=ike("mina","chosen"),last=xray().put("content","not a supported link");String before=first.toString();
        rejects(()->ConnectionBundle.parse(json(Arrays.asList(first,last))));assertEquals(before,first.toString());
    }
    @Test public void fullNativeValidatorsRejectMismatchedProtocolsUnsafeHooksAndArbitraryWorkerOptions()throws Exception {
        rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("awg","[Interface]\nPrivateKey = invalid\n"))));
        rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("xhttp",xray().getString("content")))));
        JSONObject worker=PasswordSignIn.definition("hysteria2","vpn.example.net","family","chosen",roots()).put("insecure",true);rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("hysteria2",worker.toString()))));
        JSONObject open=PasswordSignIn.definition("openvpn","vpn.example.net","family","chosen",roots());open.put("config",open.getString("config")+"up /tmp/script\n");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("openvpn",open.toString()))));
    }
    @Test public void passwordConnectionsCannotTriggerAnUnexpectedRecipientCredentialPrompt()throws Exception {
        JSONObject ike=new JSONObject(ike("family","chosen").getString("content"));ike.getJSONObject("local").remove("shared_secret");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("ikev2",ike.toString()))));
        JSONObject open=PasswordSignIn.definition("openvpn","vpn.example.net","family","chosen",roots());rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("openvpn",open.getString("config")))));
        String first="auth-user-pass\n"+open.getString("config").replace("auth-user-pass\n","");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("openvpn",first))));
        String indented=open.getString("config").replace("auth-user-pass\n","  auth-user-pass\n");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("openvpn",indented))));
    }
    @Test public void ikeGeneratedSubsetRejectsHiddenAdministrationAndUnsupportedRouting()throws Exception {
        JSONObject p=new JSONObject(ike("family","chosen").getString("content"));p.put("sshPassword","not-client-data");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("ikev2",p.toString()))));
        p.remove("sshPassword");p.getJSONObject("remote").put("cert","not-a-certificate");rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("ikev2",p.toString()))));
        p.getJSONObject("remote").remove("cert");p.getJSONObject("split-tunneling").put("block-ipv6",false);rejects(()->ConnectionBundle.pack(Collections.singletonList(envelope("ikev2",p.toString()))));
    }
    @Test public void deeplyNestedAndControlCharacterDocumentsFailWithSafeMessages()throws Exception {
        String nested=String.join("",Collections.nCopies(20,"["))+"null"+String.join("",Collections.nCopies(20,"]"));rejects(()->ConnectionBundle.parse(nested));
        rejects(()->ConnectionBundle.parse("{\"kind\":\"bad\nstring\"}"));
        JSONObject secret=xray().put("content",new JSONArray().put("DO-NOT-REFLECT-THIS-SECRET"));try{ConnectionBundle.pack(Collections.singletonList(secret));fail("Invalid collection accepted");}catch(IOException expected){assertFalse(expected.getMessage().contains("DO-NOT-REFLECT-THIS-SECRET"));assertNull(expected.getCause());}
    }
    @Test public void duplicateMembersInsideAnEmbeddedPasswordPayloadAreRejectedBeforePlatformDecoding()throws Exception {
        String worker=PasswordSignIn.definition("hysteria2","vpn.example.net","family","chosen",roots()).toString();worker=worker.substring(0,worker.length()-1)+",\"password\":\"different\"}";
        JSONObject entry=envelope("hysteria2",worker);rejects(()->ConnectionBundle.pack(Collections.singletonList(entry)));rejects(()->ConnectionBundle.parse(json(Collections.singletonList(entry))));
    }
    @Test public void optionalHumanLabelsSurviveWithoutChangingClientIdentityOrOlderFiles()throws Exception {
        JSONObject original=xray().put("display_name","Mina’s family connection");String text=ConnectionBundle.pack(Collections.singletonList(original));original.put("display_name","changed");
        JSONObject parsed=ConnectionBundle.parse(text).get(0);assertEquals("Mina’s family connection",parsed.getString("display_name"));parsed.put("display_name","recipient copy");assertEquals("Mina’s family connection",ConnectionBundle.parse(text).get(0).getString("display_name"));
        assertFalse(ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(xray()))).get(0).has("display_name"));
        JSONObject same=xray().put("display_name","Different label");rejects(()->ConnectionBundle.pack(Arrays.asList(xray(),same)));
    }
    @Test public void labelsAreBoundedVisibleMetadataAndNeverStructuredAuthority()throws Exception {
        for(Object label:new Object[]{"", "   ","\u00a0",String.join("",Collections.nCopies(101,"x")),"Line\nbreak","Hidden\u202erole",new JSONObject().put("role","owner"),12,JSONObject.NULL}){JSONObject entry=xray().put("display_name",label);rejects(()->ConnectionBundle.pack(Collections.singletonList(entry)));rejects(()->ConnectionBundle.parse(json(Collections.singletonList(entry))));}
        String hundred=String.join("",Collections.nCopies(100,"😀"));assertEquals(hundred,ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(xray().put("display_name",hundred)))).get(0).getString("display_name"));
    }
}
