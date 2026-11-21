package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

/** Real 100-codepoint envelope limit: never truncate a selected account to fit its server label. */
public final class ConnectionCollectionDisplayNameTest {
    private JSONObject access()throws Exception{return ConnectionExport.fromResponse(PasswordSignIn.withKnownPassword(PasswordSignIn.definition("ikev2","vpn.example.net","family","chosen",""),"family","chosen")).pending();}
    @Test public void everyCurrentProtocolKeepsTheFullLongestValidAccountWithinThePortableLimit()throws Exception{
        String login=String.join("",Collections.nCopies(64,"u")),server=String.join("",Collections.nCopies(80,"s"));Set<String> names=new HashSet<>();
        for(SingleProtocols protocol:SingleProtocols.values()){
            String prefix=protocol.title+" · "+login,label=ConnectionCollectionProfiles.displayName(protocol.id,login,server);
            assertTrue("Protocol/account no longer fits the schema; update its human protocol title",prefix.codePointCount(0,prefix.length())<=100);
            assertTrue("The selected VPN account was shortened",label.startsWith(prefix));assertTrue(label.codePointCount(0,label.length())<=100);assertTrue("Different protocols produced the same recipient label",names.add(label));
            if(label.length()>prefix.length())assertTrue("Truncation must apply only to the server suffix",label.startsWith(prefix+" · "));else assertEquals(prefix,label);
            JSONObject entry=access().put("display_name",label);assertEquals(label,ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(entry))).get(0).getString("display_name"));
            assertEquals("Generated labels must be deterministic",label,ConnectionCollectionProfiles.displayName(protocol.id,login,server));
        }
    }
    @Test public void aServerWithoutUsefulRoomIsOmittedInsteadOfMakingTheAccountLookTruncated(){
        String login=String.join("",Collections.nCopies(64,"x"));String label=ConnectionCollectionProfiles.displayName("shadowsocks",login,"Server with a long friendly name");assertEquals(SingleProtocols.SHADOWSOCKS.title+" · "+login,label);assertFalse(label.endsWith("…"));
    }
    @Test public void serverEllipsisRespectsUnicodeBoundariesAndKeepsTheShortIdentity()throws Exception{
        String server=String.join("",Collections.nCopies(100,"😀")),label=ConnectionCollectionProfiles.displayName("awg","mina",server);
        assertTrue(label.startsWith(SingleProtocols.AWG.title+" · mina · "));assertTrue(label.endsWith("…"));assertEquals(100,label.codePointCount(0,label.length()));assertFalse(label.codePoints().anyMatch(c->c>=0xD800&&c<=0xDFFF));
        JSONObject entry=access().put("display_name",label);assertEquals(label,ConnectionBundle.parse(ConnectionBundle.pack(Collections.singletonList(entry))).get(0).getString("display_name"));
    }
    @Test public void ordinaryNamesAreUnchangedAndUnsafeServerDirectionControlsAreSanitized(){
        assertEquals("OpenVPN · mina · Home",ConnectionCollectionProfiles.displayName("openvpn","mina","Home"));assertEquals("IKEv2 · mina",ConnectionCollectionProfiles.displayName("ikev2","mina","  "));
        assertEquals("OpenVPN · mina · Home Room",ConnectionCollectionProfiles.displayName("openvpn","mina","Home\u202eRoom"));
    }
}
