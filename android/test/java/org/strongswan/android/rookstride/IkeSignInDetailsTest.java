package org.strongswan.android.rookstride;
import org.json.*;import org.junit.Test;import static org.junit.Assert.*;
public class IkeSignInDetailsTest {
 private JSONObject profile()throws Exception{return new JSONObject().put("type","ikev2-eap").put("remote",new JSONObject().put("addr","vpn.example.net")).put("local",new JSONObject().put("eap_id","fixture-user").put("shared_secret","Sample123"));}
 @Test public void publicPasswordAccountHasReadableSignInDetailsWithoutCertificateBlob()throws Exception{String text=IkeSignInDetails.from(profile());assertNotNull(text);assertTrue(text.contains("Server: vpn.example.net\nUsername: fixture-user\nPassword: Sample123"));assertTrue(text.contains("Select automatically"));assertFalse(text.contains("uuid"));}
 @Test public void privateCertificateRequiresAccompanyingProfileAndStillShowsTheKnownPassword()throws Exception{JSONObject p=profile();p.getJSONObject("remote").put("cert","fixture certificate");String details=IkeSignInDetails.from(p);assertNotNull(details);assertTrue(details.contains("Password: Sample123"));assertTrue(details.contains("Import the accompanying .sswan connection file first"));assertFalse(details.contains("Select automatically"));assertFalse(details.contains("fixture certificate"));}
 @Test public void unknownPasswordOrCertificateAccountCannotPretendToBePasswordOnly()throws Exception{JSONObject p=profile();p.getJSONObject("local").remove("shared_secret");assertNull(IkeSignInDetails.from(p));p=profile();p.put("type","ikev2-cert");assertNull(IkeSignInDetails.from(p));}
}
