package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class VpnDiagnosisTest {
    @Test public void separatesAndroidRouteDnsTlsAndWebsiteResponse() {
        assertEquals("vpn_route_unavailable",VpnDiagnosis.web(false,false,0,0,0,0).code);
        assertEquals("vpn_dns_failed",VpnDiagnosis.web(true,false,2,2,0,0).code);
        assertEquals("vpn_tls_failed",VpnDiagnosis.web(true,false,2,0,2,0).code);
        assertEquals("vpn_web_unreachable",VpnDiagnosis.web(true,false,2,1,0,0).code);
        assertEquals("vpn_web_response_rejected",VpnDiagnosis.web(true,false,2,1,0,1).code);
        assertEquals("vpn_web_verified",VpnDiagnosis.web(true,true,2,1,0,1).code);
    }
    @Test public void endpointLookupIsDifferentFromWebsiteDns() {
        assertEquals("vpn_endpoint_lookup_failed",VpnDiagnosis.ikev2("LOOKUP_FAILED").code);
        assertNotEquals(VpnDiagnosis.ikev2("LOOKUP_FAILED").code,VpnDiagnosis.web(true,false,2,2,0,0).code);
        assertEquals("vpn_auth_rejected",VpnDiagnosis.ikev2("AUTH_FAILED").code);
        assertEquals("vpn_server_identity_rejected",VpnDiagnosis.ikev2("PEER_AUTH_FAILED").code);
        assertEquals("vpn_credentials_missing",VpnDiagnosis.ikev2("PASSWORD_MISSING").code);
        assertEquals("vpn_credentials_missing",VpnDiagnosis.ikev2("CERTIFICATE_UNAVAILABLE").code);
        assertEquals("vpn_transport_unreachable",VpnDiagnosis.ikev2("UNREACHABLE").code);
    }
    @Test public void openvpnOnlyUsesExplicitStructuredEvents() {
        assertEquals("vpn_auth_rejected",VpnDiagnosis.openvpn("AUTH_FAILED").code);
        assertEquals("vpn_server_identity_rejected",VpnDiagnosis.openvpn("CERT_VERIFY_FAIL").code);
        assertEquals("vpn_unknown",VpnDiagnosis.openvpn("AUTH_FAILED secret-host password").code);
        assertEquals("vpn_unknown",VpnDiagnosis.openvpn(null).code);
    }
    @Test public void hostileStoredDiagnosticCannotInjectPrivateDataIntoReport() throws Exception {
        JSONObject hostile=new JSONObject().put("purpose","rookstride.support.diagnosis").put("schema",1)
            .put("category","password=private-value server=private.example").put("title","Secret title")
            .put("next_action","SECRET").put("raw_log","Private browsing history")
            .put("attempts",999999).put("dns_failures",-4);
        VpnDiagnosis.Result result=VpnDiagnosis.fromReport(hostile);
        String exported=result.supportReport("server.example/private-key",99999).toString();
        assertEquals("vpn_unknown",result.code);assertEquals(10,result.attempts);assertEquals(0,result.dnsFailures);
        for(String privatePart:new String[]{"private-value","private.example","Secret title","SECRET","Private browsing","private-key","server.example"})assertFalse(exported.contains(privatePart));
        assertEquals("unknown",new JSONObject(exported).getString("protocol"));
        assertEquals(100,new JSONObject(exported).getInt("android_api"));
    }
    @Test public void observationsRoundTripWithoutRawData() throws Exception {
        VpnDiagnosis.Result result=VpnDiagnosis.web(true,false,2,2,0,0);
        VpnDiagnosis.Result restored=VpnDiagnosis.fromReport(result.observation());
        assertEquals(result.code,restored.code);assertEquals(2,restored.dnsFailures);
        JSONObject report=restored.supportReport("hysteria2",36);
        assertEquals("hysteria2",report.getString("protocol"));assertEquals(36,report.getInt("android_api"));
        assertFalse(report.has("endpoint"));assertFalse(report.has("profile"));assertFalse(report.has("log"));
    }
    @Test public void noCheckDoesNotClaimWebSuccessOrRegionalBlocking() throws Exception {
        assertEquals("vpn_transport_ready",VpnDiagnosis.ikev2("NO_ERROR").code);
        assertEquals("vpn_unknown",VpnDiagnosis.fromReport(new JSONObject().put("category","vpn_web_verified")).code);
        assertFalse(VpnDiagnosis.web(true,false,2,2,0,0).detail.toLowerCase().contains("blocked"));
        assertFalse(VpnDiagnosis.of("vpn_transport_unreachable").detail.toLowerCase().contains("censored"));
        assertTrue(VpnDiagnosis.web(true,false,2,0,0,0).detail.contains("remains on"));
    }
}
