package org.strongswan.android.rookstride;

import org.json.JSONObject;

/** Observed VPN failures. Never guesses censorship or exports raw connection data. */
public final class VpnDiagnosis {
    private VpnDiagnosis() {}

    public static final class Result {
        public final String code,title,detail,nextAction;
        public final int attempts,dnsFailures,tlsFailures,httpResponses;
        private Result(String code,int attempts,int dns,int tls,int http) {
            this.code=known(code);this.attempts=bounded(attempts);dnsFailures=bounded(dns);
            tlsFailures=bounded(tls);httpResponses=bounded(http);
            switch(this.code) {
                case "vpn_web_verified":title="Web access verified";detail="A secure website answered through this VPN. This checks the connection now; it does not test every website.";nextAction="Continue using the VPN";break;
                case "vpn_transport_ready":title="VPN connected";detail="The VPN connection is established. A separate web-access check has not completed.";nextAction="Try a website";break;
                case "vpn_no_underlying_network":title="No internet connection";detail="Android has no available Wi-Fi or mobile-data connection for the VPN.";nextAction="Connect to Wi-Fi or mobile data";break;
                case "vpn_route_unavailable":title="VPN route is not ready";detail="Android did not provide a usable VPN route. This is separate from the server’s SSH connection.";nextAction="Reconnect the VPN";break;
                case "vpn_dns_failed":title="Website names could not be resolved";detail="The test websites could not be found through the VPN. The VPN remains on; DNS or the tunnel may be unavailable.";nextAction="Check server ad blocking and DNS, then reconnect";break;
                case "vpn_tls_failed":title="Secure website check failed";detail="The secure website connection did not complete through the VPN. Check the phone’s date and time, then retry; this does not identify the underlying cause.";nextAction="Check date and time, then retry";break;
                case "vpn_web_response_rejected":title="The web test was inconclusive";detail="A website answered through the VPN, but its response did not confirm normal web access. The VPN remains on.";nextAction="Try a website or run the check again";break;
                case "vpn_web_unreachable":title="Web access did not respond";detail="The test could not get a website response through the VPN. This alone does not identify whether the network, server or test website is responsible. The VPN remains on.";nextAction="Retry the check or try another connection";break;
                case "vpn_auth_rejected":title="VPN sign-in was rejected";detail="The VPN reported an authentication failure. Check the user’s current connection details; server administrator access is a different sign-in.";nextAction="Review VPN user access";break;
                case "vpn_server_identity_rejected":title="VPN server identity could not be verified";detail="The VPN could not verify the server certificate or identity. Do not disable verification; check that this is the current connection profile.";nextAction="Review the server address and connection profile";break;
                case "vpn_endpoint_lookup_failed":title="VPN server name could not be found";detail="The phone could not resolve the VPN server’s address before connecting. This is different from website DNS inside the VPN.";nextAction="Check the server address and current network";break;
                case "vpn_credentials_missing":title="VPN sign-in details are missing";detail="This VPN connection needs its user credentials or certificate before it can connect.";nextAction="Review VPN user access";break;
                case "vpn_transport_unreachable":title="VPN server did not respond";detail="The VPN transport did not complete a connection. SSH access can still work because it uses a different connection.";nextAction="Try another network or VPN protocol";break;
                case "vpn_permission_required":title="VPN permission is needed";detail="Android has not allowed Rookstride to create this VPN connection.";nextAction="Reconnect and accept Android’s VPN request";break;
                case "vpn_process_interrupted":title="VPN process stopped";detail="Android stopped the VPN process before a clean disconnect. Check battery settings if this repeats.";nextAction="Reconnect the VPN";break;
                default:title="Connection needs attention";detail="The VPN could not complete this operation. Its connection log may show more detail.";nextAction="View the connection log";
            }
        }
        public JSONObject supportReport(String protocol,int androidApi) throws Exception {
            return new JSONObject().put("purpose","rookstride.support.diagnosis").put("schema",1)
                .put("category",code).put("protocol",protocol(protocol)).put("android_api",Math.max(0,Math.min(androidApi,100)))
                .put("attempts",attempts).put("dns_failures",dnsFailures).put("tls_failures",tlsFailures)
                .put("http_responses",httpResponses).put("next_action",nextAction);
        }
        public JSONObject observation() throws Exception {return supportReport("",0);}
    }
    private static int bounded(int value){return Math.max(0,Math.min(value,10));}
    private static String protocol(String value){
        if(value==null)return "unknown";
        switch(value){case "ikev2":case "awg":case "openvpn":case "xray":case "xhttp":case "hysteria2":case "outline":case "shadowsocks":case "trusttunnel":case "naive":return value;default:return "unknown";}
    }
    private static String known(String value){
        if(value==null)return "vpn_unknown";
        switch(value){case "vpn_web_verified":case "vpn_transport_ready":case "vpn_no_underlying_network":case "vpn_route_unavailable":case "vpn_dns_failed":case "vpn_tls_failed":case "vpn_web_response_rejected":case "vpn_web_unreachable":case "vpn_auth_rejected":case "vpn_server_identity_rejected":case "vpn_endpoint_lookup_failed":case "vpn_credentials_missing":case "vpn_transport_unreachable":case "vpn_permission_required":case "vpn_process_interrupted":return value;default:return "vpn_unknown";}
    }
    public static Result of(String code){return new Result(code,0,0,0,0);}
    public static Result web(boolean routeReady,boolean success,int attempts,int dns,int tls,int http){
        String code=success?"vpn_web_verified":!routeReady?"vpn_route_unavailable":attempts>0&&dns==attempts?"vpn_dns_failed":http>0?"vpn_web_response_rejected":attempts>0&&tls==attempts?"vpn_tls_failed":"vpn_web_unreachable";
        return new Result(code,attempts,dns,tls,http);
    }
    /** Decode only our closed-schema observations; never trust stored diagnostic prose. */
    public static Result fromReport(JSONObject value){
        if(value==null||value.optInt("schema")!=1||!"rookstride.support.diagnosis".equals(value.optString("purpose")))return of("vpn_unknown");
        return new Result(value.optString("category"),value.optInt("attempts"),value.optInt("dns_failures"),value.optInt("tls_failures"),value.optInt("http_responses"));
    }
    public static Result ikev2(String error){
        if(error==null)return of("vpn_unknown");
        switch(error){case "AUTH_FAILED":return of("vpn_auth_rejected");case "PEER_AUTH_FAILED":return of("vpn_server_identity_rejected");case "LOOKUP_FAILED":return of("vpn_endpoint_lookup_failed");case "UNREACHABLE":return of("vpn_transport_unreachable");case "PASSWORD_MISSING":case "CERTIFICATE_UNAVAILABLE":return of("vpn_credentials_missing");case "NO_ERROR":return of("vpn_transport_ready");default:return of("vpn_unknown");}
    }
    public static Result openvpn(String event){
        if(event==null)return of("vpn_unknown");
        switch(event){case "AUTH_FAILED":return of("vpn_auth_rejected");case "CERT_VERIFY_FAIL":case "PEER_CERT_VERIFY_FAILED":case "CERT_VERIFY_FAILED":return of("vpn_server_identity_rejected");case "RESOLVE_ERROR":return of("vpn_endpoint_lookup_failed");case "CONNECTION_TIMEOUT":case "CONNECTION_FAILED":return of("vpn_transport_unreachable");default:return of("vpn_unknown");}
    }
}
