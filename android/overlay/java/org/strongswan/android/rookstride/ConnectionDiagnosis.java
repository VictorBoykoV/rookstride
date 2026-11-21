package org.strongswan.android.rookstride;

import org.json.JSONObject;

/** Typed, bounded diagnosis. The shareable report excludes endpoints and raw exceptions. */
public final class ConnectionDiagnosis {
    private ConnectionDiagnosis(){}
    private static <T extends Throwable>T find(Throwable error,Class<T> type){
        for(int depth=0;error!=null&&depth<12;depth++,error=error.getCause())if(type.isInstance(error))return type.cast(error);
        return null;
    }
    public static boolean supported(Throwable error){return find(error,Ssh.Unreachable.class)!=null||find(error,Ssh.SignInRejected.class)!=null||find(error,Ssh.HostTrust.class)!=null;}
    public static String code(Throwable error){
        Ssh.HostTrust trust=find(error,Ssh.HostTrust.class);if(trust!=null)return trust.changed?"ssh_identity_changed":"ssh_identity_needed";
        if(find(error,Ssh.SignInRejected.class)!=null)return "ssh_sign_in_rejected";
        Ssh.Unreachable network=find(error,Ssh.Unreachable.class);if(network!=null)return network.relayAuthenticated?"ssh_relay_destination_unreachable":"ssh_server_unreachable";
        return "action_failed";
    }
    public static String title(Throwable error){
        switch(code(error)){
            case "ssh_identity_changed":return "Server identity changed";
            case "ssh_identity_needed":return "Verify this server";
            case "ssh_sign_in_rejected":return "Server sign-in was rejected";
            case "ssh_relay_destination_unreachable":return "The relay cannot reach this server";
            case "ssh_server_unreachable":return "Cannot reach the server";
            default:return "Action needs attention";
        }
    }
    public static String detail(Throwable error){
        Ssh.Unreachable network=find(error,Ssh.Unreachable.class);
        if(network!=null){
            if(network.relayAuthenticated)return "Connected to "+name(network.relayHost)+". SSH to "+name(network.targetHost)+" through that server did not complete. The connection between the servers, or SSH forwarding, needs checking.";
            return "SSH to "+name(network.targetHost)+" did not complete from this phone’s current connection. Check the address and port, or try another network.";
        }
        Ssh.SignInRejected auth=find(error,Ssh.SignInRejected.class);
        if(auth!=null)return name(auth.targetHost)+" answered but rejected administrator sign-in. Check its saved administrator name and password.";
        Ssh.HostTrust trust=find(error,Ssh.HostTrust.class);
        if(trust!=null)return trust.changed?"The server now presents a different SSH identity. If you rebuilt or replaced it, review the new identity before reconnecting.":"Remember this server’s identity before administrator sign-in.";
        return "The action could not finish. Review its progress or retry after checking server access.";
    }
    public static String nextAction(Throwable error){
        switch(code(error)){
            case "ssh_identity_changed":return "Review replacement server";
            case "ssh_identity_needed":return "Verify server identity";
            case "ssh_sign_in_rejected":return "Review server access";
            case "ssh_relay_destination_unreachable":return "Check the connection between servers";
            case "ssh_server_unreachable":return "Check server access";
            default:return "Review progress";
        }
    }
    private static String name(String host){return host.isEmpty()?"the server":host;}
    public static JSONObject supportReport(Throwable error)throws Exception{
        return new JSONObject().put("schema",1).put("category",code(error)).put("title",title(error))
            .put("nextAction",nextAction(error)).put("relayAuthenticated",find(error,Ssh.Unreachable.class)!=null&&find(error,Ssh.Unreachable.class).relayAuthenticated);
    }
}
