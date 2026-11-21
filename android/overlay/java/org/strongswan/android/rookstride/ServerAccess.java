package org.strongswan.android.rookstride;

import java.util.List;

/** Reuse only administrator access for the same server/account; VPN keys stay separate. */
public final class ServerAccess {
    private ServerAccess(){}
    /** An unset legacy remember flag is not an intentional opt-out. */
    public static boolean shouldRemember(Gateway node,boolean defaultEnabled){
        if(node==null)return defaultEnabled;
        if(node.data.optBoolean("saveAccessChosen"))return node.remember();
        return node.remember()||defaultEnabled;
    }
    public static boolean available(Gateway node){return !node.sshPassword.isEmpty()||!node.privateKey.isEmpty();}
    private static boolean sameAccount(Gateway a,Gateway b){
        return ServerProtocols.sameServer(a,b)&&a.get("admin").equals(b.get("admin"));
    }
    public static boolean reuse(List<Gateway> nodes,Gateway target){
        if(target.data.optBoolean("clientOnly"))return false;
        if(available(target))return true;
        java.util.ArrayList<Gateway> accounts=new java.util.ArrayList<>();for(Gateway source:nodes){accounts.add(source);if(source.exit!=null)accounts.add(source.exit);}
        for(Gateway source:accounts)if(!source.data.optBoolean("clientOnly")&&sameAccount(source,target)&&available(source)){
            target.sshPassword=source.sshPassword;target.privateKey=source.privateKey;
            try{if(!target.data.optBoolean("saveAccessChosen")){target.data.put("remember",source.remember());if(source.data.optBoolean("saveAccessChosen"))target.data.put("saveAccessChosen",true);}}catch(org.json.JSONException e){throw new IllegalStateException(e);}
            if(target.get("fingerprint").isEmpty())target.set("fingerprint",source.get("fingerprint"));
            return true;
        }
        return false;
    }
    public static void remember(List<Gateway> nodes,Gateway source,boolean enabled)throws Exception{
        if(source.data.optBoolean("clientOnly"))throw new IllegalArgumentException("Imported connections have no administrator access");
        source.data.put("remember",enabled);source.data.put("saveAccessChosen",true);
        java.util.ArrayList<Gateway> accounts=new java.util.ArrayList<>();for(Gateway target:nodes){accounts.add(target);if(target.exit!=null)accounts.add(target.exit);}
        for(Gateway target:accounts)if(target!=source&&!target.data.optBoolean("clientOnly")&&sameAccount(source,target)){
            target.sshPassword=source.sshPassword;target.privateKey=source.privateKey;target.data.put("remember",enabled);target.data.put("saveAccessChosen",true);
        }
    }
}
