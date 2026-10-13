package org.strongswan.android.rookstride;

import org.json.JSONException;
import org.json.JSONObject;
import java.util.UUID;

public final class Gateway {
    public final JSONObject data;
    public Gateway exit;
    public Gateway sshRelay;
    public String sshPassword = "", vpnPassword = "", privateKey = "";
    public Gateway() throws JSONException {
        data = new JSONObject(); data.put("id", UUID.randomUUID().toString());
    }
    public Gateway(JSONObject value) {
        data = value;
        sshPassword=value.optString("sshPassword");
        vpnPassword=value.optString("vpnPassword");
        privateKey=value.optString("privateKey");
        if(value.optJSONObject("pairExit")!=null) exit=new Gateway(value.optJSONObject("pairExit"));
        configureRelay();
    }
    public void configureRelay() {
        sshRelay=null;
        if(exit==null)return;
        exit.sshRelay=null;
        if(get("sshRoute").equals("entry-via-exit"))sshRelay=exit;
        else if(get("sshRoute").equals("exit-via-entry"))exit.sshRelay=this;
    }
    public String get(String name) { return data.optString(name); }
    public void set(String name, String value) { try { data.put(name,value); } catch(JSONException e) { throw new IllegalStateException(e); } }
    public boolean isPair() { return exit!=null; }
    public int port() { return data.optInt("port",22); }
    public boolean remember() { return data.optBoolean("remember",false); }
    public JSONObject persisted() throws JSONException {
        JSONObject copy=new JSONObject(data.toString());
        copy.remove("pairExit");
        if(exit!=null)copy.put("pairExit",exit.persisted());
        copy.remove("sshPassword"); copy.remove("vpnPassword"); copy.remove("privateKey");
        if (remember()) {
            copy.put("sshPassword",sshPassword); copy.put("vpnPassword",vpnPassword); copy.put("privateKey",privateKey);
        }
        return copy;
    }
    public Gateway swapped() throws Exception {
        if(exit==null)throw new IllegalStateException("A pair is required");
        Gateway next=exit;
        String route=get("sshRoute"),name=get("name"),login=get("vpnLogin");
        next.exit=this;exit=null;sshRelay=null;next.sshRelay=null;
        next.set("name",name);set("name",name+" · exit");
        next.set("pairId",PairController.newId());next.set("vpnLogin",login);next.vpnPassword=vpnPassword;
        next.set("vpnServer",next.get("host"));next.set("exitEndpoint",get("host"));
        next.data.put("vpnPort",data.optInt("vpnPort",500));next.data.put("tunnelPort",data.optInt("tunnelPort",443));next.data.put("pairStatistics",data.optBoolean("pairStatistics",true));
        next.set("sshRoute",route.equals("entry-via-exit")?"exit-via-entry":route.equals("exit-via-entry")?"entry-via-exit":"direct");
        set("sshRoute","direct");next.configureRelay();next.set("pairPhase","Fresh nodes · roles swapped");return next;
    }
}
