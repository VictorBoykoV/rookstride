package org.strongswan.android.rookstride;

import org.json.JSONException;
import org.json.JSONObject;
import java.util.UUID;

public final class Gateway {
    public final JSONObject data;
    public Gateway exit;
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
    }
    public String get(String name) { return data.optString(name); }
    public void set(String name, String value) { try { data.put(name,value); } catch(JSONException e) { throw new IllegalStateException(e); } }
    public boolean isPair() { return exit!=null; }
    public int port() { return data.optInt("port",22); }
    public boolean remember() { return data.optBoolean("remember",false); }
    public JSONObject persisted() throws JSONException {
        JSONObject copy=new JSONObject(data.toString());
        if(exit!=null)copy.put("pairExit",exit.persisted());
        copy.remove("sshPassword"); copy.remove("vpnPassword"); copy.remove("privateKey");
        if (remember()) {
            copy.put("sshPassword",sshPassword); copy.put("vpnPassword",vpnPassword); copy.put("privateKey",privateKey);
        }
        return copy;
    }
}
