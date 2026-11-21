package org.strongswan.android.rookstride.engine;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;

/** Small private diagnostic record. Never stores profiles, endpoints or credentials. */
final class EngineJournal {
    private final SharedPreferences prefs;
    EngineJournal(Context context,String protocol){prefs=context.getSharedPreferences("engine-journal-"+protocol,0);}
    void save(String id,String state,String error,String log){save(id,state,error,log,"");}
    void save(String id,String state,String error,String log,String diagnostic){prefs.edit().putString("id",id).putString("state",state).putString("error",error).putString("log",log).putString("diagnostic",diagnostic).apply();}
    void desired(String id){prefs.edit().putString("desired",id).commit();}
    String desired(){return prefs.getString("desired","");}
    Bundle previous(){
        Bundle b=new Bundle();b.putString("id",prefs.getString("id",""));b.putBoolean("desired",!desired().isEmpty()&&desired().equals(prefs.getString("id","")));String state=prefs.getString("state","disconnected");
        boolean interrupted=NativeVpn.isActive(state);b.putString("state",interrupted?"interrupted":state);
        b.putString("error",interrupted?"Android stopped the VPN process. Reconnect and check the phone’s battery settings.":prefs.getString("error",""));
        b.putString("diagnostic",prefs.getString("diagnostic",""));
        if(interrupted)try{b.putString("diagnostic",org.strongswan.android.rookstride.VpnDiagnosis.of("vpn_process_interrupted").observation().toString());}catch(Exception ignored){}
        b.putString("log",prefs.getString("log","")+(interrupted?"\nPrevious VPN process ended without a clean stop.":""));return b;
    }
}
