package org.strongswan.android.rookstride;

import java.io.IOException;
import java.util.regex.*;
import org.json.JSONObject;

/** An early OS eligibility check; the remote installer verifies real prerequisites. */
public final class UbuntuCompatibility {
    private UbuntuCompatibility(){}
    public static boolean eligible(String os,String version){
        if(!"ubuntu".equals(os)||version==null)return false;
        Matcher m=Pattern.compile("([0-9]{2})\\.([0-9]{2})(?:\\.[0-9]+)?").matcher(version);
        if(!m.matches())return false;
        int year=Integer.parseInt(m.group(1)),month=Integer.parseInt(m.group(2));
        return month>=1&&month<=12&&(year>22||year==22&&month>=4);
    }
    public static void require(JSONObject probe,boolean modern)throws IOException{
        if(!eligible(probe.optString("os"),probe.optString("version")))throw new IOException("Use Ubuntu 22.04 or newer on each server. The versions can differ.");
        if(!modern&&!probe.optString("version").equals("24.04"))throw new IOException("This saved legacy pair requires Ubuntu 24.04. Set up a new Double VPN to use mixed versions.");
    }
}
