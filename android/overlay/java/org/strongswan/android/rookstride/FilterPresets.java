package org.strongswan.android.rookstride;
import org.json.*;
import java.util.*;

/** Display metadata compatible with existing helpers' enabled-filter responses. */
public final class FilterPresets {
    public static final String[][] OPTIONS={
        {"standard","Standard","AdGuard DNS filter","Everyday ad and tracker blocking, with fewer website interruptions.","https://github.com/AdguardTeam/AdGuardSDNSFilter"},
        {"strong","Strong","HaGeZi Multi PRO","Broader blocking of ads, trackers and telemetry. Some website features may need an exception.","https://github.com/hagezi/dns-blocklists"},
        {"strict","Strict","HaGeZi Multi PRO++","More aggressive ad and tracking blocking. More likely to interrupt websites or app features.","https://github.com/hagezi/dns-blocklists"}
    };
    private FilterPresets(){}
    public static String selected(JSONObject response){
        JSONArray filters=response.optJSONArray("filters");if(filters==null)return "custom";
        String found="";int enabled=0;
        for(int i=0;i<filters.length();i++){JSONObject filter=filters.optJSONObject(i);if(filter==null||!filter.optBoolean("enabled"))continue;enabled++;String name=filter.optString("name");for(String[] option:OPTIONS)if(option[2].equals(name))found=option[0];}
        return enabled==1&&!found.isEmpty()?found:"custom";
    }
}
