package org.strongswan.android.rookstride;

import androidx.lifecycle.ViewModel;
import java.util.HashMap;
import java.util.Map;

/** An unfinished form survives rotation in memory. No credentials enter saved state. */
public final class PairSetupState extends ViewModel {
    public int step;
    public boolean open, remember=true;
    public String entry="awg", exit="awg";
    private final Map<String,String> fields=new HashMap<>();
    public String get(String key,String fallback){return fields.containsKey(key)?fields.get(key):fallback;}
    public void put(String key,String value){fields.put(key,value);}
    public void swapServers(){
        for(String suffix:new String[]{"Saved","Host","User","Port","Password","Key","Remember"}){
            String a=fields.remove("entry"+suffix),b=fields.remove("exit"+suffix);
            if(b!=null)fields.put("entry"+suffix,b);if(a!=null)fields.put("exit"+suffix,a);
        }
        String route=get("relay","auto");put("relay",route.equals("entry-via-exit")?"exit-via-entry":route.equals("exit-via-entry")?"entry-via-exit":route.equals("auto")?"auto":"direct");
    }
    public void clear(){fields.clear();step=0;open=false;entry="awg";exit="awg";remember=true;}
    @Override protected void onCleared(){clear();}
}
