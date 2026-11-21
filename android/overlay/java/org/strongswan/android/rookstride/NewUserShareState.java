package org.strongswan.android.rookstride;

import androidx.lifecycle.ViewModel;
import org.json.JSONObject;

/** Memory-only completion state. Sharing retries never create a second account. */
public final class NewUserShareState extends ViewModel {
    public final UserShareSecrets recent=new UserShareSecrets();
    public volatile String nodeId="",login="",password="",failureCode="",failureDetail="";
    public volatile JSONObject profile,snapshot,scopedObject;
    public volatile boolean pending,loading,confirmed;
    public void begin(String id,String user,String secret){nodeId=id;login=user;password=secret;loading=true;failureCode="";failureDetail="";profile=null;snapshot=null;scopedObject=null;confirmed=false;pending=true;}
    public void created(String id,String user,String secret){begin(id,user,secret);confirmed=true;loading=false;}
    public void clear(){pending=false;nodeId="";login="";password="";failureCode="";failureDetail="";profile=null;snapshot=null;scopedObject=null;confirmed=false;}
    @Override protected void onCleared(){clear();recent.clear();}
}
