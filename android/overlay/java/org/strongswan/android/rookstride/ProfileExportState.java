package org.strongswan.android.rookstride;

import androidx.lifecycle.ViewModel;
import org.json.JSONObject;

/** A pending user-selected document export survives rotation, never process death. */
public final class ProfileExportState extends ViewModel {
    private JSONObject pending;
    private JSONObject invitation;
    private String collection;
    public void collection(String value){collection=value;}
    public boolean collectionPending(){return collection!=null;}
    public String takeCollection(){String value=collection;collection=null;return value;}
    public void invitation(JSONObject value){invitation=value;}
    public JSONObject takeInvitation(){JSONObject value=invitation;invitation=null;return value;}
    public void set(JSONObject profile){pending=profile;}
    public JSONObject take(){JSONObject value=pending;pending=null;return value;}
    @Override protected void onCleared(){pending=null;invitation=null;collection=null;}
}
