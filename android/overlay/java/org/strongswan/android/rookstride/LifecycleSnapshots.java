package org.strongswan.android.rookstride;

import org.json.JSONObject;

/** Rollback identity snapshots retain current state, not recursively nested
 * completed-operation history. This never changes the live Gateway or receipt. */
public final class LifecycleSnapshots {
    private LifecycleSnapshots(){}
    public static JSONObject copy(Gateway gateway)throws Exception{
        JSONObject snapshot=gateway.persisted();compact(snapshot);return snapshot;
    }
    private static void compact(JSONObject gateway)throws Exception{
        for(String name:new String[]{"lastEntryMigration","lastLifecycleOperation"}){
            JSONObject record=gateway.optJSONObject(name);
            if(record!=null&&record.opt("state") instanceof String){
                String state=record.getString("state");
                if(state.equals("accepted")||state.equals("rolled-back"))gateway.remove(name);
            }
        }
        // Only Gateway structure is traversed. Pending operation records and
        // unrelated application metadata are opaque and remain complete.
        JSONObject exit=gateway.optJSONObject("pairExit");if(exit!=null)compact(exit);
    }
}
