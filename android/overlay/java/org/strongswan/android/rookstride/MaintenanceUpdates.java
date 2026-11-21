package org.strongswan.android.rookstride;

import java.io.*;
import org.json.*;

/** Explicit helper revisions; engine packages remain separately pinned/tested. */
public final class MaintenanceUpdates {
 private MaintenanceUpdates(){}
 private static JSONObject call(Ssh ssh,PairController.Bundle source,JSONObject request)throws Exception {
  try(InputStream in=source.open()){return ssh.maintenance(in,request);}
 }
 public static JSONObject review(Gateway pair,PairController.Bundle source,PairController.Progress progress)throws Exception {
  if(!pair.isPair())throw new IOException("This helper update requires a managed Double VPN");
  try(PairSsh sessions=PairSsh.connect(pair,progress)){
   return new JSONObject().put("entry",call(sessions.entry,source,new JSONObject().put("action","review")))
     .put("exit",call(sessions.exit,source,new JSONObject().put("action","review")));
  }
 }
 public static JSONObject apply(Gateway pair,JSONObject reviewed,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
  JSONObject operation=pair.data.optJSONObject("helperUpdate");
  if(operation==null){operation=new JSONObject().put("review",reviewed).put("entry",PairController.newId()).put("exit",PairController.newId()).put("state","prepared");pair.data.put("helperUpdate",operation);saved.save();}
  if(operation.optString("state").equals("accepting")||operation.optString("state").equals("rolling-back"))throw new IOException("Resume the recorded helper completion before another update");
  try(PairSsh sessions=PairSsh.connect(pair,progress)){
   JSONObject overview=sessions.exit.pair(new JSONObject().put("command","overview").put("pair",pair.get("pairId")));
   String expected=operation.optString("expected_exit_ip",overview.getString("exit_ip"));operation.put("expected_exit_ip",expected);saved.save();
   // Stage both reviews before the first live mutation. A lost reply is resumed
   // with the same operation IDs; it is never interpreted as permission to reset.
   for(String role:new String[]{"exit","entry"}){
    JSONObject review=operation.getJSONObject("review").getJSONObject(role);
    if(!review.optBoolean("available"))continue;
    Ssh ssh=role.equals("entry")?sessions.entry:sessions.exit;
    JSONObject request=new JSONObject(review.toString()).put("action","prepare").put("operation",operation.getString(role)).put("confirmation","UPDATE HELPERS AND KEEP VPN USERS");
    progress.stage(0,"Preparing the "+role+" helper update; VPN users are retained");
    JSONObject prepared=call(ssh,source,request);operation.put(role+"_state",prepared);saved.save();
   }
   for(String role:new String[]{"exit","entry"}){
    if(!operation.getJSONObject("review").getJSONObject(role).optBoolean("available"))continue;
    Ssh ssh=role.equals("entry")?sessions.entry:sessions.exit;
    progress.stage(role.equals("exit")?1:2,"Updating the "+role+" helper; VPN users are retained");
    JSONObject state=call(ssh,source,new JSONObject().put("action","apply").put("operation",operation.getString(role)).put("expected_exit_ip",expected));
    operation.put(role+"_state",state);saved.save();
   }
   operation.put("state","verified");saved.save();return operation;
  }
 }
 public static JSONObject finish(Gateway pair,boolean rollback,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
  JSONObject operation=pair.data.optJSONObject("helperUpdate");if(operation==null)throw new IOException("No helper update is recorded");
  String intent=rollback?"rolling-back":"accepting",state=operation.optString("state");
  if((state.equals("accepting")||state.equals("rolling-back"))&&!state.equals(intent))throw new IOException("Resume the recorded "+(state.equals("accepting")?"acceptance":"rollback")+" on both servers");
  if(!rollback&&!state.equals("verified")&&!state.equals("accepting"))throw new IOException("Verify both helper updates before accepting them");
  // Persist the chosen terminal action before the first node commits it. A lost
  // reply must not offer the opposite action on a half-completed pair.
  operation.put("state",intent);saved.save();
  try(PairSsh sessions=PairSsh.connect(pair,progress)){
   // Restore the entry before retiring the exit helper to preserve reachability.
   for(String role:new String[]{"entry","exit"}){
    if(!operation.getJSONObject("review").getJSONObject(role).optBoolean("available"))continue;
    Ssh ssh=role.equals("entry")?sessions.entry:sessions.exit;
    JSONObject status=call(ssh,source,new JSONObject().put("action","status").put("operation",operation.getString(role)));
    if(status.optString("state").equals("not-started")){
     if(!rollback)throw new IOException("Both helper updates must be verified before acceptance");
     operation.put(role+"_state",status);saved.save();continue;
    }
    JSONObject result=call(ssh,source,new JSONObject().put("action",rollback?"rollback":"accept").put("operation",operation.getString(role)).put("confirmation","CLIENT TRAFFIC VERIFIED"));
    operation.put(role+"_state",result);saved.save();
   }
   operation.put("state",rollback?"rolled-back":"accepted");pair.data.put("lastHelperUpdate",operation);pair.data.remove("helperUpdate");saved.save();return operation;
  }
 }
}
