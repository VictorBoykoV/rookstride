package org.strongswan.android.rookstride;
import java.io.*;import org.json.*;
/** Lifecycle sidecar. Existing pair recipes and user/profile material are immutable. */
public final class LifecycleController {
 private LifecycleController(){}
 private static JSONObject call(Ssh ssh,PairController.Bundle bundle,JSONObject request)throws Exception{try(InputStream in=bundle.open()){return ssh.lifecycle(in,request);}}
 public static JSONObject inspect(Gateway pair,PairController.Bundle bundle,PairController.Progress progress)throws Exception{
  try(PairSsh sessions=PairSsh.connect(pair,progress)){
   JSONObject a=call(sessions.entry,bundle,new JSONObject().put("action","inspect")),b=call(sessions.exit,bundle,new JSONObject().put("action","inspect"));
   if(!a.optBoolean("recognized")||!b.optBoolean("recognized")||!a.optString("deployment").equals(b.optString("deployment"))||!a.optString("role").equals("entry")||!b.optString("role").equals("exit"))throw new IOException("The pinned servers do not describe the same owned Double VPN");
   JSONObject ap=a.getJSONObject("plan"),bp=b.getJSONObject("plan");
   if(!ap.optString("server").equals(bp.optString("server"))||!a.optString("exit_host").equals(bp.optString("exit_host")))throw new IOException("The pair members disagree about their current topology; inspect the recorded migration");
   JSONObject probes=new JSONObject().put("entry",sessions.entry.probe()).put("exit",sessions.exit.probe());
   if(probes.getJSONObject("entry").optString("machine").isEmpty()||probes.getJSONObject("entry").optString("machine").equals(probes.getJSONObject("exit").optString("machine")))throw new IOException("The pair must contain two independently identified servers");
   return new JSONObject().put("deployment",a.getString("deployment")).put("revision",a.getInt("revision")).put("entry",a).put("exit",b).put("probes",probes).put("read_only",a.optBoolean("read_only")||b.optBoolean("read_only"));
  }
 }
 public static JSONObject adopt(Gateway entry,Gateway exit,PairController.Bundle bundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{
  Gateway checked=new Gateway(new JSONObject(entry.persisted().toString()));checked.sshPassword=entry.sshPassword;checked.privateKey=entry.privateKey;checked.exit=exit;
  JSONObject inventory=inspect(checked,bundle,progress),plan=inventory.getJSONObject("entry").getJSONObject("plan");
  entry.exit=exit;entry.set("pairId",inventory.getString("deployment"));entry.set("pairEngine",plan.optString("engine"));entry.set("pairEntryProtocol",plan.optString("entry_protocol","ikev2"));entry.set("pairExitProtocol",plan.optString("exit_protocol","awg"));entry.set("vpnServer",plan.getString("server"));entry.set("exitEndpoint",inventory.getJSONObject("entry").getString("exit_host"));entry.data.put("vpnPort",plan.getInt("vpn_port")).put("tunnelPort",plan.getInt("tunnel_port")).put("deploymentInventory",inventory).put("deploymentRevision",inventory.getInt("revision")).put("pairReady",inventory.getJSONObject("entry").optBoolean("active"));entry.set("protocol",entry.get("pairEntryProtocol"));entry.set("mode","pair");saved.save();return inventory;
 }
 public static JSONObject replaceExit(Gateway pair,Gateway candidate,PairController.Bundle bundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{
  if(!pair.isPair()||!PairController.modern(pair))throw new IOException("Use an owned native Double VPN for exit replacement");
  if(candidate.get("fingerprint").isEmpty())throw new IOException("Verify and pin the replacement server before reviewing migration");
  JSONObject operation=pair.data.optJSONObject("lifecycleOperation");
  if(PairNodes.same(pair,candidate)||operation==null&&PairNodes.same(pair.exit,candidate))throw new IOException("The replacement must be a distinct server");
  if(operation==null){
   JSONObject inventory=inspect(pair,bundle,progress);
   if(inventory.optBoolean("read_only"))throw new IOException("This pair supports inspection only until its owned helper and installation are verified");
   operation=new JSONObject().put("operation",PairController.newId()).put("deployment",pair.get("pairId")).put("expected_revision",inventory.getInt("revision")).put("candidate",LifecycleSnapshots.copy(candidate)).put("previous",LifecycleSnapshots.copy(pair.exit)).put("previous_endpoint",pair.get("exitEndpoint")).put("state","preparing");
   pair.data.put("lifecycleOperation",operation);saved.save();
  }else if(!operation.getJSONObject("candidate").optString("host").equals(candidate.get("host")))throw new IOException("Resume the recorded replacement before choosing another server");
  if(operation.optJSONObject("request")!=null)return resumeReplacement(pair,candidate,operation,bundle,progress,saved);
  Gateway draft=new Gateway(new JSONObject(pair.persisted().toString()));draft.sshPassword=pair.sshPassword;draft.privateKey=pair.privateKey;draft.exit=candidate;draft.set("exitEndpoint",candidate.get("host"));draft.set("sshRoute","auto");
  progress.stage(0,"Checking the current and replacement servers");
  try(PairSsh current=PairSsh.connect(pair,progress);PairSsh replacement=PairSsh.connect(draft,progress)){
   Ssh fresh=replacement.exit;
   JSONObject old=current.exit.pair(new JSONObject().put("command","overview").put("pair",pair.get("pairId"))),probe=fresh.probe();
   if(probe.optString("machine").isEmpty()||probe.optString("machine").equals(current.entry.probe().optString("machine"))||probe.optString("machine").equals(current.exit.probe().optString("machine")))throw new IOException("The replacement must be a separate machine");
   UbuntuCompatibility.require(probe,true);operation.put("previous_exit_ip",old.getString("exit_ip"));saved.save();
   JSONObject preflight=PairController.request(draft,"exit").put("command","preflight");try(InputStream in=bundle.open()){fresh.pairStart(in,preflight);}
   progress.stage(1,"Preparing the replacement exit without changing entry users");
   PairController.step(fresh,candidate,PairController.bootstrapRequest(draft,"exit"),probe.optBoolean("pair_helper"),bundle,progress,true);
   PairController.step(fresh,candidate,PairController.request(draft,"exit").put("action","configure"),true,bundle,progress,true);
   JSONObject policy;try(InputStream in=bundle.open()){policy=current.exit.recovery(in,new JSONObject().put("action","filter-policy"));}try(InputStream in=bundle.open()){fresh.recovery(in,new JSONObject().put("action","apply-filter-policy").put("policy",policy).put("confirmation","PRESERVE REVIEWED FILTERING"));}
   // Each retained migration needs its own client identity. Reusing the exit's
   // initial AWG peer makes independent bridges overwrite each other's endpoint.
   JSONObject material;try(InputStream in=bundle.open()){material=fresh.recovery(in,new JSONObject().put("action","entry-bridge").put("deployment",pair.get("pairId")).put("operation",operation.getString("operation")));}
   JSONObject overview=fresh.pair(new JSONObject().put("command","overview").put("pair",pair.get("pairId")));
   JSONObject request=new JSONObject().put("action","prepare-exit").put("operation",operation.getString("operation")).put("deployment",pair.get("pairId")).put("expected_revision",operation.getInt("expected_revision")).put("exit_host",candidate.get("host")).put("tunnel_port",PairController.request(draft,"exit").getInt("tunnel_port")).put("transport",material).put("filter_policy",policy).put("expected_exit_ip",overview.getString("exit_ip")).put("confirmation","REPLACE EXIT AND KEEP ENTRY USERS");
   operation.put("request",request);saved.save();
  }
  return resumeReplacement(pair,candidate,operation,bundle,progress,saved);
 }
 private static JSONObject resumeReplacement(Gateway pair,Gateway candidate,JSONObject operation,PairController.Bundle bundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{
  try(Ssh entry=PairSsh.connectNode(pair,candidate,progress)){
   call(entry,bundle,operation.getJSONObject("request"));JSONObject result=null;
   for(String action:new String[]{"stage","cutover"}){progress.stage(action.equals("stage")?2:3,action.equals("stage")?"Testing isolated replacement routing and DNS":"Switching the guarded route; entry profiles remain unchanged");result=call(entry,bundle,new JSONObject().put("action",action).put("deployment",pair.get("pairId")).put("operation",operation.getString("operation")));operation.put("state",result.getString("state"));saved.save();}
   pair.exit=candidate;pair.set("exitEndpoint",candidate.get("host"));pair.set("sshRoute","auto");pair.set("resolvedSshRoute","");pair.configureRelay();pair.data.put("deploymentRevision",operation.getInt("expected_revision")+1);saved.save();return result;
  }
 }
 public static JSONObject finishExit(Gateway pair,boolean rollback,PairController.Bundle bundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{
  JSONObject operation=pair.data.optJSONObject("lifecycleOperation");if(operation==null)throw new IOException("No recorded replacement");
  try(Ssh ssh=PairSsh.connectNode(pair,rollback?new Gateway(operation.getJSONObject("previous")):pair.exit,progress)){
   JSONObject req=new JSONObject().put("action",rollback?"rollback":"accept").put("deployment",pair.get("pairId")).put("operation",operation.getString("operation"));
   if(rollback)req.put("previous_exit_ip",operation.getString("previous_exit_ip"));else req.put("confirmation","CLIENT TRAFFIC VERIFIED");
   JSONObject result=call(ssh,bundle,req);operation.put("state",result.getString("state"));
   if(rollback){pair.exit=new Gateway(operation.getJSONObject("previous"));pair.set("exitEndpoint",operation.optString("previous_endpoint"));pair.data.put("deploymentRevision",operation.getInt("expected_revision"));}
   pair.data.put("lastLifecycleOperation",operation);pair.data.remove("lifecycleOperation");saved.save();return result;
  }
 }
}
