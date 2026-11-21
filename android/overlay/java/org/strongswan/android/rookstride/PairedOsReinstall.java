package org.strongswan.android.rookstride;
import java.io.*;import org.json.*;
/** Serialized destructive jobs. The usable SSH relay is always erased last. */
public final class PairedOsReinstall {
 private PairedOsReinstall(){}
 public interface BeforeErase { void check() throws Exception; }
 private static String route(Gateway pair){String selected=pair.get("sshRoute");return selected.isEmpty()||selected.equals("auto")?pair.get("resolvedSshRoute"):selected;}
 public static String[] order(String route)throws IOException{
  if(route.equals("entry-via-exit"))return new String[]{"entry","exit"};
  if(route.equals("exit-via-entry")||route.equals("direct"))return new String[]{"exit","entry"};
  throw new IOException("A proven management path independent of this VPN is required");
 }
 public static JSONObject prepare(Gateway pair,String entryVersion,String exitVersion,boolean independentAccess,PairController.Bundle reinstallBundle,PairController.Progress progress)throws Exception{
  if(!pair.isPair()||!independentAccess)throw new IOException("Confirm independent SSH or rescue access before reviewing a paired disk wipe");
  if(pair.data.optJSONObject("pairedOsOperation")!=null)throw new IOException("Resume the existing paired OS operation before planning another wipe");
  try(PairSsh sessions=PairSsh.connect(pair,progress)){
   JSONObject a=sessions.entry.probe(),b=sessions.exit.probe();if(a.optString("machine").isEmpty()||a.optString("machine").equals(b.optString("machine")))throw new IOException("Two distinct pinned machines are required");
   String route=route(pair);String[] sequence=order(route);String coordinator=PairController.newId();
   JSONObject plans=new JSONObject();for(String role:new String[]{"entry","exit"})try(InputStream in=reinstallBundle.open()){plans.put(role,(role.equals("entry")?sessions.entry:sessions.exit).reinstall(in,new JSONObject().put("action","plan").put("paired_operation",coordinator).put("version",role.equals("entry")?entryVersion:exitVersion)));}
   return new JSONObject().put("schema",1).put("operation",coordinator).put("deployment",pair.get("pairId")).put("expected_revision",pair.data.optInt("deploymentRevision",1)).put("mode","clean").put("order",new JSONArray(sequence)).put("route",route).put("plans",plans).put("verified",new JSONArray()).put("phase","reviewed").put("independent_access",true).put("warning","Both system disks, VPN users and VPN trust identities will be erased. Administrator grants are not restored.");
  }
 }
 public static JSONObject run(Gateway pair,JSONObject reviewed,boolean resume,PairController.Bundle reinstallBundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{return run(pair,reviewed,resume,reinstallBundle,progress,saved,()->{});}
 public static JSONObject run(Gateway pair,JSONObject reviewed,boolean resume,PairController.Bundle reinstallBundle,PairController.Progress progress,OsReinstall.Saved saved,BeforeErase beforeErase)throws Exception{return runInternal(pair,reviewed,resume,false,reinstallBundle,progress,saved,beforeErase);}
 private static JSONObject runInternal(Gateway pair,JSONObject reviewed,boolean resume,boolean recoveryVerified,PairController.Bundle reinstallBundle,PairController.Progress progress,OsReinstall.Saved saved,BeforeErase beforeErase)throws Exception{
  JSONObject operation=pair.data.optJSONObject("pairedOsOperation");
  JSONObject selected=resume?operation:reviewed;if(selected!=null&&selected.optString("mode").equals("restore")&&!recoveryVerified)throw new IOException("Decrypt and verify the reviewed owner archive before erasing either node");
  if(!resume){
   if(operation!=null)throw new IOException("A paired operation already exists; resume it instead");
   if(!(reviewed.optString("mode").equals("clean")||reviewed.optString("mode").equals("restore"))||!reviewed.optBoolean("independent_access")||!reviewed.optString("deployment").equals(pair.get("pairId"))||reviewed.optInt("expected_revision")!=pair.data.optInt("deploymentRevision",1))throw new IOException("The reviewed paired wipe no longer matches this deployment");
   operation=new JSONObject(reviewed.toString());pair.data.put("pairedOsOperation",operation).put("pairReady",false);saved.save();
  }
  if(operation==null)throw new IOException("No recorded paired OS operation");
  JSONArray sequence=operation.getJSONArray("order"),verified=operation.getJSONArray("verified");String[] expectedOrder=order(operation.getString("route"));
  if(sequence.length()!=2||verified.length()>2||!sequence.getString(0).equals(expectedOrder[0])||!sequence.getString(1).equals(expectedOrder[1])||!InputRules.job(operation.optString("operation")))throw new IOException("Invalid recorded paired maintenance dependencies");
  for(int i=0;i<verified.length();i++)if(!verified.getString(i).equals(sequence.getString(i)))throw new IOException("The recorded return-verification order changed");
  for(int index=verified.length();index<sequence.length();index++){
   if(Thread.currentThread().isInterrupted())throw new IOException("Paired maintenance paused before the next disk erase; resume its recorded jobs");
   String role=sequence.getString(index);Gateway node=role.equals("entry")?pair:pair.exit;
   JSONObject plan=operation.getJSONObject("plans").getJSONObject(role);
   if(node.data.optJSONObject("osReinstall")!=null&&!node.data.getJSONObject("osReinstall").optString("job").equals(plan.getString("job"))&&node.get("osReinstallState").equals("complete")){node.data.put("lastOsReinstall",node.data.getJSONObject("osReinstall"));node.data.remove("osReinstall");node.data.remove("osReinstallState");saved.save();}
   boolean alreadyStarted=node.data.optJSONObject("osReinstall")!=null;
   if(alreadyStarted&&!node.data.getJSONObject("osReinstall").optString("job").equals(plan.getString("job")))throw new IOException("Another OS job is recorded on this node");
   // Rediscovery is read-only and cannot silently alter the reviewed erase order.
   if(!alreadyStarted)try(PairSsh sessions=PairSsh.connect(pair,progress)){
    String current=route(pair);
    if(index==0&&!order(current)[0].equals(role))throw new IOException("Management dependencies changed; no disk was erased. Review a new plan.");
    if(index>0){String first=sequence.getString(0);Gateway returned=first.equals("entry")?pair:pair.exit;JSONObject actual=(first.equals("entry")?sessions.entry:sessions.exit).probe(),firstPlan=operation.getJSONObject("plans").getJSONObject(first);if(!returned.get("osReinstallState").equals("complete")||!actual.optString("os").equals("ubuntu")||!actual.optString("version").equals(firstPlan.getString("version"))||!returned.get("fingerprint").equals(firstPlan.getString("fingerprint")))throw new IOException("The first node has not verified its planned OS and SSH identity; the second disk remains untouched");}
   }
   if(!alreadyStarted)beforeErase.check();
   operation.put("phase","reinstalling-"+role).put("active_node",role);saved.save();
   final int offset=index*6;final String currentRole=role;OsReinstall.run(node,plan,alreadyStarted,reinstallBundle,new PairController.Progress(){public void update(String phase){progress.update(currentRole+" · "+phase);}public void stage(int stage,String phase){progress.stage(offset+stage,currentRole+" · "+phase);}},saved);
   verified.put(role);operation.put("phase","verified-"+role);saved.save();
  }
  operation.put("phase","clean-nodes-ready");pair.data.put("deploymentRevision",operation.getInt("expected_revision")+1);saved.save();
  return new JSONObject().put("state","clean-nodes-ready").put("operation",operation.getString("operation")).put("next","Choose new VPN users and install the exit before the entry. Old profiles require replacement.");
 }
 private static String archiveDigest(JSONObject archive)throws Exception{byte[] hash=java.security.MessageDigest.getInstance("SHA-256").digest(archive.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));StringBuilder value=new StringBuilder();for(byte b:hash)value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}
 private static void restoredGeneration(Gateway node,JSONObject snapshot,JSONObject result,OsReinstall.Saved saved)throws Exception{
  String previous=snapshot.getJSONObject("state").getString("instance"),next=result.optString("usage_generation"),job=node.data.getJSONObject("osReinstall").getString("job");
  if(!result.optBoolean("restored")||!InputRules.job(previous)||!InputRules.job(next)||!InputRules.job(job))throw new IOException("The restored VPN did not return a verified instance generation");
  if(job.equals(node.get("osRestoredJob"))&&(!previous.equals(node.get("osRestoredPreviousInstance"))||!next.equals(node.get("osRestoredInstance"))))throw new IOException("The recorded restored VPN generation changed; inspect this operation before continuing");
  node.set("osRestoredPreviousInstance",previous);node.set("osRestoredInstance",next);node.set("osRestoredJob",job);node.set("serverInstance",next);node.data.remove("snapshot");node.data.remove("statisticsCheckedAt");saved.save();
 }
 public static JSONObject prepareRestore(Gateway pair,String entryVersion,String exitVersion,boolean independentAccess,JSONObject archive,PairController.Bundle reinstallBundle,PairController.Bundle gatewayBundle,PairController.Progress progress)throws Exception{
  OwnerRecovery.validateRestore(pair,archive);JSONObject readiness=OwnerRecovery.rehearse(pair,archive,gatewayBundle,progress);
  if(readiness.optInt("readiness_schema")!=2||!readiness.optBoolean("verified"))throw new IOException("Complete the pair recovery contract review before preparing a disk wipe");
  return prepare(pair,entryVersion,exitVersion,independentAccess,reinstallBundle,progress).put("mode","restore").put("recovery_schema",2).put("recovery_digest",archiveDigest(archive)).put("warning","Both system disks are erased. Only the reviewed VPN identities and users return. Other VPNs and applications are erased. Administrator grants and SSH identities are replaced.");
 }
 static JSONObject restoreBootstrapRequest(Gateway pair,String role,JSONObject archive)throws Exception{
  JSONObject request=PairController.bootstrapRequest(pair,role);
  // Bootstrap metadata belongs to the replacement server, not the selected phone account.
  if(role.equals("entry")){JSONObject initial=archive.getJSONObject("nodes").getJSONObject("entry").getJSONObject("initial_user");request.put("login",initial.getString("login")).put("password",initial.getString("password"));}
  return request;
 }
 public static JSONObject runRestore(Gateway pair,JSONObject reviewed,boolean resume,JSONObject archive,PairController.Bundle reinstallBundle,PairController.Bundle gatewayBundle,PairController.Progress progress,OsReinstall.Saved saved)throws Exception{return runRestore(pair,reviewed,resume,archive,reinstallBundle,gatewayBundle,progress,saved,()->{});}
 public static JSONObject runRestore(Gateway pair,JSONObject reviewed,boolean resume,JSONObject archive,PairController.Bundle reinstallBundle,PairController.Bundle gatewayBundle,PairController.Progress progress,OsReinstall.Saved saved,BeforeErase beforeErase)throws Exception{
  OwnerRecovery.validateRestore(pair,archive);JSONObject recorded=resume?pair.data.getJSONObject("pairedOsOperation"):reviewed;
  if(recorded.optInt("recovery_schema")!=2||!recorded.optString("mode").equals("restore")||!archiveDigest(archive).equals(recorded.optString("recovery_digest")))throw new IOException("Decrypt the exact recovery package and complete its pair contract review before this paired wipe");
  if(!recorded.optString("phase").equals("restored")){
   if(!recorded.optString("phase").startsWith("restoring")&&!recorded.optString("phase").equals("clean-nodes-ready"))runInternal(pair,reviewed,resume,true,reinstallBundle,progress,saved,beforeErase);
   JSONObject operation=pair.data.getJSONObject("pairedOsOperation");operation.put("phase","restoring-vpn");saved.save();
   try(PairSsh sessions=PairSsh.connect(pair,progress)){
    for(String role:new String[]{"exit","entry"}){
     Ssh ssh=role.equals("entry")?sessions.entry:sessions.exit;Gateway node=role.equals("entry")?pair:pair.exit;
     progress.stage(role.equals("exit")?12:13,role.equals("exit")?"Restoring exit VPN identity and filtering":"Restoring entry VPN identity and users");
     PairController.step(ssh,node,restoreBootstrapRequest(pair,role,archive),ssh.probe().optBoolean("pair_helper"),gatewayBundle,progress,true);
     if(role.equals("exit")){
      try(InputStream in=gatewayBundle.open()){JSONObject snapshot=archive.getJSONObject("nodes").getJSONObject(role);restoredGeneration(node,snapshot,ssh.recovery(in,new JSONObject().put("action","restore").put("snapshot",snapshot).put("confirmation","RESTORE REVIEWED VPN IDENTITY")),saved);}
      PairController.step(ssh,node,PairController.request(pair,role).put("action","configure"),true,gatewayBundle,progress,true);
     }else{
      JSONObject material=sessions.exit.pair(new JSONObject().put("command","material").put("pair",pair.get("pairId")));
      PairController.step(ssh,node,PairController.request(pair,role).put("action","configure").put("transport",material),true,gatewayBundle,progress,true);
      try(InputStream in=gatewayBundle.open()){JSONObject snapshot=archive.getJSONObject("nodes").getJSONObject(role);restoredGeneration(node,snapshot,ssh.recovery(in,new JSONObject().put("action","restore").put("snapshot",snapshot).put("confirmation","RESTORE REVIEWED VPN IDENTITY")),saved);}
     }
    }
    String expected=sessions.exit.pair(new JSONObject().put("command","overview").put("pair",pair.get("pairId"))).getString("exit_ip");
    for(String action:new String[]{"verify","activate"}){progress.stage(action.equals("verify")?14:15,action.equals("verify")?"Verifying the restored exit route and DNS":"Activating restored client forwarding");PairController.step(sessions.entry,pair,PairController.request(pair,"entry").put("action",action).put("expected_exit_ip",expected).put("filtering_enabled",archive.getJSONObject("nodes").getJSONObject("exit").getJSONObject("filter_policy").getBoolean("enabled")).put("repeat",true),true,gatewayBundle,progress,true);}
   }
   try(PairSsh sessions=PairSsh.connect(pair,progress)){for(Ssh ssh:new Ssh[]{sessions.entry,sessions.exit})try(InputStream in=gatewayBundle.open()){ssh.entryMigration(in,new JSONObject().put("action","record-revision").put("deployment",pair.get("pairId")).put("operation",operation.getString("operation")).put("revision",operation.getInt("expected_revision")+1));}}
   operation.put("phase","restored");pair.data.put("pairReady",true);saved.save();
  }
  return new JSONObject().put("state","restored").put("saved_profiles_retained",true).put("client_verification_required",true).put("administrator_grants_restored",false);
 }

}
