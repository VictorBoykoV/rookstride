package org.strongswan.android.rookstride;

import org.json.*;
import java.util.*;

/** Physical VPS identity is independent of its current VPN role or protocol. */
public final class PairNodes {
 private PairNodes(){}
 public static boolean same(Gateway a,Gateway b){
  if(a==null||b==null||a.data.optBoolean("clientOnly")||b.data.optBoolean("clientOnly"))return false;
  if(a==b||a.get("id").equals(b.get("id")))return true;
  String ap=a.get("fingerprint"),bp=b.get("fingerprint");if(!ap.isEmpty()&&!bp.isEmpty()&&!ap.equals(bp))return false;
  if(!a.get("machine").isEmpty()&&a.get("machine").equals(b.get("machine"))&&!ap.isEmpty()&&ap.equals(bp))return true;
  return !a.get("host").isEmpty()&&a.get("host").equalsIgnoreCase(b.get("host"))&&a.port()==b.port();
 }
 public static Gateway owner(List<Gateway> nodes,Gateway node){for(Gateway candidate:nodes)if(candidate.isPair()&&(same(candidate,node)||same(candidate.exit,node)))return candidate;return null;}
 public static String role(Gateway owner,Gateway node){return owner!=null&&same(owner,node)?"entry":"exit";}
 public static Gateway find(List<Gateway> nodes,String id){for(Gateway node:nodes){if(node.get("id").equals(id))return node;if(node.exit!=null&&node.exit.get("id").equals(id))return node.exit;}return null;}
 /** Keep authenticated health identities on their own members. Callers retire
  * connection/credential caches only for the returned, previously known changes. */
 public static List<Gateway> rememberHealth(Gateway pair,JSONObject result)throws JSONException{
  if(pair==null||!pair.isPair())throw new IllegalArgumentException("A saved pair is required");
  JSONObject[] reports={result.getJSONObject("entry"),result.getJSONObject("exit")};
  String[] identities={healthIdentity(reports[0]),healthIdentity(reports[1])};
  Gateway[] members={pair,pair.exit};ArrayList<Gateway> changed=new ArrayList<>();
  for(int i=0;i<members.length;i++){
   Gateway member=members[i];String identity=identities[i],previous=member.get("serverInstance");
   if(!identity.isEmpty()){
    if(!previous.isEmpty()&&!previous.equals(identity))changed.add(member);
    member.set("serverInstance",identity);
   }
   member.data.put("snapshot",reports[i]);
  }
  return changed;
 }
 private static String healthIdentity(JSONObject report)throws JSONException{
  Object value=report.opt("instance");if(value==null||value==JSONObject.NULL)return "";
  if(!(value instanceof String)||((String)value).length()>128||((String)value).codePoints().anyMatch(Character::isISOControl))throw new JSONException("Invalid VPN installation identity");
  return (String)value;
 }
 public static List<Gateway> catalog(List<Gateway> nodes){
  ArrayList<Gateway> result=new ArrayList<>();
  for(Gateway root:nodes)for(Gateway node:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root)){
   int at=-1;for(int i=0;i<result.size();i++)if(same(result.get(i),node)){at=i;break;}
   if(at<0)result.add(node);else if(root.isPair())result.set(at,node);
  }
  return result;
 }
 public static Gateway copy(Gateway source)throws JSONException{
  JSONObject value=new JSONObject(source.data.toString());value.remove("pairExit");Gateway node=new Gateway(value);node.sshPassword=source.sshPassword;node.privateKey=source.privateKey;node.vpnPassword=source.vpnPassword;node.exit=null;node.sshRelay=source.sshRelay;return node;
 }
 public static void clearConnection(Gateway node){for(String key:new String[]{"favorite","coexistPair","probe","snapshot","profileUuid","nativeProfile","serverInstance","job","jobKind","jobPhase","accessMode","pairId","pairEngine","pairEntryProtocol","pairExitProtocol","pairPhase","setupIntent","setupAbandoned","pairReady","pairActivated","pairNeedsPreparation","sshRoute","resolvedSshRoute","vpnServer","exitEndpoint","checkedAt","checked"})node.data.remove(key);node.set("protocol","");node.vpnPassword="";}
 private static final String[] RESET_WORK={"lifecycleOperation","entryMigration","pairedOsOperation","helperUpdate","engineUpdate","job","jobKind","jobPhase","setupIntent","setupAbandoned","pairNeedsPreparation","deploymentInventory","deploymentRevision"};
 private static final String[] RESET_HISTORY={"lastLifecycleOperation","lastEntryMigration","lastPairedOsOperation","lastHelperUpdate","lastEngineUpdate","lastOsReinstall"};
 /** Only the successful owned full-reset callback may retire pending work.
  * Draft preparation, Forget and Abandon deliberately do not call this. */
 public static void clearAfterConfirmedReset(Gateway node,JSONObject acknowledgement,boolean phoneWorkActive)throws Exception{
  if(phoneWorkActive||acknowledgement==null||!Boolean.TRUE.equals(acknowledgement.opt("reset"))||Boolean.TRUE.equals(acknowledgement.opt("os_reinstall")))throw new java.io.IOException("A completed VPN removal acknowledgement is required before clearing recorded work.");
  if(node==null||node.data.optBoolean("clientOnly")||node.data.optBoolean("adminAccess"))throw new java.io.IOException("Choose the managed owner record for this reset.");
  if((node.data.has("osReinstall")||!node.get("osReinstallState").isEmpty())&&!node.get("osReinstallState").equals("complete"))throw new java.io.IOException("Check the recorded OS job before clearing VPN work.");
  JSONObject clean=new JSONObject(node.data.toString());retireResetWork(clean,false);
  for(String key:RESET_WORK)node.data.remove(key);
  for(String key:RESET_HISTORY)if(clean.has(key))node.data.put(key,clean.get(key));
 }
 private static void retireResetWork(JSONObject gateway,boolean historicalSnapshot)throws JSONException{
  for(String key:RESET_WORK)gateway.remove(key);
  // Keep terminal receipts, including paired OS phase=restored without state.
  // Only their embedded Gateway snapshots lose obsolete resumable operations.
  for(String key:RESET_HISTORY){JSONObject receipt=gateway.optJSONObject(key);if(receipt==null)continue;
   for(String field:new String[]{"previous","candidate"}){JSONObject snapshot=receipt.optJSONObject(field);if(snapshot!=null&&snapshot.has("id")&&snapshot.has("host"))retireResetWork(snapshot,true);}
  }
  if(historicalSnapshot){JSONObject exit=gateway.optJSONObject("pairExit");if(exit!=null)retireResetWork(exit,true);}
 }
 /** Commit only after the operator has accepted the reviewed replacement. */
 public static void attach(ArrayList<Gateway> nodes,Gateway pair)throws JSONException{
  ArrayList<Gateway> keep=new ArrayList<>();
  for(Gateway root:nodes){
   if(root.isPair()&&(same(root,pair)||same(root.exit,pair)||same(root,pair.exit)||same(root.exit,pair.exit))){
    for(Gateway part:Arrays.asList(root,root.exit))if(!same(part,pair)&&!same(part,pair.exit)){
     Gateway preserved=copy(part);preserved.exit=null;preserved.sshRelay=null;clearConnection(preserved);preserved.set("name",ServerProtocols.name(part));keep.add(preserved);
    }
   }else if(!same(root,pair)&&!same(root,pair.exit))keep.add(root);
  }
  keep.add(pair);nodes.clear();nodes.addAll(keep);
 }
}
