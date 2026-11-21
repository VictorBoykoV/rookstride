package org.strongswan.android.rookstride;
import android.content.Context;import java.util.*;import org.strongswan.android.data.*;import org.strongswan.android.rookstride.engine.*;
/** Retire erased-server and broken-route clients; preserve untouched server access. */
public final class OsInventory {
 private OsInventory(){}
 public static void finish(Context context,ArrayList<Gateway> nodes,Gateway target)throws Exception{
  applyVerifiedIdentity(context,nodes,target);
  Gateway original=PairNodes.copy(target);original.set("fingerprint",target.get("osPreviousFingerprint"));
  ArrayList<Gateway> keep=new ArrayList<>();Set<String> removed=new HashSet<>(),ikeIds=new HashSet<>();
  VpnProfileDataSource profiles=new VpnProfileSource(context);profiles.open();
  try{
   for(Gateway root:new ArrayList<>(nodes)){
    boolean broken=root.isPair()&&(affected(original,target,root)||affected(original,target,root.exit));
    for(Gateway part:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root)){
     if(broken||affected(original,target,part)||part.get("id").equals(target.get("id"))){
      if(removed.add(part.get("id"))){
       String uuid=part.get("profileUuid");if(!uuid.isEmpty()){ikeIds.add(uuid);VpnProfile profile=profiles.getVpnProfile(uuid);if(profile!=null)profiles.deleteVpnProfile(profile);}
       if(!part.get("protocol").isEmpty()&&!part.get("protocol").equals("ikev2")){if(NativeVpn.status(context,part.get("protocol")).active(part.get("id")))NativeVpn.disconnect(context,part.get("protocol"));new NativeProfileStore(context).remove(part.get("id"));}
      }
     }
     if(broken&&!affected(original,target,part)&&!part.get("id").equals(target.get("id"))){Gateway survivor=PairNodes.copy(part);survivor.exit=null;survivor.sshRelay=null;PairNodes.clearConnection(survivor);survivor.set("pairPhase","Partner server reinstalled · refresh and review its old setup");survivor.data.put("pairReady",false);keep.add(survivor);}
     else if(!root.isPair()&&!affected(original,target,part)&&!part.get("id").equals(target.get("id")))keep.add(root);
    }
    if(root.isPair()&&!broken)keep.add(root);
   }
  }finally{profiles.close();}
  PairNodes.clearConnection(target);target.exit=null;target.sshRelay=null;target.set("machine","");target.set("checked","Ubuntu reinstalled");keep.add(target);nodes.clear();nodes.addAll(keep);
  disconnectRemovedIke(context,ikeIds);
 }
 public static void finishPair(Context context,ArrayList<Gateway> nodes,Gateway pair)throws Exception{
  org.json.JSONObject operation=pair.data.optJSONObject("pairedOsOperation");
  if(!pair.isPair()||operation==null||!operation.optString("phase").equals("clean-nodes-ready")||!pair.get("osReinstallState").equals("complete")||!pair.exit.get("osReinstallState").equals("complete"))throw new java.io.IOException("Both recorded OS jobs must verify before retiring pair profiles");
  Gateway entry=pair,exit=pair.exit;org.json.JSONObject receipt=new org.json.JSONObject(operation.toString());
  // Existing retirement handles aliases, native engines and strongSwan profile storage.
  finish(context,nodes,entry);finish(context,nodes,exit);
  for(Gateway node:new Gateway[]{entry,exit}){node.data.remove("pairedOsOperation");node.data.remove("lifecycleOperation");node.data.remove("deploymentInventory");node.data.put("lastPairedOsOperation",receipt);node.set("pairPhase","");}
 }
 public static void finishRestoredPair(Context context,ArrayList<Gateway> nodes,Gateway pair)throws Exception{
  org.json.JSONObject operation=pair.data.optJSONObject("pairedOsOperation");
  if(!pair.isPair()||operation==null||!operation.optString("phase").equals("restored"))throw new java.io.IOException("Both VPN identities must restore before completing recovery");
  validateVerifiedAliases(nodes,pair);validateVerifiedAliases(nodes,pair.exit);
  applyVerifiedIdentity(context,nodes,pair);applyVerifiedIdentity(context,nodes,pair.exit);
  org.json.JSONObject receipt=new org.json.JSONObject(operation.toString());
  // A restored pair does not restore unrelated coexisting standalone protocols.
  for(Gateway root:nodes)if(root!=pair&&!root.isPair()&&!root.data.optBoolean("clientOnly")&&(ServerIdentityPins.sameEndpoint(root,pair)||ServerIdentityPins.sameEndpoint(root,pair.exit))){Gateway verified=ServerIdentityPins.sameEndpoint(root,pair)?pair:pair.exit;
   String previous=verified.get("osRestoredPreviousInstance"),restored=verified.get("osRestoredInstance");
   boolean verifiedMapping=!previous.isEmpty()&&!restored.isEmpty()&&restored.equals(verified.get("serverInstance"));
   String restoredProtocol=pair.get(verified==pair?"pairEntryProtocol":"pairExitProtocol");if(restoredProtocol.isEmpty())restoredProtocol=verified.get("protocol");
   boolean sameProtocol=root.get("protocol").equals(restoredProtocol);
   if(sameProtocol&&verifiedMapping&&root.get("serverInstance").equals(previous)){root.set("serverInstance",restored);root.data.remove("snapshot");root.data.remove("statisticsCheckedAt");}
   boolean sameRestoredInstance=sameProtocol&&!root.get("serverInstance").isEmpty()&&root.get("serverInstance").equals(verified.get("serverInstance"));
   if(!root.get("protocol").isEmpty()&&!sameRestoredInstance){retireProfile(context,root);PairNodes.clearConnection(root);root.set("checked","Server restored; this VPN setup was erased");}
  }
  pair.data.put("lastPairedOsOperation",receipt);pair.data.remove("pairedOsOperation");
 }
 private static boolean affected(Gateway previous,Gateway verified,Gateway node){return PairNodes.same(previous,node)||PairNodes.same(verified,node);}
 private static void validateVerifiedAliases(ArrayList<Gateway> nodes,Gateway target)throws java.io.IOException{
  if(target.data.optBoolean("adminAccess"))throw new java.io.IOException("A delegated administrator record cannot become owner access after an OS replacement");
  for(Gateway root:nodes)for(Gateway node:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root))if(!node.data.optBoolean("clientOnly")&&ServerIdentityPins.sameEndpoint(node,target)){
   String pin=node.get("fingerprint");if(!pin.equals(target.get("fingerprint"))&&!pin.equals(target.get("osPreviousFingerprint")))throw new java.io.IOException("An alias has an unrelated SSH identity; verify it before completing OS replacement");
  }
 }
 /** Apply each verified node before its durable checkpoint. Profile retirement is
  * separate, so the first returned node cannot erase the selected pair's client. */
 public static void applyVerifiedIdentity(Context context,ArrayList<Gateway> nodes,Gateway target)throws Exception{
  validateVerifiedAliases(nodes,target);new ServerIdentityPins(context).replaceVerifiedOsIdentity(target);
  // OS replacement changes machine-id too. Repair cached owner aliases even
  // on completion replay, without changing imported or delegated identities.
  String machine=target.get("machine");if(!machine.matches("[0-9a-f]{64}"))machine="";target.set("machine",machine);
  for(Gateway root:nodes)for(Gateway node:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root))if(!node.data.optBoolean("clientOnly")&&!node.data.optBoolean("adminAccess")&&ServerIdentityPins.sameEndpoint(node,target))node.set("machine",machine);
  boolean sameGeneration=target.get("adminIdentityFingerprint").equals(target.get("fingerprint"));
  if(sameGeneration&&!target.get("adminServerId").isEmpty()&&!target.get("adminDeploymentId").isEmpty())return;
  String serverId=sameGeneration&&!target.get("adminServerId").isEmpty()?target.get("adminServerId"):UUID.randomUUID().toString();
  String deploymentId=sameGeneration&&!target.get("adminDeploymentId").isEmpty()?target.get("adminDeploymentId"):UUID.randomUUID().toString();
  // Delegated credentials belong to the erased OS. Never turn them into owner rows.
  nodes.removeIf(node->node.data.optBoolean("adminAccess")&&!node.data.optBoolean("clientOnly")&&ServerIdentityPins.sameEndpoint(node,target));
  Set<Gateway> owners=Collections.newSetFromMap(new IdentityHashMap<Gateway,Boolean>());owners.add(target);
  for(Gateway root:nodes)for(Gateway node:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root))if(!node.data.optBoolean("clientOnly")&&!node.data.optBoolean("adminAccess")&&ServerIdentityPins.sameEndpoint(node,target))owners.add(node);
  for(Gateway node:owners){ArrayList<String> remove=new ArrayList<>();for(Iterator<String> keys=node.data.keys();keys.hasNext();){String key=keys.next();if(key.startsWith("admin")&&!key.equals("admin"))remove.add(key);}for(String key:remove)node.data.remove(key);
   node.set("fingerprint",target.get("fingerprint"));node.set("sshKeyType",target.get("sshKeyType"));node.set("adminServerId",serverId);node.set("adminDeploymentId",deploymentId);node.set("adminIdentityFingerprint",target.get("fingerprint"));node.data.remove("deploymentInventory");
  }
 }
 /** A reviewed new endpoint preserves accounts but requires a fresh local client profile. */
 public static void invalidateMigratedConnection(Context context,Gateway node)throws Exception{retireProfile(context,node);node.data.remove("profileUuid");node.data.remove("nativeProfile");node.data.remove("connectionCheckedAt");}
 private static void retireProfile(Context context,Gateway node)throws Exception{
  String uuid=node.get("profileUuid");if(!uuid.isEmpty()){VpnProfileDataSource profiles=new VpnProfileSource(context);profiles.open();try{VpnProfile profile=profiles.getVpnProfile(uuid);if(profile!=null)profiles.deleteVpnProfile(profile);}finally{profiles.close();}disconnectRemovedIke(context,new HashSet<>(Collections.singletonList(uuid)));}
  if(!node.get("protocol").isEmpty()&&!node.get("protocol").equals("ikev2")){if(NativeVpn.status(context,node.get("protocol")).active(node.get("id")))NativeVpn.disconnect(context,node.get("protocol"));new NativeProfileStore(context).remove(node.get("id"));}
 }
 private static void disconnectRemovedIke(Context context,Set<String> removed){
  if(removed.isEmpty())return;Context app=context.getApplicationContext();
  android.content.ServiceConnection binding=new android.content.ServiceConnection(){
   public void onServiceConnected(android.content.ComponentName name,android.os.IBinder binder){try{org.strongswan.android.logic.VpnStateService s=((org.strongswan.android.logic.VpnStateService.LocalBinder)binder).getService();VpnProfile active=s.getProfile();if(active!=null&&removed.contains(active.getUUID().toString()))s.disconnect();}finally{app.unbindService(this);}}
   public void onServiceDisconnected(android.content.ComponentName name){}
  };
  app.bindService(new android.content.Intent(app,org.strongswan.android.logic.VpnStateService.class),binding,Context.BIND_AUTO_CREATE);
 }
}
