package org.strongswan.android.rookstride;

import org.json.*;
import java.io.*;
import java.util.*;

/** Review both identities/scopes before any removal. Tokens stay in memory. */
public final class PairPreparationController {
 private PairPreparationController(){}
 private static Ssh open(Gateway node)throws Exception{try{return new Ssh(node);}catch(Ssh.HostTrust e){throw new PairController.TrustNeeded(e.node==null?node:e.node,e);}}
 private static JSONObject reviewNode(Ssh ssh,Gateway node,JSONObject probe,PairController.Bundle gateway,PairController.Bundle single)throws Exception{
  JSONObject result;
  if(probe.optBoolean("pair_helper"))try(InputStream b=gateway.open()){result=ssh.reset(b,new JSONObject().put("mode","node-plan"));result.put("kind","pair");}
  else{
   JSONObject inventory;try(InputStream b=single.open()){inventory=ssh.single(b,new JSONObject().put("action","inspect"));}
   if(inventory.optBoolean("pair_node"))try(InputStream bundle=gateway.open()){return ssh.reset(bundle,new JSONObject().put("mode","node-plan")).put("kind","pair").put("node",node.get("id")).put("machine",probe.getString("machine")).put("fingerprint",node.get("fingerprint"));}
   JSONArray protocols=inventory.optJSONArray("installed_protocols");JSONObject filtering=inventory.optJSONObject("filtering");
   boolean owned=probe.optBoolean("gateway")||inventory.optBoolean("owned_ikev2")||protocols!=null&&protocols.length()>0||filtering!=null&&filtering.optBoolean("installed");
   if(!owned)result=new JSONObject().put("kind","fresh").put("protocols",new JSONArray()).put("filtering",false);
   else try(InputStream b=single.open()){result=ssh.single(b,new JSONObject().put("action","reset-server-plan"));result.put("kind","single");}
  }
  return result.put("node",node.get("id")).put("machine",probe.getString("machine")).put("fingerprint",node.get("fingerprint"));
 }
 public static JSONObject review(Gateway pair,PairController.Bundle gateway,PairController.Bundle single)throws Exception{
  try(PairSsh sessions=PairSsh.connect(pair,phase->{})){
   Ssh a=sessions.entry,b=sessions.exit;
   JSONObject pa=a.probe(),pb=b.probe();String ma=pa.optString("machine"),mb=pb.optString("machine");
   if(ma.isEmpty()||mb.isEmpty()||ma.equals(mb))throw new IOException("Choose two different servers.");
   for(JSONObject p:new JSONObject[]{pa,pb})UbuntuCompatibility.require(p,PairController.modern(pair));
   return new JSONObject().put("entry",reviewNode(a,pair,pa,gateway,single)).put("exit",reviewNode(b,pair.exit,pb,gateway,single));
  }
 }
 public static boolean removalNeeded(JSONObject review){return !review.optJSONObject("entry").optString("kind").equals("fresh")||!review.optJSONObject("exit").optString("kind").equals("fresh");}
 public static List<String> order(JSONObject review){
  ArrayList<String> result=new ArrayList<>(Arrays.asList("entry","exit"));
  // A role swap still closes the OLD entry before removing its OLD exit.
  result.sort(Comparator.comparingInt(role->{JSONObject r=review.optJSONObject(role);return r.optString("kind").equals("pair")?(r.optString("role").equals("entry")?0:2):1;}));return result;
 }
 public static JSONObject apply(Gateway pair,JSONObject review,PairController.Bundle gateway,PairController.Bundle single,PairController.Progress progress)throws Exception{
  return apply(pair,review,gateway,single,progress,false);
 }
 /** Explicit removal also acknowledges each already-empty node under a fresh
  * server reset token. Ordinary fresh pair installation retains its old path. */
 public static JSONObject apply(Gateway pair,JSONObject review,PairController.Bundle gateway,PairController.Bundle single,PairController.Progress progress,boolean acknowledgeFresh)throws Exception{
  try(PairSsh sessions=PairSsh.connect(pair,phase->{})){
   Ssh a=sessions.entry,b=sessions.exit;
   JSONObject pa=a.probe(),pb=b.probe();
   if(pa.optString("machine").isEmpty()||pa.optString("machine").equals(pb.optString("machine")))throw new IOException("The server identities changed. Review again.");
   for(String role:Arrays.asList("entry","exit")){
    Gateway node=role.equals("entry")?pair:pair.exit;JSONObject current=role.equals("entry")?pa:pb,old=review.getJSONObject(role);
    if(!old.getString("node").equals(node.get("id"))||!old.getString("machine").equals(current.optString("machine"))||!old.getString("fingerprint").equals(node.get("fingerprint")))throw new IOException("The selected server changed. Review again.");
   }
   JSONObject result=new JSONObject();
   for(String role:order(review)){
    JSONObject old=review.getJSONObject(role);String kind=old.getString("kind");
    if(kind.equals("fresh")&&!acknowledgeFresh)continue;
    Gateway node=role.equals("entry")?pair:pair.exit;Ssh ssh=role.equals("entry")?a:b;progress.update("Removing the reviewed VPN setup on "+node.get("host"));
    JSONObject response;
    if(kind.equals("pair"))try(InputStream bundle=gateway.open()){response=ssh.reset(bundle,new JSONObject().put("mode","node-apply").put("token",old.getString("token")).put("confirmation","DELETE PAIR"));}
    else if(kind.equals("single"))try(InputStream bundle=single.open()){response=ssh.single(bundle,new JSONObject().put("action","reset-server-apply").put("token",old.getString("token")).put("confirmation","DELETE ALL VPNS"));}
    else if(kind.equals("fresh")){
     JSONObject empty;try(InputStream bundle=single.open()){empty=ssh.single(bundle,new JSONObject().put("action","reset-server-plan"));}
     if(!Boolean.TRUE.equals(empty.opt("already_empty")))throw new IOException("The previously empty server changed. Review its VPN removal again.");
     try(InputStream bundle=single.open()){response=ssh.single(bundle,new JSONObject().put("action","reset-server-apply").put("token",empty.getString("token")).put("confirmation","DELETE ALL VPNS"));}
    }
    else throw new IOException("Review this server again.");
    if(!Boolean.TRUE.equals(response.opt("reset")))throw new IOException("The server did not confirm the reviewed VPN removal.");
    result.put(role,response);
   }
   return result.put("reset",true);
  }
 }
}
