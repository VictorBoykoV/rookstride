package org.strongswan.android.rookstride;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.IOException;

/** Reviews both nodes first; closes/removes the entry before deleting the exit. */
public final class PairResetController {
 private static Ssh open(Gateway node) throws Exception {
  try{return new Ssh(node);}catch(Ssh.HostTrust e){throw new PairController.TrustNeeded(e.node==null?node:e.node,e);}
 }
 private static JSONObject action(Ssh ssh,Gateway entry,String role,String mode,PairController.Bundle bundle,JSONObject reviewed) throws Exception {
  JSONObject request=PairController.request(entry,role);request.put("mode",mode);
  if(reviewed!=null){request.put("token",reviewed.getString("token"));request.put("confirmation","DELETE PAIR");}
  try(InputStream source=bundle.open()){return ssh.reset(source,request);}
 }
 public static JSONObject review(Gateway entry,PairController.Bundle bundle) throws Exception {
  entry.configureRelay();
  try(Ssh a=open(entry);Ssh b=open(entry.exit)) {
   String machine=a.probe().getString("machine");
   if(machine.equals(b.probe().getString("machine")))throw new IOException("Reset requires two distinct nodes");
   return new JSONObject().put("entry",action(a,entry,"entry","pair-plan",bundle,null)).put("exit",action(b,entry,"exit","pair-plan",bundle,null));
  }
 }
 public static JSONObject apply(Gateway entry,JSONObject review,String confirmation,PairController.Bundle bundle,PairController.Progress progress) throws Exception {
  if(!"DELETE PAIR".equals(confirmation))throw new IOException("Type DELETE PAIR to confirm removal");
  entry.configureRelay();
  try(Ssh a=open(entry);Ssh b=open(entry.exit)) {
   if(a.probe().getString("machine").equals(b.probe().getString("machine")))throw new IOException("Reset requires two distinct nodes");
   progress.update("Closing and removing the entry VPN");
   JSONObject first=action(a,entry,"entry","pair-apply",bundle,review.getJSONObject("entry"));
   progress.update("Removing the exit VPN and DNS data");
   JSONObject second=action(b,entry,"exit","pair-apply",bundle,review.getJSONObject("exit"));
   return new JSONObject().put("entry",first).put("exit",second).put("reset",true);
  }
 }
}
