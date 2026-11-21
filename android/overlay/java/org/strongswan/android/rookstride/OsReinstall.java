package org.strongswan.android.rookstride;
import java.io.*;import org.json.*;
/** A resumed coordinator only polls its recorded job; it never repeats an erase. */
public final class OsReinstall {
 private OsReinstall(){}
 public interface Saved{void save()throws Exception;}
 static boolean mayWaitForAdministratorAccess(boolean rebooting,Exception error,long elapsedNanos){
  return rebooting&&elapsedNanos>=0&&elapsedNanos<300_000_000_000L&&(error instanceof com.jcraft.jsch.JSchException||error instanceof Ssh.SignInRejected||error instanceof Ssh.HandshakeFailure);
 }
 /** Called only after the matching completed job is read over the planned SSH
  * identity. Keep the authenticated replacement machine, not its erased OS. */
 static void recordVerifiedOsReturn(Gateway node,JSONObject recorded,JSONObject actual)throws Exception{
  String machine=actual.optString("machine","");
  if(!actual.optString("os").equals("ubuntu")||!actual.optString("version").equals(recorded.getString("version")))throw new IOException("The returned OS does not match the requested Ubuntu version");
  if(!machine.matches("[0-9a-f]{64}"))throw new IOException("The returned server identity could not be verified");
  node.set("fingerprint",recorded.getString("fingerprint"));node.set("sshKeyType","ecdsa-sha2-nistp256");node.set("admin","root");node.privateKey="";node.set("machine",machine);node.set("osReinstallState","complete");
 }
 public static JSONObject run(Gateway node,JSONObject plan,boolean resume,PairController.Bundle bundle,PairController.Progress progress,Saved saved)throws Exception{
  if(!resume){
   node.set("osPreviousFingerprint",node.get("fingerprint"));node.data.put("osReinstall",plan);node.set("osReinstallState","starting");saved.save();
   progress.stage(0,"Starting the reviewed OS reinstall");
   try(Ssh ssh=new Ssh(node);InputStream in=bundle.open()){
    ssh.reinstall(in,new JSONObject().put("action","start").put("job",plan.getString("job")).put("token",plan.getString("token")).put("confirmation","WIPE SERVER AND REINSTALL UBUNTU").put("password",node.sshPassword).put("ssh_port",node.port()));
   }
  }
  JSONObject recorded=node.data.getJSONObject("osReinstall");String job=recorded.getString("job"),future=recorded.getString("fingerprint");long deadline=System.nanoTime()+7_200_000_000_000L;boolean rebooting=node.get("osReinstallState").equals("rebooting")||node.get("osReinstallState").equals("complete");
  long startingServicesAt=0;
  while(System.nanoTime()<deadline){
   Gateway target=new Gateway(new JSONObject(node.persisted().toString()));target.sshPassword=node.sshPassword;target.privateKey=node.privateKey;target.sshRelay=node.sshRelay;
   // Keep the original negotiation preferences while reboot is pending. Forcing
   // ECDSA here would select another OLD key during the scheduled reboot delay.
   // The installer and final OS offer only the planned replacement key.
   if(rebooting){target.set("fingerprint",future);target.set("admin","root");target.privateKey="";}
   boolean waitingForServices=false;
   try(Ssh ssh=new Ssh(target)){
    if(rebooting){
     String raw=ssh.execute("if test -f /etc/rookstride-reinstall-result.json; then cat /etc/rookstride-reinstall-result.json; elif test -f /etc/rookstride-reinstall-error.json; then cat /etc/rookstride-reinstall-error.json; else printf '{}'; fi",null);JSONObject result=new JSONObject(raw);
     startingServicesAt=0;
     if(job.equals(result.optString("job"))&&result.optString("state").equals("failed"))throw new IOException(result.optString("phase","The Ubuntu installer stopped. Check its private log or the provider console."));
     if(job.equals(result.optString("job"))&&result.optString("state").equals("complete")&&recorded.getString("version").equals(result.optString("version"))){
      recordVerifiedOsReturn(node,recorded,ssh.probe());saved.save();progress.stage(5,"Ubuntu and administrator access verified");return result;
     }
     progress.stage(4,"Ubuntu is being installed; waiting for the final reboot");
    }else{
     JSONObject status=ssh.reinstall(new JSONObject().put("action","status").put("job",job));
     if(status.optString("state").equals("failed"))throw new IOException(status.optString("phase"));
     progress.stage(status.optInt("stage"),status.optString("phase"));
     if(status.optString("state").equals("rebooting")){rebooting=true;node.set("osReinstallState","rebooting");saved.save();}
    }
   }catch(Ssh.HostTrust e){
    if(!rebooting&&e.fingerprint.equals(future)){rebooting=true;node.set("osReinstallState","rebooting");saved.save();continue;}
    if(rebooting&&e.fingerprint.equals(node.get("fingerprint"))){Thread.sleep(4000);continue;}
    throw new IOException("The server returned an unexpected SSH identity. OS verification stopped.",e);
   }catch(Ssh.Unreachable e){progress.stage(3,"Server rebooting; waiting for SSH to return");}
   catch(com.jcraft.jsch.JSchException|Ssh.SignInRejected|Ssh.HandshakeFailure e){
    long now=System.nanoTime();if(startingServicesAt==0)startingServicesAt=now;
    if(!mayWaitForAdministratorAccess(rebooting,e,now-startingServicesAt))throw e;
    // SSH can listen before first-boot account/PAM initialization is ready.
    // A reboot can also interrupt negotiation before the key is presented.
    // The planned key is still mandatory; a wrong original sign-in never retries.
    progress.stage(4,"Ubuntu is starting administrator access");waitingForServices=true;
   }
   Thread.sleep(waitingForServices?10000:4000);
  }
  throw new IOException("The recorded OS reinstall has not returned yet. Check its progress; do not start another wipe. Your provider console can show its boot status.");
 }
}
