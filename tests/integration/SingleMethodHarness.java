import org.strongswan.android.rookstride.*;
import org.json.*;
import java.nio.file.*;
import java.io.*;
/** Runs the production phone SSH transport against explicitly supplied disposable nodes. */
public final class SingleMethodHarness {
 public static void main(String[] args)throws Exception{
  Path stage=Path.of(args[0]),project=Path.of(args[1]);int index=Integer.parseInt(args[2]);String protocol=args[3],operation=args[4];
  JSONObject input=new JSONArray(Files.readString(stage.resolve("provider-private.json"))).getJSONObject(index);Gateway node=new Gateway(input);
  Ssh.runtimeSource=new Ssh.RuntimeSource(){public JSONObject metadata()throws Exception{return new JSONObject(Files.readString(project.resolve("single/routes-pins.json")));}public InputStream open(String arch)throws Exception{return Files.newInputStream(project.resolve(".tools/native-engines/output/routes/linux/"+arch+"/runtime.tar.gz"));}};
  try(Ssh unexpected=new Ssh(node)){throw new Exception("Unpinned identity accepted");}catch(Ssh.HostTrust issue){boolean valid=false;for(Object pin:input.getJSONArray("pins"))if(pin.equals(issue.fingerprint))valid=true;if(!valid)throw new Exception("Pinned lab identity changed");node.set("fingerprint",issue.fingerprint);}
  try(Ssh ssh=new Ssh(node)){
   JSONObject result;
   if(operation.equals("reset-all")){
    try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){JSONObject review=ssh.single(bundle,new JSONObject().put("action","reset-server-plan"));result=ssh.single(Files.newInputStream(stage.resolve("single_bundle.zip")),new JSONObject().put("action","reset-server-apply").put("token",review.getString("token")).put("confirmation","DELETE ALL VPNS"));}
    if(!"preserve-unrelated".equals(ssh.execute("cat /srv/rook-lab-unrelated/check",null).trim()))throw new Exception("Unrelated file changed");
   }else if(operation.equals("install")){
    try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){result=ssh.single(bundle,new JSONObject().put("action","start").put("protocol",protocol).put("server",input.getString("vpnHost")).put("login","this-phone"));}
    String job=result.getString("job"),phase="";long deadline=System.nanoTime()+1_200_000_000_000L;
    while(true){result=ssh.single(new JSONObject().put("action","job").put("job",job));String next=result.optString("phase");if(!next.equals(phase)){phase=next;System.out.println(protocol+": "+phase);}String state=result.getString("state");if(state.equals("complete"))break;if(state.equals("failed")||System.nanoTime()>deadline)throw new Exception(protocol+": "+phase);Thread.sleep(2000);}
    result=ssh.single(new JSONObject().put("action","status").put("protocol",protocol));if(!result.getBoolean("running")||!result.getJSONObject("services").getBoolean("adguard"))throw new Exception("VPN/filter health failed");
    JSONObject profile=ssh.single(new JSONObject().put("action","profile").put("protocol",protocol).put("login","this-phone"));Files.writeString(stage.resolve(protocol+"-profile-private.json"),profile.toString());
   }else if(operation.equals("export")){result=ssh.single(new JSONObject().put("action","profile").put("protocol",protocol).put("login","this-phone"));Files.writeString(stage.resolve(protocol+"-profile-private.json"),result.toString());
   }else if(operation.equals("reset")){
    try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){JSONObject review=ssh.single(bundle,new JSONObject().put("action","reset-plan").put("protocol",protocol));result=ssh.single(new JSONObject().put("action","reset-apply").put("protocol",protocol).put("token",review.getString("token")).put("confirmation","DELETE VPN"));}
   }else if(operation.equals("users")){
    try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){ssh.single(bundle,new JSONObject().put("action","add-user").put("protocol",protocol).put("login","second-device"));}JSONObject profile=ssh.single(new JSONObject().put("action","profile").put("protocol",protocol).put("login","second-device"));Files.writeString(stage.resolve(protocol+"-second-profile-private.json"),profile.toString());result=ssh.single(new JSONObject().put("action","status").put("protocol",protocol));
   }else if(operation.equals("revoke")){try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){result=ssh.single(bundle,new JSONObject().put("action","remove-user").put("protocol",protocol).put("login","second-device"));}
   }else if(operation.equals("statistics")){try(InputStream bundle=Files.newInputStream(stage.resolve("single_bundle.zip"))){result=ssh.single(bundle,new JSONObject().put("action","status").put("protocol",protocol));}if(!result.getBoolean("monitoring_available"))throw new Exception("Statistics unavailable");long upload=0,download=0;for(Object item:result.getJSONArray("connections")){JSONObject row=(JSONObject)item;upload+=row.getLong("upload");download+=row.getLong("download");if(row.getString("generation").isEmpty())throw new Exception("Counter generation missing");}if(upload<=0||download<=0)throw new Exception("Expected real traffic counters");
   }else result=ssh.single(new JSONObject().put("action",operation).put("protocol",protocol));
   Files.writeString(stage.resolve(protocol+"-"+operation+"-private.json"),result.toString());System.out.println(protocol+" "+operation+" PASSED");
  }
 }
}
