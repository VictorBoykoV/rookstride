import org.strongswan.android.rookstride.*;import org.json.*;import java.nio.file.*;import java.io.*;import java.nio.file.attribute.PosixFilePermissions;
/** Production-controller lifecycle probe; caller supplies private pinned disposable fixtures. */
public final class LifecycleHarness {
 public static void main(String[] args)throws Exception{
  Path folder=Path.of(args[0]),project=Path.of(args[1]);String action=args[2];Path record=folder.resolve("lifecycle-pair-private.json");Gateway pair=new Gateway(new JSONObject(Files.readString(record)));
  PairController.Bundle bundle=()->Files.newInputStream(folder.resolve("gateway_bundle.zip"));PairController.Progress progress=phase->System.out.println(phase);OsReinstall.Saved saved=()->{Files.writeString(record,pair.persisted().toString());Files.setPosixFilePermissions(record,PosixFilePermissions.fromString("rw-------"));};
  Ssh.runtimeSource=new Ssh.RuntimeSource(){public JSONObject metadata()throws Exception{return new JSONObject(Files.readString(project.resolve("single/routes-pins.json")));}public InputStream open(String arch)throws Exception{return Files.newInputStream(project.resolve(".tools/native-engines/output/routes/linux/"+arch+"/runtime.tar.gz"));}};
  JSONObject result;
  if(action.equals("inspect"))result=LifecycleController.inspect(pair,bundle,progress);
  else if(action.equals("replace-exit")){Gateway candidate=new Gateway(new JSONObject(Files.readString(folder.resolve("lifecycle-candidate-private.json"))));result=LifecycleController.replaceExit(pair,candidate,bundle,progress,saved);}
  else if(action.equals("entry-stage")){Gateway candidate=new Gateway(new JSONObject(Files.readString(folder.resolve("lifecycle-candidate-private.json"))));result=EntryMigrationController.stage(pair,candidate,args.length>3&&args[3].equals("reviewed-ip-transfer"),bundle,progress,saved);}
  else if(action.equals("entry-finish")||action.equals("entry-rollback")){Gateway candidate=new Gateway(new JSONObject(Files.readString(folder.resolve("lifecycle-candidate-private.json"))));result=EntryMigrationController.finish(pair,action.equals("entry-rollback"),candidate,bundle,progress,saved);}
  else if(action.equals("rollback")||action.equals("accept"))result=LifecycleController.finishExit(pair,action.equals("rollback"),bundle,progress,saved);
  else if(action.equals("backup")){JSONObject archive=OwnerRecovery.capture(pair,bundle,progress);char[] password=Files.readString(folder.resolve("recovery-password-private.txt")).trim().toCharArray();byte[] envelope=OwnerRecovery.encrypt(archive,password);Files.write(folder.resolve("owner-private.rookrecovery"),envelope);Files.setPosixFilePermissions(folder.resolve("owner-private.rookrecovery"),PosixFilePermissions.fromString("rw-------"));result=OwnerRecovery.rehearse(pair,OwnerRecovery.decrypt(envelope,password,pair.get("pairId")),bundle,progress);java.util.Arrays.fill(password,'\0');}
  else if(action.equals("coexist-openvpn"))try(Ssh ssh=new Ssh(pair);InputStream in=Files.newInputStream(folder.resolve("single_bundle.zip"))){
   JSONObject start=ssh.single(in,new JSONObject().put("action","start").put("protocol","openvpn").put("server",pair.get("host")).put("login","independent-phone").put("coexist_pair",pair.get("pairId")));String job=start.getString("job");long deadline=System.nanoTime()+2_700_000_000_000L;
   while(true){JSONObject status=ssh.single(new JSONObject().put("action","job").put("job",job));if(status.optString("state").equals("complete"))break;if(status.optString("state").equals("failed")||System.nanoTime()>deadline)throw new IOException(status.optString("phase"));Thread.sleep(2000);}
   JSONObject profile=ssh.single(new JSONObject().put("action","profile").put("protocol","openvpn").put("login","independent-phone"));Files.writeString(folder.resolve("coexist-openvpn-private.json"),profile.toString());Files.setPosixFilePermissions(folder.resolve("coexist-openvpn-private.json"),PosixFilePermissions.fromString("rw-------"));result=ssh.single(new JSONObject().put("action","status").put("protocol","openvpn"));
  }else throw new IOException("Unsupported explicit lifecycle probe action");
  Files.writeString(folder.resolve("lifecycle-"+action+"-private.json"),result.toString());System.out.println("Lifecycle "+action+" completed; independent client evidence is a separate gate");
 }
}
