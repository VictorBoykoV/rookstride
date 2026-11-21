package org.strongswan.android.rookstride;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.util.AtomicFile;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** One app-wide policy, read once by each VPN worker when connecting. */
public final class AppRouting {
 public static final class Policy {
  public final String mode;public final SortedSet<String> packages;
  public Policy(String mode,Collection<String> packages){
   if(!Arrays.asList("all","only","exclude").contains(mode))throw new IllegalArgumentException("Unknown routing mode");
   this.mode=mode;this.packages=new TreeSet<>(packages);
   if(this.packages.size()>512)throw new IllegalArgumentException("Too many selected apps");
   for(String p:this.packages)if(!p.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+"))throw new IllegalArgumentException("Invalid app identifier");
   if(mode.equals("only")&&this.packages.isEmpty())throw new IllegalArgumentException("Choose at least one app");
  }
 }
 private static AtomicFile file(Context c){return new AtomicFile(new File(c.getNoBackupFilesDir(),"app-routing.json"));}
 public static boolean configured(Context c){return file(c).getBaseFile().exists();}
 public static Policy read(Context c){
  if(!configured(c))return new Policy("all",Collections.emptySet());
  try(FileInputStream in=file(c).openRead()){byte[] bytes=new byte[65537];int count=0,n;while(count<bytes.length&&(n=in.read(bytes,count,bytes.length-count))>0)count+=n;if(count>65536)throw new IOException();JSONObject value=new JSONObject(new String(bytes,0,count,StandardCharsets.UTF_8));TreeSet<String> packages=new TreeSet<>();JSONArray a=value.getJSONArray("packages");for(int i=0;i<a.length();i++)packages.add(a.getString(i));return new Policy(value.getString("mode"),packages);}
  catch(Exception e){throw new IllegalStateException("App routing could not be read. Save your routing choices again.",e);}
 }
 public static void save(Context c,Policy p)throws Exception{
  AtomicFile target=file(c);FileOutputStream out=null;
  try{out=target.startWrite();JSONObject j=new JSONObject().put("mode",p.mode).put("packages",new JSONArray(p.packages));out.write(j.toString().getBytes(StandardCharsets.UTF_8));target.finishWrite(out);}
  catch(Exception e){if(out!=null)target.failWrite(out);throw e;}
 }
 public static SortedSet<String> installed(Context c,Policy p){
  TreeSet<String> result=new TreeSet<>();for(String name:p.packages)try{c.getPackageManager().getApplicationInfo(name,0);if(!name.equals(c.getPackageName()))result.add(name);}catch(PackageManager.NameNotFoundException ignored){}
  if(p.mode.equals("only")&&result.isEmpty())throw new IllegalStateException("Your selected apps are no longer installed. Update App routing before connecting.");return result;
 }
 public static void apply(Context c,VpnService.Builder b)throws PackageManager.NameNotFoundException{
  Policy p=read(c);if(p.mode.equals("all"))return;
  SortedSet<String> selected=installed(c,p);
  if(p.mode.equals("only")){
   // Keep Rookstride's in-tunnel connectivity check and ordinary app requests routed.
   b.addAllowedApplication(c.getPackageName());for(String name:selected)b.addAllowedApplication(name);
  }else for(String name:selected)b.addDisallowedApplication(name);
 }
 private AppRouting(){}
}
