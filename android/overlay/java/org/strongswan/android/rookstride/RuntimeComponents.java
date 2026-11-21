package org.strongswan.android.rookstride;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipEntry;

/** Runtime payloads remain separate from the small, reviewable recipe bundle. */
public final class RuntimeComponents {
 private RuntimeComponents(){}
 public static void install(Context context){
  final android.content.res.AssetManager assets=context.getApplicationContext().getAssets();
  Ssh.runtimeSource=new Ssh.RuntimeSource(){
   public JSONObject metadata()throws Exception{try(InputStream in=assets.open("server-runtime/pins.json")){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int count;while((count=in.read(buffer))>=0){out.write(buffer,0,count);if(out.size()>65536)throw new IOException("Invalid runtime metadata");}return new JSONObject(out.toString("UTF-8"));}}
   public InputStream open(String architecture)throws Exception{if(!architecture.equals("x86_64")&&!architecture.equals("aarch64"))throw new IOException("Unsupported server");return assets.open("server-runtime/"+architecture+"/runtime.bin");}
  };
  final Context application=context.getApplicationContext();
  Ssh.artifactSource=new ArtifactBridge.Source(){
   private PublicArtifactCatalog catalog;
   public synchronized PublicArtifactCatalog catalog()throws Exception{
    if(catalog==null){byte[] raw=null;try(ZipInputStream zip=new ZipInputStream(openBundle())){ZipEntry entry;while((entry=zip.getNextEntry())!=null)if(entry.getName().equals("single/public-artifacts.json")){if(raw!=null||entry.isDirectory())throw PublicArtifactCatalog.invalid();raw=PublicArtifactCatalog.read(zip,PublicArtifactCatalog.MAX_CATALOG_BYTES);}}if(raw==null)throw PublicArtifactCatalog.invalid();catalog=new PublicArtifactCatalog(raw);}return catalog;
   }
   public InputStream openBundle()throws Exception{return assets.open("gateway_bundle.zip");}
   public File cacheDirectory()throws Exception{return ArtifactDownloader.privateCache(application.getCacheDir());}
   public ArtifactDownloader.Transport transport()throws Exception{return ArtifactNetwork.active(application);}
  };
 }
}
