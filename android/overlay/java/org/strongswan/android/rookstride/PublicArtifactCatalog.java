package org.strongswan.android.rookstride;

import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;

/** Public software identities come exclusively from this installed APK. */
public final class PublicArtifactCatalog {
    public static final int MAX_CATALOG_BYTES=32768;
    static final long MAX_ARCHIVE_BYTES=64L*1024*1024;
    public final String sha256;
    private final Map<String,Asset> assets=new HashMap<>();
    private final Set<String> redirectHosts=new HashSet<>();
    public static final class Source {
        public final URL url;
        public final Map<String,String> headers;
        Source(URL u,Map<String,String> h){url=u;headers=Collections.unmodifiableMap(h);}
    }
    public static final class Asset {
        public final String id,architecture,sha256;
        public final long bytes;
        public final List<Source> sources;
        Asset(String id,String arch,String hash,long bytes,List<Source> sources){this.id=id;architecture=arch;sha256=hash;this.bytes=bytes;this.sources=Collections.unmodifiableList(sources);}
    }
    public PublicArtifactCatalog(byte[] raw)throws Exception{
        if(raw==null||raw.length==0||raw.length>MAX_CATALOG_BYTES)throw invalid();
        String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        JSONObject root=new JSONObject(text);keys(root,"schema","redirect_hosts","artifacts");if(!(root.get("schema") instanceof Number)||root.getDouble("schema")!=1)throw invalid();
        JSONArray hosts=root.getJSONArray("redirect_hosts");Set<String> expected=new HashSet<>(Arrays.asList("github.com","api.github.com","release-assets.githubusercontent.com"));
        for(int i=0;i<hosts.length();i++){String host=hosts.getString(i);if(!expected.contains(host)||!redirectHosts.add(host))throw invalid();}
        if(!redirectHosts.equals(expected))throw invalid();
        JSONObject all=root.getJSONObject("artifacts");keys(all,"adguard","xray","trusttunnel");
        for(String id:new String[]{"adguard","xray","trusttunnel"}){
            JSONObject component=all.getJSONObject(id);keys(component,"version","assets");String version=component.getString("version");if(!version.matches("v[0-9]+(?:\\.[0-9]+){1,3}"))throw invalid();
            JSONObject architectures=component.getJSONObject("assets");keys(architectures,"x86_64","aarch64");
            for(String arch:new String[]{"x86_64","aarch64"}){
                JSONObject a=architectures.getJSONObject(arch);keys(a,"bytes","sha256","sources");long size=a.getLong("bytes");String hash=a.getString("sha256");
                if(!(a.get("bytes") instanceof Number)||size<=0||size>MAX_ARCHIVE_BYTES||a.getDouble("bytes")!=size||!hash.matches("[a-f0-9]{64}"))throw invalid();
                JSONArray ss=a.getJSONArray("sources");if(ss.length()<1||ss.length()>2)throw invalid();List<Source> sources=new ArrayList<>();Set<String> seen=new HashSet<>();
                for(int i=0;i<ss.length();i++){
                    JSONObject s=ss.getJSONObject(i);keys(s,"url","headers");String url=s.getString("url");URL parsed=new URL(url);validateUrl(parsed);if(!seen.add(url))throw invalid();
                    String repository=id.equals("adguard")?"AdguardTeam/AdGuardHome":id.equals("xray")?"XTLS/Xray-core":"TrustTunnel/TrustTunnel";
                    String prefix="/"+repository+"/releases/download/"+version+"/";
                    boolean release=parsed.getHost().equals("github.com")&&parsed.getPath().startsWith(prefix)&&parsed.getQuery()==null;
                    boolean api=id.equals("adguard")&&parsed.getHost().equals("api.github.com")&&parsed.getPath().matches("/repos/AdguardTeam/AdGuardHome/releases/assets/[0-9]+")&&parsed.getQuery()==null;
                    if(!release&&!api)throw invalid();JSONObject h=s.getJSONObject("headers");Map<String,String> headers=new HashMap<>();
                    for(Iterator<String> k=h.keys();k.hasNext();){String key=k.next();if(!key.equals("Accept")||!h.getString(key).equals("application/octet-stream"))throw invalid();headers.put(key,h.getString(key));}
                    if(api&&!headers.containsKey("Accept"))throw invalid();sources.add(new Source(parsed,headers));
                }
                assets.put(id+":"+arch,new Asset(id,arch,hash,size,sources));
            }
        }
        sha256=hash(raw);
    }
    public Asset asset(String id,String arch)throws IOException{Asset a=assets.get(id+":"+arch);if(a==null)throw invalid();return a;}
    public void validateUrl(URL url)throws IOException{
        if(!"https".equals(url.getProtocol())||url.getUserInfo()!=null||url.getRef()!=null||(url.getPort()!=-1&&url.getPort()!=443)||!redirectHosts.contains(url.getHost())||url.toExternalForm().length()>8192)throw invalid();
    }
    static void keys(JSONObject object,String... allowed)throws IOException{Set<String> expected=new HashSet<>(Arrays.asList(allowed));if(object.length()!=expected.size())throw invalid();for(Iterator<String> k=object.keys();k.hasNext();)if(!expected.remove(k.next()))throw invalid();if(!expected.isEmpty())throw invalid();}
    static IOException invalid(){return new IOException("The app's verified public component metadata is invalid.");}
    static String hash(byte[] bytes)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String hex(byte[] bytes){StringBuilder result=new StringBuilder();for(byte b:bytes)result.append(String.format(Locale.ROOT,"%02x",b&255));return result.toString();}
    static byte[] read(InputStream input,int limit)throws IOException{ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int n;while((n=input.read(buffer))!=-1){if(n==0)continue;if(output.size()>limit-n)throw invalid();output.write(buffer,0,n);}return output.toByteArray();}
}
