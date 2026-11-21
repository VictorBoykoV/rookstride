package org.strongswan.android.rookstride;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/** Bounded HTTPS and private, content-addressed cache. No credentials or URLs from a server. */
public final class ArtifactDownloader {
    public interface Transport {
        HttpsURLConnection open(URL url)throws IOException;
        /** Only the Android implementation may offer an owned VPN control underlay. */
        default Transport fallback()throws IOException{return null;}
    }
    public interface Stream {InputStream open()throws Exception;}
    static final class Unavailable extends IOException {Unavailable(){super("The public component could not be downloaded. Check this phone's internet access.");}}
    private static final class OriginRejected extends IOException {OriginRejected(){super("The official public component download was rejected.");}}
    private static final long DEADLINE_NS=180_000_000_000L;
    private static final AtomicReference<Transfer> ACTIVE=new AtomicReference<>();
    private static final ThreadPoolExecutor WORKER=new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<Runnable>(1),r->{Thread t=new Thread(r,"rookstride-public-https");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private static final ThreadPoolExecutor CLEANUP=new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<Runnable>(1),r->{Thread t=new Thread(r,"rookstride-public-https-close");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    private static final class Transfer {
        volatile boolean cancelled;boolean started,cleanupScheduled;volatile HttpsURLConnection current;
        void check(long deadline)throws IOException{if(cancelled)throw new InterruptedIOException("Public component preparation was interrupted.");checkTime(deadline);}
        void cancel(){HttpsURLConnection connection;synchronized(this){cancelled=true;if(!started)ACTIVE.compareAndSet(this,null);connection=current;if(connection==null||cleanupScheduled)return;cleanupScheduled=true;}try{CLEANUP.execute(()->{try{connection.disconnect();}catch(RuntimeException ignored){}});}catch(RejectedExecutionException ignored){/* The one bounded cleanup worker is still occupied; never block this caller. */}}
    }
    private final PublicArtifactCatalog catalog;
    private final File cache;
    private final Transport transport;
    private final long callerTimeoutMillis;
    public ArtifactDownloader(PublicArtifactCatalog catalog,File cache,Transport transport)throws IOException{
        this(catalog,cache,transport,180000);
    }
    ArtifactDownloader(PublicArtifactCatalog catalog,File cache,Transport transport,long timeoutMillis)throws IOException{
        if(timeoutMillis<=0||timeoutMillis>180000)throw new IOException("Invalid public component deadline.");this.catalog=catalog;this.cache=cache;this.transport=transport;callerTimeoutMillis=timeoutMillis;safeCache(cache);
    }
    static File privateCache(File trustedAppCache)throws IOException{
        // Context's /data/user/0 root may legitimately alias /data/data on API26.
        // Canonicalize that trusted root, then reject links in our own children.
        File root=trustedAppCache.getCanonicalFile();if(!root.isDirectory())throw new IOException("The phone's private cache is unavailable.");File child=new File(root,"public-components");if(Files.isSymbolicLink(child.toPath()))throw new IOException("Unexpected public component cache link.");return child;
    }
    public File acquire(PublicArtifactCatalog.Asset asset)throws Exception{
        checkTime(Long.MAX_VALUE);
        File existing=cached(asset);if(existing!=null)return existing;
        Transfer transfer=new Transfer();if(!ACTIVE.compareAndSet(null,transfer))throw new IOException("A previous public component download is still stopping. Try again shortly.");
        Future<File> future;
        try{future=WORKER.submit(()->{try{synchronized(transfer){if(transfer.cancelled)throw new InterruptedIOException("Public component preparation was interrupted.");transfer.started=true;}return acquireOnWorker(asset,transfer);}finally{ACTIVE.compareAndSet(transfer,null);}});}catch(RejectedExecutionException refused){ACTIVE.compareAndSet(transfer,null);throw new IOException("The public component download worker is unavailable.",refused);}
        try{return future.get(callerTimeoutMillis,TimeUnit.MILLISECONDS);}
        catch(TimeoutException timedOut){future.cancel(true);transfer.cancel();throw new Unavailable();}
        catch(InterruptedException interrupted){future.cancel(true);transfer.cancel();Thread.currentThread().interrupt();throw new InterruptedIOException("Public component preparation was interrupted.");}
        catch(ExecutionException failed){Throwable cause=failed.getCause();if(cause instanceof Exception)throw (Exception)cause;throw new IOException("Public component preparation failed.",cause);}
    }
    static boolean downloadBusy(){return ACTIVE.get()!=null;}
    private File acquireOnWorker(PublicArtifactCatalog.Asset asset,Transfer transfer)throws Exception{
        long deadline=System.nanoTime()+Math.min(DEADLINE_NS,TimeUnit.MILLISECONDS.toNanos(callerTimeoutMillis));Transport selected=transport;Unavailable unavailable=null;
        for(int route=0;route<2&&selected!=null;route++){
            for(int index=0;index<asset.sources.size();index++){
                PublicArtifactCatalog.Source source=asset.sources.get(index);
                transfer.check(deadline);
                try{return download(asset,source,selected,deadline,transfer);}catch(Unavailable failure){unavailable=failure;}catch(OriginRejected rejected){if(index+1==asset.sources.size())throw rejected;}
            }
            // TLS, redirect, checksum and filesystem errors never enter this branch.
            selected=route==0?selected.fallback():null;
        }
        throw unavailable==null?new Unavailable():unavailable;
    }
    public synchronized File cached(PublicArtifactCatalog.Asset asset)throws Exception{
        safeCache(cache);File file=new File(cache,asset.sha256);if(!Files.exists(file.toPath(),LinkOption.NOFOLLOW_LINKS))return null;verify(file,asset);return file;
    }
    /** Peer SSH streams are independently checked before they become local cache bytes. */
    public synchronized File accept(PublicArtifactCatalog.Asset asset,Stream source)throws Exception{
        File existing=cached(asset);if(existing!=null)return existing;
        File temporary=temporary();try(InputStream input=source.open()){copy(input,temporary,asset,System.nanoTime()+DEADLINE_NS);return publish(temporary,asset);}finally{if(temporary.exists()&&!temporary.delete())temporary.deleteOnExit();}
    }
    private File download(PublicArtifactCatalog.Asset asset,PublicArtifactCatalog.Source source,Transport selected,long deadline,Transfer transfer)throws Exception{
        URL current=source.url;File temporary=null;
        try{
            for(int redirects=0;;redirects++){
                catalog.validateUrl(current);transfer.check(deadline);HttpsURLConnection connection=null;
                try{
                    connection=selected.open(current);transfer.current=connection;transfer.check(deadline);if(connection==null)throw new IOException("No explicit download network is available.");
                    connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(12000);connection.setReadTimeout(15000);connection.setUseCaches(false);connection.setRequestMethod("GET");
                    connection.setRequestProperty("User-Agent","Rookstride-component-fetch");connection.setRequestProperty("Accept-Encoding","identity");
                    for(java.util.Map.Entry<String,String> header:source.headers.entrySet())connection.setRequestProperty(header.getKey(),header.getValue());
                    int status=connection.getResponseCode();transfer.check(deadline);
                    if(status==301||status==302||status==303||status==307||status==308){
                        if(redirects>=3)throw new IOException("The public component exceeded its redirect limit.");String location=connection.getHeaderField("Location");if(location==null||location.length()>8192)throw new IOException("Invalid public component redirect.");URL next=new URL(current,location);catalog.validateUrl(next);current=next;continue;
                    }
                    if(status==403||status==408||status==425||status==429||status==500||status==502||status==503||status==504)throw new Unavailable();
                    if(status!=200)throw new OriginRejected();
                    String encoding=connection.getHeaderField("Content-Encoding");if(encoding!=null&&!encoding.equalsIgnoreCase("identity"))throw new IOException("Unexpected public component encoding.");
                    long length=connection.getContentLengthLong();if(length>=0&&length!=asset.bytes)throw new IOException("The public component size differs from this app's verified copy.");
                    temporary=temporary();try(InputStream input=connection.getInputStream()){copy(input,temporary,asset,deadline);}transfer.check(deadline);return publish(temporary,asset,transfer,deadline);
                }catch(IOException e){if(transientNetwork(e))throw new Unavailable();throw e;}finally{transfer.current=null;if(connection!=null)connection.disconnect();}
            }
        }finally{if(temporary!=null&&temporary.exists()&&!temporary.delete())temporary.deleteOnExit();}
    }
    private File temporary()throws IOException{safeCache(cache);File file=File.createTempFile(".download-",".part",cache);if(!file.setReadable(false,false)||!file.setWritable(false,false)||!file.setReadable(true,true)||!file.setWritable(true,true)){if(!file.delete())file.deleteOnExit();throw new IOException("Could not protect the public component cache.");}return file;}
    private File publish(File temporary,PublicArtifactCatalog.Asset asset)throws Exception{
        return publish(temporary,asset,null,Long.MAX_VALUE);
    }
    private File publish(File temporary,PublicArtifactCatalog.Asset asset,Transfer transfer,long deadline)throws Exception{
        verify(temporary,asset);File destination=new File(cache,asset.sha256);File prior=cached(asset);if(prior!=null)return prior;
        if(transfer!=null)transfer.check(deadline);
        Files.move(temporary.toPath(),destination.toPath(),StandardCopyOption.ATOMIC_MOVE);verify(destination,asset);return destination;
    }
    static void verify(File file,PublicArtifactCatalog.Asset asset)throws Exception{
        if(Files.isSymbolicLink(file.toPath())||!Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS)||file.length()!=asset.bytes)throw new IOException("The saved public component has an unexpected size or file type.");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");long count=0;try(InputStream input=new FileInputStream(file)){byte[] buffer=new byte[65536];int n;while((n=input.read(buffer))!=-1){count+=n;if(count>asset.bytes)throw new IOException("The saved public component is too large.");hash.update(buffer,0,n);}}
        if(count!=asset.bytes||!PublicArtifactCatalog.hex(hash.digest()).equals(asset.sha256))throw new IOException("The public component checksum differs from this app's verified copy.");
    }
    private static void copy(InputStream input,File output,PublicArtifactCatalog.Asset asset,long deadline)throws Exception{
        if(input==null)throw new IOException("The public component stream is unavailable.");MessageDigest hash=MessageDigest.getInstance("SHA-256");long count=0;
        try(FileOutputStream file=new FileOutputStream(output)){byte[] buffer=new byte[65536];int n;while((n=input.read(buffer))!=-1){checkTime(deadline);if(n==0)continue;count+=n;if(count>asset.bytes)throw new IOException("The public component exceeds its verified size.");hash.update(buffer,0,n);file.write(buffer,0,n);}checkTime(deadline);if(count!=asset.bytes||!PublicArtifactCatalog.hex(hash.digest()).equals(asset.sha256))throw new IOException("The public component size or checksum differs from this app's verified copy.");file.getFD().sync();}
    }
    private static void safeCache(File cache)throws IOException{
        if(Files.isSymbolicLink(cache.toPath())||!cache.getCanonicalFile().equals(cache.getAbsoluteFile()))throw new IOException("Unexpected public component cache location.");
        if(!cache.exists()&&!cache.mkdir()&&!cache.isDirectory())throw new IOException("Could not create the public component cache.");if(!cache.isDirectory())throw new IOException("Unexpected public component cache file.");
    }
    static void checkTime(long deadline)throws IOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("Public component preparation was interrupted.");if(System.nanoTime()>deadline)throw new Unavailable();}
    private static boolean transientNetwork(Throwable e){
        for(Throwable cause=e;cause!=null;cause=cause.getCause())if(cause instanceof java.security.cert.CertificateException||cause instanceof java.security.cert.CertPathValidatorException||cause instanceof SSLPeerUnverifiedException||cause instanceof ProtocolException||cause instanceof InterruptedIOException&&!(cause instanceof SocketTimeoutException))return false;
        for(Throwable cause=e;cause!=null;cause=cause.getCause())if(cause instanceof Unavailable||cause instanceof SocketTimeoutException||cause instanceof UnknownHostException||cause instanceof ConnectException||cause instanceof NoRouteToHostException||cause instanceof SocketException||cause instanceof EOFException)return true;
        return false;
    }
}
