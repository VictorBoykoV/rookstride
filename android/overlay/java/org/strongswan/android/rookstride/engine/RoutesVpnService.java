package org.strongswan.android.rookstride.engine;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import org.json.JSONObject;
import org.rookstride.engine.xray.libXray.LibXray;
import org.rookstride.engine.xray.libXray.Tun2SocksConfig;
import org.strongswan.android.rookstride.SingleProtocols;
import go.Seq;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Private worker; only its transport descriptors bypass the VPN. */
public final class RoutesVpnService extends EngineVpnService {
    private LocalServerSocket protector;
    private String protection,content,method,endpoint,user,password;
    private int port;private volatile Process process;private boolean tunStarted;
    protected String protocol(){return "routes";}
    protected boolean acceptsProtocol(String value){return SingleProtocols.from(value).worker();}
    protected void startEngine(String text)throws Exception{
        JSONObject profile=new JSONObject(text);method=profile.getString("protocol");content=text;
        NativeProfiles.workerProfile(method,content);
        InetAddress[] addresses=underlying.getAllByName(profile.getString("server"));endpoint="";
        for(InetAddress address:addresses)if(address instanceof Inet4Address){endpoint=address.getHostAddress();break;}
        if(endpoint.isEmpty())throw new IOException("No IPv4 server address");
        String socket="rookstride-"+UUID.randomUUID().toString();protection="@"+socket;protector=new LocalServerSocket(socket);
        Thread protectionThread=new Thread(this::protectDescriptors,"VPN socket protection");protectionThread.setDaemon(true);protectionThread.start();
        try(ServerSocket s=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){port=s.getLocalPort();}
        user=UUID.randomUUID().toString().replace("-","");password=UUID.randomUUID().toString().replace("-","");
        startWorker();if(stopping)return;
        Seq.setContext(getApplicationContext());Builder builder=builder().addAddress("10.254.254.1",30).addDnsServer("1.1.1.1").addDnsServer("9.9.9.9").addRoute("0.0.0.0",0);
        try(ParcelFileDescriptor tun=builder.establish()){
            if(tun==null)throw new IOException("VPN interface unavailable");
            Tun2SocksConfig socks=new Tun2SocksConfig();socks.setMTU(1280);socks.setProxy("socks5://"+user+":"+password+"@127.0.0.1:"+port);socks.setLogLevel("silent");int fd=tun.detachFd();socks.setDevice("fd://"+fd);
            String error=LibXray.startTun2Socks(socks,fd);if(error!=null&&!error.isEmpty())throw new IOException("VPN interface could not start");tunStarted=true;
        }
        verifyTraffic();
    }
    private void protectDescriptors(){
        while(!stopping&&protector!=null)try(LocalSocket socket=protector.accept()){
            socket.setSoTimeout(5000);if(socket.getPeerCredentials().getUid()!=getApplicationInfo().uid)continue;
            if(socket.getInputStream().read()<0)continue;FileDescriptor[] descriptors=socket.getAncillaryFileDescriptors();boolean success=underlying!=null&&descriptors!=null&&descriptors.length==1;
            if(descriptors!=null)for(FileDescriptor descriptor:descriptors){try(ParcelFileDescriptor duplicate=ParcelFileDescriptor.dup(descriptor)){if(!protectSocket(duplicate.getFd()))success=false;}finally{try{Os.close(descriptor);}catch(Exception ignored){}}}
            // ProtectPath treats any single-byte reply as success. Failure must
            // close without a reply, rather than send an unsuccessful status byte.
            if(success){socket.getOutputStream().write(1);socket.getOutputStream().flush();}
        }catch(Exception e){if(!stopping)record("Transport protection channel interrupted");}
    }
    private void startWorker()throws Exception{
        JSONObject profile=new JSONObject(content);endpoint="";
        if(underlying==null)throw new IOException("No underlying network");
        for(InetAddress address:underlying.getAllByName(profile.getString("server")))if(address instanceof Inet4Address){endpoint=address.getHostAddress();break;}
        if(endpoint.isEmpty())throw new IOException("No IPv4 server address");
        JSONObject config=NativeProfiles.worker(method,content,port,user,password,protection,endpoint);
        File binary=new File(getApplicationInfo().nativeLibraryDir,"librook-routes.so");if(!binary.isFile()||!binary.canExecute())throw new IOException("VPN runtime unavailable");
        Process child=new ProcessBuilder(binary.getAbsolutePath()).redirectErrorStream(true).start();process=child;
        try(OutputStream input=child.getOutputStream()){input.write(config.toString().getBytes(StandardCharsets.UTF_8));}
        Thread drain=new Thread(()->{try(InputStream input=child.getInputStream()){byte[] b=new byte[2048];while(input.read(b)>=0){/* Never retain native messages containing endpoints or secrets. */}}catch(IOException ignored){}} ,"VPN worker output");drain.setDaemon(true);drain.start();
        long deadline=android.os.SystemClock.elapsedRealtime()+15000;boolean ready=false;
        while(!stopping&&child.isAlive()&&android.os.SystemClock.elapsedRealtime()<deadline){try(Socket s=new Socket()){s.connect(new InetSocketAddress("127.0.0.1",port),200);ready=true;break;}catch(IOException e){Thread.sleep(100);}}
        if(!ready){if(!child.isAlive())record("VPN worker exit code "+child.exitValue());throw new IOException("VPN worker did not become ready");}
        record("Protected VPN worker ready");Thread watch=new Thread(()->{try{child.waitFor();if(!stopping&&process==child)worker.execute(()->{if(!stopping&&process==child)fail("The VPN worker stopped. Reconnect to try again.");});}catch(InterruptedException e){Thread.currentThread().interrupt();}},"VPN worker lifecycle");watch.setDaemon(true);watch.start();
    }
    private void stopWorker(){Process child=process;process=null;if(child!=null){child.destroy();try{if(!child.waitFor(6,TimeUnit.SECONDS)){child.destroyForcibly();child.waitFor(2,TimeUnit.SECONDS);}}catch(InterruptedException e){Thread.currentThread().interrupt();child.destroyForcibly();}}}
    protected void networkChanged(){if(!tunStarted||stopping)return;state("reconnecting");stopWorker();try{startWorker();verifyTraffic();}catch(Exception e){fail("Could not reconnect the VPN after the network changed.");}}
    protected void stopEngine(){stopWorker();if(protector!=null){try{protector.close();}catch(IOException ignored){}protector=null;}if(tunStarted){LibXray.stopTun2Socks();tunStarted=false;}content=null;password=null;}
}
