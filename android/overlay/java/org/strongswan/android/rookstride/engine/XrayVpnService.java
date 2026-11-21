package org.strongswan.android.rookstride.engine;

import android.os.ParcelFileDescriptor;
import org.json.JSONObject;
import org.rookstride.engine.xray.libXray.*;
import go.Seq;
import java.io.IOException;
import java.net.*;
import java.util.UUID;

public final class XrayVpnService extends EngineVpnService {
    private volatile boolean loaded,running;
    protected String protocol(){return "xray";}
    protected boolean acceptsProtocol(String value){return value.equals("xray")||value.equals("xhttp");}
    protected void startEngine(String link)throws Exception{
        Seq.setContext(getApplicationContext());loaded=true;
        check(LibXray.registerProtection(fd->protectSocket((int)fd)));
        int port;try(ServerSocket s=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){port=s.getLocalPort();}
        String user=UUID.randomUUID().toString().replace("-",""),password=UUID.randomUUID().toString().replace("-","");
        JSONObject config=NativeProfiles.xray(link,port,user,password);
        // Resolve the endpoint before taking over device DNS; preserve REALITY SNI.
        JSONObject server=config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0);
        server.put("address",InetAddress.getByName(server.getString("address")).getHostAddress());
        if(stopping)return;check(LibXray.startMemory(config.toString()));running=true;
        Builder builder=builder().addAddress("10.254.254.1",30).addDnsServer("1.1.1.1").addDnsServer("9.9.9.9").addRoute("0.0.0.0",0);
        try(ParcelFileDescriptor tun=builder.establish()){
            if(tun==null)throw new IOException("VPN interface unavailable");
            Tun2SocksConfig socks=new Tun2SocksConfig();socks.setMTU(1280);socks.setProxy("socks5://"+user+":"+password+"@127.0.0.1:"+port);socks.setLogLevel("silent");int fd=tun.detachFd();socks.setDevice("fd://"+fd);check(LibXray.startTun2Socks(socks,fd));
        }
        verifyTraffic();
    }
    private void check(String error)throws IOException{if(error!=null&&!error.isEmpty())throw new IOException("Xray engine could not start");}
    protected void networkChanged(){if(running)verifyTraffic();}
    protected void stopEngine(){if(!loaded)return;LibXray.stopTun2Socks();LibXray.stopMemory();running=false;}
}
