package org.strongswan.android.rookstride.engine;

import android.os.ParcelFileDescriptor;
import org.amnezia.awg.GoBackend;
import org.amnezia.awg.config.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

public final class AwgVpnService extends EngineVpnService {
    private volatile int handle=-1;
    private String profile;
    private ParcelFileDescriptor tunnelGuard;
    private ScheduledFuture<?> poll;
    private long startedAt,lastRecovery,lastHandshake;
    private boolean handshaken;
    protected String protocol(){return "awg";}
    protected void startEngine(String content)throws Exception{
        System.loadLibrary("rook-awg");profile=content;Config config=Config.parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        if(config.getPeers().size()!=1)throw new IOException("Use a single-server AmneziaWG profile");
        Builder b=builder();for(InetNetwork a:config.getInterface().getAddresses())if(a.getAddress() instanceof java.net.Inet4Address)b.addAddress(a.getAddress(),a.getMask());
        for(java.net.InetAddress a:config.getInterface().getDnsServers())if(a instanceof java.net.Inet4Address)b.addDnsServer(a);if(config.getInterface().getDnsServers().isEmpty())b.addDnsServer("1.1.1.1");
        // Full-device IPv4; unsupported IPv6 is blocked by not allowing its family.
        b.addRoute("0.0.0.0",0);b.setMtu(config.getInterface().getMtu().orElse(1280));
        String settings=config.toAwgUserspaceString();if(stopping)return;
        try(ParcelFileDescriptor tun=b.establish()){if(tun==null)throw new IOException("VPN interface unavailable");tunnelGuard=ParcelFileDescriptor.dup(tun.getFileDescriptor());handle=GoBackend.awgTurnOn("rookvpn",tun.detachFd(),settings);}
        if(handle<0)throw new IOException("AmneziaWG engine did not start");
        int v4=GoBackend.awgGetSocketV4(handle),v6=GoBackend.awgGetSocketV6(handle);if(v4>=0&&!protectSocket(v4)||v6>=0&&!protectSocket(v6))throw new IOException("Could not protect VPN transport");
        startedAt=android.os.SystemClock.elapsedRealtime();handshaken=false;lastHandshake=0;record("AmneziaWG transport started; waiting for handshake");poll=worker.scheduleWithFixedDelay(this::check,1,2,TimeUnit.SECONDS);
    }
    private void check(){
        if(stopping||handle<0)return;if(underlying==null){state("reconnecting");return;}String config=GoBackend.awgGetConfig(handle);long handshake=0;
        if(config!=null)for(String line:config.split("\n"))if(line.startsWith("last_handshake_time_sec="))try{handshake=Long.parseLong(line.substring(line.indexOf('=')+1));}catch(NumberFormatException ignored){}
        if(handshake>0){
            if(!handshaken){handshaken=true;record("AmneziaWG handshake established");}else if(handshake>lastHandshake)record("AmneziaWG handshake renewed");lastHandshake=handshake;
            long age=Math.max(0,System.currentTimeMillis()/1000-handshake);state(age<180?"connected":"reconnecting");
            long now=android.os.SystemClock.elapsedRealtime();
            if(age>240&&now-lastRecovery>180000){lastRecovery=now;record("Handshake stale; recovering AmneziaWG transport");networkChanged();}
        }
        else if(android.os.SystemClock.elapsedRealtime()-startedAt>45000)fail(org.strongswan.android.rookstride.VpnDiagnosis.of("vpn_transport_unreachable"));
    }
    protected void networkChanged(){if(stopping||profile==null)return;record("Rebinding AmneziaWG transport");state("reconnecting");ParcelFileDescriptor retained=tunnelGuard;tunnelGuard=null;try{stopEngine();startEngine(profile);}catch(Exception e){record("AmneziaWG recovery failed: "+e.getClass().getSimpleName());fail("Could not reconnect AmneziaWG");}finally{if(retained!=null)try{retained.close();}catch(IOException ignored){}}}
    protected void stopEngine(){if(poll!=null){poll.cancel(false);poll=null;}int h=handle;handle=-1;if(h>=0)GoBackend.awgTurnOff(h);if(tunnelGuard!=null){try{tunnelGuard.close();}catch(IOException ignored){}tunnelGuard=null;}}
}
