package org.strongswan.android.rookstride.engine;

import android.os.ParcelFileDescriptor;
import java.io.IOException;
import java.util.concurrent.*;

public final class OpenVpnService extends EngineVpnService {
    private Builder tunBuilder;
    private volatile Thread core;
    private volatile boolean loaded;
    private volatile ParcelFileDescriptor tunnelGuard;
    protected String protocol(){return "openvpn";}
    protected void startEngine(String profile)throws Exception{
        NativeProfiles.validate("openvpn",profile);System.loadLibrary("rook-openvpn");loaded=true;if(stopping)return;
        org.json.JSONObject login=NativeProfiles.openVpnCredentials(profile);String config=NativeProfiles.openVpnConfiguration(profile);
        core=new Thread(()->{String result=OpenVpnNative.run(this,config,login.optString("login"),login.optString("password"));if(!stopping)fail("OpenVPN connection ended. View log for status events.");},"rook-openvpn");core.start();
    }
    protected void stopEngine(){if(!loaded)return;OpenVpnNative.stop();Thread t=core;if(t!=null&&t!=Thread.currentThread())try{t.join(5000);}catch(InterruptedException e){Thread.currentThread().interrupt();}core=null;ParcelFileDescriptor guard=tunnelGuard;tunnelGuard=null;if(guard!=null)try{guard.close();}catch(IOException ignored){}}
    protected void networkChanged(){if(loaded){state("reconnecting");OpenVpnNative.reconnect();}}
    public boolean openvpnNew(){try{tunBuilder=builder();return !stopping;}catch(Exception e){return false;}}
    public boolean openvpnMtu(int mtu){try{tunBuilder.setMtu(Math.max(1280,Math.min(mtu,1500)));return true;}catch(Exception e){return false;}}
    public boolean openvpnAddress(String address,int prefix){try{if(address.indexOf(':')>=0)return true;tunBuilder.addAddress(address,prefix);return true;}catch(Exception e){return false;}}
    public boolean openvpnRoute(String address,int prefix){try{if(address.indexOf(':')>=0)return true;tunBuilder.addRoute(address,prefix);return true;}catch(Exception e){return false;}}
    public boolean openvpnDns(String address,int unused){try{if(address.indexOf(':')>=0)return true;tunBuilder.addDnsServer(address);return true;}catch(Exception e){return false;}}
    public int openvpnEstablish(){try{if(stopping)return -1;tunBuilder.addRoute("0.0.0.0",0);ParcelFileDescriptor fd=tunBuilder.establish();if(fd==null)return -1;ParcelFileDescriptor old=tunnelGuard;tunnelGuard=ParcelFileDescriptor.dup(fd.getFileDescriptor());if(old!=null)old.close();return fd.detachFd();}catch(Exception e){return -1;}}
    public void openvpnEvent(String event,boolean error){if(stopping)return;if(error){record("OpenVPN: "+(event.matches("[A-Z_0-9]{1,64}")?event:"CORE_ERROR"));fail(org.strongswan.android.rookstride.VpnDiagnosis.openvpn(event));return;}if(event.equals("CONNECTED"))state("connected");else if(event.equals("RECONNECTING"))state("reconnecting");}
}
