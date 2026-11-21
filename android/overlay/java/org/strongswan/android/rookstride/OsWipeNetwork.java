package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;

/** Full disk replacement must not destroy the VPN carrying its own management. */
public final class OsWipeNetwork {
    private OsWipeNetwork(){}
    static final class State {final boolean vpn,notVpn;State(boolean vpn,boolean notVpn){this.vpn=vpn;this.notVpn=notVpn;}}
    interface Source {State read(Context context);}
    static volatile Source source=context->{ConnectivityManager manager=context.getSystemService(ConnectivityManager.class);NetworkCapabilities network=manager==null?null:manager.getNetworkCapabilities(manager.getActiveNetwork());return network==null?null:new State(network.hasTransport(NetworkCapabilities.TRANSPORT_VPN),network.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));};
    public static void requireDirect(Context context){requireDirect(source.read(context));}
    static void requireDirect(State network){
        if(network==null)throw new IllegalStateException("Connect directly through Wi-Fi, mobile data or Ethernet before reviewing a disk wipe.");
        if(network.vpn||!network.notVpn)throw new IllegalStateException("Disconnect the current VPN before wiping these servers. Use your network directly, verify SSH access and review the disks again.");
    }
    static void beforeLaunch(Context context,String kind,boolean resume){if(!resume&&(kind.equals("os")||kind.equals("paired-os")||kind.equals("paired-restore")))requireDirect(context);}
}
