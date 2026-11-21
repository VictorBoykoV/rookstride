package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.*;
import android.os.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.HttpsURLConnection;

/** Both DNS and HTTPS stay on one explicit Android Network, including redirects. */
final class ArtifactNetwork implements ArtifactDownloader.Transport {
    private final Context context;
    private final ConnectivityManager connectivity;
    private final Network network;
    private final boolean mayFindOwnedFallback;
    private ArtifactNetwork(Context context,Network network,boolean fallback)throws IOException{
        this.context=context.getApplicationContext();connectivity=this.context.getSystemService(ConnectivityManager.class);this.network=network;mayFindOwnedFallback=fallback;requireNetwork(false);
    }
    static ArtifactDownloader.Transport active(Context context)throws IOException{
        ConnectivityManager connectivity=context.getSystemService(ConnectivityManager.class);Network active=connectivity==null?null:connectivity.getActiveNetwork();
        if(active==null)throw new IOException("This phone has no active network for public component downloads.");return new ArtifactNetwork(context,active,true);
    }
    private NetworkCapabilities requireNetwork(boolean physical)throws IOException{
        NetworkCapabilities capabilities=connectivity==null?null:connectivity.getNetworkCapabilities(network);
        if(capabilities==null||!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)||physical&&!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))throw new IOException("The selected public component download network is no longer available.");return capabilities;
    }
    public HttpsURLConnection open(URL url)throws IOException{
        requireNetwork(!mayFindOwnedFallback);URLConnection connection=network.openConnection(url,java.net.Proxy.NO_PROXY);
        if(!(connection instanceof HttpsURLConnection))throw new IOException("Public components require a secure HTTPS connection.");
        // Platform TLS roots, hostname verification and SNI remain unchanged.
        return (HttpsURLConnection)connection;
    }
    public ArtifactDownloader.Transport fallback()throws IOException{
        if(!mayFindOwnedFallback||!requireNetwork(false).hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;
        // This temporary FD discovers current Rook ownership/underlay. It does
        // not protect URLConnection's sockets: Network.openConnection does the
        // actual DNS/socket binding. A foreign VPN never grants this fallback.
        try(Socket socket=new Socket()){
            socket.bind(new InetSocketAddress(0));
            try(ParcelFileDescriptor view=ParcelFileDescriptor.fromSocket(socket)){
                for(String protocol:new String[]{"awg","xray","openvpn","routes"}){
                    try(ParcelFileDescriptor copy=view.dup()){
                        Bundle request=new Bundle();request.putParcelable("socket",copy);
                        Bundle result=context.getContentResolver().call(Uri.parse("content://"+context.getPackageName()+".engine."+protocol),"protect",null,request);
                        if(result!=null&&result.getBoolean("present")){
                            if(!result.getBoolean("protected"))throw new IOException("The VPN's public component control connection is unavailable.");Network underlay=result.getParcelable("network");
                            if(underlay==null||underlay.equals(network))throw new IOException("The VPN has no independent public component control network.");
                            return new ArtifactNetwork(context,underlay,false);
                        }
                    }
                }
            }
        }catch(IOException e){throw e;}catch(Exception e){throw new IOException("The public component control network could not be checked.",e);}
        return null;
    }
}
