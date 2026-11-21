package org.strongswan.android.rookstride.engine;

import android.content.Context;
import android.net.Network;
import android.net.Uri;
import android.os.*;
import com.jcraft.jsch.SocketFactory;
import org.strongswan.android.rookstride.Ssh;
import java.io.*;
import java.net.*;

/** Only SSH transport sockets bypass the VPN; other app traffic remains tunneled. */
public final class AdminSocketFactory implements SocketFactory {
    private final Context context;
    private static final class AdminSocket extends Socket {
        ParcelFileDescriptor view;
        @Override public synchronized void close()throws IOException{try{super.close();}finally{if(view!=null){try{view.close();}catch(IOException ignored){}view=null;}}}
    }
    private AdminSocketFactory(Context c){context=c.getApplicationContext();}
    public static void install(Context c){Ssh.socketFactory=new AdminSocketFactory(c);}
    public Socket createSocket(String host,int port)throws IOException{
        // Local forwarding belongs to this app process, never to a physical network.
        if(host.equals("127.0.0.1")||host.equals("::1")){Socket local=new Socket();try{local.connect(new InetSocketAddress(host,port),12000);return local;}catch(IOException e){local.close();throw e;}}
        return connect(host,port);
    }
    private Socket connect(String host,int port)throws IOException{
        // Retry alternate DNS addresses with a fresh descriptor, never reuse a failed socket.
        IOException failure=null;InetAddress[] candidates=null;
        for(int attempt=0;attempt<4;attempt++){
        AdminSocket socket=new AdminSocket();
        try{
            socket.bind(new InetSocketAddress(0));Network underlay=null;
            // Before API29 fromSocket shares the Socket's descriptor. Keep the view
            // alive until Socket.close(), and transfer only an independent dup.
            socket.view=ParcelFileDescriptor.fromSocket(socket);
            try(ParcelFileDescriptor fd=socket.view.dup()){
                if(fd==null)throw new IOException("Could not prepare SSH transport");
                Bundle request=new Bundle();request.putParcelable("socket",fd);
                for(String protocol:new String[]{"awg","xray","openvpn","routes"}){
                    Bundle result=context.getContentResolver().call(Uri.parse("content://"+context.getPackageName()+".engine."+protocol),"protect",null,request);
                    if(result!=null&&result.getBoolean("present")){
                        if(!result.getBoolean("protected"))throw new IOException("Could not protect administrator connection");
                        underlay=result.getParcelable("network");break;
                    }
                }
            }
            InetAddress[] addresses=candidates==null?(underlay==null?InetAddress.getAllByName(host):underlay.getAllByName(host)):candidates; candidates=addresses;
            if(addresses.length==0)throw new UnknownHostException(host);
            if(attempt>=addresses.length){socket.close();break;}socket.connect(new InetSocketAddress(addresses[attempt],port),6000);socket.setTcpNoDelay(true);return socket;
        }catch(Exception e){try{socket.close();}catch(IOException ignored){}if(e instanceof IOException){failure=(IOException)e;if(candidates!=null&&attempt+1<candidates.length)continue;throw failure;}throw new IOException("SSH transport unavailable",e);}
        }
        throw failure==null?new IOException("No SSH address answered"):failure;
    }
    public InputStream getInputStream(Socket socket)throws IOException{return socket.getInputStream();}
    public OutputStream getOutputStream(Socket socket)throws IOException{return socket.getOutputStream();}
}
