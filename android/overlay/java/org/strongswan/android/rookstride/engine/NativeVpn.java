package org.strongswan.android.rookstride.engine;

import android.content.*;
import android.net.Uri;
import android.os.Bundle;
import org.strongswan.android.rookstride.SingleProtocols;

/** Same-UID control/status channel; no credentials cross Intents or providers. */
public final class NativeVpn {
    private static String engine(String p){if(p.equals("xhttp"))return "xray";return SingleProtocols.from(p).worker()?"routes":p;}
    private static final java.util.concurrent.atomic.AtomicLong generation=new java.util.concurrent.atomic.AtomicLong();
    private static final java.util.Map<String,Bundle> errors=new java.util.concurrent.ConcurrentHashMap<>();
    public static final class Status {
        public final String id,state,error,log,diagnostic;public final boolean desired,present;
        Status(Bundle b){present=b!=null&&b.getBoolean("service",false);desired=b!=null&&b.getBoolean("desired",false);id=b==null?"":b.getString("id","");state=b==null?"disconnected":b.getString("state","disconnected");error=b==null?"":b.getString("error","");log=b==null?"":b.getString("log","");diagnostic=b==null?"":b.getString("diagnostic","");}
        public boolean active(String profile){return id.equals(profile)&&isActive(state);}
    }
    static Status rawStatus(Context c,String protocol){protocol=engine(protocol);if(errors.containsKey(protocol))return new Status(errors.get(protocol));try{return new Status(c.getContentResolver().call(uri(c,protocol),"status",null,null));}catch(Exception e){return new Status(null);}}
    public static Status status(Context c,String protocol){protocol=engine(protocol);Status state=rawStatus(c,protocol);if(state.state.equals("interrupted")&&ConnectionKeeper.wants(protocol,state.id)){Bundle b=new Bundle();b.putString("id",state.id);b.putString("state","reconnecting");b.putString("log",state.log);return new Status(b);}return state;}
    static Class<?> serviceClass(String protocol){switch(engine(protocol)){case "awg":return AwgVpnService.class;case "xray":return XrayVpnService.class;case "openvpn":return OpenVpnService.class;case "routes":return RoutesVpnService.class;default:throw new IllegalArgumentException("Unsupported engine");}}
    static void startError(String protocol,String id){Bundle b=new Bundle();b.putString("id",id);b.putString("state","failed");b.putString("error","Open Rookstride and reconnect. Android did not allow a background restart.");errors.put(protocol,b);}
    public static boolean isActive(String state){return state.equals("connecting")||state.equals("connected")||state.equals("reconnecting")||state.equals("checking")||state.equals("limited")||state.equals("stopping");}
    public static void recheck(Context c,String protocol){try{c.getContentResolver().call(uri(c,protocol),"recheck",null,null);}catch(Exception ignored){}}
    private static Uri uri(Context c,String p){p=engine(p);if(!p.equals("awg")&&!p.equals("xray")&&!p.equals("openvpn")&&!p.equals("routes"))throw new IllegalArgumentException("Unsupported engine");return Uri.parse("content://"+c.getPackageName()+".engine."+p);}
    public static void disconnect(Context c,String protocol){protocol=engine(protocol);generation.incrementAndGet();errors.remove(protocol);ConnectionKeeper.release(c,protocol,"");try{c.getContentResolver().call(uri(c,protocol),"disconnect",null,null);}catch(Exception ignored){}}
    public static void disconnectAll(Context c){for(String p:new String[]{"awg","xray","openvpn","routes"})disconnect(c,p);}
    public static void start(Context c,String type,String id){
        String protocol=engine(type);Class<?> cls=serviceClass(protocol);
        disconnectAll(c);long request=generation.incrementAndGet();
        android.os.Handler h=new android.os.Handler(android.os.Looper.getMainLooper());long deadline=android.os.SystemClock.elapsedRealtime()+7000;
        Runnable begin=new Runnable(){public void run(){if(request!=generation.get())return;boolean active=false;for(String p:new String[]{"awg","xray","openvpn","routes"}){Status s=status(c,p);if(s.present||isActive(s.state))active=true;}
            if(active&&android.os.SystemClock.elapsedRealtime()<deadline){h.postDelayed(this,150);return;}
            try{if(active)throw new IllegalStateException();ConnectionKeeper.begin(c,protocol,id);c.startForegroundService(new Intent(c,cls).setAction("connect").putExtra("id",id));}catch(RuntimeException e){Bundle b=new Bundle();b.putString("id",id);b.putString("state","failed");b.putString("error","Could not start the VPN. Keep Rookstride open and try again.");errors.put(protocol,b);ConnectionKeeper.release(c,protocol,id);}
        }};h.post(begin);
    }
}
