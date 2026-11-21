package org.strongswan.android.rookstride.engine;

import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import org.strongswan.android.R;
import org.strongswan.android.ui.RookstrideActivity;

/** Separate from Android's VPN binding, which can be stopped when its binder dies. */
public final class ConnectionKeeper extends Service {
    static final int NOTIFICATION=310;
    private static ConnectionKeeper current;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private String protocol="",id="",name="VPN",shown="";
    private long lastAttempt;private boolean foreground;
    static void begin(Context c,String protocol,String id){c.startForegroundService(new Intent(c,ConnectionKeeper.class).setAction("connect").putExtra("protocol",protocol).putExtra("id",id));}
    static void release(Context c,String protocol,String id){try{c.startService(new Intent(c,ConnectionKeeper.class).setAction("release").putExtra("protocol",protocol).putExtra("id",id));}catch(RuntimeException ignored){}}
    static boolean wants(String p,String id){return current!=null&&current.protocol.equals(p)&&current.id.equals(id)&&!id.isEmpty();}
    @Override public void onCreate(){super.onCreate();current=this;}
    @Override public IBinder onBind(Intent intent){return null;}
    private SharedPreferences prefs(){return getSharedPreferences("native-connection",0);}
    private void remember(){prefs().edit().putString("protocol",protocol).putString("id",id).commit();}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null&&"release".equals(intent.getAction())){
            String p=intent.getStringExtra("protocol"),value=intent.getStringExtra("id");
            if(protocol.isEmpty()){protocol=prefs().getString("protocol","");id=prefs().getString("id","");}
            if(protocol.equals(p)&&(value==null||value.isEmpty()||id.equals(value))){finish();return START_NOT_STICKY;}
            if(id.isEmpty()||!foreground){stopSelfResult(startId);return START_NOT_STICKY;}return START_STICKY;
        }
        if(intent!=null&&"disconnect".equals(intent.getAction())){String p=protocol;finish();if(!p.isEmpty())NativeVpn.disconnect(this,p);return START_NOT_STICKY;}
        if(intent==null){protocol=prefs().getString("protocol","");id=prefs().getString("id","");}
        else if("connect".equals(intent.getAction())){protocol=intent.getStringExtra("protocol");id=intent.getStringExtra("id");remember();}
        if(id==null||id.isEmpty()||!(protocol.equals("awg")||protocol.equals("xray")||protocol.equals("openvpn")||protocol.equals("routes"))){finish();return START_NOT_STICKY;}
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("rookstride-vpn","VPN connection",NotificationManager.IMPORTANCE_LOW));
        startForeground(NOTIFICATION,notification("Connecting…"));foreground=true;
        try{name=new NativeProfileStore(this).read(id).getString("name");}catch(Exception e){finish();return START_NOT_STICKY;}
        lastAttempt=SystemClock.elapsedRealtime();handler.removeCallbacks(poll);handler.postDelayed(poll,1500);return START_STICKY;
    }
    private final Runnable poll=new Runnable(){public void run(){
        if(id.isEmpty())return;
        if(VpnService.prepare(ConnectionKeeper.this)!=null){String p=protocol;finish();NativeVpn.disconnect(ConnectionKeeper.this,p);return;}
        NativeVpn.Status state=NativeVpn.rawStatus(ConnectionKeeper.this,protocol);
        if(state.id.equals(id)&&(state.state.equals("failed")||!state.desired&&SystemClock.elapsedRealtime()-lastAttempt>=5000)){finish();return;}
        String text=state.id.equals(id)&&state.state.equals("connected")?"Connected":state.state.equals("limited")?"Check internet access":state.state.equals("checking")?"Checking internet…":state.state.equals("connecting")?"Connecting…":"Reconnecting…";
        if(!shown.equals(text)){shown=text;getSystemService(NotificationManager.class).notify(NOTIFICATION,notification(text));}
        if(!state.present&&(!state.id.equals(id)||!NativeVpn.isActive(state.state))&&SystemClock.elapsedRealtime()-lastAttempt>=5000){
            lastAttempt=SystemClock.elapsedRealtime();
            try{startForegroundService(new Intent(ConnectionKeeper.this,NativeVpn.serviceClass(protocol)).setAction("connect").putExtra("id",id).putExtra("recovering",true));}
            catch(RuntimeException e){NativeVpn.startError(protocol,id);finish();return;}
        }
        handler.postDelayed(this,2000);
    }};
    private Notification notification(String status){
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,RookstrideActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TOP),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop=PendingIntent.getService(this,311,new Intent(this,ConnectionKeeper.class).setAction("disconnect"),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"rookstride-vpn").setSmallIcon(R.drawable.rook_notification).setContentTitle(name).setContentText(status).setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null,"Disconnect",stop).build()).build();
    }
    private void finish(){id="";protocol="";remember();handler.removeCallbacks(poll);stopForeground(true);stopSelf();}
    @Override public void onDestroy(){handler.removeCallbacksAndMessages(null);if(current==this)current=null;super.onDestroy();}
}
