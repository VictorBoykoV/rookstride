package org.strongswan.android.rookstride.engine;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import org.json.JSONObject;
import org.strongswan.android.rookstride.VpnDiagnosis;
import org.strongswan.android.R;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.*;

/** Foreground ownership is independent of the Activity, including process recovery. */
public abstract class EngineVpnService extends VpnService {
    static volatile EngineVpnService current;
    private static volatile String lastId="",lastState="disconnected",lastError="",lastDiagnostic="";
    private static final java.util.ArrayDeque<String> events=new java.util.ArrayDeque<>();
    private EngineJournal journal;
    protected final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor();
    protected volatile boolean stopping;
    protected String id="",name="VPN";
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networks;
    private boolean started,engineStarted;
    private Network engineNetwork;
    private ScheduledFuture<?> networkUpdate;
    private final java.util.Set<Network> available=new java.util.HashSet<>();
    volatile Network underlying;
    private int notificationId;
    private final ExecutorService probes=Executors.newSingleThreadExecutor();
    private volatile javax.net.ssl.HttpsURLConnection verification;
    private final java.util.concurrent.atomic.AtomicLong trafficRevision=new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong stateRevision=new java.util.concurrent.atomic.AtomicLong();
    protected abstract String protocol();
    protected boolean acceptsProtocol(String value){return protocol().equals(value);}
    protected abstract void startEngine(String content)throws Exception;
    protected abstract void stopEngine();
    protected void networkChanged(){}
    protected final void record(String text){synchronized(EngineVpnService.class){if(events.size()>=80)events.removeFirst();events.addLast(java.time.Instant.now()+" · "+text);persist();}}
    private void persist(){if(journal!=null)journal.save(lastId,lastState,lastError,String.join("\n",events),lastDiagnostic);}
    static Bundle status(Context context,String protocol){
        if(current==null&&lastId.isEmpty())return new EngineJournal(context,protocol).previous();
        Bundle b=new Bundle();b.putBoolean("service",current!=null);b.putBoolean("desired",new EngineJournal(context,protocol).desired().equals(lastId)&&!lastId.isEmpty());b.putString("id",lastId);b.putString("state",lastState);b.putString("error",lastError);b.putString("diagnostic",lastDiagnostic);
        synchronized(EngineVpnService.class){b.putString("log",String.join("\n",events));}return b;
    }
    @Override public void onCreate(){super.onCreate();current=this;journal=new EngineJournal(this,protocol());if(lastId.isEmpty()){Bundle previous=journal.previous();synchronized(EngineVpnService.class){String[] lines=previous.getString("log","").split("\n");for(int i=Math.max(0,lines.length-60);i<lines.length;i++)if(!lines[i].isEmpty())events.addLast(lines[i]);}}notificationId=ConnectionKeeper.NOTIFICATION;}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        boolean systemRestart=intent==null,recovering=systemRestart||(intent!=null&&intent.getBooleanExtra("recovering",false));
        if(!systemRestart&&!"connect".equals(intent.getAction())){record("Disconnect requested");requestStop();return START_NOT_STICKY;}
        if(started)return START_STICKY;
        String requested=systemRestart?journal.desired():intent.getStringExtra("id");
        if(requested==null||requested.isEmpty()){stopSelf();return START_NOT_STICKY;}
        started=true;id=requested;lastId=id;lastError="";lastDiagnostic="";lastState="connecting";journal.desired(id);
        record(recovering?"Recovering VPN engine":"Connecting");
        record("Android "+Build.VERSION.SDK_INT+" · battery optimization "+(getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName())?"unrestricted":"enabled"));
        try{String privateDns=android.provider.Settings.Global.getString(getContentResolver(),"private_dns_mode");record("Android Private DNS: "+("hostname".equals(privateDns)?"custom provider":"off".equals(privateDns)?"off":"opportunistic".equals(privateDns)?"automatic":"not reported"));}catch(SecurityException e){record("Android Private DNS: unavailable");}
        NotificationManager nm=getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("rookstride-vpn","VPN connection",NotificationManager.IMPORTANCE_LOW));
        startForeground(notificationId,notification());
        worker.execute(()->{
            try{
                if(VpnService.prepare(this)!=null){fail(VpnDiagnosis.of("vpn_permission_required"));return;}
                JSONObject p=new NativeProfileStore(this).read(id);if(!acceptsProtocol(p.getString("protocol")))throw new IOException("VPN protocol mismatch");
                name=p.getString("name");if(stopping)return;watchNetworks();
                long deadline=SystemClock.elapsedRealtime()+12000;while(!stopping&&underlying==null&&SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);
                if(stopping)return;if(underlying==null){fail(VpnDiagnosis.of("vpn_no_underlying_network"));return;}
                Network initial=underlying;startEngine(p.getString("content"));engineNetwork=initial;engineStarted=true;scheduleNetworkUpdate();
            }catch(Exception|LinkageError e){record("Engine start failed: "+e.getClass().getSimpleName());fail(e instanceof NativeProfileStore.StorageException?e.getMessage():"Could not start the VPN. Open View log for details.");}
        });return START_STICKY;
    }
    protected final Builder builder()throws android.content.pm.PackageManager.NameNotFoundException{Builder b=new Builder().setSession(name).setMtu(1280).setBlocking(true);if(Build.VERSION.SDK_INT>=29)b.setMetered(false);org.strongswan.android.rookstride.AppRouting.apply(this,b);return b;}
    public final boolean nativeStopping(){return stopping;}
    public final boolean protectSocket(int fd){return fd>=0&&protect(fd)&&bindProtectedSocket(fd);}
    final boolean bindProtectedSocket(int fd){Network network=underlying;if(network!=null)try(ParcelFileDescriptor duplicate=ParcelFileDescriptor.fromFd(fd)){network.bindSocket(duplicate.getFileDescriptor());}catch(Exception e){record("Transport binding failed: "+e.getClass().getSimpleName());return false;}return true;}
    protected final void state(String value){
        if(value.equals("reconnecting")){cancelTrafficCheck();lastDiagnostic="";}
        if(stopping||lastState.equals(value))return;long revision=stateRevision.incrementAndGet();
        if(value.equals("connected"))worker.execute(()->{Network ready=awaitVpnNetwork();if(stopping||revision!=stateRevision.get())return;if(ready!=null)publishState(value);else fail(VpnDiagnosis.of("vpn_route_unavailable"));});
        else publishState(value);
    }
    private void publishState(String value){if(stopping||lastState.equals(value))return;lastState=value;if(value.equals("connected")){lastError="";if(lastDiagnostic.isEmpty())diagnosis(VpnDiagnosis.of("vpn_transport_ready"));}record(value);getSystemService(NotificationManager.class).notify(notificationId,notification());}
    private Network awaitVpnNetwork(){
        long deadline=SystemClock.elapsedRealtime()+15000;ConnectivityManager cm=getSystemService(ConnectivityManager.class);
        while(!stopping&&SystemClock.elapsedRealtime()<deadline){
            Network active=cm.getActiveNetwork();NetworkCapabilities caps=cm.getNetworkCapabilities(active);NetworkInfo info=cm.getNetworkInfo(active);
            if(underlying!=null&&caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&info!=null&&info.isConnected())return active;
            try{Thread.sleep(100);}catch(InterruptedException e){Thread.currentThread().interrupt();return null;}
        }return null;
    }
    private void diagnosis(VpnDiagnosis.Result result){try{lastDiagnostic=result.observation().toString();}catch(Exception ignored){lastDiagnostic="";}}
    protected final void fail(VpnDiagnosis.Result result){diagnosis(result);failKnown(result.detail);}
    protected final void fail(String message){diagnosis(VpnDiagnosis.of("vpn_unknown"));failKnown(message);}
    private void failKnown(String message){if(stopping)return;lastError=message;lastState="failed";record(message);requestStop();}
    /** TLS probes are bound to the VPN network, never the protected underlay. */
    protected final void verifyTraffic(){
        if(stopping)return;
        final long revision=cancelTrafficCheck();lastError="";lastDiagnostic="";
        state("checking");probes.execute(()->{
            if(stopping||revision!=trafficRevision.get())return;
            boolean success=false,routeReady=false;int dnsFailures=0,tlsFailures=0,httpResponses=0,attempts=0;
            try{
                Network network=awaitVpnNetwork();routeReady=network!=null;if(network==null)record("Check: Android VPN route not ready");
                else for(String target:new String[]{"https://example.com/","https://www.cloudflare.com/cdn-cgi/trace"}){
                    if(stopping||revision!=trafficRevision.get())break;
                    attempts++;
                    javax.net.ssl.HttpsURLConnection connection=null;
                    try{
                        connection=(javax.net.ssl.HttpsURLConnection)network.openConnection(new URL(target));verification=connection;
                        connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(8000);connection.setReadTimeout(8000);connection.setUseCaches(false);
                        int code=connection.getResponseCode();httpResponses++;record("HTTPS check "+new URL(target).getHost()+": HTTP "+code);
                        if(code>=200&&code<400){success=true;break;}
                    }catch(Exception e){if(e instanceof java.net.UnknownHostException){dnsFailures++;record("DNS failed through VPN for "+new URL(target).getHost()+" (UnknownHostException)");}else{if(e instanceof javax.net.ssl.SSLException)tlsFailures++;record("HTTPS check "+new URL(target).getHost()+": "+e.getClass().getSimpleName());}}
                    finally{if(connection!=null)connection.disconnect();if(verification==connection)verification=null;}
                }
            }catch(Exception e){record("Traffic check: "+e.getClass().getSimpleName());}
            finishTrafficCheck(revision,VpnDiagnosis.web(routeReady,success,attempts,dnsFailures,tlsFailures,httpResponses));
        });
    }
    private synchronized void finishTrafficCheck(long revision,VpnDiagnosis.Result result){
        if(stopping||revision!=trafficRevision.get())return;
        diagnosis(result);
        if(result.code.equals("vpn_web_verified"))state("connected");else{
            lastError=result.detail;
            // Retain the VPN routes after a failed public check.
            state("limited");record("VPN retained after inconclusive traffic check");
        }
    }
    private synchronized long cancelTrafficCheck(){
        long revision=trafficRevision.incrementAndGet();stateRevision.incrementAndGet();
        javax.net.ssl.HttpsURLConnection check=verification;if(check!=null)check.disconnect();return revision;
    }
    private synchronized void scheduleNetworkUpdate(){
        if(stopping||worker.isShutdown())return;if(networkUpdate!=null)networkUpdate.cancel(false);
        networkUpdate=worker.schedule(()->{
            if(stopping||!engineStarted)return;Network next=underlying;
            if(next==null){engineNetwork=null;return;}
            if(java.util.Objects.equals(next,engineNetwork))return;
            // A callback received during startup must not restart the transport
            // that startup already bound. Real changes get one serialized restart.
            engineNetwork=next;record("Underlying network changed; restarting VPN transport");networkChanged();
            if(!java.util.Objects.equals(next,underlying))scheduleNetworkUpdate();
        },400,TimeUnit.MILLISECONDS);
    }
    private Notification notification(){
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,RookstrideActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TOP),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop=PendingIntent.getService(this,0,new Intent(this,getClass()).setAction("disconnect"),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        String status=lastState.equals("connected")?"Connected":lastState.equals("limited")?"Check internet access":lastState.equals("checking")?"Checking internet…":lastState.equals("reconnecting")?"Reconnecting…":"Connecting…";
        return new Notification.Builder(this,"rookstride-vpn").setSmallIcon(R.drawable.rook_notification).setContentTitle(name).setContentText(status).setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null,"Disconnect",stop).build()).build();
    }
    private void watchNetworks(){
        connectivity=getSystemService(ConnectivityManager.class);
        networks=new ConnectivityManager.NetworkCallback(){
            @Override public void onAvailable(Network n){available.add(n);selectUnderlay();}
            @Override public void onCapabilitiesChanged(Network n,NetworkCapabilities caps){if(available.contains(n))selectUnderlay();}
            @Override public void onLost(Network n){available.remove(n);if(n.equals(underlying))state("reconnecting");selectUnderlay();}
            private void selectUnderlay(){
                if(stopping)return;Network best=null;int score=-1;
                for(Network n:available){NetworkCapabilities caps=connectivity.getNetworkCapabilities(n);if(caps==null||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))continue;int value=(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)?10:0)+(caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)?3:caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?2:1);if(value>score||value==score&&n.equals(underlying)){score=value;best=n;}}
                if(java.util.Objects.equals(best,underlying))return;underlying=best;setUnderlyingNetworks(best==null?new Network[0]:new Network[]{best});
                record(best==null?"Underlying network lost":"Underlying network selected");
                scheduleNetworkUpdate();
            }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networks);
    }
    public final synchronized void requestStop(){
        if(stopping)return;journal.desired("");ConnectionKeeper.release(this,protocol(),id);stopping=true;javax.net.ssl.HttpsURLConnection check=verification;if(check!=null)check.disconnect();
        if(!lastState.equals("failed"))lastState="stopping";record("Disconnecting");
        worker.execute(()->{try{stopEngine();}finally{new Handler(getMainLooper()).post(()->{stopForeground(true);stopSelf();});}});
    }
    @Override public void onRevoke(){record("Android revoked the VPN permission or selected another VPN");requestStop();}
    @Override public void onTaskRemoved(Intent intent){record("App removed from recent apps; VPN service retained");super.onTaskRemoved(intent);}
    @Override public void onDestroy(){
        boolean requested=stopping;stopping=true;if(!lastState.equals("failed"))lastState=requested?"stopping":"interrupted";record(requested?"Service stopping":"Android destroyed the VPN service");
        if(!worker.isShutdown())worker.execute(()->{try{stopEngine();}catch(Exception ignored){}finally{if(current==this){if(!lastState.equals("failed")&&requested){lastState="disconnected";record("Disconnected");}current=null;}}});
        if(networks!=null)try{connectivity.unregisterNetworkCallback(networks);}catch(Exception ignored){}
        probes.shutdownNow();worker.shutdown();super.onDestroy();
    }
}
