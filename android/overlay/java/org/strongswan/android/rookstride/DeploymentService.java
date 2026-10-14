package org.strongswan.android.rookstride;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import org.json.JSONObject;
import org.strongswan.android.R;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** User-started SSH transfers and job polling survive Activity/tab recreation.
 * Server jobs are detached; process death never causes a fresh reinstall.
 * Secrets stay in the active process or the existing encrypted Vault, never an Intent. */
public final class DeploymentService extends Service {
    public interface Listener {void changed();}
    public static final class Session {
        public final Gateway node; public final ArrayList<Gateway> gateways;
        public final JSONObject config; public final boolean resume;
        public final InstallationProgress progress;
        public volatile JSONObject result; public volatile Exception error;
        private int serviceStartId;
        Session(Gateway node,ArrayList<Gateway> gateways,String kind,JSONObject config,boolean resume,long started){this.node=node;this.gateways=gateways;this.config=config;this.resume=resume;progress=new InstallationProgress(kind,node.get("id"),started);}
    }
    private static volatile Session current;
    interface Engine {JSONObject execute(DeploymentService service,Session session)throws Exception;}
    private static Engine engine=(service,session)->service.remote(session);
    private static final Set<Listener> listeners=new HashSet<>();
    private static final Handler main=new Handler(Looper.getMainLooper());
    private static final int NOTIFICATION=7351;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private PowerManager.WakeLock wake;
    private Session owned;
    public static Session current(){return current;}
    public static boolean active(){Session s=current;return s!=null&&s.progress.state.equals("running");}
    public static void observe(Listener listener){listeners.add(listener);}
    public static void unobserve(Listener listener){listeners.remove(listener);}
    public static void forget(Context context,Gateway node){
        if(active())return;
        if(current!=null&&current.node.get("id").equals(node.get("id")))current=null;
        android.content.SharedPreferences prefs=context.getSharedPreferences("rookstride-deployment",0);
        try{if(new JSONObject(prefs.getString("progress","{}")).optString("gateway").equals(node.get("id")))prefs.edit().remove("progress").apply();}catch(Exception ignored){}
    }
    public static synchronized void launch(Context context,Gateway node,ArrayList<Gateway> gateways,String kind,JSONObject config,boolean resume){
        if(active())throw new IllegalStateException("An installation is already running");
        if(!kind.equals("pair"))node.set("jobKind",kind);
        long started=System.currentTimeMillis();
        if(resume)try{InstallationProgress saved=InstallationProgress.from(new JSONObject(context.getSharedPreferences("rookstride-deployment",0).getString("progress","{}")));if(saved.gatewayId.equals(node.get("id"))&&saved.kind.equals(kind)&&!saved.state.equals("complete")&&saved.started>0&&saved.started<=started)started=saved.started;}catch(Exception ignored){}
        current=new Session(node,gateways,kind,config,resume,started);
        Intent intent=new Intent(context,DeploymentService.class);
        try{context.startForegroundService(intent);}catch(RuntimeException e){current.progress.state="needs-attention";current.error=e;throw e;}
    }
    @Override public IBinder onBind(Intent intent){return null;}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        Session s=current;if(s==null||!s.progress.state.equals("running")){stopSelf();return START_NOT_STICKY;}
        if(owned==s)return START_NOT_STICKY;
        owned=s;s.serviceStartId=startId;
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel("deployment","Gateway installation",NotificationManager.IMPORTANCE_LOW));
        if(Build.VERSION.SDK_INT>=29)startForeground(NOTIFICATION,notification(s),ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);else startForeground(NOTIFICATION,notification(s));
        releaseWake();wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"rookstride:deployment");wake.acquire(5*60*60*1000L);
        publish(s);
        worker.execute(()->{
            try{
                JSONObject result=engine.execute(this,s);
                main.post(()->{try{
                    if(current!=s||!s.progress.state.equals("running"))return;
                    s.result=result;
                    if(s.progress.kind.equals("pair")){s.node.data.put("snapshot",result.getJSONObject("entry"));s.node.exit.data.put("snapshot",result.getJSONObject("exit"));s.node.set("pairPhase","Ready · IPv4 exit "+result.optString("exit_ip"));}
                    else{s.node.data.put("snapshot",result);s.node.set("job","");}
                    s.node.set("checked","Installation checks passed");s.progress.finish();publish(s);releaseWake();stopForeground(STOP_FOREGROUND_REMOVE);stopSelf(s.serviceStartId);
                }catch(Exception e){failed(s,e);}});
            }catch(Exception e){main.post(()->failed(s,e));}
        });return START_NOT_STICKY;
    }
    private JSONObject remote(Session s)throws Exception{
        if(!s.progress.kind.equals("pair"))return single(s);
        return PairController.install(s.node,()->getAssets().open("gateway_bundle.zip"),new PairController.Progress(){
            private int checkpoint=0;
            public void update(String phase){DeploymentService.this.update(s,checkpoint,phase);}
            public void stage(int index,String phase){checkpoint=index;DeploymentService.this.update(s,index,phase);}
        },s.resume);
    }
    void checkpoint(Session s,int index,String phase){update(s,index,phase);}
    private JSONObject single(Session s)throws Exception{
        try(Ssh ssh=new Ssh(s.node)){
            update(s,0,"Checking the pinned SSH identity");ssh.probe();
            String job=s.node.get("job");
            if(job.isEmpty()){
                update(s,1,"Sending the reviewed installer");
                try(InputStream bundle=getAssets().open("gateway_bundle.zip")){job=ssh.deploy(bundle,s.config).getString("job");}
                final String id=job;main.post(()->{s.node.set("job",id);publish(s);});
            }
            long deadline=System.nanoTime()+5_400_000_000_000L;
            while(true){
                JSONObject status=ssh.job(job);String state=status.optString("state"),phase=status.optString("phase");
                int index=s.progress.kind.equals("enroll")?2:phase.contains("management")?3:2;
                update(s,index,phase);
                if(state.equals("complete"))break;
                if(state.equals("failed"))throw new IOException(phase);
                if(System.nanoTime()>deadline)throw new IOException("The server job may still be running. Check and resume its recorded job; do not install again.");
                Thread.sleep(4000);
            }
            update(s,s.progress.steps().length-1,"Reading gateway health");return ssh.admin(new JSONObject().put("action","status"));
        }
    }
    private void update(Session s,int index,String phase){main.post(()->{if(!s.progress.state.equals("running")||(s.progress.completed==index&&s.progress.phase.equals(phase)))return;s.progress.stage(index,phase);if(s.progress.kind.equals("pair"))s.node.set("pairPhase",phase);else s.node.set("jobPhase",phase);publish(s);});}
    private void publish(Session s){
        getSharedPreferences("rookstride-deployment",0).edit().putString("progress",s.progress.json().toString()).apply();
        try{new Vault(this).write(s.gateways);}catch(Exception e){s.progress.phase="Could not save local progress. Server jobs continue; inspect before resuming.";}
        if(s.progress.state.equals("running"))((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTIFICATION,notification(s));
        for(Listener listener:new ArrayList<>(listeners))listener.changed();
    }
    private Notification notification(Session s){
        Intent open=new Intent(this,RookstrideActivity.class).putExtra("rookstride.progress",true).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP|Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pending=PendingIntent.getActivity(this,0,open,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification publicNotice=new Notification.Builder(this,"deployment").setSmallIcon(R.drawable.rook_icon).setContentTitle("Rookstride gateway installation").setContentText("Open to view progress").setContentIntent(pending).build();
        return new Notification.Builder(this,"deployment").setVisibility(Notification.VISIBILITY_PRIVATE).setPublicVersion(publicNotice).setSmallIcon(R.drawable.rook_icon).setContentTitle("Rookstride · "+s.progress.completed+" / "+s.progress.steps().length+" checkpoints")
            .setContentText(s.progress.phase).setContentIntent(pending).setOngoing(true).setOnlyAlertOnce(true).setProgress(s.progress.steps().length,s.progress.completed,false).build();
    }
    private void failed(Session s,Exception error){
        if(!s.progress.state.equals("running"))return;
        s.error=error;s.progress.state=error instanceof PairController.RebootNeeded?"awaiting-reboot":"needs-attention";
        s.progress.phase=error instanceof Ssh.HostTrust||error instanceof PairController.TrustNeeded?"Verify SSH identity to continue":error.getMessage()==null?"Check the recorded server job before resuming":error.getMessage();
        publish(s);releaseWake();stopForeground(STOP_FOREGROUND_REMOVE);stopSelf(s.serviceStartId);
    }
    @Override public void onTimeout(int startId,int type){Session s=owned;if(s!=null&&s.progress.state.equals("running"))failed(s,new IOException("Android ended background polling. Detached VPS jobs continue. Reopen and resume the recorded installation."));worker.shutdownNow();stopSelf(startId);}
    @Override public void onDestroy(){
        Session s=owned;
        if(s!=null&&s.progress.state.equals("running")){
            s.progress.state="needs-attention";s.progress.phase="Phone polling ended. Detached VPS jobs may continue; reopen and check the recorded job.";publish(s);
        }
        worker.shutdownNow();releaseWake();super.onDestroy();
    }
    private void releaseWake(){if(wake!=null&&wake.isHeld())wake.release();}
}
