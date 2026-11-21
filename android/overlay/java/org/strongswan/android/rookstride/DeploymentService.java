package org.strongswan.android.rookstride;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import org.json.JSONObject;
import org.json.JSONException;
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
        public Gateway candidate;
        public JSONObject recoveryArchive;
        public final InstallationProgress progress;
        public volatile JSONObject result; public volatile Exception error;
        private volatile JSONObject pendingCompletion;
        private volatile long serverCompletedAt;
        private int serviceStartId;
        Session(Gateway node,ArrayList<Gateway> gateways,String kind,JSONObject config,boolean resume,long started){this.node=node;this.gateways=gateways;this.config=config;this.resume=resume;progress=new InstallationProgress(kind,node.get("id"),started);}
    }
    private static volatile Session current;
    interface Engine {JSONObject execute(DeploymentService service,Session session)throws Exception;}
    private static Engine engine=(service,session)->service.remote(session);
    /** Package-local instrumentation seam, invoked only after the real durable save.
     * No intent, preference or server response can install an observer. */
    interface CheckpointObserver {void saved(Session session)throws Exception;}
    static volatile CheckpointObserver checkpointObserver;
    private static final Set<Listener> listeners=new HashSet<>();
    private static final Handler main=new Handler(Looper.getMainLooper());
    private static final int NOTIFICATION=7351;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private PowerManager.WakeLock wake;
    private Session owned;
    private static java.lang.ref.WeakReference<DeploymentService> live=new java.lang.ref.WeakReference<>(null);
    public static void refreshLanguage(){main.post(()->{DeploymentService service=live.get();Session session=current;if(service!=null&&session!=null&&active())((NotificationManager)service.getSystemService(NOTIFICATION_SERVICE)).notify(NOTIFICATION,service.notification(session));});}
    @Override public void onCreate(){super.onCreate();live=new java.lang.ref.WeakReference<>(this);}

    public static Session current(){return current;}
    public static boolean active(){Session s=current;return s!=null&&s.progress.state.equals("running");}
    /** The remote result is confirmed; retry only its local durable publication. */
    public static boolean needsLocalSave(){Session s=current;return s!=null&&s.pendingCompletion!=null;}
    public static synchronized void retryLocalSave(Context context)throws Exception {
        Session s=current;if(s==null||s.pendingCompletion==null)throw new IOException("There is no completed result waiting to be saved.");
        JSONObject completed=s.pendingCompletion;
        try{
            new Vault(context).write(s.gateways);
            if(s.progress.kind.equals("protocol"))StandaloneInstallRetry.forget(context,s.node);
            if(!context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",completed.toString()).commit())throw new IOException("Phone progress could not be saved.");
            s.progress.finished=completed.optLong("finished");s.progress.completed=completed.optInt("completed");s.progress.phase=completed.optString("phase");s.progress.state="complete";
            s.pendingCompletion=null;s.error=null;
        }catch(Exception failure){localSaveFailed(context,s,completed,failure);throw s.error;}
        main.post(()->{for(Listener listener:new ArrayList<>(listeners))listener.changed();});
    }
    public static void observe(Listener listener){listeners.add(listener);}
    public static void unobserve(Listener listener){listeners.remove(listener);}
    public static void forget(Context context,Gateway node)throws Exception{
        if(active()||needsLocalSave())return;
        StandaloneInstallRetry.forget(context,node);
        if(current!=null&&current.node.get("id").equals(node.get("id")))current=null;
        android.content.SharedPreferences prefs=context.getSharedPreferences("rookstride-deployment",0);
        try{if(new JSONObject(prefs.getString("progress","{}")).optString("gateway").equals(node.get("id")))prefs.edit().remove("progress").apply();}catch(Exception ignored){}
    }
    /** Dismiss only an inactive coordinator record; detached VPS jobs are untouched. */
    public static synchronized boolean abandon(Context context,InstallationProgress expected)throws Exception{
        if(active()||needsLocalSave())return false;
        android.content.SharedPreferences prefs=context.getSharedPreferences("rookstride-deployment",0);
        InstallationProgress saved=current==null?null:current.progress;
        if(saved==null)try{saved=InstallationProgress.from(new JSONObject(prefs.getString("progress","{}")));}catch(Exception ignored){}
        if(saved==null||!saved.gatewayId.equals(expected.gatewayId)||!saved.kind.equals(expected.kind)||saved.started!=expected.started)return false;
        if(saved.kind.equals("protocol")){
            ArrayList<Gateway> catalog=new Vault(context).read();Gateway owner=null;
            for(Gateway node:catalog)if(node.get("id").equals(saved.gatewayId)){if(owner!=null)throw new IOException("The saved installation owner is ambiguous");owner=node;}
            if(owner==null)throw new IOException("The saved installation owner is unavailable. Inspect its recorded setup before abandoning.");
            final Gateway actual=owner;
            StandaloneInstallRetry.abandonWithMarker(context,actual,()->{actual.set("setupAbandoned","true");new Vault(context).write(catalog);});
        }
        if(!prefs.edit().remove("progress").commit())throw new IOException("The local setup notice could not be saved. Its recorded state was preserved.");
        if(current!=null){current.node.set("setupAbandoned","true");current=null;}
        NotificationManager manager=(NotificationManager)context.getSystemService(NOTIFICATION_SERVICE);manager.cancel(NOTIFICATION);manager.cancel(NOTIFICATION+1);
        return true;
    }
    public static synchronized void launch(Context context,Gateway node,ArrayList<Gateway> gateways,String kind,JSONObject config,boolean resume){launch(context,node,gateways,kind,config,resume,null);}
    public static synchronized void launch(Context context,Gateway node,ArrayList<Gateway> gateways,String kind,JSONObject config,boolean resume,Gateway candidate){
        if(active())throw new IllegalStateException("An installation is already running");
        if(needsLocalSave()){
            if(current.node.get("id").equals(node.get("id"))&&current.progress.kind.equals(kind)){try{retryLocalSave(context);}catch(Exception failure){throw new IllegalStateException(failure.getMessage(),failure);}return;}
            throw new IllegalStateException("Save the completed server result on this phone before starting another setup.");
        }
        OsWipeNetwork.beforeLaunch(context,kind,resume);
        node.set("setupAbandoned","");
        if(!kind.equals("pair"))node.set("jobKind",kind);
        long started=System.currentTimeMillis();
        if(resume)try{InstallationProgress saved=InstallationProgress.from(new JSONObject(context.getSharedPreferences("rookstride-deployment",0).getString("progress","{}")));if(saved.gatewayId.equals(node.get("id"))&&saved.kind.equals(kind)&&!saved.state.equals("complete")&&saved.started>0&&saved.started<=started)started=saved.started;}catch(Exception ignored){}
        current=new Session(node,gateways,kind,config,resume,started);current.candidate=candidate;
        Intent intent=new Intent(context,DeploymentService.class);
        try{context.startForegroundService(intent);}catch(RuntimeException e){current.progress.state="needs-attention";current.error=e;throw e;}
    }
    public static synchronized void launchRecovery(Context context,Gateway node,ArrayList<Gateway> gateways,JSONObject plan,boolean resume,JSONObject archive){launch(context,node,gateways,"paired-restore",plan,resume);current.recoveryArchive=archive;}
    @Override public IBinder onBind(Intent intent){return null;}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        Session s=current;if(s==null||!s.progress.state.equals("running")){stopSelf();return START_NOT_STICKY;}
        if(owned==s)return START_NOT_STICKY;
        owned=s;s.serviceStartId=startId;
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        nm.cancel(NOTIFICATION+1);nm.createNotificationChannel(new NotificationChannel("deployment",RookText.t(RookText.localized(this),"Gateway installation"),NotificationManager.IMPORTANCE_LOW));
        if(Build.VERSION.SDK_INT>=29)startForeground(NOTIFICATION,notification(s),ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);else startForeground(NOTIFICATION,notification(s));
        releaseWake();wake=((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"rookstride:deployment");wake.acquire(5*60*60*1000L);
        publish(s);
        worker.execute(()->{
            try{
                JSONObject result=engine.execute(this,s);
                main.post(()->{try{
                    if(current!=s||!s.progress.state.equals("running"))return;
                    s.result=result;
                    if((s.progress.kind.equals("paired-os")||s.progress.kind.equals("paired-restore"))){if(result.optString("state").equals("restored"))OsInventory.finishRestoredPair(this,s.gateways,s.node);else OsInventory.finishPair(this,s.gateways,s.node);}
                    else if(s.progress.kind.startsWith("lifecycle-")||s.progress.kind.equals("helper-update")||s.progress.kind.equals("engine-update")){s.node.set("maintenanceStatus",result.optString("state","Review client traffic"));}
                    else if(s.progress.kind.equals("os")){OsInventory.finish(this,s.gateways,s.node);}
                    else if(s.progress.kind.equals("pair")){for(Gateway changed:PairNodes.rememberHealth(s.node,result))OsInventory.invalidateMigratedConnection(this,changed);s.node.set("pairPhase","Ready · IPv4 exit "+result.optString("exit_ip"));}
                    else{if(!s.progress.kind.equals("filter"))ServerProtocols.rememberConnection(s.gateways,s.node,result);if(ServerProtocols.publicCertificateMigration(s.node,result,result.optString("instance")))IkeProfileTrust.usePublicCa(this,s.node);ServerProtocols.rememberIkeCertificateNames(s.gateways,s.node,result);s.node.data.put("snapshot",result);s.node.set("job","");if(!result.optString("instance").isEmpty())s.node.set("serverInstance",result.optString("instance"));if(!s.progress.kind.equals("filter"))ServerProtocols.recordInstalled(s.gateways,s.node,result.optString("instance"));}
                    if(s.progress.kind.equals("lifecycle-entry")&&result.optString("state").equals("accepted")&&s.node.data.optJSONObject("lastEntryMigration")!=null&&s.node.data.optJSONObject("lastEntryMigration").optBoolean("new_address")){OsInventory.invalidateMigratedConnection(this,s.node);new Vault(this).write(s.gateways);}
                    s.node.set("checked","Installation checks passed");s.progress.finishAt(s.serverCompletedAt,System.currentTimeMillis());if(result.optString("state").equals("restored"))s.progress.phase="VPN identity and users restored. Verify unchanged clients on their actual networks. Administrator grants were not restored.";if(maintenance(s)&&result.optString("state").equals("accepted"))s.progress.phase="The reviewed change was accepted. Keep checking existing VPN clients on their usual networks.";else if(maintenance(s)&&result.optString("state").equals("rolled-back"))s.progress.phase="The previous configuration was restored. Check an existing VPN client.";s.recoveryArchive=null;boolean saved=publish(s);releaseWake();stopForeground(STOP_FOREGROUND_REMOVE);if(saved)completedNotification(s);stopSelf(s.serviceStartId);
                }catch(Exception e){failed(s,e);}});
            }catch(Exception e){main.post(()->failed(s,e));}
        });return START_NOT_STICKY;
    }
    private JSONObject remote(Session s)throws Exception{
        if(maintenance(s)){
            PairController.Progress progress=new PairController.Progress(){private int step;public void update(String phase){DeploymentService.this.update(s,step,phase);}public void stage(int index,String phase){step=index;DeploymentService.this.update(s,index,phase);}};
            OsReinstall.Saved saved=()->{JSONObject operation=s.node.data.optJSONObject("pairedOsOperation");if((s.progress.kind.equals("paired-os")||s.progress.kind.equals("paired-restore"))&&operation!=null){for(String role:new String[]{"entry","exit"}){Gateway part=role.equals("entry")?s.node:s.node.exit;JSONObject completed=part.data.optJSONObject("osReinstall"),planned=operation.getJSONObject("plans").getJSONObject(role);if(part.get("osReinstallState").equals("complete")&&completed!=null&&completed.optString("job").equals(planned.getString("job")))OsInventory.applyVerifiedIdentity(this,s.gateways,part);}}new Vault(this).write(s.gateways);CheckpointObserver observer=checkpointObserver;if(observer!=null)observer.saved(s);};
            if(s.progress.kind.equals("lifecycle-entry")){
                String action=s.config.optString("action","stage");Gateway candidate=s.candidate;if(candidate==null&&s.node.data.optJSONObject("entryMigration")!=null)candidate=new Gateway(s.node.data.getJSONObject("entryMigration").getJSONObject("candidate"));if(candidate==null)throw new IOException("Choose or resume a reviewed replacement entry.");
                return action.equals("stage")?EntryMigrationController.stage(s.node,candidate,s.config.optBoolean("endpoint_transfer"),s.config.optBoolean("new_address",s.node.data.optJSONObject("entryMigration")!=null&&s.node.data.optJSONObject("entryMigration").optBoolean("new_address")),()->getAssets().open("gateway_bundle.zip"),progress,saved):EntryMigrationController.finish(s.node,action.equals("rollback"),candidate,()->getAssets().open("gateway_bundle.zip"),progress,saved);
            }
            if(s.progress.kind.equals("engine-update")){String action=s.config.optString("action","prepare");PairController.Bundle source=()->getAssets().open("gateway_bundle.zip");if(action.equals("prepare"))return EngineUpdates.prepare(s.node,s.config.getString("group"),s.config.getJSONObject("review"),source,progress,saved);if(action.equals("apply"))return EngineUpdates.apply(s.node,source,progress,saved);if(action.equals("abandon"))return EngineUpdates.abandon(s.node,source,progress,saved);return EngineUpdates.finish(s.node,action.equals("rollback"),source,progress,saved);}
            if(s.progress.kind.equals("helper-update")){String action=s.config.optString("action","apply");return action.equals("apply")?MaintenanceUpdates.apply(s.node,s.config.getJSONObject("review"),()->getAssets().open("gateway_bundle.zip"),progress,saved):MaintenanceUpdates.finish(s.node,action.equals("rollback"),()->getAssets().open("gateway_bundle.zip"),progress,saved);}
            if((s.progress.kind.equals("paired-os")||s.progress.kind.equals("paired-restore"))){if(s.config.optString("mode").equals("restore")){if(s.recoveryArchive==null)throw new IOException("Open the reviewed owner recovery package before resuming restore.");return PairedOsReinstall.runRestore(s.node,s.config,s.resume,s.recoveryArchive,()->getAssets().open("reinstall_bundle.zip"),()->getAssets().open("gateway_bundle.zip"),progress,saved,()->OsWipeNetwork.requireDirect(this));}return PairedOsReinstall.run(s.node,s.config,s.resume,()->getAssets().open("reinstall_bundle.zip"),progress,saved,()->OsWipeNetwork.requireDirect(this));}
            String action=s.config.optString("action","replace");
            if(action.equals("accept")||action.equals("rollback"))return LifecycleController.finishExit(s.node,action.equals("rollback"),()->getAssets().open("gateway_bundle.zip"),progress,saved);
            Gateway candidate=s.candidate;if(candidate==null&&s.node.data.optJSONObject("lifecycleOperation")!=null)candidate=new Gateway(s.node.data.getJSONObject("lifecycleOperation").getJSONObject("candidate"));
            if(candidate==null)throw new IOException("Choose or resume a reviewed replacement server.");
            return LifecycleController.replaceExit(s.node,candidate,()->getAssets().open("gateway_bundle.zip"),progress,saved);
        }

        if(s.progress.kind.equals("os")){if(!s.resume)OsWipeNetwork.requireDirect(this);return OsReinstall.run(s.node,s.config,s.resume,()->getAssets().open("reinstall_bundle.zip"),new PairController.Progress(){public void update(String phase){DeploymentService.this.update(s,0,phase);}public void stage(int index,String phase){DeploymentService.this.update(s,index,phase);}},()->new Vault(this).write(s.gateways));}
        if(s.progress.kind.equals("protocol")||s.progress.kind.equals("filter"))return protocol(s);
        if(!s.progress.kind.equals("pair"))return single(s);
        if(s.config!=null&&s.config.optJSONObject("replacementReview")!=null){
            PairPreparationController.apply(s.node,s.config.getJSONObject("replacementReview"),()->getAssets().open("gateway_bundle.zip"),()->getAssets().open("single_bundle.zip"),phase->update(s,0,phase));
            main.post(()->{s.node.data.remove("pairNeedsPreparation");publish(s);});
        }
        JSONObject result=PairController.install(s.node,()->getAssets().open("gateway_bundle.zip"),new PairController.Progress(){
            private int checkpoint=0;
            public void update(String phase){DeploymentService.this.update(s,checkpoint,phase);}
            public void stage(int index,String phase){checkpoint=index;DeploymentService.this.update(s,index,phase);}
        },s.resume);
        double completed=result.optDouble("completed_at",0);if(Double.isFinite(completed)&&completed>0&&completed<Long.MAX_VALUE/1000.0)s.serverCompletedAt=(long)(completed*1000);return result;
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
                int index=InstallationProgress.singleStage(s.progress.kind,phase);
                update(s,index,phase);
                if(state.equals("complete")){double updated=status.optDouble("updated",0);if(Double.isFinite(updated)&&updated>0&&updated<Long.MAX_VALUE/1000.0)s.serverCompletedAt=(long)(updated*1000);break;}
                if(state.equals("failed"))throw new IOException(phase);
                if(System.nanoTime()>deadline)throw new IOException("The server job may still be running. Check and resume its recorded job; do not install again.");
                Thread.sleep(4000);
            }
            update(s,s.progress.steps().length-1,"Reading gateway health");return ssh.admin(new JSONObject().put("action","status"));
        }
    }
    private JSONObject protocol(Session s)throws Exception{
        try(AdminConnection access=AdminConnection.open(s.node,PairNodes.owner(s.gateways,s.node),phase->update(s,0,phase))){
            Ssh ssh=access.ssh;
            update(s,0,"Connecting to your server");String job=s.node.get("job");
            boolean bound=s.progress.kind.equals("protocol")&&!s.node.get("protocol").equals("ikev2")&&!s.node.isPair()&&s.node.get("coexistPair").isEmpty()&&!s.node.data.optBoolean("clientOnly")&&!s.node.data.optBoolean("adminAccess");
            JSONObject completed=StandaloneInstallCoordinator.run(job,s.config,s.resume,bound,new StandaloneInstallCoordinator.Local(){
                public boolean has()throws Exception{return StandaloneInstallRetry.has(DeploymentService.this,s.node);}
                public String recordedJob()throws Exception{return StandaloneInstallRetry.recordedJob(DeploymentService.this,s.node);}
                public JSONObject startRequest(JSONObject original)throws Exception{return StandaloneInstallRetry.startRequest(DeploymentService.this,s.node,original);}
                public void rememberJob(JSONObject response)throws Exception{StandaloneInstallRetry.rememberJob(DeploymentService.this,s.node,response);}
                public JSONObject retryRequest(JSONObject failure)throws Exception{return StandaloneInstallRetry.retryRequest(DeploymentService.this,s.node,failure);}
                public void saveJob(JSONObject response,boolean port)throws Exception{saveProtocolJob(s,response,port);}
                public void progress(JSONObject status){int stage=status.optInt("stage");if(s.progress.kind.equals("filter"))stage=stage>=6?4:stage>=4?3:stage>=3?2:1;update(s,Math.max(0,Math.min(s.progress.steps().length-1,stage)),status.optString("phase"));}
            },(request,bundled)->{if(bundled)try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,request);}return ssh.single(request);},()->Thread.sleep(3000));
            double end=completed.optDouble("updated",0);if(Double.isFinite(end)&&end>0&&end<Long.MAX_VALUE/1000.0)s.serverCompletedAt=(long)(end*1000);
            return ssh.single(new JSONObject().put("action","status").put("protocol",s.node.get("protocol")));
        }
    }
    /** Acknowledged catalog save, unlike best-effort progress publication. The
     * private retry record is saved first, so a lost catalog write can reconcile. */
    private void saveProtocolJob(Session s,JSONObject response,boolean port)throws Exception{
        String job=response==null?null:response.getString("job");if(job!=null&&!InputRules.job(job))throw new IOException("Invalid recorded installer identity");
        java.util.concurrent.CountDownLatch done=new java.util.concurrent.CountDownLatch(1);Exception[] failure={null};
        main.post(()->{try{if(current!=s)throw new IOException("The selected installation changed");if(job!=null)s.node.set("job",job);if(port){s.node.data.put("vpnPort",response.getJSONObject("plan").getInt("port")).put("vpnPortAuto",false);}new Vault(this).write(s.gateways);}catch(Exception e){failure[0]=e;}finally{done.countDown();}});
        if(!done.await(30,TimeUnit.SECONDS))throw new IOException("The recorded installer could not be saved on this phone. Check its existing job before continuing.");
        if(failure[0]!=null)throw failure[0];
    }
    private void update(Session s,int index,String phase){main.post(()->{if(!s.progress.state.equals("running")||(s.progress.completed==index&&s.progress.phase.equals(phase)))return;s.progress.stage(index,phase);if(s.progress.kind.equals("pair"))s.node.set("pairPhase",phase);else if(!maintenance(s))s.node.set("jobPhase",phase);publish(s);});}
    private static boolean maintenance(Session s){return s.progress.kind.startsWith("lifecycle-")||(s.progress.kind.equals("paired-os")||s.progress.kind.equals("paired-restore"))||s.progress.kind.equals("helper-update")||s.progress.kind.equals("engine-update");}
    /** Context is also the isolated-storage instrumentation seam; no remote work. */
    static boolean persistProgress(Context context,Session s){
        JSONObject completed=s.progress.state.equals("complete")?s.progress.json():null;
        try{
            if(!maintenance(s)||!s.progress.state.equals("running"))new Vault(context).write(s.gateways);
            if(completed!=null&&s.progress.kind.equals("protocol"))StandaloneInstallRetry.forget(context,s.node);
            android.content.SharedPreferences.Editor edit=context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",s.progress.json().toString());
            if(completed!=null){if(!edit.commit())throw new IOException("Phone progress could not be saved.");}else edit.apply();
            return true;
        }catch(Exception failure){
            if(completed!=null)localSaveFailed(context,s,completed,failure);
            else{s.progress.phase="Could not save local progress. Server jobs continue; inspect before resuming.";context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",s.progress.json().toString()).apply();}
            return false;
        }
    }
    private static void localSaveFailed(Context context,Session s,JSONObject completed,Exception failure){
        s.pendingCompletion=completed;s.error=new IOException("The server operation completed, but this phone could not save its result. Save the result on this phone; do not install again.",failure);
        s.progress.state="needs-attention";s.progress.phase=s.error.getMessage();s.progress.finished=0;
        context.getSharedPreferences("rookstride-deployment",0).edit().putString("progress",s.progress.json().toString()).commit();
    }
    private boolean publish(Session s){
        boolean saved=persistProgress(this,s);
        if(s.progress.state.equals("running"))((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTIFICATION,notification(s));
        for(Listener listener:new ArrayList<>(listeners))listener.changed();
        return saved;
    }
    private Notification notification(Session s){
        Context display=RookText.localized(this);
        Intent open=new Intent(this,RookstrideActivity.class).putExtra("rookstride.progress",true).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP|Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pending=PendingIntent.getActivity(this,0,open,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification publicNotice=new Notification.Builder(this,"deployment").setSmallIcon(R.drawable.rook_notification).setContentTitle(RookText.t(display,"Rookstride gateway installation")).setContentText(RookText.t(display,"Open to view progress")).setContentIntent(pending).build();
        return new Notification.Builder(this,"deployment").setVisibility(Notification.VISIBILITY_PRIVATE).setPublicVersion(publicNotice).setSmallIcon(R.drawable.rook_notification).setContentTitle(maintenance(s)?"Rookstride server maintenance":RookText.summary(display,s.progress))
            .setContentText(RookText.t(display,s.progress.phase)).setContentIntent(pending).setOngoing(true).setOnlyAlertOnce(true).setProgress(s.progress.steps().length,s.progress.completed,false).build();
    }
    private void completedNotification(Session s){
        NotificationManager nm=getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("deployment-results","Installation results",NotificationManager.IMPORTANCE_DEFAULT));
        Intent open=new Intent(this,RookstrideActivity.class).putExtra("rookstride.progress",true).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP|Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pending=PendingIntent.getActivity(this,1,open,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification note=new Notification.Builder(this,"deployment-results").setSmallIcon(R.drawable.rook_notification).setContentTitle(maintenance(s)?"Server maintenance complete":s.progress.kind.equals("os")?"Ubuntu reinstalled":s.progress.kind.equals("filter")?"Ad blocking is ready":"Your VPN is installed").setContentText("Open Rookstride to continue.").setContentIntent(pending).setAutoCancel(true).setVisibility(Notification.VISIBILITY_PUBLIC).build();
        try{nm.notify(NOTIFICATION+1,note);}catch(SecurityException ignored){} // Android may withhold notification permission; in-app completion remains visible.
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
        worker.shutdownNow();releaseWake();if(live.get()==this)live.clear();super.onDestroy();
    }
    private void releaseWake(){if(wake!=null&&wake.isHeld())wake.release();}
}
