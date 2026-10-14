package org.strongswan.android.ui;

import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.webkit.*;
import android.widget.*;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import org.json.*;
import org.strongswan.android.R;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.*;
import org.strongswan.android.rookstride.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;

/** Rookstride administration shell; the upstream engine owns the VPN lifecycle. */
public final class RookstrideActivity extends AppCompatActivity implements VpnStateService.VpnStateListener {
    private static final int RED=Color.rgb(238,48,56), INK=Color.rgb(20,20,24), MUTED=Color.rgb(106,106,119), BACK=Color.rgb(246,246,248);
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private final Handler handler=new Handler(Looper.getMainLooper());
    private ArrayList<Gateway> gateways=new ArrayList<>();
    private Gateway selected;
    private Vault vault;
    private LinearLayout root,body;
    private String tab="Gateways",message="";
    private boolean busy=false,demo=false,vaultFailed=false;
    private VpnStateService vpn;
    private AlertDialog editor;
    private EditText keyField;
    private TextView deploymentLabel,elapsedLabel;
    private final Runnable progressTick=new Runnable(){public void run(){InstallationProgress p=currentProgress();if(elapsedLabel!=null&&p!=null)elapsedLabel.setText(p.remaining()+" · "+p.elapsed(System.currentTimeMillis()));handler.postDelayed(this,1000);}};
    private ProgressBar deploymentBar;
    private Exception handledDeploymentError;
    private final DeploymentService.Listener deploymentListener=this::deploymentChanged;
    private WebView storyView;
    private StoryVoice storyVoice;
    private static final int PICK_KEY=84;
    private final ServiceConnection binding=new ServiceConnection() {
        public void onServiceConnected(ComponentName n,IBinder b) { vpn=((VpnStateService.LocalBinder)b).getService(); vpn.registerListener(RookstrideActivity.this); stateChanged(); }
        public void onServiceDisconnected(ComponentName n) { vpn=null; stateChanged(); }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        vault=new Vault(this);
        try { gateways=vault.read(); } catch(Exception e) { vaultFailed=true; message="Saved gateway data could not be unlocked. It has been preserved."; }
        DeploymentService.Session running=DeploymentService.current();
        if(running!=null)gateways=running.gateways;
        if(state!=null)tab=state.getString("tab","Gateways");
        if(getIntent().getBooleanExtra("rookstride.progress",false))tab="Progress";
        String remembered=getSharedPreferences("rookstride-ui",0).getString("selected","");
        for(Gateway n:gateways) if(n.get("id").equals(remembered)) selected=n;
        if(selected==null && !gateways.isEmpty()) selected=gateways.get(0);
        bindService(new Intent(this,VpnStateService.class),binding,BIND_AUTO_CREATE);
        render();
        if(!getSharedPreferences("rookstride-ui",0).getBoolean("onboarded",false)) handler.post(()->onboarding(0));
    }
    @Override protected void onStart(){super.onStart();DeploymentService.observe(deploymentListener);deploymentChanged();}
    @Override protected void onStop(){DeploymentService.unobserve(deploymentListener);handler.removeCallbacks(progressTick);if(storyView!=null)storyView.evaluateJavascript("window.rookStopNarration && window.rookStopNarration()",null);if(storyVoice!=null)storyVoice.stop();super.onStop();}
    @Override protected void onSaveInstanceState(Bundle state){state.putString("tab",tab);super.onSaveInstanceState(state);}
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);if(intent.getBooleanExtra("rookstride.progress",false)){tab="Progress";render();}}
    @Override protected void onResume() {
        super.onResume();handler.removeCallbacks(progressTick);handler.post(progressTick);
        if(selected!=null && !selected.get("job").isEmpty() && !busy && !DeploymentService.active() && hasAuth(selected)) pollJob(selected);
    }
    @Override protected void onDestroy() {
        if(vpn!=null) vpn.unregisterListener(this);
        DeploymentService.unobserve(deploymentListener);if(storyVoice!=null)storyVoice.close();if(storyView!=null){ViewParent parent=storyView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(storyView);storyView.destroy();}unbindService(binding); handler.removeCallbacksAndMessages(null); executor.shutdownNow(); super.onDestroy();
    }
    public void stateChanged() { if(!tab.equals("Stories")&&!tab.equals("Guide"))render(); }
    private int dp(float n) { return (int)(getResources().getDisplayMetrics().density*n+.5f); }
    private GradientDrawable shape(int color,int radius) { GradientDrawable d=new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(radius)); return d; }
    private TextView text(String value,int size,int color,boolean bold) {
        TextView v=new TextView(this); v.setText(value); v.setTextSize(size); v.setTextColor(color);
        v.setTypeface(Typeface.create(bold?"sans-serif-medium":"sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));
        v.setLineSpacing(dp(3),1); return v;
    }
    private void space(LinearLayout into,int height) { View v=new View(this); into.addView(v,new LinearLayout.LayoutParams(1,dp(height))); }
    private LinearLayout stack() { LinearLayout v=new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v=new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); v.setGravity(Gravity.CENTER_VERTICAL); return v; }
    private LinearLayout card() {
        LinearLayout v=stack(); v.setPadding(dp(18),dp(18),dp(18),dp(18)); v.setBackground(shape(Color.WHITE,20));
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2); p.bottomMargin=dp(14); body.addView(v,p); return v;
    }
    private Button button(String title,boolean primary,Runnable action) {
        Button v=new Button(this); v.setText(title); v.setAllCaps(false); v.setTextSize(15); v.setTypeface(Typeface.create("sans-serif-medium",0));
        v.setTextColor(primary?Color.WHITE:INK); v.setBackground(shape(primary?RED:Color.rgb(236,236,241),13));
        v.setPadding(dp(14),dp(5),dp(14),dp(5)); v.setMinHeight(dp(48));
        v.setOnClickListener(x->{ if(!busy && !DeploymentService.active()) action.run(); });
        v.setEnabled(!busy && !DeploymentService.active()); return v;
    }
    private void fullButton(LinearLayout target,String title,boolean primary,Runnable action) {
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,dp(48)); p.topMargin=dp(10); target.addView(button(title,primary,action),p);
    }
    private void title(String headline,String copy) { body.addView(text(headline,30,INK,true)); space(body,5); body.addView(text(copy,14,MUTED,false)); space(body,20); }
    private JSONObject snapshot() { return selected==null?new JSONObject():selected.data.optJSONObject("snapshot")!=null?selected.data.optJSONObject("snapshot"):new JSONObject(); }
    private boolean hasAuth(Gateway n) { return !n.sshPassword.isEmpty() || !n.privateKey.isEmpty(); }
    private void save() {
        if(vaultFailed) return;
        try { vault.write(gateways); } catch(Exception e) { message="Could not save gateway settings securely."; }
    }
    private boolean isDemo() { return demo; }
    private void demoNotice() { Toast.makeText(this,"Demo data — add your own gateway to perform this action.",Toast.LENGTH_LONG).show(); }
    private void error(Exception e) {
        if(isFinishing()) return;
        new AlertDialog.Builder(this).setTitle("Action needs attention").setMessage(e.getMessage()==null?"The action could not finish.":e.getMessage())
            .setPositiveButton("Close",null).setNeutralButton("Read guide",(d,w)->{tab="Guide";render();}).show();
    }

    private void render() {
        if(isFinishing()) return;
        if(storyView!=null&&storyView.getUrl()!=null&&storyView.getUrl().startsWith("https://rookstride.invalid/stories/"))getSharedPreferences("rookstride-ui",0).edit().putString("storyUrl",storyView.getUrl()).apply();
        if(storyVoice!=null){storyVoice.close();storyVoice=null;}
        if(storyView!=null){ViewParent parent=storyView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(storyView);storyView.removeJavascriptInterface("RookVoice");storyView.destroy();}
        storyView=null;deploymentLabel=null;deploymentBar=null;elapsedLabel=null;
        root=stack(); root.setBackgroundColor(BACK);
        ViewCompat.setOnApplyWindowInsetsListener(root,(v,insets)->{
            androidx.core.graphics.Insets b=insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(b.left,b.top,b.right,b.bottom); return insets;
        });
        LinearLayout header=row(); header.setPadding(dp(22),dp(16),dp(22),dp(14));
        TextView brand=text("ROOKSTRIDE",18,INK,true); brand.setLetterSpacing(.12f); header.addView(brand,new LinearLayout.LayoutParams(0,-2,1));
        TextView badge=text(demo?"DEMO":"ADMIN",11,demo?RED:MUTED,true); badge.setLetterSpacing(.12f); header.addView(badge);
        root.addView(header);
        if(!message.isEmpty() || busy) {
            TextView status=text((busy?"Working · ":"")+message,12,busy?RED:MUTED,false); status.setPadding(dp(22),0,dp(22),dp(10));root.addView(status);
        }
        InstallationProgress progress=currentProgress();
        if(progress!=null){
            LinearLayout shortcut=stack();shortcut.setPadding(dp(22),0,dp(22),dp(10));
            deploymentLabel=text(progressSummary(progress)+" · Tap to view",12,RED,true);shortcut.addView(deploymentLabel);
            deploymentBar=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);deploymentBar.setMax(progress.steps().length);deploymentBar.setProgress(progress.completed);shortcut.addView(deploymentBar,new LinearLayout.LayoutParams(-1,dp(8)));
            shortcut.setFocusable(true);shortcut.setContentDescription("View installation progress");shortcut.setOnClickListener(v->{tab="Progress";render();});root.addView(shortcut);
        }
        if(demo) {
            TextView note=text("Sample data. No server is connected.",12,RED,true); note.setPadding(dp(22),0,dp(22),dp(10)); root.addView(note);
        }
        if(tab.equals("Stories")) {
            storyView=new WebView(this);storyView.setBackgroundColor(Color.WHITE);
            storyView.getSettings().setJavaScriptEnabled(true);storyView.getSettings().setAllowFileAccess(false);storyView.getSettings().setAllowContentAccess(false);
            storyView.getSettings().setBlockNetworkLoads(true);storyView.getSettings().setDomStorageEnabled(false);
            storyVoice=new StoryVoice(this,storyView);storyView.addJavascriptInterface(storyVoice,"RookVoice");
            storyView.setWebViewClient(new OfflineStories(this));storyView.loadUrl(getSharedPreferences("rookstride-ui",0).getString("storyUrl","https://rookstride.invalid/stories/index.html"));
            root.addView(storyView,new LinearLayout.LayoutParams(-1,0,1));
        } else if(tab.equals("Guide")) {
            WebView guide=new WebView(this); guide.setBackgroundColor(Color.WHITE);
            guide.getSettings().setJavaScriptEnabled(false); guide.getSettings().setAllowFileAccess(false); guide.getSettings().setAllowContentAccess(false);
            guide.setWebViewClient(new WebViewClient() {
                @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r) {
                    if("rookstride:stories".equals(r.getUrl().toString())){tab="Stories";render();return true;}
                    if("rookstride:licenses".equals(r.getUrl().toString()) || "rookstride:guide".equals(r.getUrl().toString())) {
                        String asset=r.getUrl().toString().endsWith("licenses")?"licenses.html":"guide.html";
                        try(InputStream in=getAssets().open(asset)) {v.loadDataWithBaseURL("https://rookstride.invalid/",new String(read(in,250000),StandardCharsets.UTF_8),"text/html","UTF-8",null);}catch(Exception e){error(e);}return true;
                    }
                    Uri u=r.getUrl(); if("https".equals(u.getScheme())) { try { startActivity(new Intent(Intent.ACTION_VIEW,u)); } catch(ActivityNotFoundException e) { Toast.makeText(RookstrideActivity.this,"No browser available",0).show(); } return true; }
                    return !"file".equals(u.getScheme());
                }
            });
            // Read the bundled guide ourselves so file access can remain disabled.
            try(InputStream in=getAssets().open("guide.html")) { guide.loadDataWithBaseURL("https://rookstride.invalid/",new String(read(in,100000),StandardCharsets.UTF_8),"text/html","UTF-8",null); } catch(Exception e) { error(e); }
            root.addView(guide,new LinearLayout.LayoutParams(-1,0,1));
        } else {
            ScrollView scroll=new ScrollView(this); scroll.setFillViewport(true); body=stack(); body.setPadding(dp(20),dp(4),dp(20),dp(24)); scroll.addView(body); root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
            if(tab.equals("Progress"))progressScreen();else if(tab.equals("Gateways")) gatewayScreen(); else if(tab.equals("People")) peopleScreen(); else connectionsScreen();
        }
        LinearLayout navigation=row(); navigation.setPadding(dp(8),dp(8),dp(8),dp(8)); navigation.setBackgroundColor(Color.WHITE);
        for(String name:new String[]{"Gateways","People","Sessions","Guide","Stories"}) {
            Button v=browseButton(name,()->{tab=name;message="";render();}); v.setTextSize(12); v.setPadding(0,0,0,0);
            v.setTextColor(tab.equals(name)?RED:MUTED); v.setBackground(shape(tab.equals(name)?Color.rgb(255,237,238):Color.WHITE,12));
            navigation.addView(v,new LinearLayout.LayoutParams(0,dp(45),1));
        }
        root.addView(navigation); setContentView(root); ViewCompat.requestApplyInsets(root);
    }

    private Button browseButton(String title,Runnable action){
        Button b=button(title,false,action);b.setEnabled(true);b.setOnClickListener(v->action.run());return b;
    }
    private InstallationProgress currentProgress(){
        DeploymentService.Session s=DeploymentService.current();if(s!=null)return s.progress;
        try{String raw=getSharedPreferences("rookstride-deployment",0).getString("progress","");if(raw.isEmpty())return null;InstallationProgress p=InstallationProgress.from(new JSONObject(raw));if(p.state.equals("running")){p.state="needs-attention";p.phase="Phone polling ended. Detached VPS jobs may continue; check the recorded installation.";}return p;}catch(Exception e){return null;}
    }
    private String progressSummary(InstallationProgress p){return (p.kind.equals("pair")?"Two-server":p.kind.equals("enroll")?"Enrollment":"Single-server")+" setup · "+p.completed+" / "+p.steps().length+" complete · "+p.state.replace('-',' ');}
    private void deploymentChanged(){
        if(isFinishing()||isDestroyed())return;
        InstallationProgress p=currentProgress();if(p!=null){if(deploymentLabel!=null)deploymentLabel.setText(progressSummary(p)+" · Tap to view");if(deploymentBar!=null)deploymentBar.setProgress(p.completed);if(tab.equals("Progress")&&body!=null){body.removeAllViews();progressScreen();}}
        DeploymentService.Session s=DeploymentService.current();
        if(s!=null&&s.error!=null&&handledDeploymentError!=s.error){
            handledDeploymentError=s.error;Exception e=s.error;
            if(e instanceof PairController.TrustNeeded){PairController.TrustNeeded t=(PairController.TrustNeeded)e;trust(t.node,t.issue,()->startDeployment(s.node,s.progress.kind,s.config,s.resume));}
            else if(e instanceof Ssh.HostTrust)trust(s.node,(Ssh.HostTrust)e,()->startDeployment(s.node,s.progress.kind,s.config,s.resume));
            else if(e instanceof PairController.RebootNeeded){PairController.RebootNeeded r=(PairController.RebootNeeded)e;new AlertDialog.Builder(this).setTitle("Node reboot required").setMessage(r.getMessage()).setNegativeButton("Later",null).setPositiveButton("Reboot this node",(x,w)->withSsh(r.node,"Scheduling the owned reboot",ssh->ssh.pair(json("command","reboot","pair",s.node.get("pairId"))),j->{message="Reboot requested. Wait for SSH, then resume the pair.";render();})).show();}
            else error(e);
        }
    }
    private void startDeployment(Gateway node,String kind,JSONObject config,boolean resume){
        if(busy||DeploymentService.active())return;
        if(!hasAuth(node)){passwordDialog(node,()->startDeployment(node,kind,config,resume));return;}
        if(node.isPair()&&!hasAuth(node.exit)){passwordDialog(node.exit,()->startDeployment(node,kind,config,resume));return;}
        if(node.sshRelay!=null&&!hasAuth(node.sshRelay)){passwordDialog(node.sshRelay,()->startDeployment(node,kind,config,resume));return;}
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},85);
        try{DeploymentService.launch(this,node,gateways,kind,config,resume);tab="Progress";render();}catch(Exception e){error(e);}
    }
    private void progressScreen(){
        InstallationProgress p=currentProgress();title("Rook is on the route.","Browse the guide or stories while setup runs. Return here using the progress shortcut.");
        if(p==null){empty("No installation has started yet.");return;}
        LinearLayout hero=card();LinearLayout head=row();ImageView rook=new ImageView(this);rook.setImageResource(p.state.equals("complete")?R.drawable.rook_celebrate:!p.state.equals("running")?R.drawable.rook_wait:p.completed<2?R.drawable.rook_map:p.completed<5?R.drawable.rook_builder:R.drawable.rook_lantern);rook.setContentDescription("Rook, your installation guide");head.addView(rook,new LinearLayout.LayoutParams(dp(90),dp(90)));
        LinearLayout copy=stack();copy.addView(text(progressSummary(p),17,INK,true));copy.addView(text(p.phase,13,MUTED,false));head.addView(copy,new LinearLayout.LayoutParams(0,-2,1));hero.addView(head);
        if(p.state.equals("running")&&android.provider.Settings.Global.getFloat(getContentResolver(),android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,1)>0){android.animation.ObjectAnimator motion=android.animation.ObjectAnimator.ofFloat(rook,"rotation",-4f,4f);motion.setDuration(1800);motion.setRepeatCount(android.animation.ValueAnimator.INFINITE);motion.setRepeatMode(android.animation.ValueAnimator.REVERSE);motion.start();rook.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener(){public void onViewAttachedToWindow(View v){}public void onViewDetachedFromWindow(View v){motion.cancel();}});}
        ProgressBar bar=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);bar.setMax(p.steps().length);bar.setProgress(p.completed);hero.addView(bar,new LinearLayout.LayoutParams(-1,dp(12)));
        elapsedLabel=text(p.remaining()+" · "+p.elapsed(System.currentTimeMillis()),12,RED,true);hero.addView(elapsedLabel);space(hero,8);hero.addView(text(p.estimate(),13,INK,true));hero.addView(text("A planning range, not a countdown. Package downloads, network waits and a required reboot can take longer. The bar counts finished checkpoints.",12,MUTED,false));
        if(p.state.equals("running")){ProgressBar working=new ProgressBar(this);working.setContentDescription("Waiting for the current server stage");hero.addView(working,new LinearLayout.LayoutParams(dp(24),dp(24)));}
        LinearLayout stages=card();String[] names=p.steps();for(int i=0;i<names.length;i++){String symbol=i<p.completed?"✓":i==p.completed&&p.state.equals("running")?"›":"○";stages.addView(text(symbol+"  "+(i+1)+". "+names[i],14,i==p.completed?RED:INK,i==p.completed));space(stages,12);}
        LinearLayout reading=card();reading.addView(text("Keep exploring.",20,INK,true));Button stories=browseButton("Read Rook’s worlds",()->{tab="Stories";render();});reading.addView(stories,new LinearLayout.LayoutParams(-1,dp(48)));space(reading,8);reading.addView(browseButton("Learn the architecture",()->{tab="Guide";render();}),new LinearLayout.LayoutParams(-1,dp(48)));
        if(!p.state.equals("running")&&!p.state.equals("complete")){
            reading.addView(text("A stopped phone coordinator does not cancel detached VPS jobs. Resume uses the recorded owner and stages. Do not reset a running job.",13,MUTED,false));
            fullButton(reading,"Check and resume",true,()->{Gateway n=null;for(Gateway g:gateways)if(g.get("id").equals(p.gatewayId))n=g;if(n==null){error(new IOException("Open the saved gateway and inspect its job first."));return;}selected=n;if(n.isPair())runPair(n,true);else if(!n.get("job").isEmpty())pollJob(n);else inspect(n);});
        }
    }

    private void gatewayPicker() {
        if(gateways.size()<2 && !demo) return;
        HorizontalScrollView h=new HorizontalScrollView(this); h.setHorizontalScrollBarEnabled(false); LinearLayout choices=row();
        for(Gateway n:gateways) {
            Button b=button(n.get("name"),n==selected,()->{selected=n;demo=false;getSharedPreferences("rookstride-ui",0).edit().putString("selected",n.get("id")).apply();render();});
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-2,dp(40));p.rightMargin=dp(8);choices.addView(b,p);
        }
        h.addView(choices);body.addView(h);space(body,18);
    }
    private void gatewayScreen() {
        title("Own your route.","Your gateways. Your access. One place to steer.");
        gatewayPicker();
        if(selected==null) {
            LinearLayout hero=card(); hero.setBackground(shape(INK,24));
            ImageView rook=new ImageView(this); rook.setImageResource(R.drawable.rook_mascot);hero.addView(rook,new LinearLayout.LayoutParams(-1,dp(180)));
            hero.addView(text("Meet your next gateway.",24,Color.WHITE,true));space(hero,8);
            hero.addView(text("Bring a fresh VPS. Rook will take care of the setup, then help you share and manage access.",15,Color.rgb(199,199,207),false));
            fullButton(hero,"Add your first gateway",true,()->editGateway(null));
            fullButton(body,"Add a two-server gateway",true,this::addPair);
            fullButton(body,"Explore a sample gateway",false,this::openDemo);
            fullButton(body,"Read the field guide",false,()->{tab="Guide";render();});return;
        }
        JSONObject s=snapshot();
        LinearLayout hero=card();hero.setBackground(shape(INK,24));
        LinearLayout top=row();TextView name=text(selected.get("name"),27,Color.WHITE,true);top.addView(name,new LinearLayout.LayoutParams(0,-2,1));
        ImageView rook=new ImageView(this);rook.setImageResource(R.drawable.rook_mascot);top.addView(rook,new LinearLayout.LayoutParams(dp(72),dp(72)));hero.addView(top);
        hero.addView(text(demo?"Sample gateway":selected.get("host"),14,Color.rgb(185,185,196),false));space(hero,20);
        boolean connected=vpn!=null && vpn.getState()==VpnStateService.State.CONNECTED && vpn.getProfile()!=null && vpn.getProfile().getUUID().toString().equals(selected.get("profileUuid"));
        String vpnState=connected?"This phone is connected":vpn!=null && vpn.getState()==VpnStateService.State.CONNECTING?"VPN is connecting…":"Ready when you are.";
        hero.addView(text(demo?"Preview of your connection panel":vpnState,16,Color.WHITE,true));
        fullButton(hero,connected?"Disconnect":"Connect",true,()->{if(demo){demoNotice();return;} if(connected){vpn.disconnect();return;} connectPhone(selected);});
        if(!selected.get("job").isEmpty()) {
            LinearLayout job=card();job.addView(text("Installation",19,INK,true));job.addView(text(selected.get("jobPhase"),14,MUTED,false));
            fullButton(job,"Check installation",true,()->pollJob(selected));
        }
        LinearLayout health=card();health.addView(text("Gateway health",19,INK,true));space(health,10);
        JSONObject services=s.optJSONObject("services");
        if(selected.isPair() && selected.exit.data.optJSONObject("snapshot")!=null) {
            JSONObject exitServices=selected.exit.data.optJSONObject("snapshot").optJSONObject("services");
            if(exitServices!=null && services!=null)try{services=new JSONObject(services.toString());services.put("adguardhome",exitServices.optBoolean("adguardhome"));services.put("unbound",exitServices.optBoolean("unbound"));}catch(JSONException ignored){}
        }
        for(String[] item:new String[][]{{"strongswan-starter","VPN"},{"adguardhome","AdGuard"},{"unbound","DNS"}}) {
            LinearLayout r=row();r.addView(text(item[1],15,INK,false),new LinearLayout.LayoutParams(0,-2,1));
            String value=services==null?"Not checked":services.optBoolean(item[0])?"Running":"Stopped";
            r.addView(text(value,13,services!=null && services.optBoolean(item[0])?Color.rgb(0,121,88):MUTED,true));health.addView(r);space(health,8);
        }
        health.addView(text(selected.get("checked").isEmpty()?"Check the server to get its current status.":"Last checked "+selected.get("checked"),11,MUTED,false));
        fullButton(health,"Refresh server",false,()->inspect(selected));
        LinearLayout controls=card();controls.addView(text("Steer this gateway",19,INK,true));
        if(selected.isPair()) {
            controls.addView(text("IKEv2 → AmneziaWG 3.1 · experimental",14,RED,true));
            controls.addView(text("Entry: "+selected.get("host")+"\nExit: "+selected.exit.get("host")+"\n"+selected.get("pairPhase"),13,MUTED,false));
            fullButton(controls,"Install / resume / verify pair",true,()->runPair(selected,true));
            fullButton(controls,"Pause client forwarding",false,()->confirm("Pause this route?","Connected clients lose Internet access. SSH management stays available. Use Resume pair to verify and activate again.",()->withSsh(selected,"Closing forwarding",ssh->ssh.pair(json("command","pause","pair",selected.get("pairId"))),r->{selected.set("pairPhase","Paused · client forwarding blocked");save();render();})));
            fullButton(controls,"Exit SSH settings",false,()->editGateway(selected.exit));
        } else {
            fullButton(controls,"Install gateway on fresh VPS",true,()->installation(selected,false));
            fullButton(controls,"Manage an existing gateway",false,()->installation(selected,true));
        }
        fullButton(controls,"Choose VPN login for this phone",false,()->chooseLogin(selected));
        fullButton(controls,"AdGuard controls",false,()->adguard(selected));
        fullButton(controls,"Gateway settings",false,()->editGateway(selected));
        if(!selected.isPair())fullButton(controls,"Reset gateway data",false,()->resetGateway(selected));
        else fullButton(controls,"Reset both VPN nodes",false,()->resetPair(selected));
        if(selected.isPair())fullButton(controls,"Swap entry and exit",false,()->{
            if(!selected.get("pairPhase").startsWith("Fresh nodes")){message="Reset both VPN nodes before swapping their roles.";render();return;}
            try{Gateway old=selected,next=old.swapped();gateways.set(gateways.indexOf(old),next);selected=next;save();message="Roles swapped. Install the fresh pair; custom VPN addresses now default to the new nodes.";render();}catch(Exception e){error(e);}
        });
        fullButton(body,"Add another gateway",false,()->editGateway(null));
        fullButton(body,"Add a two-server gateway",false,this::addPair);
        fullButton(body,"VPN profiles & advanced settings",false,()->startActivity(new Intent(this,MainActivity.class)));
        if(demo) fullButton(body,"Leave demo",false,()->{demo=false;selected=gateways.isEmpty()?null:gateways.get(0);render();});
    }
    private void peopleScreen() {
        title("Access with intent.","Group people, label device logins, and share profiles.");gatewayPicker();
        if(selected==null) {empty("Add a gateway first.");return;}
        JSONObject s=snapshot();JSONArray users=s.optJSONArray("users");
        fullButton(body,"Add access",true,()->addUser(selected));space(body,18);
        if(users==null || users.length()==0) {empty("No users loaded. Refresh a managed gateway to see access.");return;}
        Map<String,long[]> usage=new HashMap<>();JSONArray monthly=s.optJSONArray("monthly");
        if(monthly!=null) for(int i=0;i<monthly.length();i++) {JSONObject u=monthly.optJSONObject(i);if(u!=null) usage.put(u.optString("user"),new long[]{u.optLong("upload"),u.optLong("download")});}
        LinkedHashMap<String,ArrayList<JSONObject>> people=new LinkedHashMap<>();
        for(int i=0;i<users.length();i++) {JSONObject u=users.optJSONObject(i);if(u==null)continue;String person=u.optString("person",u.optString("login"));people.computeIfAbsent(person,x->new ArrayList<>()).add(u);}
        for(Map.Entry<String,ArrayList<JSONObject>> group:people.entrySet()) {
            LinearLayout c=card();c.addView(text(group.getKey(),22,INK,true));long total=0;
            for(JSONObject u:group.getValue()) {long[] bytes=usage.get(u.optString("login"));if(bytes!=null)total+=bytes[0]+bytes[1];}
            c.addView(text(formatBytes(total)+" this month · UTC",13,MUTED,false));space(c,15);
            for(JSONObject u:group.getValue()) {
                String login=u.optString("login");int active=0;JSONArray cs=s.optJSONArray("connections");
                if(cs!=null)for(int i=0;i<cs.length();i++)if(login.equals(cs.optJSONObject(i).optString("user")))active++;
                LinearLayout r=row();r.addView(text(u.optString("device","Shared login"),16,INK,true),new LinearLayout.LayoutParams(0,-2,1));r.addView(text(active>0?active+" online":"Offline",12,active>0?Color.rgb(0,121,88):MUTED,true));c.addView(r);
                c.addView(text(login,12,MUTED,false));long[] bytes=usage.get(login);if(bytes!=null)c.addView(text("↑ "+formatBytes(bytes[0])+"  ↓ "+formatBytes(bytes[1]),12,MUTED,false));
                fullButton(c,"Manage "+u.optString("device","login"),false,()->userActions(selected,u));space(c,10);
            }
        }
        if(!s.optBoolean("statistics_enabled")) body.addView(text("Monthly history is disabled. Live session counters remain available.",13,MUTED,false));
        fullButton(body,"Refresh access",false,()->inspect(selected));
    }
    private void connectionsScreen() {
        title("Every connection.","Network endpoints and current session traffic.");gatewayPicker();
        if(selected==null){empty("Add a gateway to inspect connections.");return;}
        JSONObject s=snapshot();JSONArray cs=s.optJSONArray("connections");
        if(s.has("monitoring_available") && !s.optBoolean("monitoring_available")) empty("Connection monitoring is unavailable. Refresh to try again.");
        else if(cs==null || cs.length()==0) empty("No active connections in the latest server snapshot.");
        else for(int i=0;i<cs.length();i++) {
            JSONObject c=cs.optJSONObject(i);if(c==null)continue;LinearLayout panel=card();
            panel.addView(text(c.optString("user"),21,INK,true));panel.addView(text(c.optString("endpoint")+":"+c.optInt("port"),13,MUTED,false));space(panel,14);
            panel.addView(text("↑ "+formatBytes(c.optLong("upload"))+"     ↓ "+formatBytes(c.optLong("download")),19,INK,true));
            panel.addView(text("Connected for "+duration(c.optLong("age"))+" · session "+c.optString("id"),12,MUTED,false));
            JSONArray addresses=c.optJSONArray("vpn_addresses");StringBuilder addressText=new StringBuilder();
            if(addresses!=null)for(int addressIndex=0;addressIndex<addresses.length();addressIndex++){if(addressIndex>0)addressText.append(", ");addressText.append(addresses.optString(addressIndex));}
            panel.addView(text("VPN address "+addressText,12,MUTED,false));
            fullButton(panel,"Disconnect this session",false,()->confirm("Disconnect session?","The user can reconnect while their login remains enabled.",()->command(selected,json("action","disconnect","session",c.optString("id")),r->inspect(selected))));
        }
        fullButton(body,"Refresh connections",true,()->inspect(selected));
        fullButton(body,s.optBoolean("statistics_enabled")?"Disable usage history":"Enable usage history",false,()->confirm("Change usage history?","History is stored on the VPS. Enabling starts collection; disabling keeps saved totals but stops new collection.",()->command(selected,json("action","stats-toggle","enabled",!s.optBoolean("statistics_enabled")),r->inspect(selected))));
        JSONObject accounting=s.optJSONObject("accounting");
        if(accounting!=null && (accounting.has("gap") || accounting.has("counter_reset"))) {space(body,12);body.addView(text("Accounting has recorded a monitoring gap or counter reset. Totals are estimates.",13,RED,false));}
        space(body,16);body.addView(text("Endpoints can change between mobile data and Wi-Fi. They do not identify physical devices. Refresh shows the server's current observation.",13,MUTED,false));
    }
    private void empty(String copy) {LinearLayout c=card();c.addView(text(copy,16,MUTED,false));}
    private static String formatBytes(long n) {return n>=1_000_000_000?String.format(Locale.US,"%.2f GB",n/1e9):n>=1_000_000?String.format(Locale.US,"%.1f MB",n/1e6):String.format(Locale.US,"%.1f KB",n/1e3);}
    private static String duration(long s) {return s>=3600?(s/3600)+"h "+(s%3600/60)+"m":(s/60)+"m";}
    private static JSONObject json(Object...pairs) {JSONObject j=new JSONObject();try{for(int i=0;i<pairs.length;i+=2)j.put((String)pairs[i],pairs[i+1]);}catch(JSONException e){throw new IllegalArgumentException(e);}return j;}
    private static byte[] read(InputStream in,int limit) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>limit)throw new IOException("File is too large");}return out.toByteArray();}

    private interface Task {JSONObject run(Ssh ssh) throws Exception;}
    private interface Done {void finish(JSONObject result);}
    private void withSsh(Gateway node,String work,Task task,Done done) {
        if(demo){demoNotice();return;}if(busy || DeploymentService.active())return;
        if(!hasAuth(node)) {passwordDialog(node,()->withSsh(node,work,task,done));return;}
        if(node.sshRelay!=null && !hasAuth(node.sshRelay)){passwordDialog(node.sshRelay,()->withSsh(node,work,task,done));return;}
        busy=true;message=work;render();
        executor.execute(()->{
            try(Ssh ssh=new Ssh(node)) {JSONObject result=task.run(ssh);handler.post(()->{busy=false;message="";done.finish(result);render();});}
            catch(Exception e) {handler.post(()->{busy=false;message="";render();if(e instanceof Ssh.HostTrust)trust(node,(Ssh.HostTrust)e,()->withSsh(node,work,task,done));else error(e);});}
        });
    }
    private void command(Gateway node,JSONObject request,Done done) {withSsh(node,"Updating "+node.get("name"),s->s.admin(request),done);}
    private void inspect(Gateway node) {
        if(node.isPair()){refreshPair(node);return;}
        withSsh(node,"Checking "+node.get("name"),s->{JSONObject p=s.probe();if(p.optBoolean("helper"))p.put("status",s.admin(json("action","status")));return p;},p->{
            node.set("checked",new java.text.SimpleDateFormat("MMM d, HH:mm",Locale.getDefault()).format(new Date()));
            try {node.data.put("probe",p);if(p.has("status"))node.data.put("snapshot",p.getJSONObject("status"));}catch(JSONException ignored){}
            JSONObject job=p.optJSONObject("job");
            InstallationProgress recorded=currentProgress();
            boolean recovering=recorded!=null&&recorded.gatewayId.equals(node.get("id"))&&!recorded.kind.equals("pair")&&!recorded.state.equals("complete");
            if(job!=null && InputRules.job(job.optString("job")) && (job.optString("state").equals("running") || job.optString("state").equals("starting") || (recovering&&p.optBoolean("helper")&&job.optString("state").equals("complete")))) {
                if(recovering)node.set("jobKind",recorded.kind);
                node.set("job",job.optString("job"));node.set("jobPhase",job.optString("phase"));handler.postDelayed(()->pollJob(node),3000);
            }
            save();if(!p.optBoolean("helper"))message=node.get("job").isEmpty()?"SSH works · "+p.optString("os")+" "+p.optString("version")+" · choose install or enrollment.":"Installation found on the VPS; reconnecting to its status.";
        });
    }
    private void trust(Gateway requested,Ssh.HostTrust t,Runnable retry) {
        Gateway node=t.node==null?requested:t.node;
        if(t.changed) {new AlertDialog.Builder(this).setTitle("SSH identity changed").setMessage("Rookstride stopped before sending credentials. Verify a VPS replacement or key change with your provider.\n\nSaved: "+node.get("fingerprint")+"\n\nPresented: "+t.fingerprint).setPositiveButton("Close",null).show();return;}
        new AlertDialog.Builder(this).setTitle("Verify your server").setMessage(node.get("host")+":"+node.port()+"\n\n"+t.fingerprint+"\n\nCompare this SSH fingerprint with your provider's console if available. Trust it only when it belongs to your server.")
            .setNegativeButton("Cancel",null).setPositiveButton("Trust this server",(d,w)->{node.set("fingerprint",t.fingerprint);save();retry.run();}).show();
    }
    private EditText field(LinearLayout into,String label,String value,boolean password) {
        TextView l=text(label,12,MUTED,true);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.topMargin=dp(12);into.addView(l,lp);
        EditText e=new EditText(this);e.setSingleLine(true);e.setTextSize(16);e.setText(value);e.setInputType(password?InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD:InputType.TYPE_CLASS_TEXT);
        into.addView(e,new LinearLayout.LayoutParams(-1,dp(48)));return e;
    }
    private LinearLayout form() {LinearLayout f=stack();f.setPadding(dp(22),dp(8),dp(22),dp(12));return f;}
    private ScrollView scrolling(LinearLayout f) {ScrollView s=new ScrollView(this);s.addView(f);return s;}
    private void secure(AlertDialog dialog) {if(dialog.getWindow()!=null)dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);}
    private void passwordDialog(Gateway node,Runnable next) {
        LinearLayout f=form();EditText p=field(f,"Administrator password or key passphrase","",true);
        CheckBox remember=new CheckBox(this);remember.setText("Remember securely on this phone");remember.setChecked(node.remember());f.addView(remember);
        AlertDialog d=new AlertDialog.Builder(this).setTitle("Administrator access").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Continue",(a,w)->{node.sshPassword=p.getText().toString();try{node.data.put("remember",remember.isChecked());}catch(JSONException ignored){}save();next.run();}).create();d.show();secure(d);
    }
    private void editGateway(Gateway node) {
        if(demo && node!=null){demoNotice();return;}if(vaultFailed){error(new IOException("Saved data is locked; preserve it before clearing app storage."));return;}
        Gateway parent=null;for(Gateway candidate:gateways)if(candidate.exit==node)parent=candidate;final Gateway pairParent=parent;
        LinearLayout f=form();EditText name=field(f,"Gateway name",node==null?"My gateway":node.get("name"),false);
        EditText host=field(f,"VPS IPv4 address or hostname",node==null?"":node.get("host"),false);
        EditText port=field(f,"SSH port",node==null?"22":String.valueOf(node.port()),false);port.setInputType(InputType.TYPE_CLASS_NUMBER);
        EditText user=field(f,"Administrator login",node==null?"root":node.get("admin"),false);
        EditText password=field(f,"SSH password / key passphrase",node==null?"":node.sshPassword,true);
        keyField=field(f,"SSH private key (optional)",node==null?"":node.privateKey,true);keyField.setSingleLine(false);keyField.setMaxLines(3);
        fullButton(f,"Choose SSH key file",false,()->{Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(pick,PICK_KEY);});
        CheckBox remember=new CheckBox(this);remember.setText("Remember credentials securely on this phone");remember.setChecked(node!=null && node.remember());f.addView(remember);
        if(node!=null)fullButton(f,"Reset saved SSH identity",false,()->confirm("Reset SSH identity?","Do this after verifying the server was replaced or its SSH keys intentionally changed. The next connection will ask you to verify the new fingerprint.",()->{node.set("fingerprint","");save();editor.dismiss();}));
        editor=new AlertDialog.Builder(this).setTitle(node==null?"Add a gateway":"Gateway settings").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();
        if(node!=null && pairParent==null)editor.setButton(AlertDialog.BUTTON_NEUTRAL,"Remove saved gateway",(d,w)->confirm("Remove from this phone?","This removes saved access from this app. The VPS and its users continue running.",()->{DeploymentService.forget(this,node);gateways.remove(node);selected=gateways.isEmpty()?null:gateways.get(0);save();render();}));
        editor.show();secure(editor);
        editor.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            try {
                int p=Integer.parseInt(port.getText().toString());String h=host.getText().toString().trim(),u=user.getText().toString().trim(),n=name.getText().toString().trim();
                if(!InputRules.host(h)||!InputRules.port(p)||!InputRules.username(u)||n.isEmpty()||n.length()>80)throw new IllegalArgumentException("Check the name, address, port and administrator login.");
                Gateway target=node==null?new Gateway():node;
                if(!h.equals(target.get("host"))||p!=target.port())target.set("fingerprint","");
                target.set("name",n);target.set("host",h);target.set("admin",u);target.data.put("port",p);target.data.put("remember",remember.isChecked());target.sshPassword=password.getText().toString();target.privateKey=keyField.getText().toString();
                if(node==null)gateways.add(target);selected=pairParent==null?target:pairParent;demo=false;save();editor.dismiss();render();
            }catch(Exception e){Toast.makeText(this,e.getMessage(),Toast.LENGTH_LONG).show();}
        });
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==PICK_KEY && result==RESULT_OK && data!=null && keyField!=null)try(InputStream in=getContentResolver().openInputStream(data.getData())){keyField.setText(new String(read(in,65536),StandardCharsets.UTF_8));}catch(Exception e){error(e);}
    }
    private static String generatedPassword() {byte[] b=new byte[24];new SecureRandom().nextBytes(b);return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
    private void confirm(String title,String copy,Runnable action) {new AlertDialog.Builder(this).setTitle(title).setMessage(copy).setNegativeButton("Cancel",null).setPositiveButton("Continue",(d,w)->action.run()).show();}
    private void installation(Gateway node,boolean enroll) {
        if(demo){demoNotice();return;}
        LinearLayout f=form();f.addView(text(enroll?"Adds the management helper to a supported existing gateway. Enabling the monitoring interface may briefly restart the VPN; clients can reconnect.":"Installs StrongSwan, AdGuard Home, DNS and firewall settings on a fresh Ubuntu 24.04 VPS. Existing VPN configurations are refused.",14,MUTED,false));
        EditText login=enroll?null:field(f,"Initial VPN login","admin-device",false);
        EditText password=enroll?null:field(f,"VPN password (16+ characters)",generatedPassword(),true);
        CheckBox stats=new CheckBox(this);stats.setText("Enable lightweight usage history");stats.setChecked(true);f.addView(stats);
        AlertDialog d=new AlertDialog.Builder(this).setTitle(enroll?"Manage existing gateway":"Install your gateway").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton(enroll?"Enroll gateway":"Install",null).create();d.show();secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            String u=enroll?"":login.getText().toString().trim(),pw=enroll?"":password.getText().toString();
            if(!enroll && (!InputRules.username(u)||pw.length()<16)){Toast.makeText(this,"Use a valid login and a password of at least 16 characters.",1).show();return;}
            JSONObject config=json("mode",enroll?"enroll":"install","server",node.get("host"),"login",u,"password",pw,"statistics",stats.isChecked());
            if(!enroll){node.set("vpnLogin",u);node.vpnPassword=pw;save();}
            d.dismiss();startDeployment(node,enroll?"enroll":"single",config,false);
        });
    }
    private void addPair() {
        if(vaultFailed){error(new IOException("Saved gateway data is locked."));return;}
        LinearLayout f=form();
        f.addView(text("IKEv2 → AmneziaWG 3.1",20,INK,true));
        f.addView(text("Use two distinct fresh Ubuntu 24.04 nodes. Rookstride installs the exit first, keeps the entry blocked, then checks the second hop before activation. A matching kernel may require a reboot. This is an experimental installation mode.",14,MUTED,false));
        EditText name=field(f,"Gateway name","My two-hop gateway",false);
        EditText entryHost=field(f,"Entry VPS address","",false),entryPort=field(f,"Entry SSH port","22",false),entryUser=field(f,"Entry administrator","root",false),entryPassword=field(f,"Entry SSH password / key passphrase","",true);
        EditText exitHost=field(f,"Exit VPS address","",false),exitPort=field(f,"Exit SSH port","22",false),exitUser=field(f,"Exit administrator","root",false),exitPassword=field(f,"Exit SSH password / key passphrase","",true);
        LinearLayout advanced=stack();advanced.setVisibility(View.GONE);
        fullButton(f,"Advanced: SSH keys, addresses and ports",false,()->advanced.setVisibility(advanced.getVisibility()==View.GONE?View.VISIBLE:View.GONE));f.addView(advanced);
        EditText entryKey=field(advanced,"Entry private key (optional)","",true),exitKey=field(advanced,"Exit private key (optional)","",true);entryKey.setSingleLine(false);exitKey.setSingleLine(false);
        CheckBox entryRelay=new CheckBox(this);entryRelay.setText("Manage entry SSH through exit");advanced.addView(entryRelay);
        CheckBox exitRelay=new CheckBox(this);exitRelay.setText("Manage exit SSH through entry");advanced.addView(exitRelay);
        entryRelay.setOnCheckedChangeListener((b,on)->{if(on)exitRelay.setChecked(false);});exitRelay.setOnCheckedChangeListener((b,on)->{if(on)entryRelay.setChecked(false);});
        advanced.addView(text("Optional when your phone cannot reach one SSH endpoint. Both SSH identities stay pinned. This changes administration only; the VPN route stays the same.",12,MUTED,false));
        EditText server=field(advanced,"VPN hostname (defaults to entry address)","",false),endpoint=field(advanced,"Exit tunnel address (defaults to exit address)","",false),vpnPort=field(advanced,"Phone VPN port","500",false),tunnelPort=field(advanced,"Exit AWG UDP port","443",false);
        EditText login=field(f,"Initial VPN login","admin-device",false),password=field(f,"VPN password (16+ characters)",generatedPassword(),true);
        fullButton(f,"Copy VPN password",false,()->copySecret(password.getText().toString()));
        CheckBox remember=new CheckBox(this);remember.setText("Remember passwords and keys securely on this phone");f.addView(remember);
        CheckBox history=new CheckBox(this);history.setText("Enable usage history on the entry");history.setChecked(true);f.addView(history);
        AlertDialog d=new AlertDialog.Builder(this).setTitle("Add a two-server gateway").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Install pair",null).create();d.show();secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{try {
            int ep=Integer.parseInt(entryPort.getText().toString()),xp=Integer.parseInt(exitPort.getText().toString()),vp=Integer.parseInt(vpnPort.getText().toString()),tp=Integer.parseInt(tunnelPort.getText().toString());
            String eh=entryHost.getText().toString().trim(),xh=exitHost.getText().toString().trim(),eu=entryUser.getText().toString().trim(),xu=exitUser.getText().toString().trim(),u=login.getText().toString().trim(),pw=password.getText().toString();
            if(!InputRules.host(eh)||!InputRules.host(xh)||!InputRules.port(ep)||!InputRules.port(xp)||!InputRules.port(vp)||!InputRules.port(tp)||!InputRules.username(eu)||!InputRules.username(xu)||!InputRules.username(u)||pw.length()<16)throw new IOException("Check both addresses, ports, logins and the VPN password.");
            if(eh.equals(xh)&&ep==xp)throw new IOException("Entry and exit must be different nodes.");
            Gateway a=new Gateway(),b=new Gateway();a.exit=b;
            a.set("name",name.getText().toString().trim());a.set("host",eh);a.set("admin",eu);a.data.put("port",ep);a.sshPassword=entryPassword.getText().toString();a.privateKey=entryKey.getText().toString();a.data.put("remember",remember.isChecked());
            b.set("name",a.get("name")+" · exit");b.set("host",xh);b.set("admin",xu);b.data.put("port",xp);b.sshPassword=exitPassword.getText().toString();b.privateKey=exitKey.getText().toString();b.data.put("remember",remember.isChecked());
            a.set("pairId",PairController.newId());a.set("vpnLogin",u);a.vpnPassword=pw;a.set("vpnServer",server.getText().toString().trim());a.set("exitEndpoint",endpoint.getText().toString().trim());a.data.put("vpnPort",vp);a.data.put("tunnelPort",tp);a.data.put("pairStatistics",history.isChecked());a.set("pairPhase","Not installed");
            a.set("sshRoute",entryRelay.isChecked()?"entry-via-exit":exitRelay.isChecked()?"exit-via-entry":"direct");a.configureRelay();
            PairController.request(a,"entry");gateways.add(a);selected=a;demo=false;save();d.dismiss();runPair(a,false);
        }catch(Exception e){Toast.makeText(this,e.getMessage(),Toast.LENGTH_LONG).show();}});
    }
    private void runPair(Gateway node,boolean resume) {
        if(demo){demoNotice();return;}if(busy || DeploymentService.active())return;
        if(!hasAuth(node)){passwordDialog(node,()->runPair(node,resume));return;}
        if(!hasAuth(node.exit)){passwordDialog(node.exit,()->runPair(node,resume));return;}
        startDeployment(node,"pair",null,resume);
    }
    private void refreshPair(Gateway node) {
        withSsh(node,"Checking the entry",s->s.admin(json("action","status")),a->{try{node.data.put("snapshot",a);}catch(JSONException e){error(e);}
            withSsh(node.exit,"Checking the exit",s->s.admin(json("action","status")),b->{try{node.exit.data.put("snapshot",b);node.set("checked","Both nodes checked");save();render();}catch(JSONException e){error(e);}});
        });
    }

    private void resetPair(Gateway node) {
        if(demo){demoNotice();return;}if(busy || DeploymentService.active())return;
        if(!hasAuth(node)){passwordDialog(node,()->resetPair(node));return;}
        if(!hasAuth(node.exit)){passwordDialog(node.exit,()->resetPair(node));return;}
        busy=true;message="Reviewing both VPN nodes";render();
        executor.execute(()->{try {
            JSONObject review=PairResetController.review(node,()->getAssets().open("gateway_bundle.zip"));
            handler.post(()->{
                busy=false;message="";render();LinearLayout f=form();
                f.addView(text("This removes VPN accounts, certificates, tunnel keys, DNS data and usage history from both nodes. Connected clients lose access. Ubuntu, SSH and unrelated files stay installed. You can then install either role on either node.",14,RED,true));
                f.addView(text("Entry "+node.get("host")+"\n"+review.optJSONObject("entry").optJSONArray("files")+"\n\nExit "+node.exit.get("host")+"\n"+review.optJSONObject("exit").optJSONArray("files"),12,MUTED,false));
                EditText typed=field(f,"Type DELETE PAIR to continue","",false);
                AlertDialog d=new AlertDialog.Builder(this).setTitle("Reset both VPN nodes?").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Delete pair data",null).create();d.show();
                d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                    if(!typed.getText().toString().equals("DELETE PAIR")){typed.setError("Type DELETE PAIR");return;}d.dismiss();
                    if(vpn!=null && vpn.getProfile()!=null && vpn.getProfile().getUUID().toString().equals(node.get("profileUuid")))vpn.disconnect();
                    busy=true;message="Removing pair data";render();executor.execute(()->{try {
                        PairResetController.apply(node,review,"DELETE PAIR",()->getAssets().open("gateway_bundle.zip"),p->handler.post(()->{message=p;render();}));
                        handler.post(()->{try{busy=false;VpnProfileDataSource source=new VpnProfileSource(this);source.open();try{VpnProfile p=source.getVpnProfile(node.get("profileUuid"));if(p!=null)source.deleteVpnProfile(p);}finally{source.close();}DeploymentService.forget(this,node);node.data.remove("snapshot");node.exit.data.remove("snapshot");node.set("pairId",PairController.newId());node.set("pairPhase","Fresh nodes · ready to install");node.set("profileUuid","");save();message="Both nodes reset. Ubuntu and SSH retained.";render();}catch(Exception e){error(e);}});
                    }catch(Exception e){handler.post(()->{busy=false;message="Reset stopped. Review again to finish the remaining owned node.";render();error(e);});}});
                });
            });
        }catch(Exception e){handler.post(()->{busy=false;message="";render();if(e instanceof PairController.TrustNeeded){PairController.TrustNeeded t=(PairController.TrustNeeded)e;trust(t.node,t.issue,()->resetPair(node));}else error(e);});}});
    }

    private void resetGateway(Gateway node) {
        if(demo){demoNotice();return;}
        withSsh(node,"Reviewing reset",ssh->{try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","plan"));}},plan->{
            LinearLayout f=form();f.addView(text("This permanently removes VPN accounts, certificates, AdGuard settings and usage history from "+node.get("host")+". Connected users lose access. Ubuntu, SSH and installed package binaries remain.",14,RED,true));
            space(f,12);f.addView(text("Managed paths:\n"+plan.optJSONArray("files"),12,MUTED,false));
            EditText confirmation=field(f,"Type DELETE VPN to continue","",false);
            AlertDialog d=new AlertDialog.Builder(this).setTitle("Reset "+node.get("name")+"?").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Delete gateway data",null).create();d.show();
            d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                if(!confirmation.getText().toString().equals("DELETE VPN")){confirmation.setError("Type DELETE VPN");return;}d.dismiss();
                if(vpn!=null && vpn.getProfile()!=null && vpn.getProfile().getUUID().toString().equals(node.get("profileUuid"))) vpn.disconnect();
                withSsh(node,"Removing gateway data",ssh->{try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","apply","token",plan.getString("token"),"confirmation","DELETE VPN"));}},r->{
                    try {VpnProfileDataSource source=new VpnProfileSource(this);source.open();try{VpnProfile p=source.getVpnProfile(node.get("profileUuid"));if(p!=null)source.deleteVpnProfile(p);}finally{source.close();}
                    DeploymentService.forget(this,node);node.data.remove("snapshot");node.set("checked","");node.set("profileUuid","");node.set("job","");node.set("vpnLogin","");node.vpnPassword="";save();message=r.optString("message");render();}catch(Exception e){error(e);}
                });
            });
        });
    }
    private void pollJob(Gateway node) {
        if(demo){demoNotice();return;}if(node.get("job").isEmpty())return;
        startDeployment(node,node.get("jobKind").equals("enroll")?"enroll":"single",new JSONObject(),true);
    }
    private void addUser(Gateway node) {
        if(demo){demoNotice();return;}
        LinearLayout f=form();EditText person=field(f,"Person","",false),device=field(f,"Device label","Phone",false),login=field(f,"VPN login","",false),password=field(f,"Password",generatedPassword(),true);
        CheckBox shared=new CheckBox(this);shared.setText("Shared login for several devices");f.addView(shared);
        AlertDialog d=new AlertDialog.Builder(this).setTitle("Add access").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Create",null).create();d.show();secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String u=login.getText().toString().trim(),pw=password.getText().toString(),p=person.getText().toString().trim(),label=device.getText().toString().trim();
            if(!InputRules.username(u)||pw.length()<16||p.isEmpty()||label.isEmpty()){Toast.makeText(this,"Enter a person, device label, valid login and a 16+ character password.",1).show();return;}
            d.dismiss();command(node,json("action","add-user","login",u,"password",pw,"person",p,"device",shared.isChecked()?"Shared login":label,"kind",shared.isChecked()?"shared":"device"),r->{credentials(u,pw);inspect(node);});
        });
    }
    private void credentials(String user,String password) {
        new AlertDialog.Builder(this).setTitle("Access created").setMessage("Login: "+user+"\nPassword: "+password+"\n\nSave the password now; it is not returned by the user list. Share the profile and password through a trusted channel.")
            .setPositiveButton("Done",null).setNeutralButton("Copy password",(d,w)->copySecret(password)).show().getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    private void copySecret(String password) {
        ClipData c=ClipData.newPlainText("VPN password",password);
        if(Build.VERSION.SDK_INT>=33){PersistableBundle extras=new PersistableBundle();extras.putBoolean("android.content.extra.IS_SENSITIVE",true);c.getDescription().setExtras(extras);}
        ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(c);Toast.makeText(this,"Password copied",0).show();
    }
    private void userActions(Gateway node,JSONObject user) {
        String login=user.optString("login");
        new AlertDialog.Builder(this).setTitle(user.optString("person")+" · "+user.optString("device")).setItems(new String[]{"Share StrongSwan profile","Use on this phone","Change password","Revoke this login"},(d,w)->{
            if(demo){demoNotice();return;}
            if(w==0)command(node,json("action","profile","login",login,"name",node.get("name")+" · "+user.optString("device")),this::share);
            else if(w==1)fetchForPhone(node,login);
            else if(w==2){LinearLayout f=form();EditText pw=field(f,"New password",generatedPassword(),true);AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Change password").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Update",(a,b)->command(node,json("action","add-user","login",login,"password",pw.getText().toString(),"person",user.optString("person"),"device",user.optString("device"),"kind",user.optString("kind"),"replace",true),r->{credentials(login,pw.getText().toString());inspect(node);})).create();dialog.show();secure(dialog);}
            else confirm("Revoke "+login+"?","New logins will be denied and current sessions for this login will be disconnected. Other devices sharing it lose access too.",()->command(node,json("action","remove-user","login",login),r->{if(!r.optString("warning").isEmpty())new AlertDialog.Builder(this).setTitle("Login revoked").setMessage(r.optString("warning")).setPositiveButton("Close",null).show();inspect(node);}));
        }).show();
    }
    private void chooseLogin(Gateway node) {
        if(demo){demoNotice();return;}
        LinearLayout f=form();EditText user=field(f,"VPN login",node.get("vpnLogin"),false);
        new AlertDialog.Builder(this).setTitle("VPN on this phone").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Get profile",(d,w)->fetchForPhone(node,user.getText().toString().trim())).show();
    }
    private void fetchForPhone(Gateway node,String user) {
        if(!InputRules.username(user)){error(new IllegalArgumentException("Enter a valid VPN login."));return;}
        command(node,json("action","profile","login",user,"name",node.get("name")),p->{
            try {installProfile(node,p);node.set("vpnLogin",user);save();vpnPassword(node,()->connectPhone(node));}catch(Exception e){error(e);}
        });
    }
    private void installProfile(Gateway node,JSONObject data) throws Exception {
        byte[] raw=java.util.Base64.getDecoder().decode(data.getJSONObject("remote").getString("cert"));
        X509Certificate certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(raw));
        KeyStore store=KeyStore.getInstance("LocalCertificateStore");store.load(null,null);store.setCertificateEntry(null,certificate);
        String alias=null;Enumeration<String> aliases=store.aliases();while(aliases.hasMoreElements()){String a=aliases.nextElement();if(certificate.equals(store.getCertificate(a)))alias=a;}
        if(alias==null)throw new IOException("Could not store the server certificate");TrustedCertificateManager.getInstance().reset();
        VpnProfileDataSource source=new VpnProfileSource(this);source.open();
        try {
            VpnProfile p=node.get("profileUuid").isEmpty()?null:source.getVpnProfile(node.get("profileUuid"));boolean exists=p!=null;if(p==null)p=new VpnProfile();
            p.setName(node.get("name"));p.setGateway(data.getJSONObject("remote").getString("addr"));p.setRemoteId(data.getJSONObject("remote").getString("id"));
            if(data.getJSONObject("remote").has("port"))p.setPort(data.getJSONObject("remote").getInt("port"));
            p.setUsername(data.getJSONObject("local").getString("eap_id"));p.setVpnType(VpnType.IKEV2_EAP);p.setMTU(1280);p.setCertificateAlias(alias);p.setPassword(null);
            p.setSplitTunneling(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4|VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);p.setFlags(VpnProfile.FLAGS_SUPPRESS_CERT_REQS);
            if(exists)source.updateVpnProfile(p);else source.insertProfile(p);node.set("profileUuid",p.getUUID().toString());
        } finally {source.close();}
    }
    private void vpnPassword(Gateway node,Runnable next) {
        LinearLayout f=form();EditText p=field(f,"VPN password",node.vpnPassword,true);
        AlertDialog d=new AlertDialog.Builder(this).setTitle("Connect as "+node.get("vpnLogin")).setView(f).setNegativeButton("Cancel",null).setPositiveButton("Continue",(a,w)->{node.vpnPassword=p.getText().toString();save();next.run();}).create();d.show();secure(d);
    }
    private void connectPhone(Gateway node) {
        if(node.get("profileUuid").isEmpty()){chooseLogin(node);return;}
        if(node.vpnPassword.isEmpty()){vpnPassword(node,()->connectPhone(node));return;}
        Intent i=new Intent(this,VpnProfileControlActivity.class).setAction("org.strongswan.android.action.START_PROFILE");
        i.putExtra(VpnProfileControlActivity.EXTRA_VPN_PROFILE_UUID,node.get("profileUuid"));i.putExtra("rookstride.session_password",node.vpnPassword);startActivity(i);
    }
    private void share(JSONObject profile) {
        try {
            File directory=new File(getCacheDir(),"exports");directory.mkdirs();File file=new File(directory,"rookstride-"+profile.getJSONObject("local").getString("eap_id")+".sswan");
            try(FileOutputStream out=new FileOutputStream(file)){out.write(profile.toString(2).getBytes(StandardCharsets.UTF_8));}
            Uri uri=FileProvider.getUriForFile(this,getPackageName()+".files",file);
            Intent i=new Intent(Intent.ACTION_SEND).setType("application/vnd.strongswan.profile").putExtra(Intent.EXTRA_STREAM,uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(i,"Share VPN profile"));handler.postDelayed(file::delete,300000);
        } catch(Exception e){error(e);}
    }
    private void adguard(Gateway node) {
        if(node.isPair()){adguard(node.exit);return;}
        if(demo){demoNotice();return;}
        command(node,json("action","adguard"),r->new AlertDialog.Builder(this).setTitle("AdGuard Home").setMessage(r.optLong("blocked")+" blocked / "+r.optLong("queries")+" DNS requests\n\nStrong and Strict can block domains that a site needs. DNS filtering cannot reliably remove YouTube video ads.")
            .setItems(new String[]{"Standard · AdGuard DNS filter","Strong · HaGeZi Pro","Strict · HaGeZi Pro++"},(d,w)->confirm("Change filtering?","Compare website access afterward. You can return to Standard if a required domain is blocked.",()->command(node,json("action","adguard","level",new String[]{"standard","strong","strict"}[w]),a->Toast.makeText(this,"Filtering level updated",1).show())))
            .setPositiveButton("Close",null).show());
    }
    private void onboarding(int index) {
        String[] headlines={"Your server.\nYour route.","Build once.\nShare with intent.","Know your\nprotection."};
        String[] copies={"Add a fresh Ubuntu VPS using its SSH login. Rookstride installs the VPN and helps you manage it from your phone.","Keep administrator access on your phone. Give others VPN profiles for the official StrongSwan app. Label separate device logins when you want individual usage and revocation.","The VPN protects traffic to your VPS and changes the exit IP. AdGuard blocks DNS names; it cannot remove every ad. Check IP, DNS and IPv6 on each actual device."};
        LinearLayout f=form();ImageView icon=new ImageView(this);icon.setImageResource(index==0?R.drawable.rook_guide:index==1?R.drawable.rook_map:R.drawable.rook_lantern);f.addView(icon,new LinearLayout.LayoutParams(-1,dp(150)));f.addView(text(String.format(Locale.US,"0%d / 03",index+1),12,RED,true));space(f,12);f.addView(text(headlines[index],31,INK,true));space(f,14);f.addView(text(copies[index],15,MUTED,false));
        AlertDialog d=new AlertDialog.Builder(this).setView(f).setCancelable(false).setPositiveButton(index==2?"Get started":"Continue",(a,w)->{if(index<2)onboarding(index+1);else{getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).apply();render();}}).setNegativeButton("Read guide",(a,w)->{getSharedPreferences("rookstride-ui",0).edit().putBoolean("onboarded",true).apply();tab="Guide";render();}).create();d.show();
    }
    private void openDemo() {
        try {
            selected=new Gateway();selected.set("name","Rook's gateway");selected.set("host","vpn.example.net");demo=true;
            JSONObject s=json("statistics_enabled",true,"services",json("strongswan-starter",true,"adguardhome",true,"unbound",true));
            s.put("users",new JSONArray().put(json("login","alex-phone","person","Alex","device","Phone","kind","device")).put(json("login","alex-laptop","person","Alex","device","Laptop","kind","device")).put(json("login","family","person","Family","device","Shared login","kind","shared")));
            s.put("monthly",new JSONArray().put(json("user","alex-phone","upload",1300000000L,"download",16800000000L)).put(json("user","alex-laptop","upload",2700000000L,"download",28400000000L)).put(json("user","family","upload",300000000L,"download",8100000000L)));
            s.put("connections",new JSONArray().put(json("id","41","user","alex-phone","endpoint","192.0.2.24","port",4500,"age",3720,"upload",44000000,"download",580000000,"vpn_addresses",new JSONArray().put("10.252.0.2"))).put(json("id","42","user","family","endpoint","198.51.100.18","port",53120,"age",840,"upload",15000000,"download",180000000,"vpn_addresses",new JSONArray().put("10.252.0.3"))));
            selected.data.put("snapshot",s);selected.set("checked","Sample snapshot");render();
        }catch(Exception e){error(e);}
    }
}
