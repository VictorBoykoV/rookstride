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
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import org.json.*;
import org.strongswan.android.R;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.*;
import org.strongswan.android.rookstride.*;
import org.strongswan.android.rookstride.engine.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;

/** Rookstride administration shell; the upstream engine owns the VPN lifecycle. */
public final class RookstrideActivity extends AppCompatActivity implements VpnStateService.VpnStateListener {
    private static final int RED=Color.rgb(191,38,55), INK=Color.rgb(20,20,24), MUTED=Color.rgb(92,97,107), BACK=Color.rgb(245,246,248), LINE=Color.rgb(224,227,232);
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private final Handler handler=new Handler(Looper.getMainLooper());
    private ArrayList<Gateway> gateways=new ArrayList<>();
    private Gateway selected;
    private Vault vault;
    private LinearLayout root,body,progressHost,connectionControls;
    private final LinkedHashMap<String,View> serverRows=new LinkedHashMap<>();
    private final List<Runnable> homeConnectionUpdates=new ArrayList<>();
    private final Set<String> expandedServers=new HashSet<>();
    private LinearLayout homeIntro;
    private Runnable quickConnectionUpdate;
    private String homeQuickId="";
    private final Runnable connectionRefresh=this::refreshConnectionViews;
    private final Map<String,Integer> scrollPositions=new HashMap<>();
    private ScrollView pageScroll;
    private String renderedScrollKey="",tapId="",tapAction="",tapPrevious="";
    private long tapUntil;
    private ServerDrag activeDrag;
    private final Map<String,NativeVpn.Status> renderStatuses=new HashMap<>();
    private boolean rendering,scrollRestorePending,resumed,statisticsLoading,statisticsPaused;
    private LinearLayout statisticsHost;
    private TextView statisticsUpdated;
    private View operationNotice;
    private String completionNoticeKey="";
    private long completionNoticeDeadline;
    private interface StatisticsSource {JSONObject read(Gateway node)throws Exception;}
    private StatisticsSource statisticsSource=this::readStatistics;
    private interface PairReviewSource {JSONObject read(Gateway pair)throws Exception;}
    private PairReviewSource pairReviewSource=pair->PairPreparationController.review(pair,()->getAssets().open("gateway_bundle.zip"),()->getAssets().open("single_bundle.zip"));
    private String noticeMessage="",statisticsRecord="",statisticsIssue="",pendingModule="";
    private Gateway setupCheckNode;
    private InstallationProgress setupCheckProgress;
    private Runnable setupCheckRetry;
    private boolean setupCheckPair;
    private TextView setupCheckElapsed,moduleWaitLabel;
    private long moduleWaitStarted;
    private static final long STATISTICS_INTERVAL=5*60*1000L;
    private long noticeDeadline,statisticsAttempt;
    private int statisticsEpoch;
    private final Runnable noticeExpiry=()->dismissOperationNotice();
    private final Runnable statisticsTick=new Runnable(){public void run(){
        if(resumed&&tab.equals("Sessions")&&selected!=null&&!statisticsPaused&&!statisticsLoading&&!busy&&!DeploymentService.active()&&(statisticsAttempt==0||SystemClock.elapsedRealtime()-statisticsAttempt>=STATISTICS_INTERVAL))refreshStatistics(false);
        if(resumed)handler.postDelayed(this,1000);
    }};
    private String tab="Home",message="";
    private androidx.viewpager2.widget.ViewPager2 quickPager;
    private QuickAdapter quickAdapter;
    private final Map<String,Runnable> quickUpdates=new HashMap<>();
    private TextView quickPages;
    private final Set<String> faqOpen=new HashSet<>();
    private String maintenanceSection="";
    private final Map<String,View> maintenanceBodies=new HashMap<>();
    private String pendingAction="";
    private String pendingActionKey="",quickActiveId="";
    private final Map<String,Integer> buttonOccurrences=new HashMap<>();
    private final Map<Button,String> buttonIdentities=new WeakHashMap<>();
    private AlertDialog newUserDialog;
    private final AppNavigation navigation=new AppNavigation();
    private String setupProtocol="ikev2",pendingServerId="",importProtocol="ikev2";
    private boolean busy=false,demo=false,vaultFailed=false,reordering=false,renderAfterDrag=false;
    private VpnStateService vpn;
    private AlertDialog editor,leavePrompt;
    private EditText keyField;
    private TextView deploymentLabel,elapsedLabel;
    private final Runnable progressTick=new Runnable(){public void run(){
        if(setupCheckElapsed!=null&&setupCheckProgress!=null)setupCheckElapsed.setText(setupCheckElapsedCopy());
        if(moduleWaitLabel!=null&&busy)moduleWaitLabel.setText(moduleWaitCopy());
        if(reattachedUserCreation&&!newUserShare.loading){reattachedUserCreation=false;busy=false;message="";render();}
        if(newUserShare.pending&&!newUserShare.loading&&!busy)restoreCreatedUserShare();
        if(collectionState!=null&&!collectionState.recoveryReady&&!collectionState.recoveryAttempted&&!busy&&!DeploymentService.active())collectionState.recover(getApplicationContext());
        InstallationProgress p=currentProgress();if(elapsedLabel!=null&&p!=null)elapsedLabel.setText(RookText.remaining(RookstrideActivity.this,p)+" · "+RookText.elapsed(RookstrideActivity.this,p,System.currentTimeMillis()));
        StringBuilder signature=new StringBuilder();for(String protocol:new String[]{"awg","xray","openvpn","routes"}){
            NativeVpn.Status state=NativeVpn.status(RookstrideActivity.this,protocol);signature.append(state.id).append(state.state).append(state.error);
            if(state.state.equals("connected"))for(Gateway node:gateways)if(node.get("id").equals(state.id))rememberConnection(state.id);
        }
        if(!signature.toString().equals(nativeSignature)){nativeSignature=signature.toString();if(connectionScreen())refreshConnectionViews();}
        handler.postDelayed(this,1000);
    }};
    private ProgressBar deploymentBar;
    private Exception handledDeploymentError;
    private final DeploymentService.Listener deploymentListener=this::deploymentChanged;
    private WebView storyView,guideView;
    private static final int PICK_KEY=84, PICK_PROFILE=85, SAVE_PROFILE=86, PICK_ADMIN_INVITATION=89, PICK_RECOVERY=90, SAVE_RECOVERY=91, SAVE_ADMIN_INVITATION=92, PICK_COLLECTION=93, SAVE_COLLECTION=94;
    private byte[] encryptedRecoveryExport;
    private String recoveryServerId="",recoveryPurpose="";
    private ProfileExportState profileExport;
    private ConnectionCollectionState collectionState;
    private final Set<String> nativeMetadataChecked=new HashSet<>();
    private AlertDialog collectionDialog;
    private boolean collectionBusy;
    private NewUserShareState newUserShare;
    private AlertDialog userShareDialog;
    private boolean reattachedUserCreation;
    private PairSetupState pairDraft;
    private AlertDialog pairWizard;
    private String pendingNativeId="",nativeSignature="",guideDocument="app-guide.html",requestedDocument="";
    private static final int PREPARE_NATIVE_VPN=87, NATIVE_BATTERY=88;
    private final ServiceConnection binding=new ServiceConnection() {
        public void onServiceConnected(ComponentName n,IBinder b) { vpn=((VpnStateService.LocalBinder)b).getService(); vpn.registerListener(RookstrideActivity.this); stateChanged(); }
        public void onServiceDisconnected(ComponentName n) { vpn=null; stateChanged(); }
    };

    @Override protected void attachBaseContext(Context context){super.attachBaseContext(RookText.localized(context));}
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // API26 supports dark navigation icons, but its framework ignores the API27 theme attribute.
        androidx.core.view.WindowCompat.getInsetsController(getWindow(),getWindow().getDecorView()).setAppearanceLightNavigationBars(true);
        if(!androidx.appcompat.app.AppCompatDelegate.getApplicationLocales().toLanguageTags().equals("en"))androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.forLanguageTags("en"));
        profileExport=new androidx.lifecycle.ViewModelProvider(this).get(ProfileExportState.class);
        collectionState=new androidx.lifecycle.ViewModelProvider(this).get(ConnectionCollectionState.class);
        collectionState.recover(getApplicationContext());
        newUserShare=new androidx.lifecycle.ViewModelProvider(this).get(NewUserShareState.class);
        reattachedUserCreation=newUserShare.loading;collectionBusy=collectionState.working;busy=reattachedUserCreation||collectionBusy;
        pairDraft=new androidx.lifecycle.ViewModelProvider(this).get(PairSetupState.class);
        try { vault=new Vault(this);gateways=vault.read(); } catch(Exception e) { vaultFailed=true; message="Saved gateway data could not be unlocked. It has been preserved."; }
        DeploymentService.Session running=DeploymentService.current();
        if(running!=null)gateways=running.gateways;
        if(state!=null){maintenanceSection=state.getString("maintenanceSection","");ArrayList<String> expandedFaq=state.getStringArrayList("faqOpen");if(expandedFaq!=null)faqOpen.addAll(expandedFaq);ArrayList<String> expanded=state.getStringArrayList("expandedServers");if(expanded!=null)expandedServers.addAll(expanded);Bundle positions=state.getBundle("scrollPositions");if(positions!=null)for(String key:positions.keySet())scrollPositions.put(key,positions.getInt(key));recoveryServerId=state.getString("recoveryServerId","");recoveryPurpose=state.getString("recoveryPurpose","");pendingNativeId=state.getString("pendingNativeId","");navigation.restore(state.getStringArrayList("navigation"));setupProtocol=state.getString("setupProtocol","ikev2");pendingServerId=state.getString("pendingServerId","");importProtocol=state.getString("importProtocol","ikev2");guideDocument=state.getString("guideDocument","app-guide.html");}tab=navigation.current();
        if(state!=null&&state.getBoolean("setupServerCheck")){navigation.go("Setup");tab="Setup";message="Server check interrupted. Your saved servers are available to check again.";}
        if(getIntent().getBooleanExtra("rookstride.progress",false)){navigation.go("Progress");tab="Progress";}
        String remembered=getSharedPreferences("rookstride-ui",0).getString("selected","");
        for(Gateway n:gateways) if(n.get("id").equals(remembered)) selected=n;
        if(selected==null && !gateways.isEmpty()) selected=gateways.get(0);
        if(!gateways.isEmpty())getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",true).apply();
        bindService(new Intent(this,VpnStateService.class),binding,BIND_AUTO_CREATE);
        render();
        collectionState.changes.observe(this,ignored->collectionChanged());collectionState.recover(getApplicationContext());
        if(pairDraft.open)handler.post(this::showPairStep);
        if(newUserShare.pending)handler.post(this::restoreCreatedUserShare);
        getOnBackPressedDispatcher().addCallback(this,new androidx.activity.OnBackPressedCallback(true){public void handleOnBackPressed(){back();}});
    }
    @Override protected void onStart(){super.onStart();DeploymentService.observe(deploymentListener);deploymentChanged();}
    @Override protected void onPause(){pointerDown=false;touchReleasePending=false;touchGeneration++;resumed=false;statisticsEpoch++;handler.removeCallbacks(statisticsTick);super.onPause();}
    @Override protected void onStop(){DeploymentService.unobserve(deploymentListener);handler.removeCallbacks(progressTick);if(storyView!=null)OfflineStories.save(this,storyView.getUrl());super.onStop();}
    @Override protected void onSaveInstanceState(Bundle state){state.putString("maintenanceSection",maintenanceSection);if(storyView!=null)OfflineStories.save(this,storyView.getUrl());state.putStringArrayList("faqOpen",new ArrayList<>(faqOpen));state.putStringArrayList("expandedServers",new ArrayList<>(expandedServers));state.putString("guideDocument",guideView!=null&&guideView.getUrl()!=null?documentName(guideView.getUrl()):guideDocument);state.putString("recoveryServerId",recoveryServerId);state.putString("recoveryPurpose",recoveryPurpose);state.putString("pendingNativeId",pendingNativeId);state.putStringArrayList("navigation",navigation.saved());state.putString("setupProtocol",setupProtocol);state.putString("pendingServerId",pendingServerId);state.putString("importProtocol",importProtocol);if(pageScroll!=null&&!scrollRestorePending)scrollPositions.put(renderedScrollKey,pageScroll.getScrollY());Bundle positions=new Bundle();for(Map.Entry<String,Integer> item:scrollPositions.entrySet())positions.putInt(item.getKey(),item.getValue());state.putBundle("scrollPositions",positions);state.putBoolean("setupServerCheck",setupCheckProgress!=null);super.onSaveInstanceState(state);}
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);if(intent.getBooleanExtra("rookstride.progress",false)){openScreen("Progress");}}
    @Override protected void onResume() {
        super.onResume();resumed=true;handler.removeCallbacks(statisticsTick);handler.post(statisticsTick);syncNativeProfiles();handler.removeCallbacks(progressTick);handler.post(progressTick);
        restoreCollectionUi();
        flushTouchUpdates();
        if(selected!=null && !selected.get("setupAbandoned").equals("true") && !selected.get("job").isEmpty() && !busy && !DeploymentService.active() && hasAuth(selected)) pollJob(selected);
    }
    @Override protected void onDestroy() {
        if(encryptedRecoveryExport!=null)Arrays.fill(encryptedRecoveryExport,(byte)0);
        if(leavePrompt!=null)leavePrompt.dismiss();
        if(userShareDialog!=null)userShareDialog.dismiss();if(newUserDialog!=null)newUserDialog.dismiss();
        if(collectionDialog!=null)collectionDialog.dismiss();
        if(pairWizard!=null)pairWizard.dismiss();
        if(guideView!=null){if(guideView.getUrl()!=null)guideDocument=documentName(guideView.getUrl());ViewParent parent=guideView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(guideView);guideView.destroy();guideView=null;}
        if(vpn!=null) vpn.unregisterListener(this);
        DeploymentService.unobserve(deploymentListener);if(storyView!=null){OfflineStories.save(this,storyView.getUrl());ViewParent parent=storyView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(storyView);storyView.destroy();}unbindService(binding); handler.removeCallbacksAndMessages(null); if(newUserShare.loading)executor.shutdown();else executor.shutdownNow(); super.onDestroy();
    }
    public void stateChanged() { if(vpn!=null&&vpn.getProfile()!=null&&vpn.getState()==VpnStateService.State.CONNECTED)for(Gateway node:gateways)if(vpn.getProfile().getUUID().toString().equals(node.get("profileUuid")))rememberConnection(node.get("id"));if(connectionScreen())refreshConnectionViews(); }
    private void back(){
        if(tab.equals("Stories")&&storyView!=null){
            if(storyView.canGoBack()){storyView.goBack();return;}
            String storyUrl=OfflineStories.location(storyView.getUrl());
            // A restored chapter has no browser history. Replace its entry so
            // Back goes chapter -> library -> the previous app destination.
            if(storyUrl.contains("#read/")){
                storyView.evaluateJavascript("window.location.replace("+JSONObject.quote(storyUrl.replace("#read/","#library/"))+")",null);return;
            }
        }
        if(tab.equals("Guide")&&guideView!=null&&guideView.canGoBack()){guideView.goBack();return;}
        if(navigation.back()){tab=navigation.current();message="";render();return;}
        if(!tab.equals("Home")){navigation.root("Home");tab="Home";render();return;}
        if(leavePrompt!=null&&leavePrompt.isShowing())return;
        leavePrompt=RookDialogs.builder(this).setTitle("Leave Rookstride?").setNegativeButton("Stay",null)
                .setPositiveButton("Leave app",(d,w)->moveTaskToBack(true)).create();
        if(DeploymentService.active())leavePrompt.setMessage("Installation continues in the background.");
        leavePrompt.setOnDismissListener(d->leavePrompt=null);leavePrompt.show();
    }
    private String t(String source){return RookText.t(this,source).replace("gateways","VPNs").replace("Gateways","VPNs").replace("gateway","VPN").replace("Gateway","VPN");}
    private String ltr(String value){return androidx.core.text.BidiFormatter.getInstance(RookText.tag(this).equals("fa")||RookText.tag(this).equals("ar")).unicodeWrap(value,androidx.core.text.TextDirectionHeuristicsCompat.LTR,true);}
    private String tr(String key){return RookText.get(this,key);}
    private int dp(float n) { return (int)(getResources().getDisplayMetrics().density*n+.5f); }
    private GradientDrawable shape(int color,int radius) { GradientDrawable d=new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(radius)); return d; }
    private android.graphics.drawable.Drawable touchFeedback(int radius){
        return new android.graphics.drawable.RippleDrawable(android.content.res.ColorStateList.valueOf(Color.argb(36,207,36,47)),null,shape(Color.WHITE,radius));
    }
    private TextView text(String value,int size,int color,boolean bold) {
        TextView v=new TextView(this); v.setText(value); v.setTextSize(size); v.setTextColor(color);
        v.setTypeface(Typeface.create(bold?"sans-serif-medium":"sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));
        v.setLineSpacing(dp(3),1); v.setTextDirection(value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]+)?")||value.startsWith("SHA256:")?View.TEXT_DIRECTION_LTR:View.TEXT_DIRECTION_FIRST_STRONG); v.setGravity(Gravity.START); return v;
    }
    private void space(LinearLayout into,int height) { View v=new View(this); into.addView(v,new LinearLayout.LayoutParams(1,dp(height))); }
    private LinearLayout stack() { LinearLayout v=new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v=new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); v.setGravity(Gravity.CENTER_VERTICAL); return v; }
    private GradientDrawable surface(int radius){GradientDrawable d=shape(Color.WHITE,radius);d.setStroke(dp(1),LINE);return d;}
    private LinearLayout card() {
        LinearLayout v=stack(); v.setPadding(dp(18),dp(18),dp(18),dp(18)); v.setBackground(surface(16));
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2); p.bottomMargin=dp(14); body.addView(v,p); return v;
    }
    private Button button(String title,boolean primary,Runnable action) {
        String scope=tab+":"+(selected==null?"":selected.get("id"))+":"+title;
        int occurrence=buttonOccurrences.getOrDefault(scope,0);buttonOccurrences.put(scope,occurrence+1);
        return actionButton(scope+":"+occurrence,title,primary,action);
    }
    private Button actionButton(String actionKey,String title,boolean primary,Runnable action){
        Button v=new Button(this); v.setText(title); v.setAllCaps(false); v.setTextSize(15); v.setTypeface(Typeface.create("sans-serif-medium",0));
        buttonIdentities.put(v,actionKey);
        v.setTextColor(primary?Color.WHITE:INK);
        v.setBackgroundTintList(null);v.setStateListAnimator(null);v.setElevation(0);v.setOutlineProvider(null);
        v.setBackground(new android.graphics.drawable.RippleDrawable(android.content.res.ColorStateList.valueOf(primary?Color.argb(75,255,255,255):Color.argb(36,207,36,47)),(primary?shape(RED,12):surface(12)),shape(Color.WHITE,12)));
        v.setPadding(dp(14),dp(5),dp(14),dp(5)); v.setMinHeight(dp(48));
        v.setOnClickListener(x->{ if(!busy && !DeploymentService.active()){pendingAction=title;pendingActionKey=actionKey;action.run();if(!busy){pendingAction="";pendingActionKey="";}} });
        v.setEnabled(!busy && !DeploymentService.active()); if(workingButton(v))loadingButton(v,primary?Color.WHITE:RED);return v;
    }
    private boolean workingButton(Button control){return busy&&!pendingActionKey.isEmpty()&&pendingActionKey.equals(buttonIdentities.get(control));}
    private Button fullButton(LinearLayout target,String title,boolean primary,Runnable action) {return fullButtonFor("",target,title,primary,action);}
    private Button fullButtonFor(String identity,LinearLayout target,String title,boolean primary,Runnable action) {
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.topMargin=dp(primary?10:4);Button control=identity.isEmpty()?button(title,primary,action):actionButton(identity,title,primary,action);if(!primary){control.setGravity(Gravity.START|Gravity.CENTER_VERTICAL);control.setTextSize(14);control.setBackground(touchFeedback(10));control.setTextColor(title.startsWith("Remove")||title.startsWith("Uninstall")||title.startsWith("Wipe")||title.startsWith("Revoke")?RED:INK);android.graphics.drawable.Drawable icon=getDrawable(actionIcon(title)).mutate();icon.setTint(control.getCurrentTextColor());icon.setBounds(0,0,dp(20),dp(20));control.setCompoundDrawables(icon,null,null,null);control.setCompoundDrawablePadding(dp(12));}if(workingButton(control))loadingButton(control,RED);target.addView(control,p);return control;
    }
    private int actionIcon(String label){
        if(label.startsWith("Add"))return R.drawable.rook_add;
        if(label.contains("Refresh")||label.startsWith("Check")||label.startsWith("Inspect")||label.startsWith("Resume"))return R.drawable.rook_refresh;
        if(label.contains("access")||label.contains("sign-in")||label.contains("password"))return R.drawable.rook_key;
        if(label.contains("Remove")||label.startsWith("Uninstall")||label.startsWith("Delete")||label.startsWith("Wipe")||label.startsWith("Revoke"))return R.drawable.rook_delete;
        if(label.contains("blocking"))return R.drawable.rook_shield;
        if(label.contains("log")||label.contains("Log"))return R.drawable.rook_logs;
        if(label.contains("user")||label.contains("account")||label.contains("Administrator")||label.contains("administrator"))return R.drawable.rook_users;
        if(label.contains("About")||label.contains("FAQ")||label.contains("guide")||label.contains("license"))return R.drawable.rook_info;
        if(label.contains("Share")||label.contains("file")||label.contains("Copy"))return R.drawable.rook_forward;
        return R.drawable.rook_settings;
    }
    private void loadingButton(Button button,int color){
        LoadingArc arc=new LoadingArc(color,motionEnabled());arc.setBounds(0,0,dp(18),dp(18));button.setCompoundDrawables(arc,null,null,null);button.setCompoundDrawablePadding(dp(8));button.setContentDescription(button.getText()+", working");arc.start();
    }
    private ImageButton iconControl(int icon,String description,Runnable action){
        ImageButton control=new ImageButton(this);control.setImageResource(icon);control.setColorFilter(RED);control.setContentDescription(description);control.setPadding(dp(12),dp(12),dp(12),dp(12));control.setBackground(touchFeedback(12));control.setEnabled(!busy&&!DeploymentService.active());control.setOnClickListener(v->action.run());return control;
    }
    private void protocolHeading(){
        LinearLayout heading=row();heading.setGravity(Gravity.TOP);LinearLayout words=stack();LinearLayout old=body;body=words;title(clientOnly(selected)||selected.isPair()?selected.get("name"):SingleProtocols.from(selected.get("protocol")).title,clientOnly(selected)?"Imported connection":selected.isPair()?"Double VPN · "+SingleProtocols.from(selected.get("pairEntryProtocol")).title+" → "+SingleProtocols.from(selected.get("pairExitProtocol")).title:ServerProtocols.name(selected)+" · "+selected.get("host"));body=old;heading.addView(words,new LinearLayout.LayoutParams(0,-2,1));
        boolean favorite=selected.data.optBoolean("favorite");ImageButton star=iconControl(favorite?R.drawable.rook_star_filled:R.drawable.rook_star,favorite?"Remove from favorites":"Add to favorites",()->{try{selected.data.put("favorite",!selected.data.optBoolean("favorite"));save();render();}catch(Exception e){error(e);}});star.setTag("favorite-connection");heading.addView(star,new LinearLayout.LayoutParams(dp(48),dp(48)));body.addView(heading);
    }
    private void faqScreen(){
        title("Help & FAQ","Find an answer, one question at a time.");
        faq("How do I connect?","Open VPNs and tap Connect beside an installed protocol. Your recent connection and favorites are at the top. Only one VPN can be active on Android at a time.");
        faq("Where do I add or share a VPN user?","In VPNs, tap the settings cog beside a connection, then choose VPN users. Add a user or tap Share access for an existing user. The shared file or text contains private access to that VPN; send it only to someone you trust.");
        faq("What is the difference between a server and a protocol?","A server is the VPS you rent. A protocol is one way to connect to it. A server can offer several protocols, each with its own VPN users. VPNs is for connecting. Servers → Manage → Maintenance contains administrator access and changes affecting the whole server.");
        faq("The VPN is on, but websites do not open. What next?","Try a website, then reconnect. If web access still fails, try another installed protocol. Open that protocol’s Logs to review the latest attempt. Android’s VPN symbol alone does not confirm internet access.");
        faq("What does Split tunneling do?","The Split tab lets you choose which apps use the VPN: all apps, only selected apps, or all except selected apps. Apps outside it use your normal connection. Android’s Block connections without VPN setting can block those apps.");
        faq("Is an administrator invitation the same as sharing a VPN?","No. Share connection gives a person ordinary VPN access. Invite administrator gives one phone a separate management credential with the role and server or protocol scope you review. It does not share your root password.");
        faq("What can owner recovery restore?","An encrypted owner package records the selected owned Double VPN, its identities, users and policy. The restore review checks its protocol adapters and both machines before changing anything. Keep its separate password. Other VPNs, applications, SSH identities and administrator grants are not restored. Test saved clients afterward; a new entry address requires updated client connections.");
        faq("Do I need to connect before managing users?","No. Management uses the server’s SSH sign-in, separately from the VPN connection. Save server access encrypted on this phone to refresh, add users and manage your VPS without typing the password each time.");
        faq("Can Double VPN servers use different Ubuntu versions?","New Double VPN setups check each server independently. Eligible Ubuntu versions can differ. Older saved setups may use the original installer; create a new Double VPN to use the newer installer.");
        faq("What does Remove VPN setups delete?","It removes the recognized Rookstride VPN services, accounts, keys, filtering and usage data listed in the review. Ubuntu, SSH and unrelated software stay. Wipe server & reinstall Ubuntu is a separate destructive action for supported full virtual machines; other layouts need the provider’s rebuild tools.");
        faq("Will future Ubuntu versions work?","Rookstride checks Ubuntu 22.04 and newer for the services and features it needs, without an upper version limit. Prerequisites passed does not mean fully tested: package, kernel and security changes may require an update. Prefer a tested LTS release. The OS reinstall version selector has a separately reviewed image list.");
        faq("Can I manage a server while another VPN app is connected?","Yes, SSH management is independent of VPN sign-in. With another client active, Rookstride uses the network that client permits. Its app exclusions, lockdown settings or the VPS firewall can still block SSH. Double VPN setup can automatically use the reachable server as an encrypted SSH relay; this never changes which server is entry or exit.");
        faq("What happens if I leave during installation?","Installation continues in the background. Return to its progress screen to see the current checkpoint, elapsed time and remaining estimate. A failed setup can be reviewed and resumed, or abandoned.");
        faq("Where are stories and open-source information?","Journal is where Rook’s future adventures and news will appear. Licensing is in Settings. No Journal content is downloaded yet.");
        settingsLink("Read technical guide",()->openDocument("app-guide.html"));
    }
    private void faq(String question,String answer){
        LinearLayout section=stack();section.setPadding(0,dp(4),0,dp(4));boolean expanded=faqOpen.contains(question);TextView text=text(question+(expanded?"  −":"  +"),16,INK,true);text.setPadding(dp(12),dp(12),dp(12),dp(12));text.setMinHeight(dp(56));text.setBackground(touchFeedback(10));text.setContentDescription(question+(expanded?", expanded":", collapsed"));text.setFocusable(true);section.addView(text);TextView detail=text(answer,15,MUTED,false);detail.setPadding(dp(12),0,dp(12),dp(16));detail.setVisibility(expanded?View.VISIBLE:View.GONE);section.addView(detail);text.setOnClickListener(v->{boolean open=detail.getVisibility()!=View.VISIBLE;if(open)faqOpen.add(question);else faqOpen.remove(question);detail.setVisibility(open?View.VISIBLE:View.GONE);text.setText(question+(open?"  −":"  +"));text.setContentDescription(question+(open?", expanded":", collapsed"));});body.addView(section,new LinearLayout.LayoutParams(-1,-2));View divider=new View(this);divider.setBackgroundColor(LINE);body.addView(divider,new LinearLayout.LayoutParams(-1,dp(1)));
    }
    private void logButton(LinearLayout target){
        Button b=button(getString(R.string.show_log),false,()->{});
        // Reading local diagnostics must remain possible while server controls are locked.
        b.setEnabled(true);b.setOnClickListener(v->startActivity(new Intent(this,LogActivity.class)));
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.topMargin=dp(10);target.addView(b,p);
    }
    private boolean compactUi(){return getResources().getConfiguration().screenWidthDp<360||getResources().getConfiguration().fontScale>1.15f;}
    private void title(String headline,String copy) { body.addView(text(headline,compactUi()?26:28,INK,true));if(!copy.isEmpty()){space(body,5);body.addView(text(copy,14,MUTED,false));}space(body,20); }
    private void serverTitle(Gateway server,boolean pair){
        LinearLayout heading=row();heading.addView(text(pair?physicalName(server):ServerProtocols.name(server),compactUi()?26:28,INK,true),new LinearLayout.LayoutParams(0,-2,1));
        ImageButton rename=new ImageButton(this);rename.setImageResource(R.drawable.rook_edit);rename.setColorFilter(RED);rename.setPadding(dp(13),dp(13),dp(13),dp(13));rename.setBackground(touchFeedback(12));rename.setContentDescription("Rename server");rename.setEnabled(!vaultFailed&&!busy&&!DeploymentService.active());rename.setOnClickListener(v->renameServer(server,pair));heading.addView(rename,new LinearLayout.LayoutParams(dp(48),dp(48)));body.addView(heading);
        space(body,5);body.addView(text(server.get("host"),14,MUTED,false));space(body,20);
    }
    private void renameServer(Gateway server,boolean pair){
        LinearLayout f=form();EditText name=field(f,"Server name",pair?physicalName(server):ServerProtocols.name(server),false);name.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(80)});name.setSelectAllOnFocus(true);
        name.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int start,int count,int after){}public void onTextChanged(CharSequence s,int start,int before,int count){name.setError(null);}public void afterTextChanged(android.text.Editable s){}});
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Rename server").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            IdentityHashMap<Gateway,String> previous=new IdentityHashMap<>();for(Gateway root:gateways){previous.put(root,root.data.has("serverName")?root.get("serverName"):null);if(root.exit!=null)previous.put(root.exit,root.exit.data.has("serverName")?root.exit.get("serverName"):null);}
            try{ServerProtocols.rename(gateways,server,name.getText().toString());vault.write(gateways);}
            catch(Exception e){for(Map.Entry<Gateway,String> old:previous.entrySet())if(old.getValue()==null)old.getKey().data.remove("serverName");else old.getKey().set("serverName",old.getValue());name.setError(e instanceof IllegalArgumentException?e.getMessage():"Could not save the server name. Try again.");return;}
            recordActivity("Server renamed",server);dialog.dismiss();render();
        });
    }
    private JSONObject snapshot() { return selected==null?new JSONObject():selected.data.optJSONObject("snapshot")!=null?selected.data.optJSONObject("snapshot"):new JSONObject(); }
    private boolean hasAuth(Gateway n) { return ServerAccess.reuse(gateways,n); }
    private void save() {
        if(vaultFailed) return;
        try { vault.write(gateways);if(!demo&&!gateways.isEmpty())getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",true).apply(); } catch(Exception e) { message="Could not save gateway settings securely."; }
    }
    private boolean isDemo() { return demo; }
    private void demoNotice() { Toast.makeText(this,t("Demo data — add your own gateway to perform this action."),Toast.LENGTH_LONG).show(); }
    private View messageBody(String message){LinearLayout content=form();content.addView(text(message,15,INK,false));return content;}
    private void error(Exception e) {
        if(isFinishing()||isDestroyed()) return;
        if(ConnectionDiagnosis.supported(e)){
            LinearLayout content=(LinearLayout)messageBody(ConnectionDiagnosis.detail(e)+"\n\n"+ConnectionDiagnosis.nextAction(e)+".");AlertDialog[] dialog={null};space(content,12);
            if(selected!=null&&!clientOnly(selected))fullButton(content,ConnectionDiagnosis.code(e).equals("ssh_sign_in_rejected")?"Server access":"Connection options",false,()->{dialog[0].dismiss();if(selected.isPair())choosePairSshRoute(selected);else editGateway(selected,"",true);});
            fullButton(content,"Support report",false,()->{dialog[0].dismiss();reviewSupportReport(e);});dialog[0]=RookDialogs.builder(this).setTitle(ConnectionDiagnosis.title(e)).setView(content).setPositiveButton("Close",null).create();dialog[0].show();return;
        }
        RookDialogs.builder(this).setTitle(t("Action needs attention")).setView(messageBody(e.getMessage()==null?t("The action could not finish."):RookText.detail(this,e.getMessage())))
            .setPositiveButton(t("Close"),null).setNeutralButton(t("Read guide"),(d,w)->openDocument("app-guide.html")).show();
    }
    private void reviewSupportReport(Exception failure){
        try{String report=ConnectionDiagnosis.supportReport(failure).toString(2);RookDialogs.builder(this).setTitle("Review support report").setView(messageBody("This report includes only the error category and recovery guidance. It omits server addresses, credentials, keys and browsing history.\n\n"+report)).setNegativeButton("Cancel",null).setPositiveButton("Share report",(d,w)->{Intent share=new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,report);startActivity(Intent.createChooser(share,"Share support report"));}).show();}catch(Exception e){error(e);}
    }

    private boolean pointerDown,touchReleasePending,touchRenderPending,touchRefreshPending;
    private int touchGeneration;
    @Override public boolean dispatchTouchEvent(MotionEvent event){
        int action=event.getActionMasked();if(action==MotionEvent.ACTION_DOWN){pointerDown=true;touchReleasePending=true;touchGeneration++;}
        boolean release=action==MotionEvent.ACTION_UP||action==MotionEvent.ACTION_CANCEL;
        try{return super.dispatchTouchEvent(event);}finally{if(release){
            pointerDown=false;touchReleasePending=true;final int generation=touchGeneration;
            // View posts its click during ACTION_UP. Keep earlier service callbacks
            // from replacing that view until the queued click has been delivered.
            handler.post(()->{if(generation!=touchGeneration||pointerDown)return;touchReleasePending=false;flushTouchUpdates();});
        }}
    }
    private void flushTouchUpdates(){
        if(pointerDown||touchReleasePending||isFinishing()||isDestroyed())return;
        boolean rebuild=touchRenderPending,refresh=touchRefreshPending;touchRenderPending=false;touchRefreshPending=false;
        if(rebuild)render();else if(refresh)refreshConnectionViews();
    }
    private void render() {
        if(isFinishing()||isDestroyed()) return;
        if(setupCheckProgress!=null&&!busy&&!tab.equals("Progress"))clearSetupCheck();
        if(pointerDown||touchReleasePending){touchRenderPending=true;return;}
        if(tab.equals("Settings")&&selected!=null&&!clientOnly(selected)&&!selected.isPair()){navigation.ancestor("VPN");tab="VPN";}
        if(reordering){renderAfterDrag=true;return;}
        if(!tab.equals("Sessions")||selected==null||!selected.get("id").equals(statisticsRecord)){statisticsEpoch++;statisticsRecord=tab.equals("Sessions")&&selected!=null?selected.get("id"):"";statisticsAttempt=0;statisticsPaused=false;statisticsIssue="";}
        statisticsHost=null;statisticsUpdated=null;
        if(pageScroll!=null&&!scrollRestorePending)scrollPositions.put(renderedScrollKey,pageScroll.getScrollY());
        rendering=true;renderStatuses.clear();buttonOccurrences.clear();
        if(connectionScreen()){
            // The page and polling signature must describe the same snapshot.
            // Otherwise the next tick can replace an already-current button mid-tap.
            StringBuilder signature=new StringBuilder();for(String protocol:new String[]{"awg","xray","openvpn","routes"}){NativeVpn.Status state=NativeVpn.status(this,protocol);renderStatuses.put(protocol,state);signature.append(state.id).append(state.state).append(state.error);}nativeSignature=signature.toString();
        }
        try{
        pageScroll=null;
        if(storyView!=null)OfflineStories.save(this,storyView.getUrl());
        if(guideView!=null){if(guideView.getUrl()!=null)guideDocument=documentName(guideView.getUrl());ViewParent parent=guideView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(guideView);guideView.destroy();guideView=null;}
        if(storyView!=null){ViewParent parent=storyView.getParent();if(parent instanceof ViewGroup)((ViewGroup)parent).removeView(storyView);storyView.destroy();}
        storyView=null;deploymentLabel=null;deploymentBar=null;elapsedLabel=null;connectionControls=null;setupCheckElapsed=null;moduleWaitLabel=null;
        root=stack(); root.setLayoutDirection(View.LAYOUT_DIRECTION_LTR); root.setBackgroundColor(BACK);
        ViewCompat.setOnApplyWindowInsetsListener(root,(v,insets)->{
            androidx.core.graphics.Insets b=insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(b.left,b.top,b.right,b.bottom); return insets;
        });
        InstallationProgress latest=presentedProgress();if(latest!=null&&latest.state.equals("complete"))recordCompletion(latest);
        root.addView(brandHeader());

        // A pending tool already has its own spinner. A second pinned banner
        // can leave less than one whole tool visible on a short display.
        operationNotice=null;
        if((!message.isEmpty()||busy)&&!(busy&&tab.equals("VPN")&&!pendingModule.isEmpty())&&!(setupCheckProgress!=null&&tab.equals("Progress")))operationFeedback();
        progressHost=stack();progressHost.setTag("installation-shortcut");root.addView(progressHost);updateProgressShortcut(presentedProgress());
        if(demo) {
            TextView note=text(t("Sample data. No server is connected."),12,RED,true); note.setPadding(dp(22),0,dp(22),dp(10)); root.addView(note);
        }
        if(tab.equals("Guide")) {
            LinearLayout guideNavigation=stack();guideNavigation.setPadding(dp(12),0,dp(12),0);guideNavigation.addView(contextNavigation());root.addView(guideNavigation);
            WebView guide=new WebView(this);guideView=guide;guide.setTag("offline-document"); guide.setBackgroundColor(Color.WHITE);
            guide.getSettings().setJavaScriptEnabled(false); guide.getSettings().setAllowFileAccess(false); guide.getSettings().setAllowContentAccess(false);
            guide.getSettings().setBlockNetworkLoads(true);guide.getSettings().setDomStorageEnabled(false);
            if(!requestedDocument.isEmpty()){guideDocument=requestedDocument;requestedDocument="";}guide.setWebViewClient(new OfflineDocuments(this));guide.loadUrl(OfflineDocuments.url(guideDocument));
            root.addView(guide,new LinearLayout.LayoutParams(-1,0,1));
        } else {
            ScrollView scroll=new ScrollView(this);pageScroll=scroll;renderedScrollKey=scrollKey();scroll.setSaveEnabled(false);scroll.setFocusableInTouchMode(true);scroll.setDescendantFocusability(ViewGroup.FOCUS_BEFORE_DESCENDANTS);scroll.setFillViewport(true); body=stack(); body.setPadding(dp(20),dp(16),dp(20),dp(24)); scroll.addView(body); root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
            if(!Arrays.asList("Home","Servers","Stories","Routing","AppSettings").contains(tab))body.addView(contextNavigation());
            if(tab.equals("FAQ"))faqScreen();else if(tab.equals("Progress"))progressScreen();else if(tab.equals("Home"))homeScreen();else if(tab.equals("Servers"))serversScreen();else if(tab.equals("Add"))addScreen();else if(tab.equals("Setup"))setupScreen();else if(tab.equals("Protocols"))protocolScreen();else if(tab.equals("Import"))importScreen();else if(tab.equals("Settings"))settingsScreen();else if(tab.equals("PairServer"))pairServerScreen();else if(tab.equals("ServerSettings"))serverSettingsScreen();else if(tab.equals("Administrators"))administratorsScreen();else if(tab.equals("AppSettings"))appSettingsScreen();else if(tab.equals("Stories"))journalScreen();else if(tab.equals("Activity"))activityScreen();else if(tab.equals("Routing"))routingScreen();else if(tab.equals("VPN"))gatewayScreen();else if(tab.equals("People"))peopleScreen();else connectionsScreen();
        }
        if(tab.equals("VPN")&&connectionControls!=null)root.addView(connectionControls);
        InstallationProgress completed=currentProgress();if(tab.equals("Progress")&&completed!=null&&completed.state.equals("complete"))completionActions(completed);
        View divider=new View(this);divider.setBackgroundColor(Color.rgb(222,222,230));root.addView(divider,new LinearLayout.LayoutParams(-1,dp(1)));
        LinearLayout navigation=new AccessibleBottomNavigation();navigation.setBackgroundColor(Color.WHITE);navigation.setTag("bottom-navigation");
        int[] icons={R.drawable.rook_shield,R.drawable.rook_nav_vpns,R.drawable.rook_nav_split,R.drawable.rook_nav_stories,R.drawable.rook_settings};int index=0;
        for(String[] item:new String[][]{{"Home","VPNs"},{"Servers","Servers"},{"Routing","Split"},{"Stories","Journal"},{"AppSettings","Settings"}}) {
            String destination=item[0];boolean active=this.navigation.mainDestination().equals(destination);
            LinearLayout v=stack();v.setGravity(Gravity.CENTER);v.setMinimumHeight(dp(68));v.setPadding(dp(4),0,dp(4),dp(6));v.setContentDescription(destination.equals("AppSettings")?"App settings":item[1]);v.setTag("bottom-destination-"+destination);v.setSelected(active);v.setFocusable(true);v.setClickable(true);
            View indicator=new View(this);indicator.setBackgroundColor(active?RED:Color.TRANSPARENT);v.addView(indicator,new LinearLayout.LayoutParams(dp(28),dp(3)));space(v,6);
            ImageView icon=new ImageView(this);icon.setImageResource(icons[index++]);icon.setColorFilter(active?RED:MUTED);icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);v.addView(icon,new LinearLayout.LayoutParams(dp(22),dp(22)));
            TextView label=text(item[1],12,active?RED:MUTED,active);label.setTag("bottom-label");label.setGravity(Gravity.CENTER);label.setMinLines(1);label.setMaxLines(1);label.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);v.addView(label);
            v.setForeground(touchFeedback(0));v.setOnClickListener(x->{if(tab.equals(destination))return;this.navigation.main(destination);tab=destination;message="";render();});
            navigation.addView(v,new LinearLayout.LayoutParams(0,-2,1));
        }
        root.addView(navigation); setContentView(root); ViewCompat.requestApplyInsets(root);
        if(pageScroll!=null){scrollRestorePending=true;final ScrollView restore=pageScroll;final int y=scrollPositions.getOrDefault(renderedScrollKey,0);restore.requestFocus();getWindow().getDecorView().getViewTreeObserver().addOnPreDrawListener(new android.view.ViewTreeObserver.OnPreDrawListener(){public boolean onPreDraw(){getWindow().getDecorView().getViewTreeObserver().removeOnPreDrawListener(this);if(pageScroll!=restore)return true;restore.scrollTo(0,y);scrollRestorePending=false;return false;}});}
        }finally{rendering=false;}
    }

    /** Keep all five destinations usable when the system enlarges text beyond
     * the width of one equal navigation slot. No app-wide text scaling override. */
    private final class AccessibleBottomNavigation extends LinearLayout {
        AccessibleBottomNavigation(){super(RookstrideActivity.this);setOrientation(HORIZONTAL);setGravity(Gravity.CENTER_VERTICAL);}
        @Override protected void onMeasure(int widthSpec,int heightSpec){
            int available=MeasureSpec.getSize(widthSpec)-getPaddingLeft()-getPaddingRight();boolean labelsFit=available>0;
            for(int i=0;i<getChildCount();i++){
                View item=getChildAt(i);TextView label=item.findViewWithTag("bottom-label");
                if(label!=null&&label.getPaint().measureText(label.getText().toString())>available/(float)Math.max(1,getChildCount())-item.getPaddingLeft()-item.getPaddingRight())labelsFit=false;
            }
            for(int i=0;i<getChildCount();i++){
                View item=getChildAt(i);TextView label=item.findViewWithTag("bottom-label");if(label!=null)label.setVisibility(labelsFit?View.VISIBLE:View.GONE);
                // Visible words already identify the destination. Keep the native
                // tooltip gesture only for the deliberately icon-only fallback.
                CharSequence tooltip=labelsFit?null:item.getContentDescription();if(!android.text.TextUtils.equals(item.getTooltipText(),tooltip))ViewCompat.setTooltipText(item,tooltip);item.setLongClickable(!labelsFit);
            }
            super.onMeasure(widthSpec,heightSpec);
        }
    }
    private float widestWord(TextView text,String value){float width=0;for(String word:value.split("\\s+"))width=Math.max(width,text.getPaint().measureText(word));return width;}
    private LinearLayout completionHeader(String heading){
        TextView title=text(heading,22,INK,true);title.setTag("completion-heading");
        TextView context=text(heading,15,MUTED,false);context.setVisibility(View.GONE);context.setTag("completion-heading-context");
        LinearLayout header=new LinearLayout(this){
            @Override protected void onMeasure(int widthSpec,int heightSpec){
                int full=MeasureSpec.getSize(widthSpec)-getPaddingLeft()-getPaddingRight();boolean stacked=widestWord(title,heading)>full-dp(64);
                setOrientation(stacked?VERTICAL:HORIZONTAL);setGravity(stacked?Gravity.START:Gravity.CENTER_VERTICAL);
                boolean shortTitle=widestWord(title,heading)>full;String shown=shortTitle?"Complete":heading;if(!title.getText().toString().equals(shown))title.setText(shown);title.setContentDescription(heading);context.setVisibility(shortTitle?View.VISIBLE:View.GONE);
                View words=getChildAt(1);LinearLayout.LayoutParams p=(LinearLayout.LayoutParams)words.getLayoutParams();int targetWidth=stacked?-1:0,targetLeft=stacked?0:dp(12),targetTop=stacked?dp(8):0;float targetWeight=stacked?0:1;if(p.width!=targetWidth||p.weight!=targetWeight||p.leftMargin!=targetLeft||p.topMargin!=targetTop){p.width=targetWidth;p.weight=targetWeight;p.leftMargin=targetLeft;p.topMargin=targetTop;words.setLayoutParams(p);}
                super.onMeasure(widthSpec,heightSpec);
            }
        };
        header.setOrientation(LinearLayout.HORIZONTAL);header.setGravity(Gravity.CENTER_VERTICAL);ImageView rook=new ImageView(this);rook.setImageResource(R.drawable.rook_celebrate);rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);header.addView(rook,new LinearLayout.LayoutParams(dp(52),dp(56)));
        LinearLayout words=stack();words.addView(title);words.addView(context);header.addView(words,new LinearLayout.LayoutParams(0,-2,1));return header;
    }

    private String scrollKey(){return tab+":"+((tab.equals("Protocols")||tab.equals("PairServer"))?pendingServerId:Arrays.asList("VPN","Settings","ServerSettings","Administrators","People","Sessions").contains(tab)&&selected!=null?selected.get("id"):"");}
    private LinearLayout brandHeader(){
        LinearLayout header=row();header.setTag("brand-header");header.setPadding(dp(16),dp(4),dp(12),dp(4));header.setBackgroundColor(Color.WHITE);
        ImageView mark=new ImageView(this);mark.setTag("brand-mark");mark.setImageResource(R.drawable.rook_mascot);mark.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);header.addView(mark,new LinearLayout.LayoutParams(dp(32),dp(32)));
        TextView brand=text("Rookstride",20,INK,true);brand.setTag("brand-wordmark");brand.setTextDirection(View.TEXT_DIRECTION_LTR);LinearLayout.LayoutParams name=new LinearLayout.LayoutParams(0,-2,1);name.leftMargin=dp(6);header.addView(brand,name);
        ImageButton alerts=new ImageButton(this);alerts.setTag("activity-bell");alerts.setImageResource(R.drawable.rook_activity);boolean unread=getSharedPreferences("rookstride-ui",0).getBoolean("activityUnread",false);alerts.setColorFilter(unread?RED:MUTED);alerts.setContentDescription(unread?"Activity, new updates":"Activity");alerts.setBackground(touchFeedback(12));alerts.setPadding(dp(12),dp(12),dp(12),dp(12));alerts.setOnClickListener(v->{getSharedPreferences("rookstride-ui",0).edit().putBoolean("activityUnread",false).apply();message="";openScreen("Activity");});header.addView(alerts,new LinearLayout.LayoutParams(dp(48),dp(48)));
        return header;
    }
    private String scopeLabel(){
        if(tab.equals("PairServer")&&selected!=null&&selected.isPair())return physicalName(selected.exit.get("id").equals(pendingServerId)?selected.exit:selected);if(tab.equals("Activity"))return "Recent activity";if(tab.equals("Routing"))return "Split tunneling";if(tab.equals("AppSettings"))return "App preferences";if(tab.equals("Guide"))return "Help";
        if(tab.equals("Protocols"))return pendingServer()==null?"Set up a VPN":"Your VPNs";
        if(tab.equals("ServerSettings"))return selected==null?"Your VPNs":ServerProtocols.name(selected);
        if(Arrays.asList("VPN","Settings","People","Sessions").contains(tab)&&selected!=null)return clientOnly(selected)?"Imported connection":selected.isPair()?"Two-server VPN":ServerProtocols.name(selected)+" · "+SingleProtocols.from(selected.get("protocol")).title;
        return tab.equals("Progress")?progressContextLabel():tab.equals("Setup")?"Set up a VPN":tab.equals("Import")?"Import a VPN":"Your VPNs";
    }
    private String progressContextLabel(){
        InstallationProgress progress=currentProgress();if(progress==null)return "Installation";
        if(progress.kind.equals("os")||progress.kind.equals("paired-os")||progress.kind.equals("paired-restore"))return "Ubuntu reinstall";
        if(progress.kind.equals("filter"))return "Ad blocking";
        return maintenanceProgress(progress)?"Server maintenance":"Installation";
    }
    private View contextNavigation(){
        HorizontalScrollView scroll=new HorizontalScrollView(this);scroll.setTag("context-navigation");scroll.setHorizontalScrollBarEnabled(true);scroll.setScrollbarFadingEnabled(false);scroll.setFillViewport(false);
        LinearLayout trail=row();trail.setTag("breadcrumbs");scroll.addView(trail,new HorizontalScrollView.LayoutParams(-2,-2));
        boolean appScope=Arrays.asList("FAQ","Guide","Activity").contains(tab)&&navigation.mainDestination().equals("AppSettings");
        if(appScope)crumb(trail,"Settings",()->{navigation.ancestor("AppSettings");tab="AppSettings";render();});else if(navigation.mainDestination().equals("Servers"))crumb(trail,"Servers",()->{navigation.root("Servers");tab="Servers";render();});else crumb(trail,"VPNs",()->{navigation.root("Home");tab="Home";render();});
        if(tab.equals("Setup")||tab.equals("Import")||tab.equals("Protocols")&&pendingServer()==null){
            crumb(trail,"Add VPN",()->{navigation.ancestor("Add");tab="Add";render();});
            if(tab.equals("Protocols"))crumb(trail,"Set up a VPN",()->{navigation.ancestor("Setup");tab="Setup";render();});
        }
        if(tab.equals("PairServer")&&selected!=null&&selected.isPair())crumb(trail,"Double VPN",()->{navigation.ancestor("VPN");tab="VPN";render();});
        boolean protocol=selected!=null&&Arrays.asList("VPN","People","Sessions","Settings").contains(tab);
        if(selected!=null&&(protocol||tab.equals("ServerSettings"))&&!clientOnly(selected)&&!selected.isPair())crumb(trail,ServerProtocols.name(selected),()->{pendingServerId=selected.get("id");navigation.ancestor("Protocols");tab="Protocols";render();});
        if(protocol&&!tab.equals("VPN"))crumb(trail,SingleProtocols.from(selected.get("protocol")).title,()->{navigation.ancestor("VPN");tab="VPN";render();});
        String name=tab.equals("People")?"VPN users":tab.equals("Sessions")?"Usage":tab.equals("Protocols")?pendingServer()==null?"Choose a protocol":ServerProtocols.name(pendingServer()):tab.equals("VPN")&&selected!=null?SingleProtocols.from(selected.get("protocol")).title:tab.equals("FAQ")?"Help & FAQ":tab.equals("PairServer")&&selected!=null?physicalName(selected.exit!=null&&selected.exit.get("id").equals(pendingServerId)?selected.exit:selected):tab.equals("Add")?"Add VPN":tab.equals("Setup")?"Set up a VPN":tab.equals("Import")?"Import VPN":tab.equals("Administrators")?"Administrators":tab.equals("ServerSettings")?"Maintenance":tab.equals("Progress")?progressContextLabel():tab.equals("Guide")?(guideDocument.equals("licenses.html")?"Licensing":"Guide"):tab.equals("Activity")?"Activity":"Settings";
        crumb(trail,name,null);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.bottomMargin=dp(12);scroll.setLayoutParams(lp);return scroll;
    }
    private void crumb(LinearLayout trail,String label,Runnable action){
        if(trail.getChildCount()>0){TextView divider=text("›",16,MUTED,false);divider.setPadding(dp(2),0,dp(2),0);trail.addView(divider);}
        TextView link=text(label,13,action==null?MUTED:INK,action!=null);link.setGravity(Gravity.CENTER_VERTICAL);link.setPadding(dp(8),0,dp(8),0);link.setMaxLines(1);link.setMaxWidth(dp(156));link.setEllipsize(android.text.TextUtils.TruncateAt.END);link.setMinHeight(dp(48));
        if(action!=null){link.setBackground(touchFeedback(8));link.setFocusable(true);link.setContentDescription("Back to "+label);link.setOnClickListener(v->action.run());}trail.addView(link);
    }
    private void rookWelcome(){title("Your VPNs",gateways.isEmpty()?"Add a server or import a connection to get started.":"");}
    private void journalScreen(){
        title("Journal","Adventures, discoveries and news from Rook.");
        LinearLayout welcome=stack();welcome.setGravity(Gravity.CENTER);welcome.setPadding(dp(12),dp(32),dp(12),dp(24));welcome.setTag("journal-placeholder");
        ImageView rook=new ImageView(this);rook.setImageResource(R.drawable.rook_map);rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);welcome.addView(rook,new LinearLayout.LayoutParams(dp(116),dp(116)));space(welcome,20);
        TextView headline=text("A new chapter is coming.",22,INK,true);headline.setGravity(Gravity.CENTER);welcome.addView(headline);space(welcome,12);
        TextView copy=text("Rook’s adventures and field notes will live here. Check back when the Journal opens.",15,MUTED,false);copy.setGravity(Gravity.CENTER);welcome.addView(copy);space(welcome,18);TextView soon=text("Coming soon",13,RED,true);soon.setGravity(Gravity.CENTER);welcome.addView(soon);body.addView(welcome);
    }
    private void journalStorage(){RookDialogs.builder(this).setTitle("Journal storage").setMessage("No Journal content is saved on this phone yet. When the Journal opens, saved previews will stay available offline.").setPositiveButton("Done",null).show();}
    private boolean shouldRemember(Gateway node){return ServerAccess.shouldRemember(node,rememberServerAccess());}
    private boolean rememberServerAccess(){return getSharedPreferences("rookstride-ui",0).getBoolean("rememberServerAccess",true);}
    private void appSettingsScreen(){
        title("Settings","For this phone and your Rookstride app.");

        LinearLayout access=card();access.addView(text("Server sign-in",20,INK,true));space(access,6);access.addView(text("Server passwords and keys stay encrypted on this phone. Enrolled administrator devices are managed separately under Administrators.",14,MUTED,false));
        android.widget.Switch remember=new android.widget.Switch(this);remember.setText("Save server access on this phone");remember.setChecked(rememberServerAccess());remember.setMinHeight(dp(48));remember.setEnabled(!busy&&!DeploymentService.active());remember.setOnCheckedChangeListener((v,checked)->{if(checked){getSharedPreferences("rookstride-ui",0).edit().putBoolean("rememberServerAccess",true).apply();return;}remember.setChecked(true);confirmForgetAccess(()->{getSharedPreferences("rookstride-ui",0).edit().putBoolean("rememberServerAccess",false).apply();for(Gateway g:gateways){if(g.data.optBoolean("adminAccess"))continue;try{g.data.put("remember",false);g.data.put("saveAccessChosen",true);g.sshPassword="";g.privateKey="";if(g.exit!=null){g.exit.data.put("remember",false);g.exit.data.put("saveAccessChosen",true);g.exit.sshPassword="";g.exit.privateKey="";}}catch(JSONException e){error(e);}}save();render();});});access.addView(remember);
        settingsLink("Android background settings",()->startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+getPackageName()))));
        settingsLink("Help & FAQ",()->openScreen("FAQ"));settingsLink("Journal storage",this::journalStorage);
        settingsLink("Licensing",()->openDocument("licenses.html"));
        space(body,20);body.addView(text("Rookstride "+org.strongswan.android.BuildConfig.VERSION_NAME,13,MUTED,false));
    }
    private Button browseButton(String title,Runnable action){
        Button b=button(title,false,action);b.setEnabled(true);b.setOnClickListener(v->action.run());return b;
    }
    private void settingsLink(String label,Runnable action){Button link=fullButton(body,label,false,action);link.setEnabled(true);link.setOnClickListener(v->action.run());}
    private long feedbackTimeout(){
        android.view.accessibility.AccessibilityManager access=(android.view.accessibility.AccessibilityManager)getSystemService(ACCESSIBILITY_SERVICE);
        if(Build.VERSION.SDK_INT>=29)return access.getRecommendedTimeoutMillis(4000,android.view.accessibility.AccessibilityManager.FLAG_CONTENT_TEXT);
        return access.isTouchExplorationEnabled()?10000:4000;
    }
    private void operationFeedback(){
        handler.removeCallbacks(noticeExpiry);
        boolean attention=vaultFailed||message.startsWith("Could not save");
        LinearLayout notice=row();operationNotice=notice;notice.setTag("server-operation");notice.setPadding(dp(14),dp(busy?12:7),dp(14),dp(busy?12:7));notice.setBackground(shape(attention?Color.rgb(255,238,238):Color.rgb(239,242,246),12));
        ImageView guide=new ImageView(this);guide.setImageResource(busy?R.drawable.rook_wait:R.drawable.rook_map);guide.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);notice.addView(guide,new LinearLayout.LayoutParams(dp(busy?40:32),dp(busy?40:32)));
        if(busy){noticeMessage="";noticeDeadline=0;}
        LinearLayout words=stack();words.setPadding(dp(10),0,dp(8),0);words.addView(text(message.isEmpty()?"Working on your server…":message,busy?15:14,INK,busy));if(busy)words.addView(text("Waiting for your server…",12,MUTED,false));notice.addView(words,new LinearLayout.LayoutParams(0,-2,1));
        if(busy){ProgressBar spinner=new ProgressBar(this);spinner.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(RED));spinner.setContentDescription("Server action in progress");notice.addView(spinner,new LinearLayout.LayoutParams(dp(28),dp(28)));}
        else{if(!message.equals(noticeMessage)||noticeDeadline==0){noticeMessage=message;noticeDeadline=SystemClock.elapsedRealtime()+feedbackTimeout();notice.setAlpha(0);notice.setTranslationY(-dp(12));notice.animate().alpha(1).translationY(0).setDuration(160).start();}if(!vaultFailed&&!message.startsWith("Could not save"))handler.postDelayed(noticeExpiry,Math.max(0,noticeDeadline-SystemClock.elapsedRealtime()));}
        notice.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(dp(20),0,dp(20),dp(busy?12:6));root.addView(notice,lp);
    }
    private void dismissOperationNotice(){
        if(busy)return;final View old=operationNotice;message="";noticeMessage="";noticeDeadline=0;operationNotice=null;
        if(old!=null)old.animate().alpha(0).translationY(-dp(12)).setDuration(180).withEndAction(()->old.setVisibility(View.GONE)).start();
    }
    private String completionKey(InstallationProgress p){return p.kind+":"+p.gatewayId+":"+p.started;}
    private void acknowledgeCompletion(InstallationProgress p){getSharedPreferences("rookstride-ui",0).edit().putString("seenCompletion",completionKey(p)).apply();}
    private void updateProgressShortcut(InstallationProgress p){
        if(progressHost==null)return;progressHost.removeAllViews();deploymentLabel=null;deploymentBar=null;
        if(p==null||tab.equals("Progress"))return;
        if(p.state.equals("complete")){
            if(getSharedPreferences("rookstride-ui",0).getString("seenCompletion","").equals(completionKey(p)))return;
            if(p.finished<=0||System.currentTimeMillis()-p.finished>60000){acknowledgeCompletion(p);return;}
            String key=completionKey(p);if(!key.equals(completionNoticeKey)){completionNoticeKey=key;completionNoticeDeadline=SystemClock.elapsedRealtime()+feedbackTimeout();}
            if(SystemClock.elapsedRealtime()>=completionNoticeDeadline){acknowledgeCompletion(p);return;}
            TextView notice=text(maintenanceProgress(p)?"Maintenance complete":p.kind.equals("os")?"Ubuntu reinstalled":p.kind.equals("filter")?"Ad blocking is ready":"Your VPN is installed",14,INK,false);notice.setPadding(dp(14),dp(8),dp(14),dp(8));notice.setBackground(shape(Color.rgb(255,238,238),12));notice.setOnClickListener(v->openScreen("Progress"));notice.setContentDescription("View completed installation");notice.setFocusable(true);notice.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
            LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.setMargins(dp(20),0,dp(20),dp(6));progressHost.addView(notice,lp);
            handler.postDelayed(()->{acknowledgeCompletion(p);if(progressHost!=null&&completionNoticeKey.equals(key))progressHost.removeView(notice);},Math.max(0,completionNoticeDeadline-SystemClock.elapsedRealtime()));return;
        }
        LinearLayout shortcut=stack();shortcut.setPadding(dp(22),dp(10),dp(22),dp(14));deploymentLabel=text(progressSummary(p)+" · View progress",14,RED,true);shortcut.addView(deploymentLabel);
        deploymentBar=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);deploymentBar.setProgressTintList(android.content.res.ColorStateList.valueOf(RED));deploymentBar.setMax(p.steps().length);deploymentBar.setProgress(p.completed);shortcut.addView(deploymentBar,new LinearLayout.LayoutParams(-1,dp(8)));
        shortcut.setFocusable(true);shortcut.setContentDescription("View installation progress");shortcut.setOnClickListener(v->openScreen("Progress"));progressHost.addView(shortcut);
    }
    private String ikeConflictSummary(JSONObject inventory){
        StringBuilder text=new StringBuilder("IKEv2 cannot use this server yet.");JSONArray reasons=inventory.optJSONArray("ikev2_conflicts");
        if(reasons!=null)for(int i=0;i<reasons.length();i++)text.append("\n• ").append(reasons.optString(i));
        text.append("\n\nOther applications are kept. Remove a recognized Rookstride setup from Maintenance, or choose another protocol.");return text.toString();
    }
    private InstallationProgress presentedProgress(){return setupCheckProgress!=null?setupCheckProgress:currentProgress();}
    private InstallationProgress currentProgress(){
        DeploymentService.Session s=DeploymentService.current();if(s!=null)return s.progress;
        try{String raw=getSharedPreferences("rookstride-deployment",0).getString("progress","");if(raw.isEmpty())return null;InstallationProgress p=InstallationProgress.from(new JSONObject(raw));if(p.state.equals("running")){p.state="needs-attention";p.phase="Phone polling ended. Detached VPS jobs may continue; check the recorded installation.";}return p;}catch(Exception e){return null;}
    }
    private String progressSummary(InstallationProgress p){if(p==setupCheckProgress)return busy?"Checking servers":"Server check";if(maintenanceProgress(p))return p.state.equals("complete")?"Checks complete":p.state.equals("running")?"Maintaining · "+p.completed+" / "+p.steps().length:"Maintenance needs attention";return p.state.equals("complete")?(p.kind.equals("filter")?"Ad blocking ready":"Installed"):p.state.equals("running")?(p.kind.equals("filter")?"Adding ad blocking · ":"Installing · ")+p.completed+" / "+p.steps().length:"Setup needs attention";}
    private void deploymentChanged(){
        if(isFinishing()||isDestroyed())return;
        InstallationProgress p=currentProgress();if(p!=null){updateProgressShortcut(p);if(tab.equals("Progress")&&body!=null){if(p.state.equals("complete"))render();else{body.removeAllViews();progressScreen();}}}
        DeploymentService.Session s=DeploymentService.current();
        if(s!=null&&s.error!=null&&handledDeploymentError!=s.error){
            handledDeploymentError=s.error;Exception e=s.error;
            if(e instanceof PairController.TrustNeeded){PairController.TrustNeeded t=(PairController.TrustNeeded)e;trust(t.node,t.issue,()->retryDeployment(s));}
            else if(e instanceof Ssh.HostTrust)trust(s.node,(Ssh.HostTrust)e,()->retryDeployment(s));
            else if(e instanceof PairController.RebootNeeded){PairController.RebootNeeded r=(PairController.RebootNeeded)e;RookDialogs.builder(this).setTitle(t("Node reboot required")).setMessage(r.getMessage()).setNegativeButton(t("Later"),null).setPositiveButton(t("Reboot this node"),(x,w)->withSsh(r.node,"Scheduling the owned reboot",ssh->ssh.pair(json("command","reboot","pair",s.node.get("pairId"))),j->{message="Reboot requested. Wait for SSH, then resume the pair.";render();})).show();}
            else error(e);
        }
    }
    private void retryLocalDeploymentSave(){try{DeploymentService.retryLocalSave(this);render();}catch(Exception failure){error(failure);}}
    private void retryDeployment(DeploymentService.Session session){if(DeploymentService.needsLocalSave()){retryLocalDeploymentSave();return;}if(session.progress.kind.equals("engine-update")){startEngineUpdate(session.node,session.config.optString("action","apply"),session.config.optString("group"),session.config.optJSONObject("review"));return;}if(session.progress.kind.equals("lifecycle-entry")){startEntryMigration(session.node,session.config.optString("action","stage"),session.candidate,session.config.optBoolean("endpoint_transfer"),session.config.optBoolean("new_address"));return;}if(session.progress.kind.equals("helper-update")){startHelperUpdate(session.node,session.config.optString("action","apply"),session.config.optJSONObject("review"));return;}if((session.progress.kind.equals("paired-os")||session.progress.kind.equals("paired-restore"))&&session.recoveryArchive!=null){startPairedRestore(session.node,session.config,session.recoveryArchive,session.resume);return;}if(session.progress.kind.equals("lifecycle-exit"))startLifecycle(session.node,session.config.optString("action","replace"),session.candidate);else startDeployment(session.node,session.progress.kind,session.config,session.resume);}
    private boolean maintenanceProgress(InstallationProgress progress){return progress.kind.startsWith("lifecycle-")||progress.kind.equals("paired-os")||progress.kind.equals("paired-restore")||progress.kind.equals("helper-update")||progress.kind.equals("engine-update");}
    private void startDeployment(Gateway node,String kind,JSONObject config,boolean resume){
        if(busy||DeploymentService.active())return;
        if(!hasAuth(node)){passwordDialog(node,()->startDeployment(node,kind,config,resume));return;}
        if(!kind.equals("os")&&node.isPair()&&!hasAuth(node.exit)){passwordDialog(node.exit,()->startDeployment(node,kind,config,resume));return;}
        if(node.sshRelay!=null&&!hasAuth(node.sshRelay)){passwordDialog(node.sshRelay,()->startDeployment(node,kind,config,resume));return;}
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},85);
        try{DeploymentService.launch(this,node,gateways,kind,config,resume);clearSetupCheck();openScreen("Progress");}catch(Exception e){error(e);}
    }
    private void beginSetupCheck(Gateway node,boolean pair,Runnable retry){
        if(setupCheckProgress==null||setupCheckNode!=node||!setupCheckProgress.state.equals("running")){setupCheckProgress=new InstallationProgress(pair?"pair":otherProtocol(node)?"protocol":"single",node.get("id"),System.currentTimeMillis());}
        setupCheckNode=node;setupCheckPair=pair;setupCheckRetry=retry;setupCheckProgress.state="running";setupCheckProgress.finished=0;setupCheckProgress.phase="Checking server access";
        openScreen("Progress");
    }
    private void clearSetupCheck(){setupCheckNode=null;setupCheckProgress=null;setupCheckRetry=null;setupCheckElapsed=null;}
    private void setupCheckScreen(){
        InstallationProgress p=setupCheckProgress;boolean waiting=busy;
        title(waiting?"Checking your servers":p.state.equals("needs-attention")?"Server check needs attention":"Review your setup",setupCheckPair?"Double VPN":SingleProtocols.from(setupCheckNode.get("protocol")).title+" · Single-server VPN");
        LinearLayout hero=card();hero.setTag("setup-server-check");LinearLayout heading=row();heading.setGravity(Gravity.CENTER_VERTICAL);ImageView rook=new ImageView(this);rook.setImageResource(R.drawable.rook_stage_connect);rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);heading.addView(rook,new LinearLayout.LayoutParams(dp(64),dp(64)));LinearLayout copy=stack();copy.setPadding(dp(12),0,0,0);copy.addView(text(waiting?"Connecting…":p.state.equals("needs-attention")?"The check did not finish":"Server checks finished",17,INK,true));setupCheckElapsed=text(setupCheckElapsedCopy(),13,MUTED,false);copy.addView(setupCheckElapsed);heading.addView(copy,new LinearLayout.LayoutParams(0,-2,1));hero.addView(heading);space(hero,12);
        for(Gateway part:setupCheckPair?Arrays.asList(setupCheckNode,setupCheckNode.exit):Collections.singletonList(setupCheckNode)){hero.addView(text((setupCheckPair?(part==setupCheckNode?"Entry · ":"Exit · "):"")+ServerProtocols.name(part),15,INK,true));hero.addView(text(part.get("host"),13,MUTED,false));space(hero,8);}
        if(waiting){ProgressBar spinner=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);spinner.setIndeterminate(true);spinner.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(RED));hero.addView(spinner,new LinearLayout.LayoutParams(-1,dp(8)));space(hero,8);hero.addView(text("Then we’ll review and install your VPN.",13,MUTED,false));}
        else hero.addView(text(p.phase,14,MUTED,false));
        space(body,16);body.addView(text("Your installation plan",18,INK,true));space(body,8);String[] steps=p.steps();for(int i=0;i<steps.length;i++){LinearLayout step=row();step.setPadding(dp(4),dp(9),dp(4),dp(9));TextView number=text(Integer.toString(i+1),14,i==0?RED:MUTED,true);step.addView(number,new LinearLayout.LayoutParams(dp(30),-2));step.addView(text(steps[i],14,i==0?INK:MUTED,i==0),new LinearLayout.LayoutParams(0,-2,1));body.addView(step);}
        if(!waiting){fullButton(body,"Check servers again",true,()->{Runnable retry=setupCheckRetry;if(retry!=null)retry.run();});fullButton(body,"Back to setup",false,()->{clearSetupCheck();openScreen("Setup");});}
    }
    private String setupCheckElapsedCopy(){InstallationProgress p=setupCheckProgress;long end=p.finished>0?p.finished:System.currentTimeMillis();return "Elapsed "+Math.max(0,(end-p.started)/1000)+"s";}
    private String moduleWaitCopy(){long seconds=Math.max(0,(SystemClock.elapsedRealtime()-moduleWaitStarted)/1000);return (seconds>=15?"Waiting · ":"Loading · ")+seconds+"s";}
    private int installationIllustration(InstallationProgress p){
        switch(p.illustration()){
            case "connect":return R.drawable.rook_stage_connect;case "inspect":return R.drawable.rook_stage_inspect;
            case "prepare":return R.drawable.rook_stage_prepare;case "adblock":return R.drawable.rook_stage_adblock;
            case "configure":return R.drawable.rook_stage_configure;case "start":return R.drawable.rook_stage_start;
            case "verify":return R.drawable.rook_stage_verify;case "send":return R.drawable.rook_stage_send;
            case "monitor":return R.drawable.rook_stage_monitor;case "exit":return R.drawable.rook_stage_exit;
            case "bridge-exit":return R.drawable.rook_stage_bridge_exit;case "bridge-entry":return R.drawable.rook_stage_bridge_entry;
            case "forward":return R.drawable.rook_stage_forward;case "health":return R.drawable.rook_stage_health;
            case "celebrate":return R.drawable.rook_celebrate;default:return R.drawable.rook_wait;
        }
    }
    private void progressScreen(){
        if(setupCheckProgress!=null){setupCheckScreen();return;}
        InstallationProgress p=currentProgress();if(p!=null&&p.state.equals("complete")){completedScreen(p);return;}title(p!=null&&!p.state.equals("running")?"Setup needs attention":p!=null&&p.kind.equals("paired-restore")?"Rebuilding & restoring both servers":p!=null&&p.kind.equals("paired-os")?"Reinstalling both servers":p!=null&&p.kind.equals("helper-update")?"Updating management helpers":p!=null&&p.kind.equals("lifecycle-entry")?"Replacing entry server":p!=null&&p.kind.equals("lifecycle-exit")?"Replacing exit server":p!=null&&p.kind.equals("os")?"Reinstalling Ubuntu":p!=null&&p.kind.equals("filter")?"Adding ad blocking":"Installing VPN","");
        if(p==null||!p.kind.equals("protocol")&&!p.kind.equals("filter")){logButton(body);space(body,12);}
        if(p==null){empty(t("No installation has started yet."));return;}
        LinearLayout hero=card();hero.setTag("installation-progress-card");LinearLayout head=row();ImageView rook=new ImageView(this);rook.setImageResource(installationIllustration(p));rook.setTag("installation-rook-"+p.illustration());rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);head.addView(rook,new LinearLayout.LayoutParams(dp(90),dp(90)));
        LinearLayout copy=stack();copy.addView(text(progressSummary(p),17,INK,true));copy.addView(text(RookText.detail(this,p.phase),13,MUTED,false));head.addView(copy,new LinearLayout.LayoutParams(0,-2,1));hero.addView(head);
        if(p.state.equals("running")&&android.provider.Settings.Global.getFloat(getContentResolver(),android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,1)>0){android.animation.ObjectAnimator motion=android.animation.ObjectAnimator.ofFloat(rook,"rotation",-4f,4f);motion.setDuration(1800);motion.setRepeatCount(android.animation.ValueAnimator.INFINITE);motion.setRepeatMode(android.animation.ValueAnimator.REVERSE);motion.start();rook.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener(){public void onViewAttachedToWindow(View v){}public void onViewDetachedFromWindow(View v){motion.cancel();}});}
        ProgressBar bar=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);bar.setProgressTintList(android.content.res.ColorStateList.valueOf(RED));bar.setMax(p.steps().length);bar.setProgress(p.completed);hero.addView(bar,new LinearLayout.LayoutParams(-1,dp(12)));
        elapsedLabel=text(RookText.remaining(RookstrideActivity.this,p)+" · "+RookText.elapsed(RookstrideActivity.this,p,System.currentTimeMillis()),12,RED,true);hero.addView(elapsedLabel);space(hero,8);hero.addView(text(RookText.estimate(this,p),13,INK,true));
        if(p.state.equals("running")){ProgressBar working=new ProgressBar(this);working.setContentDescription(t("Waiting for the current server stage"));hero.addView(working,new LinearLayout.LayoutParams(dp(24),dp(24)));}
        TextView architecture=text("How this setup works ↗",14,RED,true);architecture.setMinHeight(dp(48));architecture.setGravity(Gravity.CENTER_VERTICAL);architecture.setFocusable(true);architecture.setBackground(touchFeedback(8));architecture.setOnClickListener(v->openDocument("guide-en-full.html"));body.addView(architecture);space(body,10);
        LinearLayout stages=card();String[] names=p.steps();for(int i=0;i<names.length;i++){
            boolean done=i<p.completed,active=i==p.completed&&p.state.equals("running");LinearLayout stage=row();stage.setPadding(0,dp(8),0,dp(8));
            TextView mark=text(done?"✓":Integer.toString(i+1),14,done?Color.WHITE:active?RED:MUTED,true);mark.setGravity(Gravity.CENTER);mark.setBackground(shape(done?RED:Color.rgb(239,242,246),14));stage.addView(mark,new LinearLayout.LayoutParams(dp(28),dp(28)));
            TextView label=text(t(names[i]),14,done||active?RED:MUTED,done||active);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);lp.leftMargin=dp(12);stage.addView(label,lp);
            if(active){ProgressBar spinner=new ProgressBar(this);spinner.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(RED));stage.addView(spinner,new LinearLayout.LayoutParams(dp(20),dp(20)));}
            stages.addView(stage);if(done&&i==p.completed-1&&android.provider.Settings.Global.getFloat(getContentResolver(),android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,1)>0){mark.setScaleX(.8f);mark.setScaleY(.8f);mark.animate().scaleX(1).scaleY(1).setDuration(220).start();}
        }
        if(!p.state.equals("running")&&!p.state.equals("complete")){
            LinearLayout reading=card();
            fullButton(reading,DeploymentService.needsLocalSave()?"Save result on this phone":t("Check and resume"),true,()->{if(DeploymentService.needsLocalSave()){retryLocalDeploymentSave();return;}Gateway n=null;for(Gateway g:gateways)if(g.get("id").equals(p.gatewayId))n=g;if(n==null){error(new IOException("Open the saved gateway and inspect its job first."));return;}selected=n;if(p.kind.equals("engine-update")){reviewEngineUpdateState(n);return;}if(p.kind.equals("lifecycle-entry")){startEntryMigration(n,"stage",null,false);return;}if(p.kind.equals("helper-update")){startHelperUpdate(n,"apply",null);return;}if(p.kind.equals("lifecycle-exit")){resumeLifecycle(n);return;}if(p.kind.equals("paired-os")||p.kind.equals("paired-restore")){resumePairedOs(n);return;}try{if(p.kind.equals("protocol")&&StandaloneInstallRetry.has(this,n)){startDeployment(n,"protocol",new JSONObject(),true);return;}}catch(Exception failure){error(failure);return;}if(p.kind.equals("os"))startDeployment(n,"os",n.data.optJSONObject("osReinstall"),true);else if(n.isPair())runPair(n,true);else if(!n.get("job").isEmpty())pollJob(n);else inspect(n);});
            if(!DeploymentService.needsLocalSave())fullButton(reading,"Abandon setup",false,()->RookDialogs.builder(this).setTitle("Abandon this setup?").setMessage("This removes the unfinished setup notice from this phone. It does not undo server changes or stop a job already running on a VPS. You can inspect each server and remove its VPN software from Maintenance.").setNegativeButton("Cancel",null).setPositiveButton("Abandon",(d,w)->{try{if(!DeploymentService.abandon(this,p)){error(new IOException("The setup changed or is still running. Check its progress first."));return;}Gateway abandoned=null;for(Gateway node:gateways)if(node.get("id").equals(p.gatewayId)){node.set("setupAbandoned","true");abandoned=node;}recordActivity("Setup abandoned",abandoned);save();navigation.root("Home");tab="Home";render();}catch(Exception failure){error(failure);}}).show());
        }
    }

    private void completedScreen(InstallationProgress p){
        recordCompletion(p);Gateway target=null;for(Gateway node:gateways)if(node.get("id").equals(p.gatewayId))target=node;
        String heading=maintenanceProgress(p)?"Maintenance complete":p.kind.equals("os")?"Ubuntu reinstalled":p.kind.equals("filter")?"Ad blocking ready":"VPN installed";
        LinearLayout success=card();success.setTag("installation-complete");success.addView(completionHeader(heading));space(success,16);
        if(target!=null){success.addView(text(clientOnly(target)?target.get("name"):ServerProtocols.name(target),15,INK,true));String address=quickAddress(target);if(!address.isEmpty()){space(success,4);success.addView(text(address,13,MUTED,false));}space(success,16);}
        String next=maintenanceProgress(p)?p.phase:p.kind.equals("os")?"Choose a protocol to set up your VPN.":"Your connection is ready to open.";
        success.addView(text(next,15,INK,false));space(success,16);success.addView(text(RookText.elapsed(this,p,System.currentTimeMillis()),13,MUTED,false));success.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
    }
    private void completionActions(InstallationProgress p){
        LinearLayout actions=row();actions.setTag("completion-actions");actions.setPadding(dp(20),dp(10),dp(20),dp(10));actions.setBackgroundColor(Color.WHITE);Gateway target=null;for(Gateway node:gateways)if(node.get("id").equals(p.gatewayId))target=node;final Gateway installed=target;
        if(installed!=null){Button open=browseButton(maintenanceProgress(p)?"Server tools":p.kind.equals("os")?"Set up VPN":"Open VPN",()->{acknowledgeCompletion(p);if(maintenanceProgress(p))openMaintenance(installed);else if(p.kind.equals("os"))serverProtocols(installed);else openVpn(installed);});actions.addView(open,new LinearLayout.LayoutParams(0,-2,1));}
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);if(installed!=null)lp.leftMargin=dp(12);Button done=browseButton("Done",()->{acknowledgeCompletion(p);navigation.root("Home");tab="Home";render();});done.setTextColor(Color.WHITE);done.setBackground(shape(RED,12));actions.addView(done,lp);root.addView(actions);
    }
    private void gatewayPicker() {
        if(gateways.size()<2 && !demo) return;
        HorizontalScrollView h=new HorizontalScrollView(this); h.setHorizontalScrollBarEnabled(false); LinearLayout choices=row();
        for(Gateway n:gateways) {
            Button b=button(n.get("name"),n==selected,()->{selected=n;demo=false;getSharedPreferences("rookstride-ui",0).edit().putString("selected",n.get("id")).apply();render();});
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-2,-2);p.rightMargin=dp(8);choices.addView(b,p);
        }
        h.addView(choices);body.addView(h);space(body,18);
    }
    private void openScreen(String route){navigation.go(route);tab=route;message="";render();}
    private boolean otherProtocol(Gateway node){return node!=null&&SingleProtocols.from(node.get("protocol"))!=SingleProtocols.IKEV2;}
    private boolean clientOnly(Gateway node){return node!=null&&node.data.optBoolean("clientOnly");}
    private void openVpn(Gateway node){selected=node;if(!node.isPair()&&!clientOnly(node)&&(pendingServer()==null||!ServerProtocols.sameServer(pendingServer(),node)))pendingServerId=node.get("id");demo=false;getSharedPreferences("rookstride-ui",0).edit().putString("selected",node.get("id")).apply();openScreen("VPN");}
    private void actionCard(String heading,String copy,Runnable action){
        LinearLayout c=card();c.addView(text(heading,20,INK,true));if(!copy.isEmpty()){space(c,6);c.addView(text(copy,14,MUTED,false));}
        c.setMinimumHeight(dp(84));c.setFocusable(true);c.setClickable(true);c.setContentDescription(heading+". "+copy);c.setOnClickListener(v->{if(!busy&&!DeploymentService.active())action.run();});
        c.setForeground(touchFeedback(16));c.setAccessibilityDelegate(new View.AccessibilityDelegate(){@Override public void onInitializeAccessibilityNodeInfo(View host,android.view.accessibility.AccessibilityNodeInfo info){super.onInitializeAccessibilityNodeInfo(host,info);info.setClassName(Button.class.getName());}});
    }
    private String protocolSummary(SingleProtocols protocol){
        if(protocol==SingleProtocols.XHTTP)return "A different web-style transport for VLESS";
        if(protocol==SingleProtocols.HYSTERIA2)return "A fast QUIC connection with traffic disguising";
        if(protocol==SingleProtocols.OUTLINE)return "Shadowsocks carried inside a secure WebSocket";
        if(protocol==SingleProtocols.SHADOWSOCKS)return "Shadowsocks with a compatible WebSocket transport";
        if(protocol==SingleProtocols.TRUSTTUNNEL)return "A tunnel carried over secure HTTP/2";
        if(protocol==SingleProtocols.NAIVE)return "A web-style tunnel using Chromium networking";
        switch(protocol){case AWG:return "Lightweight UDP VPN with traffic obfuscation";case XRAY:return "VLESS with REALITY over TCP";case OPENVPN:return "Certificate-based VPN over TCP";default:return "IPsec VPN with a login and password";}
    }
    private String protocolUse(SingleProtocols protocol){
        if(protocol==SingleProtocols.XHTTP)return "Try this if the original VLESS TCP connection is filtered. It uses a different transport; success still depends on your network.";
        if(protocol==SingleProtocols.HYSTERIA2)return "Worth trying on a fast or unstable connection when UDP is available. Choose an HTTP/2 option if UDP is blocked.";
        if(protocol==SingleProtocols.OUTLINE||protocol==SingleProtocols.SHADOWSOCKS)return "An alternative to direct VPN traffic when secure WebSockets are allowed. Rookstride handles the connection and DNS for you.";
        if(protocol==SingleProtocols.TRUSTTUNNEL||protocol==SingleProtocols.NAIVE)return "Try a secure web transport when UDP VPNs cannot connect. Your network must allow the server's HTTPS connection.";
        if(protocol==SingleProtocols.AWG)return "Suggested for a simple, fast start when UDP is available. If it cannot connect, try an HTTPS option such as TrustTunnel.";
        if(protocol==SingleProtocols.XRAY)return "Useful when your network blocks ordinary VPN connections. It resembles a secure web connection.";
        if(protocol==SingleProtocols.OPENVPN)return "A widely supported option to try when other VPNs cannot connect. It can be slower on unstable networks.";
        return "A fast, familiar option for everyday networks. Try another protocol if your network blocks its connection.";
    }
    private String protocolDetails(SingleProtocols protocol){
        if(protocol==SingleProtocols.XHTTP)return "VLESS XHTTP carries traffic over HTTP requests with REALITY server authentication. The existing VLESS TCP option uses TCP with Vision instead. Their profiles and transports differ. Rookstride selects the settings and connects directly.";
        if(protocol==SingleProtocols.HYSTERIA2)return "Hysteria 2 uses QUIC over UDP and a verified server certificate. Username/password mode needs only your sign-in details; connection-file mode also adds a Salamander obfuscation key. TCP and UDP app traffic use the encrypted connection. It requires UDP access; fake TCP on a rooted phone is not enabled.";
        if(protocol==SingleProtocols.OUTLINE)return "This recipe uses the open-source Outline SDK and Shadowsocks over TLS WebSockets, including its packet transport. Rookstride exports a self-contained .rookvpn profile with the verified server authority. This is a Rookstride deployment, not the Outline Manager service.";
        if(protocol==SingleProtocols.SHADOWSOCKS)return "Shadowsocks over TLS WebSockets with a v2ray-plugin-compatible TCP path. Rookstride also carries UDP using the Outline packet extension. The full .rookvpn profile is intended for Rookstride; a generic SIP003 link does not describe that UDP extension.";
        if(protocol==SingleProtocols.TRUSTTUNNEL)return "The open-source TrustTunnel endpoint carries TCP and UDP over authenticated HTTP/2. Rookstride uses a protected client connection, pinned certificate authority, private DNS and private session statistics.";
        if(protocol==SingleProtocols.NAIVE)return "NaïveProxy uses Chromium's Cronet network stack over HTTP/2, with authenticated encrypted forwarding and UDP over the tunnel. Rookstride verifies the server authority supplied through SSH; it never disables certificate verification.";
        switch(protocol){
            case AWG:return "AmneziaWG 3.1 uses UDP and generated device keys. It changes the appearance of VPN traffic. Rookstride connects directly and exports native AmneziaWG .conf files.\n\nA useful first option when UDP is available. It requires a compatible 3.1 client.";
            case XRAY:return "This setup uses VLESS over TCP with REALITY and generated access keys. Rookstride connects directly and shares a vless:// link.\n\nAn alternative to try when a UDP VPN does not work. Port 443 may be chosen when available; this is not a guarantee that a network will allow it.";
            case OPENVPN:return "This setup uses OpenVPN over TCP with a separate certificate and key for each device. Rookstride connects directly and exports a self-contained .ovpn file.\n\nUseful for compatibility. TCP can be slower on a poor connection.";
            default:return "IKEv2 uses IPsec and a VPN username/password. Rookstride verifies a public or pinned server certificate. Public certificates allow address, username and password sign-in. Private certificates use the shared .sswan file. Rookstride connects directly in either case.\n\nIt uses UDP 500/4500. Some networks restrict these ports.";
        }
    }
    private void protocolInfo(SingleProtocols protocol){
        LinearLayout f=form();if(protocol==SingleProtocols.AWG||protocol==SingleProtocols.TRUSTTUNNEL){f.addView(text(protocol==SingleProtocols.AWG?"Why suggested: straightforward setup and a lightweight UDP connection. Choose an HTTPS alternative if your network restricts UDP.":"Why an alternative: it uses HTTP/2 over TCP when a UDP connection is unreliable. Performance and reachability depend on your network.",15,INK,false));space(f,16);}f.addView(text(protocolDetails(protocol),15,INK,false));space(f,12);f.addView(text("Availability varies by provider, network and ISP.",13,MUTED,false));
        RookDialogs.builder(this).setTitle(protocol.title).setView(scrolling(f)).setNeutralButton("Official documentation",(d,w)->{try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(protocol.documentation())));}catch(ActivityNotFoundException e){Toast.makeText(this,"No browser available",Toast.LENGTH_SHORT).show();}}).setPositiveButton("Close",null).show();
    }
    private void protocolCard(SingleProtocols protocol,String copy,Runnable choose,String action,Runnable run,Gateway connection,boolean installed){
        if(action==null){setupProtocolCard(protocol,copy,choose);return;}
        LinearLayout c=card();boolean compact=compactUi();View.OnClickListener select=v->{if(!busy&&!DeploymentService.active())choose.run();};
        TextView name=text(protocol.title,compact?18:20,INK,true);name.setOnClickListener(select);
        TextView about=text("Details",13,RED,true);about.setGravity(Gravity.CENTER_VERTICAL);about.setMinimumHeight(dp(48));about.setMinWidth(dp(64));about.setPadding(0,0,dp(8),0);about.setForeground(touchFeedback(8));about.setContentDescription("Details about "+protocol.title);about.setFocusable(true);about.setOnClickListener(v->protocolInfo(protocol));
        TextView summary=text(copy,13,MUTED,false);summary.setOnClickListener(select);
        Button control=button(action,true,run);control.setContentDescription(action+" "+protocol.title);control.setPadding(dp(10),dp(5),dp(10),dp(5));if(connection!=null)updateConnectionAction(control,connection);
        c.setPadding(dp(14),dp(10),dp(14),dp(12));
        LinearLayout heading=row();heading.addView(name,new LinearLayout.LayoutParams(0,-2,1));if(installed){ImageButton manage=iconControl(R.drawable.rook_settings,"Settings for "+protocol.title,choose);manage.setTag("protocol-management");LinearLayout.LayoutParams mp=new LinearLayout.LayoutParams(dp(48),dp(48));mp.leftMargin=dp(8);heading.addView(manage,mp);}heading.setOnClickListener(select);c.addView(heading);
        LinearLayout actions=row(),labels=stack();summary.setMinLines(2);summary.setMaxLines(2);summary.setGravity(Gravity.CENTER_VERTICAL);labels.addView(summary);labels.addView(about,new LinearLayout.LayoutParams(-2,dp(48)));labels.setOnClickListener(select);actions.addView(labels,new LinearLayout.LayoutParams(0,-2,1));LinearLayout.LayoutParams cp=new LinearLayout.LayoutParams(dp(compact?116:120),-2);cp.leftMargin=dp(10);control.setSingleLine(true);control.setTextSize(13);if(compact&&(action.equals("Connecting…")||action.equals("Disconnecting…")))control.setText(action.startsWith("Disconnect")?"Stopping":"Starting");actions.addView(control,cp);actions.setOnClickListener(select);c.addView(actions);
        c.setMinimumHeight(dp(112));c.setFocusable(true);c.setClickable(true);c.setContentDescription("Choose "+protocol.title);c.setOnClickListener(select);c.setForeground(touchFeedback(16));
    }
    private List<SingleProtocols> setupProtocols(){
        ArrayList<SingleProtocols> result=new ArrayList<>(Arrays.asList(SingleProtocols.AWG,SingleProtocols.TRUSTTUNNEL));for(SingleProtocols protocol:SingleProtocols.values())if(!result.contains(protocol))result.add(protocol);return result;
    }
    private void recommendation(LinearLayout into,SingleProtocols protocol){
        if(protocol!=SingleProtocols.AWG&&protocol!=SingleProtocols.TRUSTTUNNEL)return;
        TextView badge=text(protocol==SingleProtocols.AWG?"Suggested start":"HTTPS alternative",12,INK,true);badge.setPadding(dp(8),dp(4),dp(8),dp(4));badge.setBackground(shape(Color.rgb(239,242,246),6));into.addView(badge,new LinearLayout.LayoutParams(-2,-2));space(into,6);
    }
    private void setupProtocolCard(SingleProtocols protocol,String copy,Runnable choose){
        View.OnClickListener select=v->{if(!busy&&!DeploymentService.active())choose.run();};
        LinearLayout c=card();c.setPadding(dp(16),dp(10),dp(16),dp(12));LinearLayout.LayoutParams spacing=(LinearLayout.LayoutParams)c.getLayoutParams();spacing.bottomMargin=dp(10);c.setLayoutParams(spacing);
        c.setFocusable(true);c.setClickable(true);c.setContentDescription("Choose "+protocol.title);c.setOnClickListener(select);c.setForeground(touchFeedback(16));
        recommendation(c,protocol);LinearLayout heading=row();TextView name=text(protocol.title,18,INK,true);name.setOnClickListener(select);heading.addView(name,new LinearLayout.LayoutParams(0,-2,1));
        TextView details=text("Details",13,RED,true);details.setGravity(Gravity.CENTER);details.setMinWidth(dp(64));details.setMinimumHeight(dp(48));details.setContentDescription("Details about "+protocol.title);details.setFocusable(true);details.setClickable(true);details.setForeground(touchFeedback(8));details.setOnClickListener(v->protocolInfo(protocol));LinearLayout.LayoutParams detailParams=new LinearLayout.LayoutParams(-2,-2);detailParams.leftMargin=dp(8);heading.addView(details,detailParams);heading.setOnClickListener(select);c.addView(heading);
        space(c,2);TextView summary=text(copy,13,MUTED,false);summary.setOnClickListener(select);c.addView(summary);space(c,6);TextView use=text(protocolUse(protocol),14,INK,false);use.setOnClickListener(select);c.addView(use);
    }
    private SwipeRevealLayout swipeCard(LinearLayout c,String label,Runnable action){
        int index=body.indexOfChild(c);android.view.ViewGroup.LayoutParams params=c.getLayoutParams();body.removeView(c);
        SwipeRevealLayout swipe=new SwipeRevealLayout(this,c,label,()->{if(!busy&&!DeploymentService.active())action.run();});body.addView(swipe,index,params);return swipe;
    }
    private NativeVpn.Status nativeStatus(Gateway node){return rendering?renderStatuses.computeIfAbsent(node.get("protocol"),protocol->NativeVpn.status(this,protocol)):NativeVpn.status(this,node.get("protocol"));}
    private String actualConnectionState(Gateway node){
        if(otherProtocol(node)){NativeVpn.Status state=nativeStatus(node);if(state.id.equals(node.get("id"))){if(state.state.equals("connected"))return "Connected";if(state.active(node.get("id")))return state.state.equals("limited")?"VPN on · Check web access":state.state.equals("checking")?"Checking web access…":state.state.equals("stopping")?"Disconnecting…":"Connecting…";if(state.state.equals("failed")||state.state.equals("interrupted"))return "Connection failed";}}
        else if(vpn!=null&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(node.get("profileUuid"))){if(vpn.getState()==VpnStateService.State.CONNECTED)return "Connected";if(vpn.getState()==VpnStateService.State.CONNECTING)return "Connecting…";if(vpn.getState()==VpnStateService.State.DISCONNECTING)return "Disconnecting…";}
        return "Disconnected";
    }
    // Only acknowledge a request while waiting for the engine; never invent Connected.
    private boolean connectionTapPending(Gateway node){
        if(!tapId.equals(node.get("id")))return false;
        if(SystemClock.uptimeMillis()>=tapUntil||!actualConnectionState(node).equals(tapPrevious)){tapId="";return false;}return true;
    }
    private String connectionState(Gateway node){return connectionTapPending(node)?tapAction:actualConnectionState(node);}
    private void beginConnectionTap(Gateway node,boolean disconnect){tapPrevious=actualConnectionState(node);tapId=node.get("id");tapAction=disconnect?"Disconnecting…":"Connecting…";tapUntil=SystemClock.uptimeMillis()+8000;refreshConnectionViews();handler.postDelayed(()->{if(!isFinishing()&&!isDestroyed()&&tapId.equals(node.get("id"))&&connectionScreen())refreshConnectionViews();},8000);}
    private void disconnectPhone(Gateway node){if(connectionTapPending(node))return;beginConnectionTap(node,true);if(otherProtocol(node))NativeVpn.disconnect(this,node.get("protocol"));else if(vpn!=null)vpn.disconnect();}
    private String connectionAction(Gateway node){String state=connectionState(node);return state.equals("Disconnecting…")?"Disconnecting…":connectionTapPending(node)?"Connecting…":connectionActive(node)?state.equals("Connecting…")?"Cancel":"Disconnect":"Connect";}
    private void toggleConnection(Gateway node){if(demo){demoNotice();return;}if(connectionTapPending(node))return;if(connectionActive(node))disconnectPhone(node);else connectPhone(node);}
    private void styleConnectionAction(Button control,Gateway node){
        if(connectionTapPending(node)||connectionState(node).equals("Disconnecting…")){control.setEnabled(false);control.setAlpha(.75f);loadingButton(control,control.getCurrentTextColor());}
        else {android.graphics.drawable.Drawable[] images=control.getCompoundDrawables();if(images[0] instanceof LoadingArc){((LoadingArc)images[0]).stop();control.setCompoundDrawables(null,null,null,null);}if(connectionActive(node)){control.setEnabled(true);control.setOnClickListener(v->toggleConnection(node));}}
        control.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
    }
    private void rememberConnection(String id){android.content.SharedPreferences prefs=getSharedPreferences("rookstride-ui",0);if(!prefs.getString("lastConnectedId","").equals(id))prefs.edit().putString("lastConnectedId",id).apply();}
    private boolean connectionActive(Gateway node){
        if(connectionTapPending(node))return true;
        if(otherProtocol(node))return nativeStatus(node).active(node.get("id"));
        return vpn!=null&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(node.get("profileUuid"))&&vpn.getState()!=VpnStateService.State.DISABLED;
    }
    private boolean savedPhoneConnection(Gateway node){return clientOnly(node)||!node.get("profileUuid").isEmpty()||new NativeProfileStore(this).exists(node.get("id"));}
    private boolean readyPhoneConnection(Gateway node){return savedPhoneConnection(node)||node.data.optBoolean("pairReady")||node.data.optJSONObject("snapshot")!=null&&node.data.optJSONObject("snapshot").has("services");}
    private Set<String> homeInstalled(Gateway server){Set<String> installed=ServerProtocols.installed(gateways,server);for(Gateway node:gateways)if(!node.isPair()&&ServerProtocols.sameServer(node,server)&&savedPhoneConnection(node))installed.add(SingleProtocols.from(node.get("protocol")).id);return installed;}
    private Gateway quickConnection(){
        Gateway active=null;for(Gateway node:gateways){String state=connectionState(node);if(state.equals("Connected"))rememberConnection(node.get("id"));if(connectionActive(node))active=node;}
        if(active!=null)return active;String id=getSharedPreferences("rookstride-ui",0).getString("lastConnectedId","");
        for(Gateway node:gateways)if(node.get("id").equals(id)&&(savedPhoneConnection(node)||node.data.optBoolean("pairReady")||node.data.optJSONObject("snapshot")!=null&&node.data.optJSONObject("snapshot").has("services")))return node;
        return null;
    }
    /** Connection callbacks update the existing Home views, never replace its ScrollView. */
    private boolean connectionScreen(){return Arrays.asList("Home","VPN","Protocols","PairServer").contains(tab);}
    private void refreshConnectionViews(){
        if(isFinishing()||isDestroyed())return;
        if(pointerDown||touchReleasePending){touchRefreshPending=true;return;}
        handler.removeCallbacks(connectionRefresh);
        if(tab.equals("PairServer")){for(Runnable update:homeConnectionUpdates)update.run();return;}
        if(!tab.equals("Home")||homeIntro==null||homeIntro.getParent()!=body){render();return;}
        if(reordering){handler.postDelayed(connectionRefresh,100);return;}
        Gateway quick=quickConnection();String id=quick==null?"":quick.get("id");
        if(quickAdapter==null){if(!QuickConnections.list(gateways,quick,this::readyPhoneConnection).isEmpty())buildHomeIntro(quick);}else quickAdapter.update(QuickConnections.list(gateways,quick,this::readyPhoneConnection));
        for(Runnable update:new ArrayList<>(quickUpdates.values()))update.run();
        for(Runnable update:homeConnectionUpdates)update.run();
    }
    private void buildHomeIntro(Gateway quick){
        homeQuickId=quick==null?"":quick.get("id");quickActiveId=quick!=null&&connectionActive(quick)?quick.get("id"):"";quickConnectionUpdate=null;quickUpdates.clear();quickPager=null;quickAdapter=null;homeIntro.removeAllViews();
        LinearLayout list=body;body=homeIntro;
        try{title("Your VPNs","");List<Gateway> options=QuickConnections.list(gateways,quick,this::readyPhoneConnection);if(!options.isEmpty()){
            quickPager=new androidx.viewpager2.widget.ViewPager2(this);quickPager.setTag("quick-connection");quickAdapter=new QuickAdapter(options);quickPager.setAdapter(quickAdapter);quickPager.setOffscreenPageLimit(1);quickPager.setPageTransformer(new androidx.viewpager2.widget.MarginPageTransformer(dp(12)));homeIntro.addView(quickPager,new LinearLayout.LayoutParams(-1,quickCardHeight()));
            quickPages=text("",12,MUTED,false);quickPages.setGravity(Gravity.CENTER);quickPages.setMinHeight(dp(22));homeIntro.addView(quickPages);quickPager.registerOnPageChangeCallback(new androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback(){@Override public void onPageSelected(int n){quickPages.setText(quickAdapter.nodes.size()>1?"Quick connections · "+(n+1)+" / "+quickAdapter.nodes.size():"Quick connection");}});
            int index=0;for(int n=0;n<options.size();n++)if(quick!=null&&options.get(n).get("id").equals(quick.get("id")))index=n;quickPager.setCurrentItem(index,false);quickPages.setText(options.size()>1?"Quick connections · "+(index+1)+" / "+options.size():"Quick connection");
        }else if(gateways.isEmpty())body.addView(text("Add a server or import a connection to get started.",15,MUTED,false));}finally{body=list;}
    }
    private final class QuickHolder extends androidx.recyclerview.widget.RecyclerView.ViewHolder{final FrameLayout host;QuickHolder(FrameLayout host){super(host);this.host=host;}}
    private final class QuickAdapter extends androidx.recyclerview.widget.RecyclerView.Adapter<QuickHolder>{
        final ArrayList<Gateway> nodes=new ArrayList<>();QuickAdapter(List<Gateway> value){nodes.addAll(value);setHasStableIds(true);}
        public int getItemCount(){return nodes.size();}public long getItemId(int position){return nodes.get(position).get("id").hashCode();}
        public QuickHolder onCreateViewHolder(ViewGroup parent,int type){FrameLayout frame=new FrameLayout(RookstrideActivity.this);frame.setLayoutParams(new ViewGroup.LayoutParams(-1,-1));return new QuickHolder(frame);}
        public void onBindViewHolder(QuickHolder holder,int position){holder.host.removeAllViews();holder.host.setPadding(dp(4),0,dp(4),0);holder.host.addView(quickCard(nodes.get(position),position),new FrameLayout.LayoutParams(-1,-1));}
        void update(List<Gateway> next){if(nodes.size()==next.size()){boolean same=true;for(int i=0;i<nodes.size();i++)same&=nodes.get(i).get("id").equals(next.get(i).get("id"));if(same){Gateway active=quickConnection();String activeId=active!=null&&connectionActive(active)?active.get("id"):"";if(!activeId.isEmpty()&&!activeId.equals(quickActiveId)){for(int i=0;i<nodes.size();i++)if(nodes.get(i).get("id").equals(activeId))quickPager.setCurrentItem(i,false);}quickActiveId=activeId;return;}}
            if(quickPager.getScrollState()!=androidx.viewpager2.widget.ViewPager2.SCROLL_STATE_IDLE)return;String current=nodes.isEmpty()?"":nodes.get(Math.min(quickPager.getCurrentItem(),nodes.size()-1)).get("id");Gateway active=quickConnection();String activeId=active!=null&&connectionActive(active)?active.get("id"):"";boolean newlyActive=!activeId.isEmpty()&&!activeId.equals(quickActiveId);quickActiveId=activeId;if(newlyActive)current=activeId;nodes.clear();nodes.addAll(next);quickUpdates.clear();notifyDataSetChanged();int index=0;for(int i=0;i<nodes.size();i++)if(nodes.get(i).get("id").equals(current))index=i;quickPager.setCurrentItem(index,false);quickPages.setText(nodes.size()>1?"Quick connections · "+(index+1)+" / "+nodes.size():"Quick connection");}
    }
    private void updateConnectionAction(Button control,Gateway node){
        String action=connectionAction(node);String label=action.equals("Connecting…")?"Starting":action.equals("Disconnecting…")?"Stopping":action;if(!label.contentEquals(control.getText()))control.setText(label);
        control.setEnabled(!busy&&!DeploymentService.active());control.setAlpha(control.isEnabled()?1f:.45f);
        styleConnectionAction(control,node);
    }
    private float spPixels(float size){return android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP,size,getResources().getDisplayMetrics());}
    private int quickContentWidth(){return Math.max(dp(80),dp(getResources().getConfiguration().screenWidthDp)-2*(dp(20)+dp(4)+dp(14)));}
    private android.text.TextPaint quickPaint(int size,boolean bold){android.text.TextPaint paint=new android.text.TextPaint();paint.setTypeface(Typeface.create(bold?"sans-serif-medium":"sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));paint.setTextSize(spPixels(size));return paint;}
    private android.text.StaticLayout quickLayout(String value,int size,boolean bold,int width){return android.text.StaticLayout.Builder.obtain(value,0,value.length(),quickPaint(size,bold),Math.max(1,width)).setIncludePad(false).setLineSpacing(dp(3),1).build();}
    private int quickMeasuredTextHeight(String value,int size,boolean bold,int width,int minimum,int maximum){
        TextView measured=text(value,size,MUTED,bold);measured.setIncludeFontPadding(false);if(minimum>0)measured.setMinLines(minimum);if(maximum<Integer.MAX_VALUE){measured.setMaxLines(maximum);measured.setEllipsize(android.text.TextUtils.TruncateAt.END);}measured.measure(View.MeasureSpec.makeMeasureSpec(Math.max(1,width),View.MeasureSpec.EXACTLY),View.MeasureSpec.makeMeasureSpec(0,View.MeasureSpec.UNSPECIFIED));return measured.getMeasuredHeight();
    }
    private int quickTextHeight(int size,boolean bold,int lines){StringBuilder sample=new StringBuilder("Ag");for(int i=1;i<lines;i++)sample.append("\nAg");return quickMeasuredTextHeight(sample.toString(),size,bold,quickContentWidth(),lines,lines);}
    private int quickTitleLines(){int lines=1;for(Gateway node:QuickConnections.list(gateways,quickConnection(),this::readyPhoneConnection))lines=Math.max(lines,quickLayout(SingleProtocols.from(node.get("protocol")).title,18,true,quickContentWidth()).getLineCount());return lines;}
    private String quickAddress(Gateway node){
        String address=node.get("host");if(node.isPair())address+=" → "+node.exit.get("host");return address.isEmpty()?"Imported connection":address;
    }
    private int quickAddressLines(){int lines=1;for(Gateway node:QuickConnections.list(gateways,quickConnection(),this::readyPhoneConnection))lines=Math.max(lines,Math.min(2,quickLayout(quickAddress(node),12,false,quickContentWidth()).getLineCount()));return lines;}
    private android.text.TextPaint quickActionPaint(){android.text.TextPaint paint=new android.text.TextPaint();paint.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));paint.setTextSize(spPixels(14));return paint;}
    private int quickActionWidth(){
        android.text.TextPaint paint=quickActionPaint();int width=dp(108);
        for(String label:new String[]{"Connect","Disconnect","Cancel","Starting","Stopping"})width=Math.max(width,(int)Math.ceil(paint.measureText(label))+dp(28+(label.equals("Starting")||label.equals("Stopping")?26:0)));
        return width;
    }
    private int quickActionHeight(){android.graphics.Paint.FontMetricsInt metrics=quickActionPaint().getFontMetricsInt();return Math.max(dp(48),metrics.bottom-metrics.top+dp(12));}
    private boolean quickStackedActions(){return quickContentWidth()-quickActionWidth()-dp(12)<dp(80);}
    private int quickWordsWidth(){return quickStackedActions()?quickContentWidth():quickContentWidth()-quickActionWidth()-dp(12);}
    private String quickStatusLabel(String state){
        switch(state){case "Connected":case "Disconnected":return state;case "Connecting…":return "Starting";case "Disconnecting…":return "Stopping";case "Checking web access…":return "Checking";case "VPN on · Check web access":return "Check internet";case "Connection failed":return "Failed";default:return "Check access";}
    }
    private int quickStatusLines(){int lines=1;for(String value:new String[]{"Connected","Disconnected","Starting","Stopping","Checking","Check internet","Failed","Check access"})lines=Math.max(lines,quickLayout(value,12,false,quickWordsWidth()).getLineCount());return lines;}
    private int quickBadgeLines(){int lines=1;for(String value:new String[]{"Current connection","Recent · Favorite","Recent connection","Favorite"})lines=Math.max(lines,quickLayout(value,12,true,quickContentWidth()-dp(28)).getLineCount());return lines;}
    private String quickServerLabel(Gateway node){String label=clientOnly(node)?node.get("name"):ServerProtocols.name(node);if(clientOnly(node)&&(label.isEmpty()||label.equalsIgnoreCase(SingleProtocols.from(node.get("protocol")).title)))label=node.get("vpnLogin").isEmpty()?"Shared connection":"VPN user "+node.get("vpnLogin");return label.equals(quickAddress(node))?"":label;}
    private int quickRowHeight(){
        int server=0;for(Gateway node:QuickConnections.list(gateways,quickConnection(),this::readyPhoneConnection)){String value=quickServerLabel(node);if(!value.isEmpty())server=Math.max(server,quickMeasuredTextHeight(value,13,false,quickWordsWidth(),0,2));}
        int words=server+quickTextHeight(12,false,quickStatusLines());return quickStackedActions()?words+dp(10)+quickActionHeight():Math.max(quickActionHeight(),words);
    }
    private int quickCardHeight(){return dp(24+4+10)+Math.max(dp(28),quickTextHeight(12,true,quickBadgeLines()))+quickTextHeight(18,true,quickTitleLines())+quickTextHeight(12,false,quickAddressLines())+quickRowHeight();}
    private View quickCard(Gateway node,int position){
        LinearLayout quick=stack();quick.setTag("quick-card-"+node.get("id"));quick.setBackground(surface(16));quick.setPadding(dp(14),dp(12),dp(14),dp(12));quick.setContentDescription("Open "+SingleProtocols.from(node.get("protocol")).title+" settings");quick.setOnClickListener(v->openVpn(node));quick.setForeground(touchFeedback(16));
        LinearLayout heading=row();TextView badge=text("",12,MUTED,true);badge.setTag("quick-connection-kind");badge.setIncludeFontPadding(false);badge.setMinLines(quickBadgeLines());badge.setMaxLines(quickBadgeLines());heading.addView(badge,new LinearLayout.LayoutParams(0,-2,1));
        ImageView rook=new ImageView(this);rook.setTag("quick-rook");int[] poses={R.drawable.rook_map,R.drawable.rook_stage_prepare,R.drawable.rook_lantern,R.drawable.rook_builder,R.drawable.rook_wait};int pose=poses[position%poses.length];rook.setImageResource(pose);rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);heading.addView(rook,new LinearLayout.LayoutParams(dp(28),dp(28)));quick.addView(heading);
        TextView name=text(SingleProtocols.from(node.get("protocol")).title,18,INK,true);name.setTag("quick-protocol-name");name.setIncludeFontPadding(false);name.setMinLines(quickTitleLines());name.setMaxLines(quickTitleLines());quick.addView(name);space(quick,4);
        TextView address=text(quickAddress(node),12,MUTED,false);address.setTag("quick-server-address");address.setIncludeFontPadding(false);address.setTextDirection(View.TEXT_DIRECTION_LTR);address.setMinLines(quickAddressLines());address.setMaxLines(2);address.setEllipsize(android.text.TextUtils.TruncateAt.END);quick.addView(address);space(quick,10);
        boolean stacked=quickStackedActions();LinearLayout line=stacked?stack():row(),words=stack();line.setTag("quick-action-row");String serverName=quickServerLabel(node);TextView server=text(serverName,13,INK,false);server.setIncludeFontPadding(false);server.setMaxLines(2);server.setEllipsize(android.text.TextUtils.TruncateAt.END);server.setContentDescription(serverName);if(!serverName.isEmpty())words.addView(server);
        TextView status=text("",12,MUTED,false);status.setTag("quick-connection-status");status.setIncludeFontPadding(false);status.setMinLines(quickStatusLines());status.setMaxLines(quickStatusLines());words.addView(status);line.addView(words,stacked?new LinearLayout.LayoutParams(-1,0,1):new LinearLayout.LayoutParams(0,-2,1));
        Button control=button("Connect",true,()->toggleConnection(node));control.setTag("quick-connection-control");control.setTextSize(14);control.setSingleLine(true);control.setPadding(dp(12),dp(6),dp(12),dp(6));LinearLayout.LayoutParams cp=new LinearLayout.LayoutParams(quickActionWidth(),quickActionHeight());if(stacked){cp.gravity=Gravity.END;cp.topMargin=dp(10);}else cp.leftMargin=dp(12);line.addView(control,cp);quick.addView(line,new LinearLayout.LayoutParams(-1,quickRowHeight()));
        Runnable update=()->{String state=connectionState(node),label=quickStatusLabel(state);boolean active=connectionActive(node),recent=getSharedPreferences("rookstride-ui",0).getString("lastConnectedId","").equals(node.get("id"));badge.setText(active?"Current connection":recent?node.data.optBoolean("favorite")?"Recent · Favorite":"Recent connection":"Favorite");badge.setTextColor(active?INK:MUTED);if(!label.contentEquals(status.getText()))status.setText(label);status.setContentDescription(state);rook.setImageResource(state.equals("Connected")?R.drawable.rook_celebrate:active?R.drawable.rook_wait:pose);updateConnectionAction(control,node);control.setContentDescription("Quick "+connectionAction(node)+" "+SingleProtocols.from(node.get("protocol")).title+" on "+ServerProtocols.name(node)+". "+state);};quickUpdates.put(node.get("id"),update);update.run();return quick;
    }
    private static final class ServerDrag {final Gateway node;final View placeholder;ServerDrag(Gateway node,View placeholder){this.node=node;this.placeholder=placeholder;}}
    private boolean motionEnabled(){return android.provider.Settings.Global.getFloat(getContentResolver(),android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,1)>0;}
    private void animateServerLayout(){if(motionEnabled()){android.transition.ChangeBounds change=new android.transition.ChangeBounds();change.setDuration(180);for(View view:serverRows.values())change.addTarget(view);android.transition.TransitionManager.beginDelayedTransition(body,change);}}
    private void orderServerViews(){
        int start=Integer.MAX_VALUE;for(View view:serverRows.values())start=Math.min(start,body.indexOfChild(view));if(start==Integer.MAX_VALUE)return;
        animateServerLayout();for(Gateway server:homeServers()){View view=serverRows.get(server.get("id"));if(view!=null){body.removeView(view);body.addView(view,start++);}}
        bindServerReorder();
    }
    private List<Gateway> homeServers(){
        List<Gateway> nodes=PairNodes.catalog(gateways);String raw=getSharedPreferences("rookstride-ui",0).getString("physicalServerOrder","[]");
        try{JSONArray ids=new JSONArray(raw);Map<String,Integer> positions=new HashMap<>();for(int i=0;i<ids.length();i++)positions.put(ids.getString(i),i);nodes.sort(Comparator.comparingInt(n->positions.getOrDefault(n.get("id"),Integer.MAX_VALUE)));}catch(JSONException ignored){}return nodes;
    }
    private void moveServer(Gateway moved,Gateway target,boolean after){
        List<Gateway> physical=homeServers();if(moved==target||!physical.remove(moved))return;int at=physical.indexOf(target);if(at<0)return;physical.add(at+(after?1:0),moved);
        ServerOrder.move(gateways,moved,target,after);JSONArray ids=new JSONArray();for(Gateway n:physical)ids.put(n.get("id"));getSharedPreferences("rookstride-ui",0).edit().putString("physicalServerOrder",ids.toString()).apply();save();orderServerViews();
    }
    private void scrollServers(View origin,float localY){
        if(pageScroll==null||serverRows.isEmpty())return;int[] at=new int[2],bounds=new int[2];origin.getLocationOnScreen(at);pageScroll.getLocationOnScreen(bounds);float y=at[1]+localY;
        if(y<bounds[1]+dp(48))pageScroll.smoothScrollBy(0,-dp(24));else if(y>bounds[1]+pageScroll.getHeight()-dp(48))pageScroll.smoothScrollBy(0,dp(24));
    }
    private float dragScreenY(View origin,float localY){int[] at=new int[2];origin.getLocationOnScreen(at);return at[1]+localY;}
    private void previewServerDrag(ServerDrag drag,float y){
        int[] at=new int[2];View before=null,last=null;
        ArrayList<View> rows=new ArrayList<>(serverRows.values());rows.sort(Comparator.comparingInt(body::indexOfChild));
        for(View view:rows){if(view==drag.placeholder)continue;last=view;view.getLocationOnScreen(at);if(y<at[1]+view.getHeight()/2f){before=view;break;}}
        if(last==null)return;int old=body.indexOfChild(drag.placeholder),destination=before!=null?body.indexOfChild(before):body.indexOfChild(last)+1;if(old<destination)destination--;if(old==destination)return;
        animateServerLayout();body.removeView(drag.placeholder);body.addView(drag.placeholder,destination);
    }
    private boolean dropServer(ServerDrag drag,float screenY){
        previewServerDrag(drag,screenY);int position=body.indexOfChild(drag.placeholder);Gateway previous=null,next=null;
        for(Gateway server:homeServers()){View view=serverRows.get(server.get("id"));if(view==null||view==drag.placeholder)continue;int index=body.indexOfChild(view);if(index<position&&(previous==null||body.indexOfChild(serverRows.get(previous.get("id")))<index))previous=server;if(index>position&&(next==null||body.indexOfChild(serverRows.get(next.get("id")))>index))next=server;}
        if(previous!=null)moveServer(drag.node,previous,true);else if(next!=null)moveServer(drag.node,next,false);else return false;
        return true;
    }
    private void bindServerReorder(){
        List<Gateway> servers=homeServers();for(int i=0;i<servers.size();i++){Gateway server=servers.get(i);SwipeRevealLayout wrapper=(SwipeRevealLayout)serverRows.get(server.get("id"));if(wrapper==null)continue;final int index=i;View card=wrapper.getChildAt(1);
            wrapper.reorderWith(()->{if(busy||DeploymentService.active())return;card.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS);reordering=true;ServerDrag drag=new ServerDrag(server,wrapper);if(card.startDragAndDrop(null,new View.DragShadowBuilder(card),drag,0)){activeDrag=drag;card.setActivated(true);card.setVisibility(View.INVISIBLE);GradientDrawable gap=shape(Color.rgb(255,238,238),16);gap.setStroke(dp(2),RED,dp(6),dp(5));wrapper.setBackground(gap);wrapper.setTag("server-insertion-space");}else reordering=false;},index>0?()->moveServer(server,servers.get(index-1),false):null,index+1<servers.size()?()->moveServer(server,servers.get(index+1),true):null);
        }
    }
    private void serverDrag(SwipeRevealLayout wrapper,LinearLayout card,Gateway server){
        serverRows.put(server.get("id"),wrapper);wrapper.setOnDragListener((v,event)->handleServerDrag(v,event));
    }
    private boolean handleServerDrag(View view,DragEvent event){
        if(!(event.getLocalState() instanceof ServerDrag))return false;ServerDrag drag=(ServerDrag)event.getLocalState();
        if(event.getAction()==DragEvent.ACTION_DRAG_LOCATION){float y=dragScreenY(view,event.getY());scrollServers(view,event.getY());handler.post(()->{if(activeDrag==drag)previewServerDrag(drag,y);});}
        if(event.getAction()==DragEvent.ACTION_DROP){float y=dragScreenY(view,event.getY());handler.post(()->{if(activeDrag==drag)dropServer(drag,y);});return true;}
        // Drag callbacks may traverse a live child set. Queue every list mutation after dispatch.
        if(event.getAction()==DragEvent.ACTION_DRAG_ENDED)handler.post(this::finishServerDrag);return true;
    }
    private void finishServerDrag(){
        if(activeDrag==null)return;ServerDrag drag=activeDrag;activeDrag=null;View wrapper=drag.placeholder;View card=((ViewGroup)wrapper).getChildAt(1);card.setVisibility(View.VISIBLE);card.setActivated(false);wrapper.setBackground(null);wrapper.setTag(null);reordering=false;orderServerViews();if(renderAfterDrag){renderAfterDrag=false;handler.post(this::render);}
    }
    private List<Gateway> independentConnections(Gateway server){
        ArrayList<Gateway> result=new ArrayList<>();
        for(Gateway node:gateways)if(!node.isPair()&&!clientOnly(node)&&!node.data.optBoolean("adminAccess")&&PairNodes.same(server,node)&&(!node.get("protocol").isEmpty()||!node.get("profileUuid").isEmpty())&&(savedPhoneConnection(node)||ServerProtocols.installed(gateways,node).contains(SingleProtocols.from(node.get("protocol")).id)))result.add(node);
        result.sort(Comparator.comparing(n->SingleProtocols.from(n.get("protocol")).title));return result;
    }
    private void homeScreen(){
        serverRows.clear();homeConnectionUpdates.clear();body.setOnDragListener(this::handleServerDrag);
        homeIntro=stack();body.addView(homeIntro);buildHomeIntro(quickConnection());
        if(!gateways.isEmpty()||getSharedPreferences("rookstride-ui",0).getBoolean("hasSavedVpn",false)){fullButton(body,"Add VPN",false,()->openScreen("Add"));space(body,10);}
        int shown=0;
        for(Gateway server:homeServers()){
            Gateway pair=PairNodes.owner(gateways,server);boolean standalone=clientOnly(server);
            Set<String> installed=homeInstalled(server);
            boolean pairReady=pair!=null&&readyPhoneConnection(pair);
            // The bridge is not a standalone client. Explicit independent phone profiles remain available.
            boolean pairedRoute=pair!=null&&PairNodes.role(pair,server).equals("entry")&&pairReady;
            List<Gateway> independent=pair==null?Collections.emptyList():independentConnections(server);
            if(!standalone&&(server.data.optBoolean("adminAccess")||pair!=null&&!pairedRoute&&independent.isEmpty()||pair==null&&installed.isEmpty()))continue;
            shown++;
            String name=standalone?server.get("name"):pair==null?ServerProtocols.name(server):physicalName(server);
            LinearLayout c=card();c.setPadding(dp(16),dp(12),dp(12),dp(12));LinearLayout r=row();TextView nameView=text(name,18,INK,true);r.addView(nameView,new LinearLayout.LayoutParams(0,-2,1));
            Runnable manage=()->{if(standalone){openVpn(server);return;}navigation.main("Servers");tab="Servers";if(pair!=null)openPairServer(pair,server);else openServer(server);};
            ImageButton settings=iconControl(R.drawable.rook_settings,standalone?"Connection settings for "+name:"Manage "+name,manage);settings.setTag("server-management");settings.setColorFilter(MUTED);r.addView(settings,new LinearLayout.LayoutParams(dp(48),dp(48)));c.addView(r);
            if(pair!=null){space(c,6);TextView badge=text("Double VPN · "+(PairNodes.role(pair,server).equals("entry")?"Entry":"Exit"),13,MUTED,false);badge.setTag("pair-role-"+PairNodes.role(pair,server));c.addView(badge);}
            if(!standalone&&!name.equalsIgnoreCase(server.get("host"))){space(c,4);c.addView(text(server.get("host"),13,MUTED,false));}
            c.setFocusable(true);c.setClickable(true);c.setContentDescription("Open "+name);c.setForeground(touchFeedback(16));
            if(!standalone){
                String preference="connectionsExpanded:"+server.get("id");boolean expanded=getSharedPreferences("rookstride-ui",0).getBoolean(preference,true);
                if(expanded)expandedServers.add(server.get("id"));else expandedServers.remove(server.get("id"));
                TextView disclosure=text("",13,MUTED,false);disclosure.setMinHeight(dp(48));disclosure.setGravity(Gravity.CENTER_VERTICAL);disclosure.setTag("connection-disclosure-"+server.get("id"));disclosure.setFocusable(true);disclosure.setBackground(touchFeedback(8));c.addView(disclosure,new LinearLayout.LayoutParams(-1,dp(48)));
                LinearLayout connections=stack();connections.setTag("server-connections-"+server.get("id"));c.addView(connections);
                if(pair!=null){if(pairedRoute)homeProtocolShortcut(connections,pair,null,SingleProtocols.from(pair.get("pairEntryProtocol")),true);for(Gateway independentVpn:independent)homeProtocolShortcut(connections,independentVpn,independentVpn,SingleProtocols.from(independentVpn.get("protocol")),false);}
                else for(SingleProtocols protocol:ServerProtocols.ordered(installed,true))homeProtocolShortcut(connections,ServerProtocols.find(gateways,server,protocol.id),server,protocol,false);
                Runnable updateDisclosure=()->{boolean open=expandedServers.contains(server.get("id"));connections.setVisibility(open?View.VISIBLE:View.GONE);disclosure.setText((open?"Hide":"Show")+" connections  "+(open?"⌃":"⌄"));disclosure.setContentDescription((open?"Hide":"Show")+" connections for "+name);};
                Runnable toggle=()->{if(expandedServers.contains(server.get("id")))expandedServers.remove(server.get("id"));else expandedServers.add(server.get("id"));getSharedPreferences("rookstride-ui",0).edit().putBoolean(preference,expandedServers.contains(server.get("id"))).apply();updateDisclosure.run();};
                disclosure.setOnClickListener(v->toggle.run());nameView.setOnClickListener(v->toggle.run());c.setOnClickListener(v->toggle.run());updateDisclosure.run();
            }else{
                c.setOnClickListener(v->openVpn(server));c.addView(text("Shared connection"+(server.get("vpnLogin").isEmpty()?"":" · "+server.get("vpnLogin")),12,MUTED,false));String address=quickAddress(server);if(!address.equals(name))c.addView(text(address,13,MUTED,false));space(c,8);
                LinearLayout actions=row();TextView status=text("",13,MUTED,false);actions.addView(status,new LinearLayout.LayoutParams(0,-2,1));Button control=button("Connect",true,()->toggleConnection(server));control.setSingleLine(true);int width=Math.max(dp(108),(int)Math.ceil(control.getPaint().measureText("Disconnect"))+dp(28));actions.addView(control,new LinearLayout.LayoutParams(width,-2));c.addView(actions);Runnable refresh=()->{status.setText(connectionState(server));updateConnectionAction(control,server);};homeConnectionUpdates.add(refresh);refresh.run();
            }
            SwipeRevealLayout wrapper=swipeCard(c,name,()->{if(pair!=null)removeSavedVpn(pair);else if(standalone)removeSavedVpn(server);else removeSavedServer(server);});serverDrag(wrapper,c,server);
        }
        bindServerReorder();
        if(gateways.isEmpty()&&!getSharedPreferences("rookstride-ui",0).getBoolean("hasSavedVpn",false))addOptions();
        else if(shown==0){empty("No VPN connections yet. Set up a VPN or import access shared with you.");if(!gateways.isEmpty())fullButton(body,"Open your servers",false,()->{navigation.main("Servers");tab="Servers";render();});}
    }
    private void serversScreen(){
        homeIntro=null;serverRows.clear();homeConnectionUpdates.clear();body.setOnDragListener(this::handleServerDrag);
        title("Your servers","Install VPNs, manage users and maintain your VPS.");
        fullButton(body,"Add server",true,()->serverDetails("manage"));space(body,14);int shown=0;
        for(Gateway server:homeServers()){
            if(clientOnly(server))continue;shown++;Gateway pair=PairNodes.owner(gateways,server);String name=pair==null?ServerProtocols.name(server):physicalName(server);
            LinearLayout c=card();c.setTag("managed-server-"+server.get("id"));c.setPadding(dp(16),dp(12),dp(12),dp(12));LinearLayout heading=row();heading.addView(text(name,18,INK,true),new LinearLayout.LayoutParams(0,-2,1));
            Runnable manage=()->{if(pair!=null)openPairServer(pair,server);else openServer(server);};ImageButton action=iconControl(R.drawable.rook_settings,"Manage "+name,manage);action.setTag("server-management");action.setColorFilter(MUTED);heading.addView(action,new LinearLayout.LayoutParams(dp(48),dp(48)));c.addView(heading);if(!name.equalsIgnoreCase(server.get("host")))c.addView(text(server.get("host"),13,MUTED,false));space(c,8);
            String summary;if(pair!=null){String role=PairNodes.role(pair,server);summary="Double VPN · "+(role.equals("entry")?"Entry server":"Exit server");}else if(server.data.optBoolean("adminAccess"))summary="Shared administrator access";else{int count=ServerProtocols.installed(gateways,server).size();summary=count==0?"No VPNs installed":count+" installed protocol"+(count==1?"":"s");}
            c.addView(text(summary,13,MUTED,false));c.setContentDescription("Manage server "+name);c.setFocusable(true);c.setClickable(true);c.setForeground(touchFeedback(16));c.setOnClickListener(v->manage.run());SwipeRevealLayout wrapper=swipeCard(c,name,()->{if(pair!=null)removeSavedVpn(pair);else removeSavedServer(server);});serverDrag(wrapper,c,server);
        }
        bindServerReorder();if(shown==0)empty("No managed servers yet. Add a VPS using the administrator sign-in from your provider. Imported VPN connections stay in VPNs.");
    }
    private void homeProtocolShortcut(LinearLayout parent,Gateway connection,Gateway server,SingleProtocols protocol,boolean pair){
        View divider=new View(this);divider.setBackgroundColor(LINE);parent.addView(divider,new LinearLayout.LayoutParams(-1,dp(1)));
        boolean compact=compactUi();LinearLayout line=stack();line.setPadding(0,dp(6),0,dp(6));
        TextView name=text(protocol.title,15,INK,true);
        TextView state=text("",12,MUTED,false);state.setMinLines(2);state.setMaxLines(2);state.setMinHeight(dp(48));state.setGravity(Gravity.CENTER_VERTICAL);
        java.util.function.Supplier<Gateway> current=()->connection!=null?connection:ServerProtocols.find(gateways,server,protocol.id);
        Runnable settings=()->{Gateway node=current.get();if(node!=null)openVpn(node);else{pendingServerId=server.get("id");selectProtocol(protocol);}};
        line.setFocusable(true);line.setClickable(true);line.setForeground(touchFeedback(12));line.setContentDescription(pair?"Open Double VPN settings":"Open "+protocol.title+" settings on "+ServerProtocols.name(server));line.setOnClickListener(v->settings.run());
        LinearLayout heading=row();heading.setMinimumHeight(dp(48));heading.setOnClickListener(v->settings.run());LinearLayout labels=stack();labels.addView(name);if(compact){state.setMinHeight(dp(40));labels.addView(state,new LinearLayout.LayoutParams(-1,dp(40)));}heading.addView(labels,new LinearLayout.LayoutParams(0,-2,1));
        Button details=button("Details",false,()->protocolInfo(protocol));details.setTextColor(MUTED);details.setTextSize(13);details.setMinWidth(dp(64));details.setPadding(dp(8),0,dp(8),0);details.setBackground(touchFeedback(8));details.setContentDescription("Details about "+protocol.title);heading.addView(details,new LinearLayout.LayoutParams(-2,dp(48)));line.addView(heading);
        Button control=button("Connect",true,()->{Gateway node=current.get();if(node!=null)toggleConnection(node);else protocolAction(server,protocol,true);});control.setTextSize(13);control.setSingleLine(true);control.setPadding(dp(10),dp(5),dp(10),dp(5));
        ImageButton manage=iconControl(R.drawable.rook_settings,"Settings for "+protocol.title,settings);manage.setColorFilter(MUTED);
        LinearLayout actions=row();if(!compact)actions.addView(state,new LinearLayout.LayoutParams(0,dp(48),1));LinearLayout.LayoutParams cp=compact?new LinearLayout.LayoutParams(0,dp(48),1):new LinearLayout.LayoutParams(dp(112),dp(48));if(!compact)cp.leftMargin=dp(8);actions.addView(control,cp);LinearLayout.LayoutParams mp=new LinearLayout.LayoutParams(dp(48),dp(48));mp.leftMargin=dp(4);actions.addView(manage,mp);line.addView(actions);parent.addView(line);
        Runnable update=()->{Gateway node=current.get();String status=node==null?"Ready to connect":connectionState(node);if(!status.contentEquals(state.getText()))state.setText(status);if(node!=null){updateConnectionAction(control,node);String action=connectionAction(node);if(compact&&(action.equals("Connecting…")||action.equals("Disconnecting…")))control.setText(action.startsWith("Disconnect")?"Stopping":"Starting");control.setContentDescription(action+" "+protocol.title+(pair?" · Double VPN":" on "+ServerProtocols.name(server)));}};homeConnectionUpdates.add(update);update.run();
    }
    private void openServer(Gateway server){
        Gateway pairedOwner=managementPair(server);if(pairedOwner!=null){openPairServer(pairedOwner,PairNodes.same(server,pairedOwner)?pairedOwner:pairedOwner.exit);return;}
        if(server.data.optBoolean("adminAccess")){openAdministrators(server);return;}
        selected=server;pendingServerId=server.get("id");getSharedPreferences("rookstride-ui",0).edit().putString("selected",server.get("id")).apply();openScreen("Protocols");
        if(hasAuth(server)&&!busy&&!DeploymentService.active()&&serverCheckDue(server))inspect(server);
    }
    private boolean serverCheckDue(Gateway server){
        long latest=server.data.optLong("checkedAt");for(Gateway node:gateways)if(ServerProtocols.sameServer(server,node))latest=Math.max(latest,node.data.optLong("checkedAt"));
        latest=Math.max(latest,getSharedPreferences("rookstride-ui",0).getLong("inspectAttempt:"+server.get("id"),0));long age=System.currentTimeMillis()-latest;return latest==0||age<0||age>=30*60*1000;
    }
    private void addScreen(){title("Add a VPN","");addOptions();}
    private void addOptions(){
        actionCard("Set up a VPN","Install on your server",()->{pendingServerId="";openScreen("Setup");});
        actionCard("Import a VPN","Use a profile you already have",()->openScreen("Import"));
        actionCard("Manage a server","Connect with administrator access",()->serverDetails("manage"));
        fullButton(body,"Accept administrator invitation",false,()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),PICK_ADMIN_INVITATION));
    }
    private void setupScreen(){
        title("Set up a VPN","Choose your setup");
        actionCard("Single-server VPN","Install your VPN on one VPS",()->{pendingServerId="";openScreen("Protocols");});
        actionCard("Double VPN","Send traffic through two servers · also called a two-hop VPN",this::addPair);
    }
    private Gateway pendingServer(){for(Gateway node:gateways)if(node.get("id").equals(pendingServerId))return node;return null;}
    private void protocolScreen(){
        Gateway server=pendingServer();
        if(server==null){title("Choose a protocol",SingleProtocols.values().length+" options");if(pageScroll!=null)pageScroll.setScrollbarFadingEnabled(false);for(SingleProtocols protocol:setupProtocols())setupProtocolCard(protocol,protocolSummary(protocol),()->selectProtocol(protocol));return;}
        serverTitle(server,false);
        boolean stackActions=getResources().getConfiguration().screenWidthDp/getResources().getConfiguration().fontScale<330;
        LinearLayout actions=stackActions?stack():row();Button refresh=button("Refresh",false,()->inspect(server));controlIcon(refresh,R.drawable.rook_refresh);actions.addView(refresh,stackActions?new LinearLayout.LayoutParams(-1,-2):new LinearLayout.LayoutParams(0,-2,1));
        Button maintenance=button("Maintenance",false,()->openMaintenance(server));maintenance.setTag("server-maintenance");controlIcon(maintenance,R.drawable.rook_settings);LinearLayout.LayoutParams mp=stackActions?new LinearLayout.LayoutParams(-1,-2):new LinearLayout.LayoutParams(0,-2,1);if(stackActions)mp.topMargin=dp(10);else mp.leftMargin=dp(10);actions.addView(maintenance,mp);body.addView(actions);space(body,14);
        if(!server.get("checked").isEmpty()){body.addView(text("Checked "+server.get("checked"),12,MUTED,false));space(body,12);}
        Set<String> installed=ServerProtocols.installed(gateways,server);body.addView(text("VPN protocols",18,INK,true));space(body,10);
        if(installed.isEmpty())empty("No VPN protocols installed. Add one to start connecting and sharing access.");
        for(SingleProtocols protocol:ServerProtocols.ordered(installed,true)){
            Gateway connection=ServerProtocols.find(gateways,server,protocol.id);
            protocolCard(protocol,connection==null?"Installed":connectionState(connection),()->selectProtocol(protocol),connection==null?"Connect":connectionAction(connection),()->protocolAction(server,protocol,true),connection,true);
            LinearLayout c=(LinearLayout)body.getChildAt(body.getChildCount()-1);if(connection!=null)fullButton(c,"VPN users",false,()->openUsers(connection));swipeCard(c,protocol.title,()->uninstallProtocol(server,protocol));
        }
        if(!installed.isEmpty()&&!server.isPair()&&!server.data.optBoolean("adminAccess"))fullButton(body,"Share several connections",false,()->startCollectionShare(server));
        if(!pairNode(server))fullButton(body,"Add protocol",true,()->chooseAdditionalProtocol(server));
        else fullButton(body,"Open server maintenance",false,()->openMaintenance(server));
    }
    private void chooseAdditionalProtocol(Gateway server){
        List<SingleProtocols> available=ServerProtocols.ordered(ServerProtocols.installed(gateways,server),false);LinearLayout choices=form();
        for(SingleProtocols protocol:available)fullButton(choices,protocol.title,false,()->{if(editor!=null)editor.dismiss();pendingServerId=server.get("id");selectProtocol(protocol);});
        editor=RookDialogs.builder(this).setTitle("Add protocol").setView(scrolling(choices)).setNegativeButton("Cancel",null).create();editor.show();
    }
    private void openMaintenance(Gateway server){selected=server;openScreen("ServerSettings");}
    private void serverTools(Gateway server){fullButton(body,"Server maintenance",false,()->openMaintenance(server));}
    private void controlIcon(Button control,int icon){if(workingButton(control)){loadingButton(control,RED);return;}android.graphics.drawable.Drawable image=getDrawable(icon).mutate();image.setTint(MUTED);image.setBounds(0,0,dp(18),dp(18));control.setCompoundDrawables(image,null,null,null);control.setCompoundDrawablePadding(dp(6));control.setTextSize(13);control.setPadding(dp(10),dp(5),dp(10),dp(5));}
    private void protocolAction(Gateway server,SingleProtocols protocol,boolean installed){
        try{Gateway node=ServerProtocols.find(gateways,server,protocol.id);if(node==null){node=ServerProtocols.create(server,protocol);gateways.add(node);save();}selected=node;
            if(installed){toggleConnection(node);return;}node.set("setupIntent","");if(protocol==SingleProtocols.IKEV2)installIke(node);else protocolInstallation(node);
        }catch(Exception e){error(e);}
    }
    private void uninstallProtocol(Gateway server,SingleProtocols protocol){
        try{Gateway target=ServerProtocols.find(gateways,server,protocol.id);if(target==null){target=ServerProtocols.create(server,protocol);gateways.add(target);save();}selected=target;if(otherProtocol(target))resetProtocol(target);else resetGateway(target);}catch(Exception e){error(e);}
    }
    private void selectProtocol(SingleProtocols protocol){
        setupProtocol=protocol.id;Gateway server=pendingServer();
        if(server!=null){try{
            Gateway node=ServerProtocols.find(gateways,server,protocol.id);
            if(node!=null){node.set("setupIntent","");openVpn(node);if(otherProtocol(node)&&ServerProtocols.installed(gateways,server).contains(protocol.id)&&!node.data.has("snapshot")&&!busy&&!DeploymentService.active())refreshProtocol(node);return;}
            node=ServerProtocols.create(server,protocol);node.set("setupIntent","");gateways.add(node);selected=node;save();openScreen("VPN");return;
        }catch(Exception e){error(e);return;}}
        serverDetails("install");
    }
    private void serverProtocols(Gateway node){openServer(node);}
    private void importScreen(){
        title("Connect to a VPN","Use sign-in details or a connection file");
        actionCard("Rookstride connection collection","Add several VPN connections from one .rookbundle file",()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),PICK_COLLECTION));
        actionCard("Username and password","Enter the VPN address and user details shared with you",this::manualSignIn);
        space(body,12);body.addView(text("Import a connection file",16,INK,true));
        for(SingleProtocols protocol:SingleProtocols.values())actionCard(protocol.title,protocol==SingleProtocols.IKEV2?"A .sswan profile":"A connection profile",()->{
            importProtocol=protocol.id;Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(pick,PICK_PROFILE);
        });
    }
    private void manualSignIn(){manualSignIn(null);}
    private void manualSignIn(Gateway existing){
        LinearLayout f=form();Spinner protocol=new Spinner(this);ArrayList<String> ids=new ArrayList<>(),names=new ArrayList<>();for(SingleProtocols p:SingleProtocols.values())if(PasswordSignIn.supported(p.id)){ids.add(p.id);names.add(p.title);}protocol.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,names));protocol.setContentDescription("VPN type");protocol.setMinimumHeight(dp(48));if(existing!=null){protocol.setSelection(ids.indexOf(existing.get("protocol")));protocol.setEnabled(false);}f.addView(protocol);
        EditText address=field(f,"VPN address (IP or domain)",existing==null?"":existing.get("host")+":"+existing.data.optInt("vpnPort",SingleProtocols.from(existing.get("protocol")).port),false);address.setHint("From the person sharing this VPN");EditText login=field(f,"VPN username",existing==null?"":existing.get("vpnLogin"),false),password=field(f,"VPN password",existing==null?"":existing.vpnPassword,true);
        f.addView(text("Use VPN-user details, not the server administrator password. The server must support trusted username/password sign-in.",13,MUTED,false));
        AlertDialog d=RookDialogs.builder(this).setTitle(existing==null?"VPN sign-in":"Edit VPN sign-in").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Save VPN",null).create();d.show();secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{try{
            String id=ids.get(protocol.getSelectedItemPosition()),user=login.getText().toString().trim(),secret=password.getText().toString();JSONObject endpoint=PasswordSignIn.endpoint(address.getText().toString().trim(),SingleProtocols.from(id).port);
            JSONObject definition=PasswordSignIn.definition(id,address.getText().toString().trim(),user,secret,id.equals("ikev2")?"":PublicTrustRoots.read());Gateway node=existing==null?new Gateway():existing;if(existing!=null&&connectionActive(existing))disconnectPhone(existing);node.set("protocol",id);node.set("host",endpoint.getString("host"));node.set("name",SingleProtocols.from(id).title+" · "+endpoint.getString("host"));node.set("vpnLogin",user);node.set("accessMode","password");node.vpnPassword=secret;node.data.put("clientOnly",true);node.data.put("rememberVpn",true);node.data.put("vpnPort",endpoint.getInt("port"));
            if(id.equals("ikev2"))installProfile(node,definition);else new NativeProfileStore(this).save(node.get("id"),id,node.get("name"),definition.toString());if(existing==null)gateways.add(node);save();d.dismiss();openVpn(node);
        }catch(Exception e){password.setError(e.getMessage());}});
    }
    private boolean passwordUsers(Gateway node){return !otherProtocol(node)||snapshot().optBoolean("manual_sign_in")||snapshot().optString("access_mode").equals("password");}
    private String vpnAddress(Gateway node){return node.get("vpnServer").isEmpty()?node.get("host"):node.get("vpnServer");}
    private void importProfile(Uri uri){
        SingleProtocols protocol=SingleProtocols.from(importProtocol);
        if(protocol==SingleProtocols.IKEV2){startActivity(new Intent(this,VpnProfileImportActivity.class).setAction(Intent.ACTION_VIEW).setData(uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));return;}
        try{
            String content;try(InputStream in=getContentResolver().openInputStream(uri)){content=new String(read(in,512000),StandardCharsets.UTF_8).trim();}
            NativeProfiles.validate(protocol.id,content);Gateway node=new Gateway();node.set("name",protocol.title);node.set("protocol",protocol.id);node.data.put("clientOnly",true);ConnectionBundleImport.populateNativeMetadata(node,content);
            if(protocol==SingleProtocols.OPENVPN&&NativeProfiles.openVpnNeedsPassword(content)){final String imported=content;nativePassword(node,imported,()->{gateways.add(node);save();openVpn(node);});return;}
            new NativeProfileStore(this).save(node.get("id"),protocol.id,node.get("name"),content);gateways.add(node);save();openVpn(node);
        }catch(Exception e){error(e);}
    }
    private void syncNativeProfiles(){
        if(vault==null||vaultFailed||DeploymentService.active()||collectionState==null||!collectionState.recoveryReady||collectionState.working||collectionState.result!=null)return;
        VpnProfileDataSource source=new VpnProfileSource(this);source.open();boolean changed=false;
        try{Set<String> pending=ConnectionBundleImport.pendingIkeProfileIds(this);for(VpnProfile profile:source.getAllVpnProfiles()){
            if(pending.contains(profile.getUUID().toString()))continue;
            String id=profile.getUUID().toString();boolean exists=false;for(Gateway node:gateways)if(id.equals(node.get("profileUuid"))){exists=true;break;}
            if(!exists){Gateway node=new Gateway();node.set("name",profile.getName());node.set("host",profile.getGateway());node.set("profileUuid",id);node.data.put("clientOnly",true);gateways.add(node);changed=true;}
        }}catch(Exception e){message="Could not read saved VPN profiles.";}finally{source.close();}
        // One local pass after import-journal recovery, not quick-card/status polling.
        // Failed/missing profiles are attempted at most once in this Activity.
        NativeProfileStore profiles=new NativeProfileStore(this);
        for(Gateway node:gateways)if(ConnectionBundleImport.needsNativeMetadata(node)&&nativeMetadataChecked.add(node.get("id"))&&profiles.exists(node.get("id"))){
            try{JSONObject saved=profiles.read(node.get("id"));if(node.get("protocol").equals(saved.getString("protocol")))changed|=ConnectionBundleImport.populateNativeMetadata(node,saved.getString("content"));}catch(Exception unavailable){/* Keep saved access and credentials intact; never use SSH to repair a label. */}
        }
        if(changed){save();if(tab.equals("Home"))render();}
    }
    private void serverDetails(String intent){if(intent.equals("manage"))setupProtocol="ikev2";editGateway(null,intent);}
    private List<Gateway> savedSetupServers(){
        List<Gateway> result=new ArrayList<>();for(Gateway server:PairNodes.catalog(gateways))if(!clientOnly(server)&&!server.data.optBoolean("adminAccess")&&!server.get("host").isEmpty())result.add(server);return result;
    }
    private void chooseSingleServer(){
        LinearLayout choices=form();AlertDialog chooser=RookDialogs.builder(this).setTitle("Choose a saved server").setView(scrolling(choices)).setNegativeButton("Cancel",null).create();
        for(Gateway server:savedSetupServers()){
            Button option=fullButton(choices,ServerProtocols.name(server)+"\n"+server.get("host"),false,()->{chooser.dismiss();if(editor!=null)editor.dismiss();useSavedSetupServer(server);});option.setTag("saved-single-server-"+server.get("id"));
        }
        chooser.show();
    }
    private void useSavedSetupServer(Gateway server){
        if(busy||DeploymentService.active())return;
        try{
            if(pairNode(server)){openServer(server);Toast.makeText(this,"This server is part of Double VPN. Use its server controls to change that setup.",Toast.LENGTH_LONG).show();return;}
            hasAuth(server);SingleProtocols protocol=SingleProtocols.from(setupProtocol);Gateway node=ServerProtocols.find(gateways,server,protocol.id);
            if(node==null){node=ServerProtocols.create(server,protocol);gateways.add(node);}
            selected=node;demo=false;
            if(ServerProtocols.installed(gateways,server).contains(protocol.id)){node.set("setupIntent","");save();openVpn(node);return;}
            node.set("setupIntent","install");save();inspect(node);
        }catch(Exception e){error(e);}
    }
    private void phoneControl(String title,boolean primary,Runnable action){
        LinearLayout controls=row();controls.setTag("connection-controls");Button control=button(title,primary,action);
        if(title.equals("Disconnect")||title.equals("Cancel")){control.setEnabled(true);control.setOnClickListener(v->action.run());}
        if(Arrays.asList("Connect","Disconnect","Cancel").contains(title)&&selected!=null){updateConnectionAction(control,selected);}
        controls.addView(control,new LinearLayout.LayoutParams(0,-2,1));

        connectionControls=controls;
    }
    private void shareSelectedConnection(Gateway node){
        if(otherProtocol(node)&&new NativeProfileStore(this).exists(node.get("id"))){exportSavedNative(node);return;}
        String login=node.get("vpnLogin");if(login.isEmpty()){openUsers(node);return;}
        command(node,json("action","profile","login",login,"name",node.get("name")),this::shareProtocolProfile,"Connection prepared");
    }
    private void openUsers(Gateway node){
        selected=node;openScreen("People");
        if(!demo&&!snapshot().has("users")&&!busy&&!DeploymentService.active())refreshUsers(node);
    }
    private void refreshUsers(Gateway node){command(node,json("action","status"),result->{try{node.data.put("snapshot",result);save();}catch(Exception e){error(e);}},"Users refreshed");}
    private void gatewayScreen(){
        if(selected==null){navigation.root("Home");tab="Home";homeScreen();return;}
        protocolHeading();
        LinearLayout hero=card();hero.setBackground(surface(18));
        boolean matches=vpn!=null&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(selected.get("profileUuid"));
        boolean connected=matches&&vpn.getState()==VpnStateService.State.CONNECTED,connecting=matches&&vpn.getState()==VpnStateService.State.CONNECTING;
        NativeVpn.Status nativeState=null;
        if(otherProtocol(selected)){nativeState=nativeStatus(selected);connected=nativeState.id.equals(selected.get("id"))&&nativeState.state.equals("connected");connecting=nativeState.active(selected.get("id"))&&!connected;}
        final boolean isConnected=connected,isConnecting=connecting;
        ImageView rook=new ImageView(this);rook.setImageResource(connected?R.drawable.rook_celebrate:connecting?R.drawable.rook_wait:R.drawable.rook_map);rook.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);hero.addView(rook,new LinearLayout.LayoutParams(-1,dp(getResources().getConfiguration().screenWidthDp<360||getResources().getConfiguration().fontScale>1.15f?48:88)));
        hero.addView(text(connectionState(selected),getResources().getConfiguration().fontScale>1.15f?22:26,INK,true));
        if(matches&&vpn.getErrorState()!=VpnStateService.ErrorState.NO_ERROR)hero.addView(text(getString(vpn.getErrorText()),14,INK,false));
        if(selected.isPair()&&!readyPhoneConnection(selected)){hero.removeView(hero.getChildAt(hero.getChildCount()-1));hero.addView(text("Installation incomplete",24,INK,true));phoneControl("Resume installation",true,()->runPair(selected,true));}
        else if(otherProtocol(selected)&&!clientOnly(selected)&&!readyPhoneConnection(selected)&&!ServerProtocols.installed(gateways,selected).contains(selected.get("protocol"))&&!snapshot().has("services")){hero.removeView(hero.getChildAt(hero.getChildCount()-1));hero.addView(text("Not installed",24,INK,true));phoneControl("Install VPN",true,()->protocolInstallation(selected));}
        else if(otherProtocol(selected)){
            phoneControl(isConnected||isConnecting&&!nativeState.state.equals("connecting")?"Disconnect":isConnecting?"Cancel":"Connect",true,()->{if(demo){demoNotice();return;}toggleConnection(selected);});
            if(nativeState!=null&&nativeState.id.equals(selected.get("id"))&&!nativeState.error.isEmpty()&&!nativeState.state.equals("connected")&&!nativeState.state.equals("checking"))hero.addView(text(nativeState.error,14,INK,false));
        }else if(!clientOnly(selected)&&!readyPhoneConnection(selected)){
            hero.removeView(hero.getChildAt(hero.getChildCount()-1));
            if(selected.isPair()){hero.addView(text("Installation incomplete",24,INK,true));phoneControl("Resume installation",true,()->runPair(selected,true));}
            else if(selected.data.optJSONObject("probe")!=null&&selected.data.optJSONObject("probe").optBoolean("gateway")){hero.addView(text("Management not enabled",24,INK,true));phoneControl("Enable management",true,()->installation(selected,true));}
            else{hero.addView(text("Not installed",24,INK,true));phoneControl("Install VPN",true,()->installIke(selected));}
        }else phoneControl(isConnected?"Disconnect":isConnecting?"Cancel":"Connect",true,()->{if(demo){demoNotice();return;}toggleConnection(selected);});
        if(nativeState!=null&&nativeState.id.equals(selected.get("id"))){
            if(nativeState.state.equals("checking"))hero.addView(text("Checking websites through the VPN…",14,INK,false));
            if(nativeState.state.equals("limited"))hero.addView(text("The VPN is on, but website access is not confirmed. Try a website or check again.",14,INK,false));
        }
        if(nativeState!=null&&nativeState.id.equals(selected.get("id"))&&(nativeState.state.equals("limited")||nativeState.state.equals("failed")||nativeState.state.equals("error")||nativeState.state.equals("interrupted"))||matches&&vpn.getErrorState()!=VpnStateService.ErrorState.NO_ERROR)fullButton(hero,"Connection help",false,()->showVpnDiagnosis(selected));
        if(connectionControls!=null){space(hero,12);hero.addView(connectionControls);connectionControls=null;}
        if(!clientOnly(selected)&&!selected.isPair()&&!snapshot().has("services")&&PasswordSignIn.supported(selected.get("protocol")))fullButton(body,"Sign-in: "+(selected.get("accessMode").equals("profile")?"connection file":"username & password"),false,()->RookDialogs.builder(this).setTitle("How users connect").setSingleChoiceItems(new String[]{"Username & password · trusted server certificate","Connection file · private server certificate"},selected.get("accessMode").equals("profile")?1:0,(d,w)->{selected.set("accessMode",w==0?"password":"profile");save();d.dismiss();render();}).setNegativeButton("Cancel",null).show());
        if(!selected.get("job").isEmpty())fullButton(body,"View installation",false,()->pollJob(selected));
        if(!clientOnly(selected)&&readyPhoneConnection(selected)){
            LinearLayout tools=stack();tools.setTag("protocol-tools");body.addView(tools);
            JSONObject filtering=snapshot().optJSONObject("filtering");boolean hasFilter=selected.isPair()||!snapshot().has("services")||!otherProtocol(selected)||filtering!=null&&filtering.optBoolean("installed");
            String[] labels={"VPN users","Logs","Usage","Ad blocking"};int[] icons={R.drawable.rook_users,R.drawable.rook_logs,R.drawable.rook_statistics,R.drawable.rook_shield};Runnable[] actions={()->openUsers(selected),()->showProtocolLog(selected),()->openScreen("Sessions"),()->{if(hasFilter)adguard(selected);else enableFiltering(selected);}};
            int columns=getResources().getConfiguration().screenWidthDp/getResources().getConfiguration().fontScale<300?1:2;LinearLayout toolRow=null;
            for(int i=0;i<labels.length;i++){if(i%columns==0){toolRow=row();toolRow.setBaselineAligned(false);toolRow.setGravity(Gravity.TOP);LinearLayout.LayoutParams line=new LinearLayout.LayoutParams(-1,-2);if(i>0)line.topMargin=dp(10);tools.addView(toolRow,line);}moduleAction(toolRow,labels[i],icons[i],actions[i]);}
            space(body,8);body.addView(text(selected.isPair()?"Ad blocking is managed on the exit server.":!otherProtocol(selected)?"Ad blocking for IKEv2.":"Ad blocking is shared by native VPNs on this server.",12,MUTED,false));
        }else if(!clientOnly(selected))fullButton(body,"Check server",false,()->inspect(selected));
        else fullButton(body,"View log",false,()->showProtocolLog(selected));
        if(!clientOnly(selected)&&!otherProtocol(selected)&&!selected.isPair()&&snapshot().has("services")&&(snapshot().optJSONObject("certificate")==null||!snapshot().optJSONObject("certificate").optBoolean("manual_sign_in")))fullButton(body,"Enable username/password sign-in",false,()->{selected.set("accessMode","password");installation(selected,true);});
        if(!clientOnly(selected)&&!selected.isPair())fullButton(body,"Server maintenance",false,()->openMaintenance(selected));
        fullButton(body,"About this protocol",false,()->protocolInfo(SingleProtocols.from(selected.get("protocol"))));
        if(otherProtocol(selected)&&selected.data.optBoolean("dnsRefresh")&&snapshot().optJSONObject("filtering")!=null&&snapshot().optJSONObject("filtering").optBoolean("running"))fullButton(body,"Reconnect to apply ad blocking",false,()->connectPhone(selected));
        if(nativeState!=null&&nativeState.id.equals(selected.get("id"))&&nativeState.state.equals("limited"))fullButton(body,"Check web access again",false,()->NativeVpn.recheck(this,selected.get("protocol")));
        if(clientOnly(selected))fullButton(body,"Connection preferences",false,()->openScreen("Settings"));
        else if(selected.isPair())fullButton(body,"Server maintenance",false,()->openMaintenance(selected));
        else{
            if(!otherProtocol(selected))fullButton(body,"Phone connection options",false,()->phoneConnectionOptions(selected));
            if(snapshot().has("services"))fullButton(body,"Uninstall this protocol",false,()->{if(otherProtocol(selected))resetProtocol(selected);else resetGateway(selected);});
        }
    }
    private void settingsScreen(){
        if(selected==null){empty("Choose a VPN first.");return;}
        title(clientOnly(selected)?"Connection preferences":"Two-server VPN",SingleProtocols.from(selected.get("protocol")).title+" · "+(clientOnly(selected)?selected.get("name"):ServerProtocols.name(selected)));
        if(clientOnly(selected)){
            if(selected.get("accessMode").equals("password"))fullButton(body,"Edit sign-in details",false,()->manualSignIn(selected));
            if(otherProtocol(selected)){fullButton(body,"Share connection",false,()->exportSavedNative(selected));fullButton(body,"View log",false,()->nativeDetails(selected));}
            else{fullButton(body,"Edit connection",false,()->startActivity(new Intent(this,VpnProfileDetailActivity.class).putExtra(VpnProfileDataSource.KEY_UUID,selected.get("profileUuid"))));logButton(body);}
            fullButton(body,"Remove VPN",false,()->removeSavedVpn(selected));return;
        }
        if(!otherProtocol(selected))fullButton(body,"Phone connection options",false,()->phoneConnectionOptions(selected));
        if(selected.isPair()){
            fullButton(body,"Change Double VPN protocols",false,()->editPair(selected));fullButton(body,"Entry server",false,()->openPairServer(selected,selected));fullButton(body,"Exit server",false,()->openPairServer(selected,selected.exit));fullButton(body,"Resume / verify two-server VPN",false,()->runPair(selected,true));fullButton(body,"Server connection",false,()->choosePairSshRoute(selected));fullButton(body,"Entry server access",false,()->editGateway(selected));fullButton(body,"Exit server access",false,()->editGateway(selected.exit));fullButton(body,"Remove both VPN setups",false,()->resetPair(selected));
        }else fullButton(body,"Uninstall this protocol",false,()->{if(otherProtocol(selected))resetProtocol(selected);else resetGateway(selected);});
    }
    private void phoneConnectionOptions(Gateway node){
        LinearLayout f=form();EditText port=field(f,"Phone VPN port",Integer.toString(node.data.optInt("vpnPort",500)),false);port.setInputType(InputType.TYPE_CLASS_NUMBER);
        AlertDialog d=RookDialogs.builder(this).setTitle("Phone connection options").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();d.show();
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{try{int value=Integer.parseInt(port.getText().toString().trim());if(!InputRules.port(value))throw new IllegalArgumentException();node.data.put("vpnPort",value);applyPhonePort(node,value);save();d.dismiss();}catch(Exception e){port.setError("Enter a port from 1 to 65535");}});
    }
    private LinearLayout maintenanceGroup(Gateway server,String key,String heading,String summary){
        String identity=server.get("id")+":"+key;LinearLayout group=card(),header=row(),labels=stack();TextView title=text(heading,16,INK,true);labels.addView(title);space(labels,4);labels.addView(text(summary,13,MUTED,false));header.addView(labels,new LinearLayout.LayoutParams(0,-2,1));TextView indicator=text("⌄",20,MUTED,false);indicator.setGravity(Gravity.CENTER);header.addView(indicator,new LinearLayout.LayoutParams(dp(40),dp(48)));header.setMinimumHeight(dp(48));header.setFocusable(true);header.setBackground(touchFeedback(10));group.addView(header);
        LinearLayout content=stack();content.setTag("maintenance-section-"+key);group.addView(content);maintenanceBodies.put(identity,content);boolean open=identity.equals(maintenanceSection);content.setVisibility(open?View.VISIBLE:View.GONE);indicator.setText(open?"⌃":"⌄");header.setContentDescription((open?"Collapse ":"Expand ")+heading);header.setOnClickListener(v->{boolean expand=!identity.equals(maintenanceSection);maintenanceSection=expand?identity:"";for(Map.Entry<String,View> entry:maintenanceBodies.entrySet())entry.getValue().setVisibility(entry.getKey().equals(maintenanceSection)?View.VISIBLE:View.GONE);render();});return content;
    }
    private void serverSettingsScreen(){
        Gateway server=selected;if(server==null||clientOnly(server)){empty("Choose a managed server first.");return;}
        boolean pair=server.isPair();title("Maintenance",pair?server.get("name"):ServerProtocols.name(server));maintenanceBodies.clear();
        String pending=server.data.has("pairedOsOperation")?"cleanup":server.data.has("entryMigration")||server.data.has("lifecycleOperation")?"route":server.data.has("engineUpdate")||server.data.has("helperUpdate")?"checks":"";
        if(!pending.isEmpty()){LinearLayout status=card();status.addView(text("A server change needs review",16,INK,true));space(status,6);status.addView(text("Continue the saved operation or review its recovery options.",14,MUTED,false));fullButton(status,"Review change",false,()->{maintenanceSection=server.get("id")+":"+pending;render();});}

        LinearLayout access=maintenanceGroup(server,"access","Access & administrators",pair?"Server sign-in, relay and shared management":"Server sign-in and shared management");
        fullButton(access,pair?"Entry administrator access":"Administrator access",false,()->editGateway(server,"",true));
        if(pair){fullButton(access,"Exit administrator access",false,()->editGateway(server.exit,"",true));fullButton(access,"Management connection",false,()->choosePairSshRoute(server));}
        else access.addView(text(hasAuth(server)&&server.remember()?"Access saved encrypted on this phone":"Save access when signing in to avoid repeated passwords.",13,MUTED,false));appendAdministrationActions(access,server);
        LinearLayout checks=maintenanceGroup(server,"checks","Checks & updates","Inspect this setup or review software updates");fullButton(checks,"Inspect server",false,()->{if(pair)refreshPair(server);else inspect(server);});appendRuntimeUpdateActions(checks,server);appendLifecycleActions(checks,server);
        if(pair){LinearLayout route=maintenanceGroup(server,"route","Double VPN & recovery","Change servers, protocols or save a backup");fullButton(route,"Change Double VPN protocols",false,()->editPair(server));appendTopologyActions(route,server);}
        LinearLayout cleanup=maintenanceGroup(server,"cleanup","Remove or rebuild","Remove VPNs, reinstall Ubuntu or forget this server");
        fullButton(cleanup,pair?"Remove both VPN setups":"Remove VPN setups",false,()->{if(pair)resetPair(server);else resetServer(server);});
        if(!pair){JSONObject probe=server.data.optJSONObject("probe"),inventory=probe==null?null:probe.optJSONObject("inventory"),filter=inventory==null?null:inventory.optJSONObject("filtering");if(filter!=null&&filter.optBoolean("installed")&&filter.optJSONArray("used_by")!=null&&filter.optJSONArray("used_by").length()==0)fullButton(cleanup,"Remove incomplete ad blocking",false,()->resetIncompleteFilter(server));fullButton(cleanup,"Wipe server & reinstall Ubuntu",false,()->chooseOsReinstall(server));}
        else appendPairRebuildActions(cleanup,server);
        fullButton(cleanup,pair?"Remove Double VPN from this phone":"Remove server from this phone",false,()->{if(pair)removeSavedVpn(server);else removeSavedServer(server);});
    }
    private void appendRuntimeUpdateActions(LinearLayout into,Gateway server){
        if(server.data.optBoolean("adminAccess"))return;
        JSONObject operation=server.data.optJSONObject("engineUpdate");
        fullButton(into,operation==null?"VPN runtime updates":"Resume VPN runtime update",false,()->{if(operation!=null)reviewEngineUpdateState(server);else pairRead(server,"Checking installed VPN runtimes",()->EngineUpdates.inspect(server,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),review->reviewEngineUpdates(server,review));});
    }
    private void reviewEngineUpdates(Gateway server,JSONObject review){
        LinearLayout f=form();f.addView(text("Updates come from the verified versions included in this Rookstride app. Prepare first, then review the exact update before restarting a listener.",14,INK,false));
        for(String group:new String[]{"xray","routes","trusttunnel","awg","openvpn","ikev2"}){
            String name=group;StringBuilder details=new StringBuilder();boolean supported=false;
            for(String role:new String[]{"single","entry","exit"}){JSONObject node=review.optJSONObject(role),item=node==null?null:EngineUpdates.group(node,group);if(item==null)continue;name=item.optString("title",group);supported|=item.optBoolean("supported");if(details.length()>0)details.append("\n");details.append(role.equals("single")?"This server":role.equals("entry")?"Entry":"Exit").append(": ").append(item.optBoolean("supported")?"Ready to prepare "+item.optString("candidate"):item.optString("reason","No compatible update"));}
            if(details.length()==0)continue;space(f,14);f.addView(text(name,17,INK,true));f.addView(text(details.toString(),13,MUTED,false));if(supported){String selectedGroup=group;fullButton(f,"Prepare "+name,false,()->startEngineUpdate(server,"prepare",selectedGroup,review));}
        }
        RookDialogs.builder(this).setTitle("VPN runtime updates").setView(scrolling(f)).setPositiveButton("Close",null).show();
    }
    private void reviewEngineUpdateState(Gateway server){
        JSONObject operation=server.data.optJSONObject("engineUpdate");if(operation==null)return;String state=operation.optString("state");LinearLayout f=form();f.addView(text("Update · "+operation.optString("group")+" · "+state.replace('-',' '),17,INK,true));boolean available=false;
        for(String role:new String[]{"single","entry","exit"}){JSONObject item=operation.optJSONObject(role+"_status");if(item==null)continue;available|=item.optBoolean("available");space(f,10);f.addView(text((role.equals("single")?"This server":role.equals("entry")?"Entry":"Exit")+" · "+item.optString("phase",item.optString("state")),14,MUTED,false));if(!item.optString("candidate").isEmpty())f.addView(text(item.optString("candidate"),13,INK,false));String hash=item.optString("new_hash");if(!hash.isEmpty())f.addView(text("Verified digest · "+hash.substring(0,Math.min(hash.length(),16)),12,MUTED,false));}
        if(state.equals("prepared")){
            f.addView(text(available?"The verified update is ready. Applying it may reconnect VPN users. The previous runtime remains available for rollback until you accept.":"The selected runtimes are already current. No restart is needed.",14,INK,false));
            if(available)fullButton(f,"Apply prepared update",true,()->confirm("Apply VPN runtime update?","The selected listeners restart. Existing accounts and profiles are kept. For Double VPN, forwarding stays guarded until route and DNS checks pass.",()->startEngineUpdate(server,"apply","",null)));
            fullButton(f,available?"Cancel prepared update":"Finish",false,()->startEngineUpdate(server,"rollback","",null));
        }else if(state.equals("verified")){
            f.addView(text("Server checks passed. Before keeping this update, connect using an unchanged saved VPN profile and check websites, the exit address and ad blocking.",14,INK,false));
            fullButton(f,"Keep update after client check",true,()->confirm("Keep the runtime update?","Confirm that an unchanged saved client connects and its internet access and filtering work. This closes the rollback window.",()->startEngineUpdate(server,"accept","",null)));fullButton(f,"Roll back update",false,()->startEngineUpdate(server,"rollback","",null));
        }else{
            String action=state.equals("preparing")?"prepare":state.equals("accepting")?"accept":state.equals("rolling-back")?"rollback":"apply";
            fullButton(f,"Resume recorded update",true,()->startEngineUpdate(server,action,operation.optString("group"),operation.optJSONObject("review")));
            if(!state.equals("accepting")&&!state.equals("rolling-back"))fullButton(f,"Cancel or roll back update",false,()->confirm("Cancel or roll back this update?","Prepared files are discarded. Any changed runtime is restored to its previous version; users may briefly reconnect.",()->startEngineUpdate(server,"rollback","",null)));
        }
        if(!state.equals("verified"))fullButton(f,"Abandon this rollback record",false,()->confirm("Abandon the runtime update record?","This does not change or stop any server software. It removes the option to roll back through this record. A guarded Double VPN route may remain closed; inspect or remove its VPN setup afterward. An active update cannot be abandoned.",()->startEngineUpdate(server,"abandon","",null)));
        RookDialogs.builder(this).setTitle("Review VPN runtime update").setView(scrolling(f)).setPositiveButton("Close",null).show();
    }
    private void startEngineUpdate(Gateway server,String action,String group,JSONObject review){
        if(busy||DeploymentService.active()||server.data.optBoolean("adminAccess"))return;
        if(!hasAuth(server)){passwordDialog(server,()->startEngineUpdate(server,action,group,review));return;}if(server.isPair()&&!hasAuth(server.exit)){passwordDialog(server.exit,()->startEngineUpdate(server,action,group,review));return;}
        try{DeploymentService.launch(this,server,gateways,"engine-update",json("action",action,"group",group,"review",review),server.data.has("engineUpdate"));openScreen("Progress");}catch(Exception e){error(e);}
    }
    private void appendLifecycleActions(LinearLayout into,Gateway server){
        if(!server.isPair()){fullButton(into,"Recognize an existing Double VPN",false,()->chooseAdoptionExit(server));return;}
        JSONObject update=server.data.optJSONObject("helperUpdate");if(update==null)fullButton(into,"Review management helper update",false,()->pairRead(server,"Reviewing management helper versions",()->MaintenanceUpdates.review(server,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),review->reviewHelperUpdate(server,review)));else if(update.optString("state").equals("accepting")){fullButton(into,"Resume helper update acceptance",false,()->startHelperUpdate(server,"accept",null));}else if(update.optString("state").equals("rolling-back")){fullButton(into,"Resume helper update rollback",false,()->startHelperUpdate(server,"rollback",null));}else if(update.optString("state").equals("verified")){fullButton(into,"Accept helper update after client check",false,()->confirm("Accept the helper update?","Confirm that existing clients still connect, browse and use the expected exit and filtering. This closes the helper rollback window.",()->startHelperUpdate(server,"accept",null)));fullButton(into,"Roll back management helper update",false,()->confirm("Roll back management helpers?","Restore the previous helper revisions. VPN identity and accounts are retained; sessions may reconnect.",()->startHelperUpdate(server,"rollback",null)));}else fullButton(into,"Resume management helper update",false,()->startHelperUpdate(server,"apply",null));
    }
    private void appendTopologyActions(LinearLayout into,Gateway server){
        fullButton(into,"Inspect both servers",false,()->pairRead(server,"Inspecting both servers",()->LifecycleController.inspect(server,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),result->{server.data.remove("deploymentInventory");try{server.data.put("deploymentInventory",result).put("deploymentRevision",result.optInt("revision"));save();}catch(Exception e){error(e);}reviewPairInventory(server,result,null);}));
        JSONObject operation=server.data.optJSONObject("lifecycleOperation");
        if(operation!=null){String state=operation.optString("state");into.addView(text("Exit replacement · "+state.replace('-', ' '),13,RED,true));if(state.equals("active")||state.equals("cutover")||state.equals("awaiting-client-check")||state.equals("switched")){fullButton(into,"Accept replacement after client check",false,()->confirm("Accept the new exit?","Confirm that your unchanged VPN clients can browse, DNS and ad blocking work, and disconnecting the exit blocks traffic. This finishes the rollback window.",()->startLifecycle(server,"accept",null)));fullButton(into,"Roll back to the previous exit",false,()->confirm("Roll back the exit?","Return to the previous exit while it remains available. Existing connections may reconnect.",()->startLifecycle(server,"rollback",null)));}else fullButton(into,"Resume exit replacement",false,()->resumeLifecycle(server));}
        else if(PairController.modern(server))fullButton(into,"Replace exit server",false,()->replacementServerForm(server));
        JSONObject entryMove=server.data.optJSONObject("entryMigration");if(entryMove!=null){if(entryMove.optString("state").equals("awaiting-endpoint-switch")){boolean newAddress=entryMove.optBoolean("new_address");into.addView(text(newAddress?"The new entry is ready. Test its updated connection before retiring the original entry.":"Entry ready: move "+(server.get("vpnServer").isEmpty()?server.get("host"):server.get("vpnServer"))+" to "+entryMove.optString("candidate_public_ip")+" and test an unchanged saved client.",14,INK,false));JSONObject updated=entryMove.optJSONObject("updated_profile");if(newAddress&&updated!=null){fullButton(into,"Share updated entry connection",false,()->shareProtocolProfile(updated));fullButton(into,"Test updated connection on this phone",false,()->testReplacementEntry(server,updated));}fullButton(into,"Verify & finish entry replacement",false,()->confirm("Finish entry replacement?",newAddress?"Confirm that an updated VPN connection works at the new entry address. Existing users must update their connections. The old route is retired after verification.":"Confirm that you moved the existing endpoint and tested an unchanged VPN client. Rookstride verifies the endpoint again before retiring the old route.",()->startEntryMigration(server,"accept",null,false)));fullButton(into,"Roll back entry replacement",false,()->confirm("Restore the original entry?",newAddress?"Keep using the original entry address. Rookstride verifies it before stopping the candidate.":"First point the existing endpoint back to the original server. Rookstride verifies it before restoring the route and stopping the candidate.",()->startEntryMigration(server,"rollback",null,false)));}else fullButton(into,"Resume entry replacement",false,()->startEntryMigration(server,"stage",null,entryMove.optBoolean("endpoint_transfer")));}
        else if(PairController.modern(server))fullButton(into,"Replace entry server",false,()->replacementServerForm(server,true));
        if(PairController.modern(server)){fullButton(into,"Save owner recovery package",false,()->pairRead(server,"Reading owner recovery material",()->OwnerRecovery.capture(server,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),archive->recoveryPassword(server,archive)));fullButton(into,"Check recovery package",false,()->pickRecovery(server,"check"));long saved=server.data.optLong("recoveryExportedAt");into.addView(text(saved>0?"Last recovery export: "+android.text.format.DateFormat.getDateFormat(this).format(new Date(saved)):"No owner recovery package exported from this phone",12,MUTED,false));}

    }
    private void reviewHelperUpdate(Gateway pair,JSONObject review){
        JSONObject entry=review.optJSONObject("entry"),exit=review.optJSONObject("exit");boolean available=entry!=null&&entry.optBoolean("available")||exit!=null&&exit.optBoolean("available");LinearLayout f=form();f.addView(text("Update Rookstride management helpers from this installed app. VPN engine versions stay unchanged. The update keeps VPN identity, users and filtering; brief traffic interruption is possible while routes are checked.",14,INK,false));
        for(String role:new String[]{"entry","exit"}){JSONObject node=review.optJSONObject(role);space(f,12);f.addView(text((role.equals("entry")?"Entry":"Exit")+": "+(node!=null&&node.optBoolean("available")?"update available":node!=null&&node.optBoolean("supported")?"up to date":"not supported"),16,INK,true));if(node!=null&&!node.optString("reason").isEmpty())f.addView(text(node.optString("reason"),13,MUTED,false));}
        AlertDialog.Builder dialog=RookDialogs.builder(this).setTitle("Update management tools").setView(scrolling(f));if(available)dialog.setNegativeButton("Cancel",null).setPositiveButton("Update",(d,w)->startHelperUpdate(pair,"apply",review));else dialog.setPositiveButton("Close",null);dialog.show();
    }
    private void startHelperUpdate(Gateway pair,String action,JSONObject reviewed){if(busy||DeploymentService.active())return;if(!hasAuth(pair)){passwordDialog(pair,()->startHelperUpdate(pair,action,reviewed));return;}if(!hasAuth(pair.exit)){passwordDialog(pair.exit,()->startHelperUpdate(pair,action,reviewed));return;}JSONObject plan=reviewed;if(plan==null&&pair.data.optJSONObject("helperUpdate")!=null)plan=pair.data.optJSONObject("helperUpdate").optJSONObject("review");try{DeploymentService.launch(this,pair,gateways,"helper-update",json("action",action,"review",plan),pair.data.has("helperUpdate"));openScreen("Progress");}catch(Exception e){error(e);}}
    private interface PairRead {JSONObject read()throws Exception;}
    private void pairReadProgress(String phase){handler.post(()->{if(!isDestroyed()&&!isFinishing()){message=phase;render();}});}
    private void pairRead(Gateway pair,String label,PairRead read,Done done){
        if(busy||DeploymentService.active())return;
        if(!hasAuth(pair)){passwordDialog(pair,()->pairRead(pair,label,read,done));return;}
        if(pair.exit!=null&&!hasAuth(pair.exit)){passwordDialog(pair.exit,()->pairRead(pair,label,read,done));return;}
        busy=true;message=label;render();executor.execute(()->{try{JSONObject result=read.read();handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;message="";done.finish(result);render();});}catch(Exception e){handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;message="";render();if(e instanceof PairController.TrustNeeded){PairController.TrustNeeded trust=(PairController.TrustNeeded)e;trust(trust.node,trust.issue,()->pairRead(pair,label,read,done));}else if(e instanceof Ssh.HostTrust)trust(pair,(Ssh.HostTrust)e,()->pairRead(pair,label,read,done));else error(e);});}});
    }
    private void chooseAdoptionExit(Gateway entry){
        ArrayList<Gateway> choices=new ArrayList<>();for(Gateway node:homeServers())if(!clientOnly(node)&&!node.data.optBoolean("adminAccess")&&!PairNodes.same(entry,node))choices.add(node);
        if(choices.isEmpty()){RookDialogs.builder(this).setTitle("Add the second server").setMessage("Save administrator access for the exit server first. Then return here to recognize the existing Double VPN. Recognition does not install or remove VPN users.").setNegativeButton("Cancel",null).setPositiveButton("Add server",(d,w)->serverDetails("manage")).show();return;}
        String[] labels=new String[choices.size()];for(int i=0;i<labels.length;i++)labels[i]=physicalName(choices.get(i))+" · "+choices.get(i).get("host");
        RookDialogs.builder(this).setTitle("Select the existing exit server").setItems(labels,(d,w)->{try{Gateway probe=PairNodes.copy(entry);probe.exit=choices.get(w);probe.set("sshRoute","auto");pairRead(probe,"Recognizing existing Double VPN",()->LifecycleController.inspect(probe,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),result->reviewPairInventory(entry,result,choices.get(w)));}catch(Exception e){error(e);}}).setNegativeButton("Cancel",null).show();
    }
    private void reviewPairInventory(Gateway entry,JSONObject inventory,Gateway exit){
        LinearLayout form=form();form.addView(text("Deployment "+inventory.optString("deployment"),15,INK,true));space(form,10);form.addView(text("Both server identities and deployment records agree. Existing VPN users and configuration stay in place.",14,INK,false));space(form,10);form.addView(text(inventory.optBoolean("read_only")?"This installation supports inspection only. Changes need a compatible adapter.":"Compatible managed Double VPN",14,MUTED,false));
        AlertDialog.Builder dialog=RookDialogs.builder(this).setTitle(exit==null?"Double VPN inspection":"Recognize Double VPN").setView(scrolling(form));
        if(exit!=null)dialog.setNegativeButton("Close",null).setPositiveButton("Add existing Double VPN",(d,w)->{try{Gateway probe=PairNodes.copy(entry);probe.exit=exit;pairRead(probe,"Attaching existing Double VPN",()->LifecycleController.adopt(entry,exit,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress,()->vault.write(gateways)),result->{try{PairNodes.attach(gateways,entry);vault.write(gateways);openVpn(entry);}catch(Exception e){error(e);}});}catch(Exception e){error(e);}});else dialog.setPositiveButton("Close",null);dialog.show();
    }
    private void replacementServerForm(Gateway pair){replacementServerForm(pair,false);}
    private void replacementServerForm(Gateway pair,boolean entryMode){
        LinearLayout f=form();f.addView(text(entryMode?"Prepare a fresh entry while keeping the exit and VPN users. Keep the existing address if you can transfer it, or use a new address and update users’ connections.":"Use a fresh server for the new exit. Entry accounts and client profiles stay. The old exit remains available for rollback until you accept the change.",14,INK,false));
        EditText address=field(f,"Replacement server address","",false),login=field(f,"Administrator login","root",false),password=field(f,"Server password (SSH)","",true),port=field(f,"SSH port","22",false);port.setInputType(InputType.TYPE_CLASS_NUMBER);
        CheckBox remember=new CheckBox(this);remember.setText("Save server access on this phone");remember.setChecked(rememberServerAccess());remember.setMinHeight(dp(48));f.addView(remember);
        CheckBox newAddress=new CheckBox(this);newAddress.setText("Use a new VPN address; users will update their connections");newAddress.setMinHeight(dp(48));if(entryMode)f.addView(newAddress);
        CheckBox transfer=new CheckBox(this);transfer.setText("I can transfer the exact IP address used by existing clients");transfer.setMinHeight(dp(48));if(entryMode)f.addView(transfer);newAddress.setOnCheckedChangeListener((view,checked)->{transfer.setEnabled(!checked);if(checked)transfer.setChecked(false);});
        AlertDialog dialog=RookDialogs.builder(this).setTitle(entryMode?"Replace entry server":"Replace exit server").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Check server",null).create();dialog.show();secure(dialog);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{try{Gateway candidate=new Gateway();String host=address.getText().toString().trim(),user=login.getText().toString().trim();int sshPort=Integer.parseInt(port.getText().toString().trim());if(!InputRules.host(host)||!InputRules.username(user)||!InputRules.port(sshPort)||password.length()==0)throw new IOException("Enter the replacement address, administrator login, password and SSH port.");candidate.set("host",host);candidate.set("name",host);candidate.set("serverName",host);candidate.set("admin",user);candidate.data.put("port",sshPort).put("remember",remember.isChecked()).put("saveAccessChosen",true);candidate.sshPassword=password.getText().toString();if(PairNodes.same(pair,candidate)||PairNodes.same(pair.exit,candidate))throw new IOException("Choose a third server, separate from the current entry and exit.");dialog.dismiss();if(demo){demoNotice();return;}pairRead(pair,"Checking replacement server",()->{try(Ssh ssh=PairSsh.connectNode(candidate,entryMode?pair.exit:pair,this::pairReadProgress)){JSONObject probe=ssh.probe();String machine=probe.optString("machine");if(!machine.matches("[a-f0-9]{64}"))throw new IOException("The replacement server identity could not be verified");candidate.set("machine",machine);return probe;}},probe->{if(entryMode)reviewEntryReplacement(pair,candidate,probe,transfer.isChecked(),newAddress.isChecked());else reviewExitReplacement(pair,candidate,probe);});}catch(Exception e){address.setError(e.getMessage());}});
    }
    private void reviewEntryReplacement(Gateway pair,Gateway candidate,JSONObject probe,boolean transfer,boolean newAddress){
        try{UbuntuCompatibility.require(probe,true);JSONObject preview=EntryMigrationController.preview(pair,candidate,transfer,newAddress);LinearLayout f=form();f.addView(text("Current entry: "+pair.get("host"),14,INK,false));f.addView(text("Replacement entry: "+candidate.get("host"),15,INK,true));f.addView(text("Exit stays: "+pair.exit.get("host"),14,INK,false));space(f,12);f.addView(text("Saved client endpoint: "+preview.getString("endpoint"),15,INK,true));space(f,10);f.addView(text(preview.getString("reason"),14,preview.optBoolean("supported")?INK:RED,false));
            if(preview.optBoolean("supported"))f.addView(text(newAddress?"Stage the replacement, share or test the updated connection, then return here to finish. The original entry stays available until you accept.":"Stage the replacement first. Then change your DNS or transfer the reviewed address through your provider, test an unchanged client and return to finish. Existing internet sessions may reconnect.",14,MUTED,false));
            AlertDialog.Builder dialog=RookDialogs.builder(this).setTitle(preview.optBoolean("client_update_required")?"Updated client profiles are required":"Review entry replacement").setView(scrolling(f)).setNegativeButton("Cancel",null);if(preview.optBoolean("supported"))dialog.setPositiveButton("Stage replacement entry",(d,w)->startEntryMigration(pair,"stage",candidate,transfer,newAddress));dialog.show();
        }catch(Exception e){error(e);}
    }
    private void startEntryMigration(Gateway pair,String action,Gateway provided,boolean transfer){startEntryMigration(pair,action,provided,transfer,false);}
    private void startEntryMigration(Gateway pair,String action,Gateway provided,boolean transfer,boolean newAddress){
        if(busy||DeploymentService.active())return;Gateway candidate=provided;try{if(candidate==null){JSONObject recorded=pair.data.getJSONObject("entryMigration");candidate=new Gateway(recorded.getJSONObject("candidate"));transfer=recorded.optBoolean("endpoint_transfer");newAddress=recorded.optBoolean("new_address");}}catch(Exception e){error(e);return;}final Gateway target=candidate;final boolean transferable=transfer;final boolean changedAddress=newAddress;
        if(!hasAuth(pair)){passwordDialog(pair,()->startEntryMigration(pair,action,target,transferable,changedAddress));return;}if(!hasAuth(pair.exit)){passwordDialog(pair.exit,()->startEntryMigration(pair,action,target,transferable,changedAddress));return;}if(!hasAuth(target)){passwordDialog(target,()->startEntryMigration(pair,action,target,transferable,changedAddress));return;}
        try{DeploymentService.launch(this,pair,gateways,"lifecycle-entry",json("action",action,"endpoint_transfer",transferable,"new_address",changedAddress),pair.data.has("entryMigration"),target);openScreen("Progress");}catch(Exception e){error(e);}
    }
    private void testReplacementEntry(Gateway pair,JSONObject response){
        try{ConnectionExport profile=ConnectionExport.fromResponse(response);Gateway test=new Gateway();test.set("protocol",profile.protocol);test.set("name","Replacement entry test · "+SingleProtocols.from(profile.protocol).title);test.set("vpnLogin",PasswordSignIn.login(response));JSONObject operation=pair.data.getJSONObject("entryMigration");test.set("host",operation.getJSONObject("candidate").getString("host"));test.data.put("clientOnly",true);test.data.put("rememberVpn",true);String secret="";
            if(profile.protocol.equals("ikev2"))secret=response.getJSONObject("local").optString("shared_secret");else if(profile.protocol.equals("openvpn"))secret=response.optString("password");else if(profile.content.trim().startsWith("{"))secret=new JSONObject(profile.content).optString("password");test.vpnPassword=secret;
            Runnable ready=()->{gateways.add(test);save();openVpn(test);connectPhone(test);};
            if(profile.protocol.equals("ikev2")){installProfile(test,response);ready.run();}else if(profile.protocol.equals("openvpn")&&NativeProfiles.openVpnNeedsPassword(profile.content))nativePassword(test,profile.content,ready);else{new NativeProfileStore(this).save(test.get("id"),profile.protocol,test.get("name"),profile.content);ready.run();}
        }catch(Exception e){error(e);}
    }
    private void reviewExitReplacement(Gateway pair,Gateway candidate,JSONObject probe){
        try{UbuntuCompatibility.require(probe,true);}catch(Exception e){error(e);return;}
        LinearLayout f=form();f.addView(text("Entry stays: "+pair.get("host"),15,INK,true));f.addView(text("Old exit: "+pair.exit.get("host"),14,MUTED,false));f.addView(text("New exit: "+candidate.get("host"),15,INK,true));space(f,12);f.addView(text("Keeps entry users, listener and client profiles. Prepares the new exit, checks isolated routing and DNS, then switches the guarded route. Internet sessions may reconnect. You can roll back while the old exit remains available.",14,INK,false));space(f,10);f.addView(text("After switching, verify real client traffic and filtering before accepting the replacement.",14,RED,true));
        RookDialogs.builder(this).setTitle("Review exit replacement").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Prepare & switch exit",(d,w)->startLifecycle(pair,"replace",candidate)).show();
    }
    private void startLifecycle(Gateway pair,String action,Gateway candidate){
        if(busy||DeploymentService.active())return;
        if(!hasAuth(pair)){passwordDialog(pair,()->startLifecycle(pair,action,candidate));return;}if(pair.exit!=null&&!hasAuth(pair.exit)){passwordDialog(pair.exit,()->startLifecycle(pair,action,candidate));return;}if(candidate!=null&&!hasAuth(candidate)){passwordDialog(candidate,()->startLifecycle(pair,action,candidate));return;}
        try{DeploymentService.launch(this,pair,gateways,"lifecycle-exit",json("action",action),pair.data.has("lifecycleOperation"),candidate);openScreen("Progress");}catch(Exception e){error(e);}
    }
    private void resumeLifecycle(Gateway pair){try{JSONObject operation=pair.data.getJSONObject("lifecycleOperation");Gateway candidate=new Gateway(operation.getJSONObject("candidate"));startLifecycle(pair,"replace",candidate);}catch(Exception e){error(e);}}

    private void appendAdministrationActions(LinearLayout into,Gateway server){fullButton(into,"Administrators",false,()->openAdministrators(server));}
    private void openAdministrators(Gateway node){selected=node;openScreen("Administrators");if(node.data.optJSONObject("adminEnrollment")==null&&(node.data.optBoolean("adminEnabled")||node.data.optBoolean("adminAccess")))refreshAdministrators(node);}
    private boolean adminCapability(JSONObject state,String action){JSONArray capabilities=state==null?null:state.optJSONArray("capabilities");if(capabilities!=null)for(int i=0;i<capabilities.length();i++)if(action.equals(capabilities.optString(i)))return true;return false;}
    private String adminRole(String role){return role.equals("infrastructure")?"Infrastructure administrator":role.equals("user_manager")?"VPN user manager":role.equals("viewer")?"Viewer":"Owner";}
    private String adminObjectLabel(Gateway node,JSONObject object){String server=node.isPair()?(object.optString("server_id").equals(node.get("adminServerId"))?"Entry server":"Exit server"):"This server";return SingleProtocols.from(object.optString("protocol")).title+" · "+server;}
    private String adminScope(JSONObject scope){
        if(scope==null)return "All managed VPNs";String kind=scope.optString("kind"),label=kind.equals("protocol")?"One VPN protocol":kind.equals("deployment")?"This VPN deployment":"This server";
        JSONObject snapshot=selected==null?null:selected.data.optJSONObject("adminSnapshot");JSONArray objects=snapshot==null?null:snapshot.optJSONArray("objects");if(kind.equals("protocol")&&objects!=null)for(int i=0;i<objects.length();i++){JSONObject object=objects.optJSONObject(i);if(object!=null&&object.optString("id").equals(scope.optString("id"))){label=adminObjectLabel(selected,object);break;}}
        return label+(scope.optString("users").equals("own")?" · only users issued by this phone":" · all users in scope");
    }
    private void administratorsScreen(){
        Gateway node=selected;if(node==null){empty("Choose a server first.");return;}title("Administrators",ServerProtocols.name(node)+" · "+node.get("host"));
        if(node.data.optJSONObject("adminEnrollment")!=null){fullButton(body,"Resume invitation enrollment",true,()->acceptAdminInvitation(node.data.optJSONObject("adminEnrollment"),node));return;}
        if(!node.data.optBoolean("adminEnabled")&&!node.data.optBoolean("adminAccess")){LinearLayout c=card();c.addView(text("Share administrator access",20,INK,true));space(c,10);c.addView(text("Invite a phone to manage selected VPNs with its own restricted credential. Ordinary VPN sharing stays separate. Enabling this module keeps existing VPN users and listeners.",14,MUTED,false));fullButton(c,"Enable administrator sharing",true,()->confirm("Enable scoped administration?","Install the restricted management module using your owner access. This keeps current VPN users and connection profiles.",()->enableAdministrators(node)));return;}
        JSONObject state=node.data.optJSONObject("adminSnapshot");if(state==null){empty("Read current permissions to load administrator controls.");fullButton(body,"Refresh permissions",true,()->refreshAdministrators(node));return;}
        LinearLayout summary=card();summary.addView(text(adminRole(state.optString("role")),20,INK,true));space(summary,6);summary.addView(text(adminScope(state.optJSONObject("scope")),13,MUTED,false));space(summary,8);summary.addView(text(adminRoleDescription(state.optString("role")),13,MUTED,false));fullButton(summary,"Refresh permissions",false,()->refreshAdministrators(node));
        if(adminCapability(state,"invitations.manage"))fullButton(body,"Invite administrator",true,()->chooseAdminRole(node,null));
        if(!node.data.optBoolean("adminAccess")&&adminCapability(state,"peers.manage"))fullButton(body,"Inspect installed protocols",false,()->refreshAdminInventory(node));
        JSONArray objects=state.optJSONArray("objects");if(adminCapability(state,"users.read")&&objects!=null&&objects.length()>0){space(body,14);body.addView(text("VPN users in your scope",18,INK,true));for(int i=0;i<objects.length();i++){JSONObject object=objects.optJSONObject(i);if(object!=null){fullButton(body,adminObjectLabel(node,object),false,()->scopedUsers(node,object));if(adminCapability(state,"usage.read"))fullButton(body,"Usage · "+SingleProtocols.from(object.optString("protocol")).title,false,()->scopedUsage(node,object));if(adminCapability(state,"services.manage")&&object.optJSONObject("maintenance")!=null&&object.optJSONObject("maintenance").optBoolean("listener"))fullButton(body,"Maintain · "+SingleProtocols.from(object.optString("protocol")).title,false,()->scopedServiceMenu(node,object));if(adminCapability(state,"filtering.read")&&object.optJSONObject("maintenance")!=null&&object.optJSONObject("maintenance").optBoolean("filtering"))fullButton(body,"Ad blocking · "+SingleProtocols.from(object.optString("protocol")).title,false,()->scopedFiltering(node,object));}}}
        JSONObject access=state.optJSONObject("access");JSONArray devices=access==null?null:access.optJSONArray("devices");if(devices!=null){space(body,16);body.addView(text("Administrator devices",18,INK,true));for(int i=0;i<devices.length();i++){JSONObject device=devices.optJSONObject(i);if(device==null)continue;LinearLayout c=card();c.addView(text(device.optString("name","Administrator phone"),17,INK,true));c.addView(text(adminRole(device.optString("role"))+" · "+(device.optBoolean("revoked")?"Revoked":"Active"),13,MUTED,false));c.addView(text(adminScope(device.optJSONObject("scope")),12,MUTED,false));if(adminCapability(state,"grants.manage")&&!device.optBoolean("revoked")){fullButton(c,"Change role or scope",false,()->chooseAdminRole(node,device));fullButton(c,"Revoke administrator device",false,()->confirm("Revoke this administrator device?","New management requests lose this authority. Ordinary VPN accounts and profiles stay unchanged. Accepted work and unreachable peers may need reconciliation.",()->adminMutation(node,json("operation","devices.revoke","device_id",device.optString("id")))));}}}
        JSONArray invitations=access==null?null:access.optJSONArray("invitations");if(invitations!=null&&invitations.length()>0){body.addView(text("Invitations",18,INK,true));for(int i=0;i<invitations.length();i++){JSONObject invitation=invitations.optJSONObject(i);if(invitation==null||invitation.optBoolean("revoked"))continue;LinearLayout c=card();c.addView(text(adminRole(invitation.optString("role")),16,INK,true));c.addView(text("Expires "+android.text.format.DateFormat.getDateFormat(this).format(new Date(invitation.optLong("expires")*1000))+" · "+invitation.optString("id"),12,MUTED,false));if(adminCapability(state,"grants.manage"))fullButton(c,"Revoke invitation",false,()->confirm("Revoke this invitation?","This prevents a new phone from accepting this invitation. Existing VPN access stays unchanged.",()->adminMutation(node,json("operation","invitations.revoke","invitation_id",invitation.optString("id")))));}}
        if(adminCapability(state,"audit.read"))fullButton(body,"Administrator activity",false,()->withSsh(node,"Reading administrator activity",ssh->AdminAccessController.request(ssh,json("operation","audit.read")),this::showAdminAudit,""));
        if(!node.isPair()&&!node.data.optBoolean("adminAccess")&&adminCapability(state,"grants.manage"))fullButton(body,"Remove administrator sharing from this server",false,()->reviewRemoveAdministration(node));
        if(!node.data.optBoolean("adminAccess")&&adminCapability(state,"grants.manage"))fullButton(body,"Update administrator tools",false,()->confirm("Update administrator tools?","Install the version included in this app. Existing grants, enrolled phones and VPN users stay in place.",()->updateAdministrationTools(node)));
        if(node.data.optBoolean("adminAccess"))fullButton(body,"Remove administrator access from this phone",false,()->removeSavedVpn(node));
    }
    private JSONObject enableOwnerAdministration(Gateway node)throws Exception{
        if(node.isPair()){
            try(PairSsh ssh=PairSsh.connect(node,this::pairReadProgress)){
                JSONObject entryConfig=AdminAccessController.ownerEnableConfig(ssh.entry,node,node.get("pairId"));JSONObject exitConfig=AdminAccessController.ownerEnableConfig(ssh.exit,node.exit,node.get("pairId"));
                try(InputStream entry=getAssets().open("gateway_bundle.zip");InputStream exit=getAssets().open("gateway_bundle.zip")){
                    AdminAccessController.enable(ssh.entry,entry,entryConfig);AdminAccessController.rememberOwnerIdentity(node,entryConfig);
                    AdminAccessController.enable(ssh.exit,exit,exitConfig);AdminAccessController.rememberOwnerIdentity(node.exit,exitConfig);
                }
                return AdminAccessController.ensurePairLink(ssh.entry,ssh.exit,node,node.exit,node.get("pairId"));
            }
        }
        try(Ssh ssh=new Ssh(node);InputStream source=getAssets().open("gateway_bundle.zip")){
            JSONObject config=AdminAccessController.ownerEnableConfig(ssh,node,"");JSONObject result=AdminAccessController.enable(ssh,source,config);AdminAccessController.rememberOwnerIdentity(node,config);return result;
        }
    }
    private void enableAdministrators(Gateway node){
        pairRead(node,"Opening administrator sharing",()->enableOwnerAdministration(node),result->{try{node.data.put("adminEnabled",true);if(node.isPair())node.exit.data.put("adminEnabled",true);save();refreshAdministrators(node);}catch(Exception e){error(e);}});
    }
    private JSONObject refreshAdminInventory(Ssh ssh)throws Exception{JSONObject state=AdminAccessController.request(ssh,json("operation","capabilities"));return AdminAccessController.request(ssh,json("operation","inventory.refresh","expected_revision",state.getLong("revision")));}
    private void refreshAdminInventory(Gateway node){
        pairRead(node,"Inspecting administrator scope and installed protocols",()->{if(node.isPair()){try(PairSsh ssh=PairSsh.connect(node,this::pairReadProgress)){refreshAdminInventory(ssh.exit);return refreshAdminInventory(ssh.entry);}}try(Ssh ssh=new Ssh(node)){return refreshAdminInventory(ssh);}},result->refreshAdministrators(node));
    }
    private void updateAdministrationTools(Gateway node){
        pairRead(node,"Updating administrator tools",()->enableOwnerAdministration(node),result->refreshAdministrators(node));
    }
    private void refreshAdministrators(Gateway node){withSsh(node,"Reading current administrator permissions",ssh->{JSONObject state=AdminAccessController.request(ssh,json("operation","capabilities"));if(adminCapability(state,"access.read"))state.put("access",AdminAccessController.request(ssh,json("operation","access.list")));return state;},state->{try{node.data.put("adminSnapshot",state);save();}catch(Exception e){error(e);}},"");}
    private void adminMutation(Gateway node,JSONObject request){JSONObject reviewed=node.data.optJSONObject("adminSnapshot");if(reviewed==null){refreshAdministrators(node);return;}final long revision=reviewed.optLong("revision",-1);withSsh(node,"Updating administrator access",ssh->{request.put("expected_revision",revision);return AdminAccessController.request(ssh,request);},result->refreshAdministrators(node),"Administrator access updated");}
    private void chooseAdminRole(Gateway node,JSONObject device){String[] roles={"user_manager","viewer","infrastructure"},names={"VPN user manager","Viewer","Infrastructure administrator"};RookDialogs.builder(this).setTitle("Choose administrator role").setItems(names,(d,w)->chooseAdminScope(node,roles[w],device)).setNegativeButton("Cancel",null).show();}
    private void chooseAdminScope(Gateway node,String role,JSONObject device){
        JSONObject state=node.data.optJSONObject("adminSnapshot");JSONArray objects=state==null?null:state.optJSONArray("objects");ArrayList<JSONObject> scopes=new ArrayList<>();ArrayList<String> labels=new ArrayList<>();Set<String> added=new HashSet<>();
        if(objects!=null)for(int i=0;i<objects.length();i++){JSONObject object=objects.optJSONObject(i);if(object==null)continue;for(String kind:new String[]{"protocol","deployment","server"}){String id=kind.equals("protocol")?object.optString("id"):object.optString(kind+"_id");if(id.isEmpty()||!added.add(kind+":"+id))continue;scopes.add(json("kind",kind,"id",id,"users","own"));labels.add(kind.equals("protocol")?adminObjectLabel(node,object):kind.equals("deployment")?"This deployment · all its VPN protocols":"Selected server · all its VPN protocols");}}
        RookDialogs.builder(this).setTitle("Choose exact authority scope").setItems(labels.toArray(new String[0]),(d,w)->{JSONObject scope=scopes.get(w);RookDialogs.builder(this).setTitle("Which VPN users can they manage?").setItems(new String[]{"Only users issued by this phone","All users in the selected scope"},(choice,index)->{try{scope.put("users",index==0?"own":"all");reviewAdminGrant(node,role,scope,device);}catch(Exception e){error(e);}}).setNegativeButton("Cancel",null).show();}).setNegativeButton("Cancel",null).show();
    }
    private void reviewAdminGrant(Gateway node,String role,JSONObject scope,JSONObject device){
        String consequence=adminRole(role)+"\n"+adminScope(scope)+"\n\n"+adminRoleDescription(role)+"\n\n"+(device==null?"One phone can accept this invitation within one hour. It automatically receives its own management credential. No root password or ordinary VPN access is shared.":"New management requests will use this role and scope. Ordinary VPN access stays unchanged.");
        LinearLayout f=form();f.addView(text(consequence,14,INK,false));EditText name=device==null?field(f,"Administrator or device name","",false):null;
        AlertDialog dialog=RookDialogs.builder(this).setTitle(device==null?"Review administrator invitation":"Review authority change").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton(device==null?"Create invitation":"Apply authority",null).create();dialog.show();dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String label=name==null?"":name.getText().toString().trim();if(name!=null&&(label.isEmpty()||label.length()>80)){name.setError("Enter a name you will recognize, up to 80 characters");return;}dialog.dismiss();if(device==null){JSONObject reviewed=node.data.optJSONObject("adminSnapshot");long revision=reviewed==null?-1:reviewed.optLong("revision",-1);withSsh(node,"Creating one-use administrator invitation",ssh->AdminAccessController.request(ssh,json("operation","invitations.create","role",role,"scope",scope,"name",label,"ttl_seconds",3600,"expected_revision",revision)).getJSONObject("invitation"),this::shareAdminInvitation,"");}else adminMutation(node,json("operation","grants.update","grant_id",device.optString("grant_id"),"role",role,"scope",scope));});
    }
    private void shareAdminInvitation(JSONObject invitation){
        AlertDialog d=RookDialogs.builder(this).setTitle("Administrator invitation ready").setMessage("Share this one-use file privately with the intended administrator. It grants "+adminRole(invitation.optString("role"))+" authority, not a VPN connection. It expires in one hour.").setNegativeButton("Close",null).setNeutralButton("Save invitation file",(dialog,w)->{profileExport.invitation(invitation);startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE,"rookstride-administrator.rookadmin"),SAVE_ADMIN_INVITATION);}).setPositiveButton("Share invitation",(dialog,w)->{try{Uri uri=ProfileExportProvider.issue(this,"rookstride-administrator.rookadmin",invitation.toString());Intent share=new Intent(Intent.ACTION_SEND).setType("application/octet-stream").putExtra(Intent.EXTRA_STREAM,uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);share.setClipData(ClipData.newRawUri("Administrator invitation",uri));startActivity(Intent.createChooser(share,"Share administrator invitation"));}catch(Exception e){error(e);}}).create();d.show();secure(d);
    }
    private void finishAdminInvitationExport(int result,Intent data){
        JSONObject invitation=profileExport.takeInvitation();if(result!=RESULT_OK)return;
        if(invitation==null){error(new IOException("Invitation export expired. Create a new invitation or share it again."));return;}
        try{Uri uri=data==null?null:data.getData();if(uri==null||!"content".equals(uri.getScheme()))throw new IOException("Choose a document location.");try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Could not open the document.");out.write(invitation.toString().getBytes(StandardCharsets.UTF_8));}RookDialogs.builder(this).setTitle("Invitation file saved").setMessage("Give this one-use invitation privately to the intended administrator.").setPositiveButton("Done",null).show();}catch(Exception e){error(e);}
    }
    private void reviewAdminInvitation(JSONObject invitation){
        RookDialogs.builder(this).setTitle("Accept administrator invitation").setMessage(invitation.optJSONObject("endpoint").optString("host")+"\n"+adminRole(invitation.optString("role"))+"\n"+adminScope(invitation.optJSONObject("scope"))+"\n\nAccept only an invitation from the server owner you trust. This phone creates its own management credential. VPN connection access is separate.").setNegativeButton("Cancel",null).setPositiveButton("Accept invitation",(d,w)->acceptAdminInvitation(invitation,null)).show();
    }
    private void acceptAdminInvitation(JSONObject invitation,Gateway existing){
        if(busy||DeploymentService.active())return;busy=true;message="Enrolling this administrator phone";render();executor.execute(()->{Gateway draft=existing;try{if(draft==null){draft=AdminAccessController.deviceDraft(invitation);gateways.add(draft);vault.write(gateways);}new ServerIdentityPins(this).remember(draft,draft.get("fingerprint"));Gateway enrolled=AdminAccessController.accept(invitation,draft);vault.write(gateways);handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;message="";openAdministrators(enrolled);});}catch(Exception e){final Gateway retained=draft;handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;message="";if(retained!=null){selected=retained;openScreen("Administrators");}else render();showAdminEnrollmentFailure(invitation,retained,e);});}});
    }
    private void showAdminEnrollmentFailure(JSONObject invitation,Gateway draft,Exception failure){
        String code=ConnectionDiagnosis.code(failure);
        String detail=code.equals("ssh_sign_in_rejected")?"The invitation or this phone’s management key was not accepted. Ask the server owner to check that administrator sharing and this invitation are still valid. You do not need the server’s root password.":code.startsWith("ssh_identity")?"The server’s identity does not match this invitation. Ask the owner to review it; do not replace the saved identity to bypass this check.":code.startsWith("ssh_")?"This phone could not reach the invitation’s server. Check the current network and try again.":"Administrator enrollment could not finish. Ask the server owner to check this invitation if the problem continues.";
        if(draft!=null)detail+="\n\nThis phone’s saved enrollment and management key are kept. Resume uses the same invitation and key.";
        LinearLayout explanation=form();explanation.addView(text(detail,15,INK,false));
        AlertDialog.Builder dialog=RookDialogs.builder(this).setTitle("Administrator setup paused").setView(explanation);
        if(draft!=null&&!code.startsWith("ssh_identity"))dialog.setNegativeButton("Close",null).setPositiveButton("Continue setup",(d,w)->acceptAdminInvitation(invitation,draft));
        else dialog.setPositiveButton("Close",null);
        dialog.show();
    }
    private void showAdminAudit(JSONObject report){LinearLayout f=form();JSONArray events=report.optJSONArray("events");if(events!=null)for(int i=0;i<events.length();i++){JSONObject event=events.optJSONObject(i);if(event!=null){f.addView(text(event.optString("operation")+" · "+event.optString("result"),15,INK,true));f.addView(text((event.optLong("at")>0?java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT,java.text.DateFormat.SHORT).format(new java.util.Date(event.optLong("at")*1000))+" · ":"")+event.optString("actor")+" · "+event.optString("object_id"),12,MUTED,false));space(f,12);}}RookDialogs.builder(this).setTitle("Administrator activity").setView(scrolling(f)).setPositiveButton("Close",null).show();}
    private void scopedUsage(Gateway node,JSONObject object){withSsh(node,"Reading usage in your scope",ssh->AdminAccessController.request(ssh,json("operation","usage.read","object_id",object.optString("id"),"parameters",new JSONObject())),report->{LinearLayout f=form();f.addView(text("Operational estimates for the VPN users in your scope. Session and counter generations may restart; these are not billing records.",14,MUTED,false));JSONArray connections=report.optJSONArray("connections");if(connections==null||connections.length()==0)f.addView(text("No usage samples available in this scope.",14,INK,false));if(connections!=null)for(int i=0;i<connections.length();i++){JSONObject row=connections.optJSONObject(i);if(row==null)continue;space(f,12);f.addView(text(row.optString("user"),16,INK,true));f.addView(text("↑ "+formatBytes(row.optLong("upload"))+"  ↓ "+formatBytes(row.optLong("download")),14,INK,false));f.addView(text(row.optString("counter_scope")+" · generation "+row.optString("generation"),12,MUTED,false));}RookDialogs.builder(this).setTitle("Scoped VPN usage").setView(scrolling(f)).setPositiveButton("Close",null).show();},"");}
    private void reviewRemoveAdministration(Gateway node){withSsh(node,"Reviewing administrator sharing removal",ssh->AdminAccessController.request(ssh,json("operation","module.removal-plan")),plan->{RookDialogs.builder(this).setTitle("Remove administrator sharing?").setMessage("Remove the generated administrator accounts and invitation credentials on this server. Ordinary VPN users, VPN profiles and owner SSH access remain. This action is separate from revoking a VPN account.").setNegativeButton("Cancel",null).setPositiveButton("Remove sharing",(d,w)->withSsh(node,"Removing administrator sharing",ssh->AdminAccessController.request(ssh,json("operation","module.remove","token",plan.optString("token"),"confirmation","REMOVE ADMINISTRATION","expected_revision",plan.optLong("revision"))),result->{node.data.remove("adminEnabled");node.data.remove("adminSnapshot");save();render();},"Administrator sharing removed")).show();},"");}
    private void scopedUsers(Gateway node,JSONObject object){withSsh(node,"Reading scoped VPN users",ssh->AdminAccessController.request(ssh,json("operation","users.list","object_id",object.optString("id"),"parameters",new JSONObject())),result->{
        LinearLayout f=form();JSONObject state=node.data.optJSONObject("adminSnapshot");if(adminCapability(state,"users.create"))fullButton(f,"Add VPN user",true,()->scopedAddUser(node,object));JSONArray users=result.optJSONArray("users");if(users==null||users.length()==0)f.addView(text("No VPN users in your current scope.",14,MUTED,false));if(users!=null)for(int i=0;i<users.length();i++){JSONObject user=users.optJSONObject(i);if(user==null)continue;f.addView(text(user.optString("person",user.optString("login")),17,INK,true));f.addView(text(user.optString("login"),13,MUTED,false));if(adminCapability(state,"users.profile"))fullButtonFor("share-scoped:"+node.get("id")+":"+object.optString("id")+":"+user.optString("login"),f,"Share VPN connection",false,()->withSsh(node,"Preparing VPN connection",ssh->AdminAccessController.request(ssh,json("operation","users.profile","object_id",object.optString("id"),"parameters",json("login",user.optString("login")))),profile->shareScopedProfile(node,object,profile),""));if(adminCapability(state,"users.update"))fullButton(f,"Edit VPN user",false,()->scopedEditUser(node,object,user));if(adminCapability(state,"users.revoke"))fullButton(f,"Revoke VPN user",false,()->confirm("Revoke this VPN user?","Only this VPN account is revoked. Administrator authority is unchanged.",()->scopedMutation(node,object,"users.revoke",json("login",user.optString("login")))));space(f,12);}RookDialogs.builder(this).setTitle("VPN users · "+SingleProtocols.from(object.optString("protocol")).title).setView(scrolling(f)).setPositiveButton("Close",null).show();
    },"");}
    private void scopedMutation(Gateway node,JSONObject object,String action,JSONObject parameters){scopedMutation(node,object,action,parameters,false);}
    private void scopedMutation(Gateway node,JSONObject object,String action,JSONObject parameters,boolean restartReviewed){
        JSONObject updates=object.optJSONObject("user_updates");String change=action.equals("users.create")?"create":action.equals("users.update")?"update":"revoke";boolean restarts=(!action.equals("users.update")||parameters.has("password"))&&updates!=null&&updates.optString(change).equals("restart-review");
        if(restarts&&!restartReviewed){confirm("Review VPN user change",updates.optString("warning","This protocol may restart its listener. Other connected users may briefly reconnect."),()->scopedMutation(node,object,action,parameters,true));return;}
        String operationId=UUID.randomUUID().toString();boolean creating=action.equals("users.create");
        withSsh(node,"Updating scoped VPN users",ssh->{
            JSONObject current=AdminAccessController.request(ssh,json("operation","capabilities"));
            JSONObject request=json("operation",action,"object_id",object.optString("id"),"parameters",parameters,"expected_revision",current.getLong("revision"),"operation_id",operationId,"acknowledge_restart",restartReviewed);
            if(!creating)return AdminAccessController.request(ssh,request);
            newUserShare.begin(node.get("id"),parameters.optString("login"),parameters.optString("password"));newUserShare.scopedObject=new JSONObject(object.toString());
            try{AdminAccessController.request(ssh,request);newUserShare.confirmed=true;newUserShare.recent.remember(node.get("id"),object.optString("id"),newUserShare.login,newUserShare.password);loadCreatedProfile(ssh,node);}
            catch(Exception failure){rememberUserShareFailure(failure);/* Mutation confirmation survives recreation; only the profile read is retried. */}
            finally{newUserShare.loading=false;}
            return json("confirmed",newUserShare.confirmed);
        },result->{
            if(creating){message="";if(result.optBoolean("confirmed"))recordActivity("VPN user created",node);restoreCreatedUserShare();}
            else{if(action.equals("users.revoke")||parameters.has("password"))newUserShare.recent.forget(node.get("id"),object.optString("id"),parameters.optString("login"));if(parameters.has("password"))newUserShare.recent.remember(node.get("id"),object.optString("id"),parameters.optString("login"),parameters.optString("password"));scopedUsers(node,object);}
        },creating?"":"VPN user updated");
    }

    private String adminRoleDescription(String role){
        if(role.equals("infrastructure"))return "Manage users and reviewed listener maintenance within this scope. Shared ad blocking requires permission for every VPN using it. Full server wipes, installation and route replacement stay with the owner.";
        if(role.equals("user_manager"))return "Create, edit, share and revoke the VPN users allowed by this scope. Server maintenance and administrator invitations stay with the owner.";
        if(role.equals("viewer"))return "Read users, usage and activity in this scope. Cannot export access or change the server.";
        return "Owner access controls server setup, maintenance and administrator permissions.";
    }
    private void scopedEditUser(Gateway node,JSONObject object,JSONObject user){
        LinearLayout f=form();f.addView(text(user.optString("login"),17,INK,true));EditText person=field(f,"Name",user.optString("person"),false),device=field(f,"Device",user.optString("device"),false);f.addView(text("Leave a label empty to keep its current value.",13,MUTED,false));
        boolean passwordSupported=AdminAccessController.passwordUsers(object);EditText password=passwordSupported?field(f,"New VPN password (optional)","",true):null;
        if(password!=null)f.addView(text("Leave empty to keep the current password. This does not rename the username.",13,MUTED,false));
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Edit VPN user").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();dialog.show();secure(dialog);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{if(password!=null&&!password.getText().toString().isEmpty()&&!acceptPasswordAdvice(password,()->dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()))return;try{JSONObject parameters=AdminAccessController.editUserParameters(object,user.optString("login"),person.getText().toString(),device.getText().toString(),password==null?"":password.getText().toString());dialog.dismiss();scopedMutation(node,object,"users.update",parameters);}catch(Exception e){error(e);}});
    }
    private void scopedServiceMenu(Gateway node,JSONObject object){
        RookDialogs.builder(this).setTitle("Maintain "+SingleProtocols.from(object.optString("protocol")).title).setMessage("Restart the owned listener, or restore its saved configuration. Accounts and profiles are kept. Double VPN routing maintenance and IKEv2 system-service repairs require the owner.").setNegativeButton("Close",null).setNeutralButton("Review repair",(d,w)->reviewScopedMaintenance(node,object,"services",json("action","repair"))).setPositiveButton("Review restart",(d,w)->reviewScopedMaintenance(node,object,"services",json("action","restart"))).show();
    }
    private void scopedFiltering(Gateway node,JSONObject object){
        withSsh(node,"Reading shared ad blocking",ssh->AdminAccessController.request(ssh,json("operation","filtering.read","object_id",object.optString("id"),"parameters",new JSONObject())),result->{LinearLayout f=form();boolean enabled=result.optBoolean("protection_enabled",true);f.addView(text(enabled?"Ad blocking is on":"Ad blocking is paused",18,INK,true));f.addView(text("Applies to all VPNs sharing this resolver. Your permission must cover each of them.",14,MUTED,false));JSONObject state=node.data.optJSONObject("adminSnapshot");if(adminCapability(state,"filtering.manage")){fullButton(f,enabled?"Pause ad blocking":"Turn on ad blocking",false,()->reviewScopedMaintenance(node,object,"filtering",json("enabled",!enabled)));String[] values={"standard","strong","strict"},labels={"Standard","Strong","Strict"};for(int i=0;i<values.length;i++){String level=values[i];fullButton(f,labels[i],false,()->reviewScopedMaintenance(node,object,"filtering",json("level",level)));}}RookDialogs.builder(this).setTitle("Shared ad blocking").setView(scrolling(f)).setPositiveButton("Close",null).show();},"");
    }
    private void reviewScopedMaintenance(Gateway node,JSONObject object,String group,JSONObject parameters){
        withSsh(node,"Preparing a reviewed server change",ssh->AdminAccessController.request(ssh,json("operation",group+".review","object_id",object.optString("id"),"parameters",parameters)),review->{LinearLayout f=form();f.addView(text(SingleProtocols.from(object.optString("protocol")).title+" · "+ServerProtocols.name(node),17,INK,true));space(f,10);f.addView(text(review.optString("message"),14,INK,false));JSONArray affected=review.optJSONArray("affected");if(affected!=null){space(f,10);for(int i=0;i<affected.length();i++){JSONObject consumer=affected.optJSONObject(i);if(consumer!=null)f.addView(text(SingleProtocols.from(consumer.optString("protocol")).title,14,MUTED,false));}}RookDialogs.builder(this).setTitle("Review server change").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Apply change",(d,w)->withSsh(node,"Applying reviewed server change",ssh->AdminAccessController.request(ssh,json("operation",group+".apply","object_id",object.optString("id"),"parameters",json("review_token",review.getString("review_token")),"expected_revision",review.getLong("revision"),"operation_id",UUID.randomUUID().toString())),result->{recordActivity(group.equals("services")?"VPN service maintained":"Ad blocking updated",node);refreshAdministrators(node);},"Server change completed")).show();},"");
    }

    private void scopedAddUser(Gateway node,JSONObject object){if(newUserShare.pending){restoreCreatedUserShare();return;}LinearLayout f=form();EditText login=field(f,"VPN username","",false);boolean needsPassword=AdminAccessController.passwordUsers(object);EditText password=needsPassword?field(f,"VPN password",generatedPassword(),true):null;AlertDialog d=RookDialogs.builder(this).setTitle("Add VPN user").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Create user",null).create();d.show();secure(d);d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String user=login.getText().toString().trim();if(!InputRules.username(user)){login.setError("Enter a valid VPN username");return;}if(needsPassword&&!acceptPasswordAdvice(password,()->d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()))return;try{JSONObject parameters=AdminAccessController.newUserParameters(object,user,password==null?"":password.getText().toString());d.dismiss();scopedMutation(node,object,"users.create",parameters);}catch(Exception failure){error(failure);}});}

    private void appendPairRebuildActions(LinearLayout into,Gateway server){
        if(server.data.optJSONObject("pairedOsOperation")!=null)fullButton(into,"Resume both-server reinstall",false,()->resumePairedOs(server));
        else{fullButton(into,"Wipe both servers & reinstall Ubuntu",false,()->choosePairOs(server));if(PairController.modern(server))fullButton(into,"Rebuild & restore from recovery package",false,()->pickRecovery(server,"restore"));}
    }
    private void choosePairOs(Gateway pair){choosePairOs(pair,null);}
    private void choosePairOs(Gateway pair,JSONObject archive){
        if(!directOsNetwork())return;
        LinearLayout f=form();f.addView(text(archive==null?"Erase both system disks one at a time. All VPNs, applications, users and administrator grants on those disks are removed. The usable management relay is kept until the dependent server returns.":"Erase both disks, then restore only this reviewed Double VPN's identities, users and policy. Other VPNs and applications on those disks are erased. Administrator grants and SSH identities are replaced.",14,INK,false));
        String[] versions={"24.04","22.04","26.04"};Spinner entryVersion=osVersionSpinner(f,"Entry Ubuntu version",versions),exitVersion=osVersionSpinner(f,"Exit Ubuntu version",versions);
        CheckBox independent=new CheckBox(this);independent.setText("I have independent SSH or provider rescue access, with all phone VPNs disconnected");independent.setMinHeight(dp(48));f.addView(independent);
        AlertDialog dialog=RookDialogs.builder(this).setTitle(archive==null?"Clean rebuild of both servers":"Rebuild & restore both servers").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Check & prepare review",null).create();dialog.show();Button next=dialog.getButton(AlertDialog.BUTTON_POSITIVE);next.setEnabled(false);independent.setOnCheckedChangeListener((v,on)->next.setEnabled(on));next.setOnClickListener(v->{if(!directOsNetwork())return;String entry=versions[entryVersion.getSelectedItemPosition()],exit=versions[exitVersion.getSelectedItemPosition()];dialog.dismiss();pairRead(pair,"Checking both reinstall plans",()->{OsWipeNetwork.requireDirect(this);return archive==null?PairedOsReinstall.prepare(pair,entry,exit,true,()->getAssets().open("reinstall_bundle.zip"),this::pairReadProgress):PairedOsReinstall.prepareRestore(pair,entry,exit,true,archive,()->getAssets().open("reinstall_bundle.zip"),()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress);},plan->reviewPairOs(pair,plan,archive));});
    }
    private Spinner osVersionSpinner(LinearLayout into,String label,String[] versions){into.addView(text(label,13,MUTED,true));Spinner choice=new Spinner(this);choice.setTag(label);choice.setContentDescription(label);choice.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,versions));choice.setMinimumHeight(dp(48));into.addView(choice);return choice;}
    private boolean directOsNetwork(){try{OsWipeNetwork.requireDirect(this);return true;}catch(IllegalStateException e){error(e);return false;}}
    private void reviewPairOs(Gateway pair,JSONObject plan){reviewPairOs(pair,plan,null);}
    private void reviewPairOs(Gateway pair,JSONObject plan,JSONObject archive){
        try{LinearLayout f=form();f.addView(text(plan.getString("warning"),15,RED,true));f.addView(text("Erase order: "+plan.getJSONArray("order").join(" → ").replace("\"",""),15,INK,true));
            for(String role:new String[]{"entry","exit"}){JSONObject node=plan.getJSONObject("plans").getJSONObject(role);space(f,14);f.addView(text(role.equals("entry")?"Entry · "+pair.get("host"):"Exit · "+pair.exit.get("host"),16,INK,true));f.addView(text("Ubuntu "+node.optString("version")+" · disk "+node.optString("disk",node.optString("target_disk")),14,INK,false));f.addView(text("Planned SSH identity: "+node.optString("fingerprint"),12,MUTED,false));}
            space(f,12);CheckBox accept=new CheckBox(this);accept.setText("Erase both reviewed system disks and their VPN data");accept.setMinHeight(dp(48));f.addView(accept);
            AlertDialog d=RookDialogs.builder(this).setTitle("Review both-server disk wipe").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Erase & reinstall both",null).create();d.show();Button go=d.getButton(AlertDialog.BUTTON_POSITIVE);go.setEnabled(false);accept.setOnCheckedChangeListener((v,on)->go.setEnabled(on));go.setOnClickListener(v->{d.dismiss();if(archive==null)startDeployment(pair,"paired-os",plan,false);else startPairedRestore(pair,plan,archive,false);});
        }catch(Exception e){error(e);}
    }

    private void pickRecovery(Gateway pair,String purpose){recoveryServerId=pair.get("id");recoveryPurpose=purpose;startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),PICK_RECOVERY);}
    private void recoveryPassword(Gateway pair,JSONObject archive){
        LinearLayout f=form();f.addView(text("This owner package contains VPN identities and user credentials. Choose a separate recovery password and keep it somewhere safe. Anyone with both the file and password can recover this VPN.",14,INK,false));EditText password=field(f,"Recovery password · at least 12 characters","",true),repeat=field(f,"Repeat recovery password","",true);
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Encrypt owner recovery package").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Encrypt & save",null).create();dialog.show();secure(dialog);dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String secret=password.getText().toString();if(secret.length()<12||!secret.equals(repeat.getText().toString())){repeat.setError("Use matching passwords of at least 12 characters");return;}char[] key=secret.toCharArray();password.setText("");repeat.setText("");dialog.dismiss();busy=true;message="Encrypting owner recovery package";render();executor.execute(()->{try{byte[] bytes=OwnerRecovery.encrypt(archive,key);handler.post(()->{if(isDestroyed()||isFinishing()){Arrays.fill(bytes,(byte)0);return;}busy=false;message="";encryptedRecoveryExport=bytes;recoveryServerId=pair.get("id");startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"rookstride-owner.rookrecovery"),SAVE_RECOVERY);render();});}catch(Exception e){handler.post(()->{busy=false;message="";render();error(e);});}finally{Arrays.fill(key,'\0');}});});
    }
    private void finishRecoveryExport(int result,Intent intent){byte[] bytes=encryptedRecoveryExport;encryptedRecoveryExport=null;if(bytes==null){if(result==RESULT_OK)error(new IOException("The export expired. Create the recovery package again."));return;}try{if(result!=RESULT_OK)return;Uri uri=intent==null?null:intent.getData();if(uri==null||!"content".equals(uri.getScheme()))throw new IOException("Choose a document destination.");try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Cannot open the selected document");out.write(bytes);}for(Gateway node:gateways)if(node.get("id").equals(recoveryServerId))node.data.put("recoveryExportedAt",System.currentTimeMillis());save();Toast.makeText(this,"Encrypted owner recovery package saved",Toast.LENGTH_LONG).show();}catch(Exception e){error(e);}finally{Arrays.fill(bytes,(byte)0);}}
    private void decryptRecovery(Gateway pair,byte[] envelope,String purpose){
        LinearLayout f=form();f.addView(text("The package must match this Double VPN. Checking it validates saved identity material; it does not prove a live restore on another server.",14,INK,false));EditText password=field(f,"Recovery password","",true);AlertDialog d=RookDialogs.builder(this).setTitle("Open owner recovery package").setView(scrolling(f)).setNegativeButton("Cancel",(dialog,w)->Arrays.fill(envelope,(byte)0)).setPositiveButton("Decrypt & check",null).create();d.show();secure(d);d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{char[] key=password.getText().toString().toCharArray();password.setText("");d.dismiss();busy=true;message="Checking recovery package";render();executor.execute(()->{try{JSONObject archive=OwnerRecovery.decrypt(envelope,key,pair.get("pairId"));handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;message="";if(purpose.equals("resume"))startPairedRestore(pair,pair.data.optJSONObject("pairedOsOperation"),archive,true);else if(purpose.equals("restore"))choosePairOs(pair,archive);else pairRead(pair,"Checking recovery material on both servers",()->OwnerRecovery.rehearse(pair,archive,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),report->RookDialogs.builder(this).setTitle("Recovery material checked").setMessage("The package decrypts, matches both deployment members and contains the required identity material. A live restore on disposable nodes remains a separate test.").setPositiveButton("Done",null).show());});}catch(Exception e){handler.post(()->{busy=false;message="";render();error(new IOException("The recovery package could not be opened for this deployment. Check its password and file.",e));});}finally{Arrays.fill(key,'\0');Arrays.fill(envelope,(byte)0);}});});
    }
    private void resumePairedOs(Gateway pair){JSONObject operation=pair.data.optJSONObject("pairedOsOperation");if(operation!=null&&operation.optString("mode").equals("restore"))pickRecovery(pair,"resume");else startDeployment(pair,"paired-os",operation,true);}
    private void startPairedRestore(Gateway pair,JSONObject plan,JSONObject archive,boolean resume){
        if(busy||DeploymentService.active())return;if(!hasAuth(pair)){passwordDialog(pair,()->startPairedRestore(pair,plan,archive,resume));return;}if(!hasAuth(pair.exit)){passwordDialog(pair.exit,()->startPairedRestore(pair,plan,archive,resume));return;}
        try{DeploymentService.launchRecovery(this,pair,gateways,plan,resume,archive);openScreen("Progress");}catch(Exception e){error(e);}
    }
    private void forgetQuickConnection(Gateway node){
        QuickConnections.forget(node);android.content.SharedPreferences prefs=getSharedPreferences("rookstride-ui",0);if(prefs.getString("lastConnectedId","").equals(node.get("id")))prefs.edit().remove("lastConnectedId").apply();
    }
    private void forgetVpn(Gateway node)throws Exception{
        newUserShare.recent.forget(node.get("id"));forgetQuickConnection(node);invalidatePhoneProfile(node);DeploymentService.forget(this,node);gateways.remove(node);
    }
    private void removedFromPhone(Gateway removed)throws Exception{
        vault.write(gateways);ServerIdentityPins pins=new ServerIdentityPins(this);if(!clientOnly(removed)){pins.forgetIfUnreferenced(removed,gateways);if(removed.exit!=null)pins.forgetIfUnreferenced(removed.exit,gateways);}
        selected=null;pendingServerId="";navigation.root("Home");tab="Home";render();
    }
    private void removeSavedVpn(Gateway node){
        confirm(node.isPair()?"Remove Double VPN from this phone?":"Remove from this phone?",node.isPair()?"This Double VPN and its saved entry/exit access will be removed from this phone. Both servers and other devices keep running.":"The server and other devices keep their access.",()->{try{forgetVpn(node);removedFromPhone(node);}catch(Exception e){error(e);}});
    }
    private void removeSavedServer(Gateway server){
        confirm("Remove server from this phone?","All saved connections and administrator access for this server will be removed from this phone. The server keeps running.",()->{
            try{for(Gateway node:new ArrayList<>(gateways))if(ServerProtocols.sameServer(server,node))forgetVpn(node);removedFromPhone(server);}catch(Exception e){error(e);}
        });
    }
    private void peopleScreen() {
        title("VPN users",selected==null?"":SingleProtocols.from(selected.get("protocol")).title+" · "+ServerProtocols.name(selected));
        if(selected==null) {empty(t("Add a gateway first."));return;}
        JSONObject s=snapshot();JSONArray users=s.optJSONArray("users");
        if(otherProtocol(selected)&&PasswordSignIn.supported(selected.get("protocol"))&&!passwordUsers(selected))body.addView(text("This installation uses a connection file. Reinstall in username/password mode to share reusable sign-in details.",13,MUTED,false));
        fullButton(body,"Add new user",true,()->addUser(selected));space(body,18);
        if(users==null || users.length()==0) {empty("No users loaded. Refresh users to load accounts and status.");return;}
        Map<String,long[]> usage=new HashMap<>();JSONArray monthly=s.optJSONArray("monthly");
        if(monthly!=null) for(int i=0;i<monthly.length();i++) {JSONObject u=monthly.optJSONObject(i);if(u!=null) usage.put(u.optString("user"),new long[]{u.optLong("upload"),u.optLong("download")});}
        ArrayList<JSONObject> accounts=new ArrayList<>();for(int i=0;i<users.length();i++)if(users.optJSONObject(i)!=null)accounts.add(users.optJSONObject(i));
        accounts.sort(Comparator.comparing(u->u.optString("person",u.optString("login")).toLowerCase(Locale.ROOT)+" "+u.optString("device")));
        for(JSONObject u:accounts){
            LinearLayout c=card();String login=u.optString("login");c.addView(text(u.optString("person",login),22,INK,true));c.addView(text(u.optString("device",login)+" · "+login,13,MUTED,false));
            int active=0;JSONArray cs=s.optJSONArray("connections");if(cs!=null)for(int i=0;i<cs.length();i++)if(cs.optJSONObject(i)!=null&&login.equals(cs.optJSONObject(i).optString("user")))active++;
            if(!otherProtocol(selected)){space(c,8);c.addView(text(active>0?active+" online":"Offline",13,MUTED,false));long[] bytes=usage.get(login);if(bytes!=null)c.addView(text("↑ "+formatBytes(bytes[0])+"  ↓ "+formatBytes(bytes[1])+" this month",13,MUTED,false));}
            if(otherProtocol(selected)&&s.optBoolean("monitoring_available")){JSONArray peers=s.optJSONArray("connections");if(peers!=null)for(int n=0;n<peers.length();n++){JSONObject peer=peers.optJSONObject(n);if(peer!=null&&login.equals(peer.optString("user"))){space(c,8);String kind=s.optString("statistics_kind","handshake");c.addView(text(kind.equals("sessions")?peer.optInt("sessions")+" active sessions":kind.equals("traffic")?"Current traffic totals":peer.optBoolean("recent")?"Recent handshake":"No recent handshake",13,MUTED,false));String scope=s.optString("statistics_scope").equals("active-sessions")?"active connections":"current server VPN";c.addView(text("↑ "+formatBytes(peer.optLong("upload"))+"  ↓ "+formatBytes(peer.optLong("download"))+" · "+scope,13,MUTED,false));}}}
            space(c,12);LinearLayout actions=row();actions.setBaselineAligned(false);actions.addView(button("Edit",false,()->editUser(selected,u)),new LinearLayout.LayoutParams(0,-1,1));
            LinearLayout.LayoutParams ap=new LinearLayout.LayoutParams(0,-1,1);ap.leftMargin=dp(10);actions.addView(actionButton("share-user:"+selected.get("id")+":"+selected.get("serverInstance")+":"+u.optString("login"),"Share access",false,()->shareUserAccess(selected,u)),ap);c.addView(actions);
            swipeCard(c,login,()->removeUser(selected,u));
        }
        if(!otherProtocol(selected)&&!s.optBoolean("statistics_enabled")) body.addView(text(t("Monthly history is disabled. Live session counters remain available."),13,MUTED,false));
        fullButton(body,"Refresh users",false,()->refreshUsers(selected));
    }
    private void moduleAction(LinearLayout row,String title,int icon,Runnable action){
        boolean loading=busy&&title.equals(pendingModule);android.widget.FrameLayout control=new android.widget.FrameLayout(this);control.setTag("module-"+title);control.setMinimumHeight(dp(76));control.setPadding(dp(12),dp(14),dp(12),dp(14));control.setBackground(new android.graphics.drawable.RippleDrawable(android.content.res.ColorStateList.valueOf(Color.argb(40,207,36,47)),loading?shape(Color.rgb(255,232,234),12):surface(12),shape(Color.WHITE,12)));
        LinearLayout content=row();content.setGravity(Gravity.CENTER_VERTICAL);ImageView image=new ImageView(this);image.setImageResource(icon);image.setColorFilter(loading?RED:INK);image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);content.addView(image,new LinearLayout.LayoutParams(dp(30),dp(30)));View gap=new View(this);content.addView(gap,new LinearLayout.LayoutParams(dp(10),1));LinearLayout words=stack();TextView label=text(title,14,INK,true);words.addView(label);TextView detail=text(loading?moduleWaitCopy():"",12,MUTED,false);detail.setMinLines(1);if(loading){moduleWaitLabel=detail;moduleWaitLabel.setTag("module-wait-time");}else detail.setVisibility(View.INVISIBLE);words.addView(detail);content.addView(words,new LinearLayout.LayoutParams(0,-2,1));control.addView(content,new android.widget.FrameLayout.LayoutParams(-1,-2,Gravity.CENTER));
        if(loading){image.setVisibility(View.INVISIBLE);ProgressBar spinner=new ProgressBar(this);spinner.setIndeterminateTintList(android.content.res.ColorStateList.valueOf(RED));android.widget.FrameLayout.LayoutParams sp=new android.widget.FrameLayout.LayoutParams(dp(28),dp(28),Gravity.CENTER_VERTICAL|Gravity.START);control.addView(spinner,sp);control.setContentDescription(title+", loading");}else control.setContentDescription(title);
        control.setFocusable(true);control.setEnabled((title.equals("Logs")||title.equals("View log"))||!busy&&!DeploymentService.active());control.setOnClickListener(v->{if(!(title.equals("Logs")||title.equals("View log"))&&(busy||DeploymentService.active()))return;if(!(title.equals("Logs")||title.equals("View log"))){control.requestRectangleOnScreen(new android.graphics.Rect(0,0,control.getWidth(),control.getHeight()),true);pendingModule=title;}try{action.run();}finally{if(!busy)pendingModule="";}});LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,-1,1);if(row.getChildCount()>0)p.leftMargin=dp(10);row.addView(control,p);
    }
    private void showProtocolLog(Gateway node){if(otherProtocol(node))nativeDetails(node);else startActivity(new Intent(this,LogActivity.class));}
    private VpnDiagnosis.Result vpnDiagnosis(Gateway node){
        if(otherProtocol(node)){NativeVpn.Status status=NativeVpn.status(this,node.get("protocol"));if(!status.id.equals(node.get("id")))return VpnDiagnosis.of("vpn_unknown");try{return VpnDiagnosis.fromReport(new JSONObject(status.diagnostic));}catch(Exception ignored){return VpnDiagnosis.of("vpn_unknown");}}
        if(vpn!=null&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(node.get("profileUuid")))return VpnDiagnosis.ikev2(vpn.getErrorState().name());return VpnDiagnosis.of("vpn_unknown");
    }
    private void showVpnDiagnosis(Gateway node){
        VpnDiagnosis.Result result=vpnDiagnosis(node);LinearLayout content=(LinearLayout)messageBody(result.detail+"\n\n"+result.nextAction+".");AlertDialog[] dialog={null};space(content,12);fullButton(content,"View log",false,()->{dialog[0].dismiss();showProtocolLog(node);});fullButton(content,"Support report",false,()->{dialog[0].dismiss();reviewVpnSupportReport(node,result);});dialog[0]=RookDialogs.builder(this).setTitle(result.title).setView(content).setPositiveButton("Close",null).create();dialog[0].show();
    }
    private void reviewVpnSupportReport(Gateway node,VpnDiagnosis.Result result){
        try{String report=result.supportReport(node.get("protocol"),Build.VERSION.SDK_INT).toString(2);LinearLayout f=form();f.addView(text("Includes the connection type, Android version and check result. Server addresses, users, passwords, keys and browsing history are excluded.",14,INK,false));space(f,12);TextView content=text(report,13,MUTED,false);content.setTextIsSelectable(true);f.addView(content);RookDialogs.builder(this).setTitle("Review support report").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Share report",(d,w)->startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,report),"Share connection diagnosis"))).show();}catch(Exception e){error(e);}
    }
    private void connectionsScreen() {
        title("Connection statistics",selected==null?"":SingleProtocols.from(selected.get("protocol")).title+" · "+ServerProtocols.name(selected));
        if(selected==null){empty("Choose a VPN first.");return;}
        statisticsUpdated=text("",13,MUTED,false);statisticsUpdated.setTag("statistics-freshness");body.addView(statisticsUpdated);space(body,8);updateStatisticsLabel();
        statisticsHost=stack();statisticsHost.setTag("statistics-content");body.addView(statisticsHost);renderStatistics();
        fullButton(body,"Refresh statistics",false,()->refreshStatistics(true));
    }
    private void renderStatistics(){
        if(statisticsHost==null||selected==null)return;LinearLayout original=body;body=statisticsHost;body.removeAllViews();try{statisticsContent();}finally{body=original;}updateStatisticsLabel();
    }
    private void updateStatisticsLabel(){
        if(statisticsUpdated==null||selected==null)return;
        long checked=selected.data.optLong("statisticsCheckedAt");String when=checked>0?"Checked "+new java.text.SimpleDateFormat("HH:mm:ss",Locale.ENGLISH).format(new Date(checked)):"Saved snapshot";
        statisticsUpdated.setText(statisticsLoading?"Updating statistics…":!statisticsIssue.isEmpty()?statisticsIssue+" · "+when:demo?"Sample statistics":when+" · Updates when opened and every 5 minutes");
    }
    private void refreshStatistics(boolean manual){
        if(selected==null||!tab.equals("Sessions")||statisticsLoading||busy||DeploymentService.active())return;
        final Gateway node=selected;
        if(demo){if(manual)demoNotice();return;}
        if(!hasAuth(node)||node.sshRelay!=null&&!hasAuth(node.sshRelay)){
            statisticsPaused=true;statisticsIssue="Sign in to update statistics";updateStatisticsLabel();
            if(manual)passwordDialog(!hasAuth(node)?node:node.sshRelay,()->refreshStatistics(true));return;
        }
        if(!manual&&(node.get("fingerprint").isEmpty()||node.sshRelay!=null&&node.sshRelay.get("fingerprint").isEmpty())){statisticsPaused=true;statisticsIssue="Refresh to verify server access";updateStatisticsLabel();return;}
        statisticsPaused=false;statisticsLoading=true;statisticsIssue="";statisticsAttempt=SystemClock.elapsedRealtime();final int epoch=statisticsEpoch;updateStatisticsLabel();
        executor.execute(()->{
            try{
                JSONObject result=statisticsSource.read(node);
                handler.post(()->{statisticsLoading=false;if(!resumed||epoch!=statisticsEpoch||selected!=node||!tab.equals("Sessions"))return;
                    try{node.data.put("snapshot",result);node.data.put("statisticsCheckedAt",System.currentTimeMillis());save();renderStatistics();if(manual){recordActivity("Statistics refreshed",node);if(!busy&&!DeploymentService.active())showStatisticsFeedback();}}catch(Exception e){statisticsIssue="Statistics could not be saved";updateStatisticsLabel();}
                });
            }catch(Exception e){handler.post(()->{statisticsLoading=false;if(!resumed||epoch!=statisticsEpoch||selected!=node||!tab.equals("Sessions"))return;statisticsIssue="Could not update · try Refresh";statisticsPaused=true;updateStatisticsLabel();if(manual){recordActivity("Statistics refresh failed",node);if(e instanceof Ssh.HostTrust)trust(node,(Ssh.HostTrust)e,()->refreshStatistics(true));else error(e);}});}
        });
    }
    private JSONObject readStatistics(Gateway node)throws Exception{
        try(Ssh ssh=new Ssh(node)){
            // Existing installations can retain an older current helper. Stage the
            // same reviewed read-only adapter used by an explicit protocol refresh.
            if(otherProtocol(node))try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,json("action","status","protocol",node.get("protocol")));}
            return ssh.admin(json("action","status"));
        }
    }
    private void showStatisticsFeedback(){
        message="Statistics refreshed";noticeDeadline=0;
        if(operationNotice!=null&&operationNotice.getParent() instanceof ViewGroup)((ViewGroup)operationNotice.getParent()).removeView(operationNotice);
        operationFeedback();root.removeView(operationNotice);root.addView(operationNotice,root.indexOfChild(progressHost));
    }
    private void statisticsContent(){
        JSONObject s=snapshot();JSONArray cs=s.optJSONArray("connections");
        if(otherProtocol(selected)){
            String kind=s.optString("statistics_kind","handshake");boolean sessions=kind.equals("sessions"),traffic=kind.equals("traffic"),available=s.optBoolean("monitoring_available");
            body.addView(text(available?(traffic?"Traffic by user":s.optInt("recent_peers")+(sessions?" users active now":" active recently")):"Statistics could not be read. Try Refresh.",16,INK,true));
            body.addView(text(available?(s.optString("statistics_scope").equals("active-sessions")?"Traffic covers active connections and starts again when they reconnect. Shared profiles count as one user.":sessions?"Active sessions are network connections, not a count of devices. Totals reset when the server VPN restarts.":traffic?"Totals cover the current server VPN process and reset on restart. Shared profiles count as one user.":"Handshake within 3 minutes. Traffic totals reset when this server VPN restarts; shared profiles count as one user."):"The VPN may still be running. Check server access and refresh these numbers.",13,MUTED,false));
            if(available){usageTotals("Reported traffic",cs,s.optString("statistics_scope").equals("active-sessions")?"Active connections only":"Since the current VPN counters started");}
            if(available&&cs!=null)for(int i=0;i<cs.length();i++){JSONObject peer=cs.optJSONObject(i);if(peer==null)continue;LinearLayout panel=card();panel.addView(text(peer.optString("user"),20,INK,true));panel.addView(text(sessions?peer.optInt("sessions")+" active sessions":traffic?"Current traffic totals":peer.optBoolean("recent")?"Recent handshake":"No recent handshake",14,MUTED,false));usageAmounts(panel,peer);}
            return;
        }
        JSONArray monthly=s.optJSONArray("monthly");
        usageTotals("This month",monthly,"Recorded usage, including users who are offline");
        if(monthly!=null)for(int i=0;i<monthly.length();i++){JSONObject user=monthly.optJSONObject(i);if(user==null)continue;LinearLayout panel=card();panel.addView(text(user.optString("user"),17,INK,true));panel.addView(text("Recorded this month",12,MUTED,false));usageAmounts(panel,user);}
        space(body,12);body.addView(text("Current connections",18,INK,true));space(body,8);
        if(cs!=null&&cs.length()>0)usageTotals("Live session traffic",cs,"Current sessions only · separate from monthly history");
        if(s.has("monitoring_available") && !s.optBoolean("monitoring_available")) empty(t("Connection monitoring is unavailable. Refresh to try again."));
        else if(cs==null || cs.length()==0) empty(t("No active connections in the latest server snapshot."));
        else for(int i=0;i<cs.length();i++) {
            JSONObject c=cs.optJSONObject(i);if(c==null)continue;LinearLayout panel=card();
            panel.addView(text(c.optString("user"),21,INK,true));panel.addView(text(c.optString("endpoint")+":"+c.optInt("port"),13,MUTED,false));space(panel,14);
            usageAmounts(panel,c);
            panel.addView(text(t("Connected for ")+duration(c.optLong("age"))+t(" · session ")+c.optString("id"),12,MUTED,false));
            JSONArray addresses=c.optJSONArray("vpn_addresses");StringBuilder addressText=new StringBuilder();
            if(addresses!=null)for(int addressIndex=0;addressIndex<addresses.length();addressIndex++){if(addressIndex>0)addressText.append(", ");addressText.append(addresses.optString(addressIndex));}
            panel.addView(text(t("VPN address ")+addressText,12,MUTED,false));
            fullButton(panel,t("Disconnect this session"),false,()->confirm(t("Disconnect session?"),t("The user can reconnect while their login remains enabled."),()->command(selected,json("action","disconnect","session",c.optString("id")),r->refreshStatistics(true))));
        }
        fullButton(body,s.optBoolean("statistics_enabled")?t("Disable usage history"):t("Enable usage history"),false,()->confirm(t("Change usage history?"),t("History is stored on the VPS. Enabling starts collection; disabling keeps saved totals but stops new collection."),()->command(selected,json("action","stats-toggle","enabled",!s.optBoolean("statistics_enabled")),r->refreshStatistics(true))));
        JSONObject accounting=s.optJSONObject("accounting");
        if(accounting!=null && (accounting.has("gap") || accounting.has("counter_reset"))) {space(body,12);body.addView(text(t("Accounting has recorded a monitoring gap or counter reset. Totals are estimates."),13,RED,false));}

    }
    private static boolean usageCounter(JSONObject value,String key){Object n=value.opt(key);return n instanceof Number&&((Number)n).longValue()>=0;}
    private void usageAmounts(LinearLayout into,JSONObject value){
        space(into,8);into.addView(text(usageCounter(value,"upload")?"Uploaded · "+formatBytes(value.optLong("upload")):"Upload total unavailable",15,INK,true));into.addView(text(usageCounter(value,"download")?"Downloaded · "+formatBytes(value.optLong("download")):"Download total unavailable",15,INK,true));
    }
    private void usageTotals(String heading,JSONArray rows,String scope){
        LinearLayout panel=card();panel.setTag("usage-totals-"+heading);panel.addView(text(heading,17,INK,true));panel.addView(text(scope,12,MUTED,false));
        if(rows==null||rows.length()==0){panel.addView(text("No recorded traffic available in this snapshot.",14,MUTED,false));return;}
        long upload=0,download=0;boolean up=true,down=true;
        for(int i=0;i<rows.length();i++){JSONObject value=rows.optJSONObject(i);if(value==null)continue;up&=usageCounter(value,"upload");down&=usageCounter(value,"download");upload=Math.min(Long.MAX_VALUE-upload,Math.max(0,value.optLong("upload")))+upload;download=Math.min(Long.MAX_VALUE-download,Math.max(0,value.optLong("download")))+download;}
        JSONObject total=new JSONObject();try{if(up)total.put("upload",upload);if(down)total.put("download",download);}catch(JSONException e){throw new IllegalStateException(e);}usageAmounts(panel,total);
    }
    private void empty(String copy) {LinearLayout c=card();c.addView(text(copy,16,MUTED,false));}
    private static String formatBytes(long n) {return n>=1_000_000_000?String.format(Locale.US,"%.2f GB",n/1e9):n>=1_000_000?String.format(Locale.US,"%.1f MB",n/1e6):String.format(Locale.US,"%.1f KB",n/1e3);}
    private static String duration(long s) {return s>=3600?(s/3600)+"h "+(s%3600/60)+"m":(s/60)+"m";}
    private static JSONObject json(Object...pairs) {JSONObject j=new JSONObject();try{for(int i=0;i<pairs.length;i+=2)j.put((String)pairs[i],pairs[i+1]);}catch(JSONException e){throw new IllegalArgumentException(e);}return j;}
    private static byte[] read(InputStream in,int limit) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>limit)throw new IOException("File is too large");}return out.toByteArray();}

    private Gateway managementPair(Gateway node){for(Gateway pair:gateways)if(pair.isPair()&&(PairNodes.same(node,pair)||PairNodes.same(node,pair.exit)))return pair;return null;}
    private interface Task {JSONObject run(Ssh ssh) throws Exception;}
    private interface Done {void finish(JSONObject result);}
    private void withSsh(Gateway node,String work,Task task,Done done) {withSsh(node,work,task,done,work.startsWith("Checking")?"Server refreshed":work.startsWith("Removing")?"Removal complete":work.startsWith("Reviewing")?"Review ready":"Server updated");}
    private void withSsh(Gateway node,String work,Task task,Done done,String completed) {
        withSsh(node,work,task,done,completed,false);
    }
    private void withSsh(Gateway node,String work,Task task,Done done,String completed,boolean installationCheck) {
        if(demo){demoNotice();return;}if(busy || DeploymentService.active())return;
        if(!hasAuth(node)) {closeNewUserDialog();passwordDialog(node,()->withSsh(node,work,task,done,completed,installationCheck));return;}
        if(node.sshRelay!=null && !hasAuth(node.sshRelay)){closeNewUserDialog();passwordDialog(node.sshRelay,()->withSsh(node,work,task,done,completed,installationCheck));return;}
        busy=true;message=work;if(!pendingModule.isEmpty())moduleWaitStarted=SystemClock.elapsedRealtime();if(installationCheck&&node.get("setupIntent").equals("install")&&!node.isPair())beginSetupCheck(node,false,()->inspect(node));else render();
        executor.execute(()->{
            try(AdminConnection connection=AdminConnection.open(node,managementPair(node),phase->handler.post(()->{message=phase;render();}))) {JSONObject result=task.run(connection.ssh);handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;if(installationCheck&&setupCheckNode==node&&setupCheckProgress!=null){setupCheckProgress.finished=System.currentTimeMillis();setupCheckProgress.state="review";setupCheckProgress.phase="Review any existing VPN software before continuing.";}pendingModule="";pendingAction="";pendingActionKey="";message=completed.equals("Server refreshed")?serverCheckSummary(node,result):completed;if(!completed.isEmpty())recordActivity(completed.equals("Server refreshed")?"Server checked":completed,node);done.finish(result);render();});}
            catch(Exception e) {handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;if(installationCheck&&setupCheckNode==node&&setupCheckProgress!=null){setupCheckProgress.finished=System.currentTimeMillis();setupCheckProgress.state="needs-attention";setupCheckProgress.phase="Check the server address and administrator access, then try the check again.";}pendingModule="";pendingAction="";pendingActionKey="";closeNewUserDialog();message="";if(!(e instanceof Ssh.HostTrust)&&collectionState.share.phase.startsWith("read-"))collectionState.share.phase="failed";render();if(e instanceof Ssh.HostTrust)trust(node,(Ssh.HostTrust)e,()->withSsh(node,work,task,done,completed,installationCheck));else{recordActivity("Server action failed",node);error(e);}});}
        });
    }
    private String serverCheckSummary(Gateway node,JSONObject result){
        JSONObject inventory=result.optJSONObject("inventory");
        if(inventory==null)return "Server checked · "+node.get("host")+"\nVPN service status updated";
        JSONArray protocols=inventory.optJSONArray("installed_protocols");int count=(protocols==null?0:protocols.length())+(result.optBoolean("gateway")?1:0);
        return "Server checked · "+node.get("host")+"\n"+count+" installed VPN"+(count==1?"":"s")+" · software and port inventory updated";
    }
    private void command(Gateway node,JSONObject request,Done done) {command(node,request,done,null);}
    private void command(Gateway node,JSONObject request,Done done,String completion) {
        String action=request.optString("action"),event=action.equals("status")?"Protocol refreshed":action.equals("profile")?"Connection prepared":action.equals("add-user")?"VPN account created":action.equals("edit-user")?"VPN account updated":action.equals("remove-user")?"VPN account deleted":action.equals("reset-plan")?"Removal review ready":action.equals("reset-apply")?"Protocol removed":action.equals("adguard")?(request.has("level")||request.has("enabled")?"Ad blocking updated":"Ad blocking checked"):"Server updated";
        if(completion!=null)event=completion;
        String work=action.equals("status")&&tab.equals("People")?"Loading VPN users":t("Updating ")+node.get("name");
        if(!otherProtocol(node)&&action.equals("profile"))try{request.put("server",vpnAddress(node)).put("port",node.data.optInt("vpnPort",500));}catch(JSONException e){error(e);return;}
        if(otherProtocol(node))try{request.put("protocol",node.get("protocol"));withSsh(node,work,ssh->{try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,request);}},done,event);}catch(Exception e){error(e);}else withSsh(node,work,ssh->ssh.admin(request),done,event);
    }

    private void inspect(Gateway node){
        if(busy||DeploymentService.active())return;getSharedPreferences("rookstride-ui",0).edit().putLong("inspectAttempt:"+node.get("id"),System.currentTimeMillis()).apply();
        if(node.isPair()){refreshPair(node);return;}
        withSsh(node,"Checking "+node.get("name"),ssh->{
            JSONObject p=ssh.probe();
            try(InputStream bundle=getAssets().open("single_bundle.zip")){p.put("inventory",ssh.single(bundle,json("action","inspect")));}
            if(p.optBoolean("helper"))p.put("status",ssh.admin(json("action","status")));
            return p;
        },p->{try{
            node.data.put("checkedAt",System.currentTimeMillis());node.data.put("probe",p);node.set("machine",p.optString("machine"));JSONObject inventory=p.getJSONObject("inventory");reconcileServerInventory(node,p,inventory);node.set("checked",new java.text.SimpleDateFormat("MMM d, HH:mm",Locale.ENGLISH).format(new Date()));
            if(p.has("status")&&!otherProtocol(node))node.data.put("snapshot",p.getJSONObject("status"));
            JSONArray installed=inventory.optJSONArray("installed_protocols");String intent=node.get("setupIntent");
            if(intent.equals("manage")){
                ArrayList<String> ids=new ArrayList<>();if(p.optBoolean("gateway"))ids.add("ikev2");if(installed!=null)for(int i=0;i<installed.length();i++)ids.add(installed.getString(i));
                node.set("setupIntent","");if(ids.isEmpty()){node.set("protocol","");handler.post(()->openServer(node));}if(ids.size()==1){node.set("protocol",ids.get(0));save();if(otherProtocol(node))refreshProtocol(node);}
                else if(ids.size()>1){node.set("protocol",ids.get(0));for(String id:ids)if(ServerProtocols.find(gateways,node,id)==null){Gateway sibling=ServerProtocols.create(node,SingleProtocols.from(id));sibling.set("setupIntent","");gateways.add(sibling);}save();handler.post(()->serverProtocols(node));}
            }else if(otherProtocol(node)){
                boolean exists=false;if(installed!=null)for(int i=0;i<installed.length();i++)if(installed.getString(i).equals(node.get("protocol")))exists=true;
                JSONObject job=inventory.optJSONObject("job");
                if(job!=null&&job.optString("protocol").equals(node.get("protocol"))&&!job.optString("state").equals("failed")&&!job.optString("state").equals("complete")){node.set("job",job.optString("job"));node.set("jobKind",job.optBoolean("filter_only")?"filter":"protocol");node.set("jobPhase",job.optString("phase"));save();pollJob(node);}
                else if(exists){node.set("setupIntent","");clearSetupCheck();save();openVpn(node);refreshProtocol(node);}
                else if(intent.equals("install")){node.set("setupIntent","");handler.post(()->protocolInstallation(node));}
            }else if(intent.equals("install")&&!p.optBoolean("gateway")){
                node.set("setupIntent","");if(inventory.optBoolean("ikev2_ready"))handler.post(()->installation(node,false));else {clearSetupCheck();openVpn(node);RookDialogs.builder(this).setTitle("IKEv2 needs a free configuration").setMessage(ikeConflictSummary(inventory)).setPositiveButton("Choose protocol",(d,w)->{pendingServerId=node.get("id");openScreen("Protocols");}).setNegativeButton("Close",null).show();}
            }else if(intent.equals("install")&&p.optBoolean("gateway")){node.set("setupIntent","");clearSetupCheck();openVpn(node);}
            JSONObject oldJob=p.optJSONObject("job");InstallationProgress recorded=currentProgress();boolean recovering=recorded!=null&&recorded.gatewayId.equals(node.get("id"))&&!recorded.kind.equals("pair")&&!recorded.state.equals("complete");
            if(!otherProtocol(node)&&oldJob!=null&&InputRules.job(oldJob.optString("job"))&&(oldJob.optString("state").equals("running")||oldJob.optString("state").equals("starting")||(recovering&&p.optBoolean("helper")&&oldJob.optString("state").equals("complete")))){if(recovering)node.set("jobKind",recorded.kind);node.set("job",oldJob.optString("job"));node.set("jobPhase",oldJob.optString("phase"));handler.postDelayed(()->pollJob(node),1000);}
            save();
        }catch(Exception e){error(e);}},"Server refreshed",true);
    }
    private boolean runningJob(JSONObject job){return job!=null&&(job.optString("state").equals("starting")||job.optString("state").equals("running"));}
    private void reconcileServerInventory(Gateway server,JSONObject probe,JSONObject inventory)throws Exception{
        ServerProtocols.rememberIkeCertificateNames(gateways,server,probe.optJSONObject("status"));
        Set<String> installed=new HashSet<>();if(probe.optBoolean("gateway"))installed.add("ikev2");JSONArray ids=inventory.optJSONArray("installed_protocols");if(ids!=null)for(int i=0;i<ids.length();i++)installed.add(ids.optString(i));
        JSONObject instances=inventory.optJSONObject("installed_instances");boolean installing=runningJob(probe.optJSONObject("job"))||runningJob(inventory.optJSONObject("job"));
        for(Gateway sibling:gateways)if(ServerProtocols.sameServer(server,sibling)){
            String protocol=SingleProtocols.from(sibling.get("protocol")).id;String instance=instances==null?"":instances.optString(protocol);
            if(protocol.equals("ikev2")&&probe.optJSONObject("status")!=null)instance=probe.getJSONObject("status").optString("instance");
            if(!installing&&!installed.contains(protocol))clearRemovedProtocol(sibling);else if(!installing&&ServerProtocols.changedInstance(sibling,instance)){if(ServerProtocols.publicCertificateMigration(sibling,probe.optJSONObject("status"),instance))IkeProfileTrust.usePublicCa(this,sibling);else clearRemovedProtocol(sibling);}
            JSONObject coexist=inventory.optJSONObject("coexisting_protocols");ServerProtocols.rememberCoexistence(sibling,coexist==null?"":coexist.optString(protocol));
            if(!instance.isEmpty())sibling.set("serverInstance",instance);sibling.data.put("probe",new JSONObject(probe.toString()));
        }
    }
    private void refreshProtocol(Gateway node){command(node,json("action","status"),r->{try{node.data.put("snapshot",r);ServerProtocols.rememberConnection(gateways,node,r);save();render();}catch(Exception e){error(e);}});}
    private void protocolInstallation(Gateway node){
        SingleProtocols protocol=SingleProtocols.from(node.get("protocol"));String user="this-phone";
        node.set("vpnLogin",user);if(PasswordSignIn.supported(protocol.id)&&!node.get("accessMode").equals("profile")){node.set("accessMode","password");node.vpnPassword=generatedPassword();try{node.data.put("rememberVpn",true);}catch(JSONException e){error(e);return;}}
        save();JSONObject config=json("protocol",protocol.id,"server",vpnAddress(node),"sshPort",node.port(),"login",user);
        if(!node.get("coexistPair").isEmpty())try{config.put("coexist_pair",node.get("coexistPair"));}catch(JSONException e){error(e);return;}
        if(node.get("accessMode").equals("password"))try{config.put("access_mode","password").put("password",node.vpnPassword);}catch(JSONException e){error(e);return;}
        if(!node.data.optBoolean("vpnPortAuto",false))try{config.put("port",node.data.optInt("vpnPort",protocol.port));}catch(JSONException e){error(e);return;}
        startDeployment(node,"protocol",config,false);
    }
    private void removalReview(String title,LinearLayout content,Runnable remove){
        space(content,14);CheckBox accepted=new CheckBox(this);accepted.setText("I understand that affected users will lose access.");accepted.setMinHeight(dp(48));content.addView(accepted);
        AlertDialog d=RookDialogs.builder(this).setTitle(title).setView(content).setNegativeButton("Cancel",null).setPositiveButton("Remove",null).create();d.show();
        Button confirm=d.getButton(AlertDialog.BUTTON_POSITIVE);confirm.setEnabled(false);accepted.setOnCheckedChangeListener((v,checked)->confirm.setEnabled(checked));confirm.setOnClickListener(v->{if(!accepted.isChecked())return;d.dismiss();remove.run();});
    }
    private void resetIncompleteFilter(Gateway node){
        withSsh(node,"Reviewing incomplete ad blocking",ssh->{try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,json("action","filter-reset-plan"));}},plan->{
            LinearLayout f=form();f.addView(text("Remove unused Rookstride DNS filtering files and statistics. Ubuntu, SSH and other applications stay.",14,INK,false));
            removalReview("Remove incomplete ad blocking?",f,()->withSsh(node,"Removing incomplete ad blocking",ssh->{try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,json("action","filter-reset-apply","token",plan.optString("token"),"confirmation","DELETE VPN"));}},r->inspect(node)));
        });
    }
    private void chooseOsReinstall(Gateway node){
        if(node.data.optJSONObject("osReinstall")!=null&&!node.get("osReinstallState").equals("complete")){RookDialogs.builder(this).setTitle("Recorded OS reinstall").setMessage("Check the recorded job first. A new review is allowed only if the server has no active reinstall job.").setPositiveButton("Check progress",(d,w)->startDeployment(node,"os",node.data.optJSONObject("osReinstall"),true)).setNeutralButton("Review again",(d,w)->osVersionChoice(node)).setNegativeButton("Cancel",null).show();return;}
        osVersionChoice(node);
    }
    private void osVersionChoice(Gateway node){
        if(!directOsNetwork())return;
        String[] versions={"Ubuntu 24.04 LTS","Ubuntu 22.04 LTS","Ubuntu 26.04 LTS"};String[] values={"24.04","22.04","26.04"};
        RookDialogs.builder(this).setTitle("Wipe server & reinstall Ubuntu").setMessage("Replace this server’s operating system and erase its system disk. Rookstride checks whether SSH reinstallation is supported before asking you to confirm.").setNegativeButton("Cancel",null).setPositiveButton("Choose Ubuntu version",(d,w)->RookDialogs.builder(this).setTitle("Ubuntu version").setItems(versions,(choice,index)->withSsh(node,"Checking OS reinstall support",ssh->{OsWipeNetwork.requireDirect(this);try(InputStream bundle=getAssets().open("reinstall_bundle.zip")){return ssh.reinstall(bundle,json("action","plan","version",values[index]));}},plan->reviewOsReinstall(node,plan),"")).setNegativeButton("Cancel",null).show()).show();
    }
    private void reviewOsReinstall(Gateway node,JSONObject plan){
        JSONObject scope=plan.optJSONObject("scope");LinearLayout f=form();f.addView(text(node.get("host"),18,INK,true));space(f,8);
        f.addView(text("Install Ubuntu "+plan.optString("version")+" on "+(scope==null?"the system disk":scope.optString("disk"))+". All applications, VPNs, accounts and files on this disk will be erased. Provider snapshots and backups are separate.",15,INK,false));space(f,10);
        if(pairNode(node))f.addView(text("This breaks the Double VPN that uses this server. The other server is not erased.",14,RED,true));
        f.addView(text("Administrator access and the network are set up again. SSH goes offline during installation; progress continues here when it returns. The server stays in your list with no installed VPNs.",14,MUTED,false));
        if(node.sshPassword.isEmpty()||!node.privateKey.isEmpty()||!node.get("admin").equals("root")){f.addView(text("Use root password sign-in in Server access, then review again. A private-key passphrase is not the root password.",14,RED,true));RookDialogs.builder(this).setTitle("Root access needed").setView(scrolling(f)).setPositiveButton("Done",null).show();return;}
        CheckBox agree=new CheckBox(this);agree.setText("I understand that this server’s system disk will be erased");f.addView(agree);
        AlertDialog d=RookDialogs.builder(this).setTitle("Erase server and reinstall Ubuntu?").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Wipe & reinstall",null).create();d.show();d.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);agree.setOnCheckedChangeListener((b,on)->d.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(on));d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{d.dismiss();startDeployment(node,"os",plan,false);});
    }
    private boolean pairNode(Gateway node){JSONObject probe=node.data.optJSONObject("probe"),inventory=probe==null?null:probe.optJSONObject("inventory");return node.isPair()||inventory!=null&&inventory.optBoolean("pair_node");}
    private void resetServer(Gateway node){
        withSsh(node,"Reviewing VPN removal",ssh->{if(ssh.probe().optBoolean("pair_helper")){try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","node-plan"));}}try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,json("action","reset-server-plan"));}},plan->reviewServerReset(node,plan));
    }
    private void reviewServerReset(Gateway node,JSONObject plan){
        if(plan.optBoolean("already_empty")){applyServerReset(node,plan);return;}
        LinearLayout f=form();f.addView(text("Remove the Rookstride VPN services and configuration, accounts, certificates and device keys on "+node.get("host")+".",14,INK,false));space(f,10);
        JSONArray ids=plan.optJSONArray("protocols");if(ids!=null)for(int i=0;i<ids.length();i++)f.addView(text("• "+SingleProtocols.from(ids.optString(i)).title,15,INK,true));
        if(plan.optBoolean("filtering"))f.addView(text("• Private ad blocking and DNS statistics",15,INK,true));space(f,12);
        if(plan.optBoolean("node_only"))f.addView(text("This server belongs to a two-server VPN. Removing it breaks that route. The other server is not changed; remove its setup separately if you no longer need it.",14,RED,true));
        f.addView(text("Ubuntu, SSH, administrator credentials, downloaded packages and unrelated applications stay. You can install a new VPN afterward.",14,MUTED,false));
        removalReview("Remove all VPN setups?",f,()->applyServerReset(node,plan));
    }
    private void applyServerReset(Gateway node,JSONObject plan){
        withSsh(node,plan.optBoolean("already_empty")?"Checking server setup":"Removing VPN setups",ssh->{if(plan.optBoolean("node_only")){try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","node-apply","token",plan.getString("token"),"confirmation","DELETE PAIR"));}}try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,json("action","reset-server-apply","token",plan.getString("token"),"confirmation","DELETE ALL VPNS"));}},result->{
            try{for(Gateway sibling:gateways)if(ServerProtocols.sameServer(node,sibling)){PairNodes.clearAfterConfirmedReset(sibling,result,DeploymentService.active()||DeploymentService.needsLocalSave());clearRemovedProtocol(sibling);}save();message=result.optString("message");serverProtocols(node);}catch(Exception e){error(e);}
        });
    }
    private void disconnectNativeProfile(Gateway node){if(NativeVpn.status(this,node.get("protocol")).active(node.get("id")))NativeVpn.disconnect(this,node.get("protocol"));}
    private void invalidatePhoneProfile(Gateway node)throws Exception{
        if(otherProtocol(node)){disconnectNativeProfile(node);new NativeProfileStore(this).remove(node.get("id"));}
        else if(!node.get("profileUuid").isEmpty()){
            if(vpn!=null&&vpn.getProfile()!=null&&vpn.getProfile().getUUID().toString().equals(node.get("profileUuid")))vpn.disconnect();
            VpnProfileDataSource source=new VpnProfileSource(this);source.open();try{VpnProfile profile=source.getVpnProfile(node.get("profileUuid"));if(profile!=null)source.deleteVpnProfile(profile);}finally{source.close();}
        }
        node.set("profileUuid","");node.vpnPassword="";
    }
    private void clearRemovedProtocol(Gateway node)throws Exception{
        newUserShare.recent.forget(node.get("id"));forgetQuickConnection(node);invalidatePhoneProfile(node);DeploymentService.forget(this,node);node.data.remove("snapshot");node.data.remove("probe");node.set("job","");node.set("vpnLogin","");node.set("serverInstance","");
    }
    private boolean separatePairVpn(Gateway node){Gateway pair=managementPair(node);return !node.isPair()&&node.get("protocol").equals("openvpn")&&!node.get("coexistPair").isEmpty()&&pair!=null&&PairNodes.same(pair,node)&&node.get("coexistPair").equals(pair.get("pairId"));}
    private void resetProtocol(Gateway node){
        if(pairNode(node)&&!separatePairVpn(node)){resetServer(node);return;}
        command(node,json("action","reset-plan"),plan->{LinearLayout f=form();f.addView(text("Remove "+SingleProtocols.from(node.get("protocol")).title+" and its configuration, accounts and device keys from "+node.get("host")+". Other VPN protocols, Ubuntu and SSH stay.",14,INK,false));
            removalReview("Uninstall this protocol?",f,()->command(node,json("action","reset-apply","confirmation","DELETE VPN","token",plan.optString("token")),r->{try{ServerProtocols.recordRemoved(gateways,node);clearRemovedProtocol(node);save();serverProtocols(node);}catch(Exception e){error(e);}}));
        });
    }
    /** Ordinary VPN collections are separate from administrator invitations and recovery files. */
    private void collectionChanged(){
        if(isDestroyed()||isFinishing())return;
        boolean wasWorking=collectionBusy;collectionBusy=collectionState.working;
        if(collectionBusy){busy=true;message=collectionState.operation.equals("import")?"Adding VPN connections":collectionState.operation.equals("save")?"Saving connection file":collectionState.operation.equals("export")?"Preparing selected connections":collectionState.operation.equals("recovery")?"Checking saved connections":"Reading connection file";render();return;}
        if(wasWorking){busy=false;message="";pendingAction="";pendingActionKey="";}
        ConnectionBundleImport.Result imported=collectionState.takeResult();
        if(imported!=null){
            gateways=imported.catalog;selected=gateways.isEmpty()?null:gateways.get(gateways.size()-1);pendingServerId="";
            if(!gateways.isEmpty())getSharedPreferences("rookstride-ui",0).edit().putBoolean("hasSavedVpn",true).apply();
            navigation.root("Home");tab="Home";render();
            recordActivity(imported.added+" VPN connection"+(imported.added==1?"":"s")+" imported",null);
            RookDialogs.builder(this).setTitle(imported.added==0?"Connections already saved":"VPN connections added").setMessage(imported.added+" added"+(imported.existing>0?" · "+imported.existing+" already saved":"")+". Find them in VPNs.").setPositiveButton("Done",null).show();
        }else if(wasWorking)render();
        if(collectionState.documentSaved){collectionState.documentSaved=false;recordActivity("Connection collection saved",null);RookDialogs.builder(this).setTitle("Connection file saved").setMessage("Import this .rookbundle file in Rookstride to add all selected connections.").setPositiveButton("Done",null).show();}
        String failure=collectionState.takeFailure();if(!failure.isEmpty()){
            AlertDialog notice=RookDialogs.builder(this).setTitle("Connection file needs attention").setView(messageBody(failure)).setPositiveButton("Close",null).create();collectionDialog(notice,null);
            notice.setOnDismissListener(d->{if(collectionDialog==notice)collectionDialog=null;handler.post(this::restoreCollectionUi);});return;
        }
        if(resumed&&collectionState.recoveryReady)syncNativeProfiles();
        restoreCollectionUi();
    }
    private void collectionDialog(AlertDialog dialog,Runnable cancel){
        collectionDialog=dialog;dialog.setOnDismissListener(d->{if(collectionDialog==dialog)collectionDialog=null;});
        if(cancel!=null)dialog.setOnCancelListener(d->cancel.run());dialog.show();
    }
    private void restoreCollectionUi(){
        if(!resumed||isDestroyed()||isFinishing()||busy||DeploymentService.active()||collectionDialog!=null)return;
        if(collectionState.importReviewPending&&collectionState.preview!=null){reviewCollectionImport();return;}
        if(collectionState.exportReviewPending&&collectionState.exportBundle!=null&&!profileExport.collectionPending()){reviewCollectionExport();return;}
        ConnectionCollectionState.ShareDraft draft=collectionState.share;if(!draft.active())return;
        if(draft.phase.equals("protocols"))chooseCollectionProtocols();
        else if(draft.phase.equals("users"))chooseCollectionUser();
        else if(draft.phase.equals("password"))collectionPassword();
        else if(draft.phase.equals("read-users"))readCollectionUsers();
        else if(draft.phase.equals("read-profile"))readCollectionProfile();
    }
    private LinearLayout collectionReview(ConnectionBundleImport.Preview preview){
        LinearLayout f=form();f.addView(text(preview.connections.size()+" VPN connections",16,INK,true));
        space(f,6);f.addView(text("VPN access only. Server administrator access is not included.",13,MUTED,false));
        for(ConnectionBundleImport.Summary item:preview.connections){space(f,16);f.addView(text(item.title+" · "+item.account,15,INK,true));
            if(item.login.isEmpty())f.addView(text(item.displayName,14,INK,false));f.addView(text(item.server+":"+item.port,13,MUTED,false));}
        return f;
    }
    private void reviewCollectionImport(){
        ConnectionBundleImport.Preview preview=collectionState.preview;LinearLayout f=collectionReview(preview);
        if(preview.existing>0){space(f,12);f.addView(text(preview.existing+" already saved; these will stay as they are.",13,MUTED,false));}
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Import VPN connections").setView(scrolling(f)).setNegativeButton("Cancel",(d,w)->collectionState.clearImport()).setPositiveButton(preview.toAdd==0?"Done":"Import all",null).create();
        collectionDialog(dialog,collectionState::clearImport);dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{if(collectionState.working||DeploymentService.active())return;dialog.dismiss();collectionState.apply(getApplicationContext());});
    }
    private void reviewCollectionExport(){
        LinearLayout f=collectionReview(collectionState.exportPreview);space(f,14);
        f.addView(text("Anyone with this file can use these VPN accounts. Share it privately.",13,MUTED,false));
        fullButton(f,"Share connection file",true,()->{
            try{String content=collectionState.exportBundle;Uri uri=ProfileExportProvider.issue(this,"rookstride-connections.rookbundle",content);Intent share=new Intent(Intent.ACTION_SEND).setType(ConnectionBundle.MIME).putExtra(Intent.EXTRA_STREAM,uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);share.setClipData(ClipData.newRawUri("VPN connections",uri));startActivity(Intent.createChooser(share,"Share VPN connections"));collectionState.clearExport();if(collectionDialog!=null)collectionDialog.dismiss();recordActivity("Connection collection shared",null);}catch(Exception e){error(e);}
        });
        fullButton(f,"Save connection file",false,()->{
            profileExport.collection(collectionState.exportBundle);collectionState.exportReviewPending=false;
            if(collectionDialog!=null)collectionDialog.dismiss();
            startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(ConnectionBundle.MIME).putExtra(Intent.EXTRA_TITLE,"rookstride-connections.rookbundle"),SAVE_COLLECTION);
        });
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Connections ready to share").setView(scrolling(f)).setPositiveButton("Close",(d,w)->collectionState.clearExport()).create();collectionDialog(dialog,collectionState::clearExport);secure(dialog);
    }
    private void finishCollectionExport(int result,Intent data){
        String content=profileExport.takeCollection();
        if(result!=RESULT_OK){collectionState.exportReviewPending=collectionState.exportBundle!=null;handler.post(this::restoreCollectionUi);return;}
        if(content==null){error(new IOException("This export expired. Select the VPN connections again."));return;}
        collectionState.save(getApplicationContext(),data==null?null:data.getData(),content);
    }
    private Gateway collectionServer(){return PairNodes.find(gateways,collectionState.share.serverId);}
    private Gateway collectionNode()throws Exception{
        ConnectionCollectionState.ShareDraft draft=collectionState.share;Gateway server=collectionServer();
        if(server==null||server.isPair()||server.data.optBoolean("clientOnly")||draft.step<0||draft.step>=draft.protocols.size())throw new IOException("Choose a managed single-server VPN again.");
        String protocol=draft.protocols.get(draft.step);if(!ServerProtocols.installed(gateways,server).contains(protocol))throw new IOException("This protocol is no longer installed. Refresh the server and select its connections again.");
        Gateway node=ServerProtocols.find(gateways,server,protocol);return node==null?ServerProtocols.create(server,SingleProtocols.from(protocol)):node;
    }
    private void startCollectionShare(Gateway server){
        if(busy||DeploymentService.active())return;collectionState.clearExport();collectionState.share.clear();
        collectionState.share.serverId=server.get("id");collectionState.share.phase="protocols";chooseCollectionProtocols();
    }
    private void chooseCollectionProtocols(){
        Gateway server=collectionServer();if(server==null){collectionState.share.clear();return;}
        ConnectionCollectionState.ShareDraft draft=collectionState.share;LinearLayout f=form();
        f.addView(text("Choose the protocols to share. Next, choose an existing VPN user for each one.",14,MUTED,false));space(f,12);
        List<SingleProtocols> available=ServerProtocols.ordered(ServerProtocols.installed(gateways,server),true);ArrayList<CheckBox> choices=new ArrayList<>();
        for(SingleProtocols protocol:available){CheckBox box=new CheckBox(this);box.setText(protocol.title);box.setTextSize(15);box.setMinHeight(dp(52));box.setButtonTintList(android.content.res.ColorStateList.valueOf(RED));box.setChecked(draft.protocols.contains(protocol.id));box.setTag(protocol.id);f.addView(box);choices.add(box);}
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Share several connections").setView(scrolling(f)).setNegativeButton("Cancel",(d,w)->draft.clear()).setPositiveButton("Next",null).create();
        collectionDialog(dialog,draft::clear);Button next=dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        Runnable update=()->next.setEnabled(choices.stream().anyMatch(CheckBox::isChecked));update.run();for(CheckBox box:choices)box.setOnCheckedChangeListener((v,checked)->{draft.protocols.clear();for(CheckBox c:choices)if(c.isChecked())draft.protocols.add((String)c.getTag());update.run();});
        next.setOnClickListener(v->{if(draft.protocols.isEmpty())return;draft.step=0;draft.phase="read-users";dialog.dismiss();readCollectionUsers();});
    }
    private void collectionRead(Gateway node,JSONObject request,String work,Done done){
        if(!otherProtocol(node)&&request.optString("action").equals("profile"))try{request.put("server",vpnAddress(node)).put("port",node.data.optInt("vpnPort",500));}catch(Exception e){collectionState.share.phase="failed";error(e);return;}
        withSsh(node,work,ssh->{if(otherProtocol(node)){request.put("protocol",node.get("protocol"));try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,request);}}return ssh.admin(request);},done,"");
    }
    private void readCollectionUsers(){
        try{Gateway node=collectionNode();collectionState.share.phase="read-users";
            collectionRead(node,json("action","status"),"Reading VPN users · "+SingleProtocols.from(node.get("protocol")).title,result->{
                ConnectionCollectionState.ShareDraft draft=collectionState.share;if(!draft.active())return;JSONArray values=result.optJSONArray("users");draft.users=values==null?new JSONArray():values;draft.instance=result.optString("instance");draft.login="";draft.phase="users";chooseCollectionUser();
            });
        }catch(Exception e){collectionState.share.clear();error(e);}
    }
    private String collectionAccountLabel(JSONObject user){
        String login=user.optString("login"),person=user.optString("person"),device=user.optString("device");String label=person.isEmpty()?login:person;
        if(!device.isEmpty()&&!device.equals(label)&&!device.equals(login))label+=" · "+device;
        return label.equals(login)?login:label+" · "+login;
    }
    private void chooseCollectionUser(){
        try{Gateway node=collectionNode();ConnectionCollectionState.ShareDraft draft=collectionState.share;LinearLayout f=form();
            f.addView(text((draft.step+1)+" of "+draft.protocols.size()+" · "+SingleProtocols.from(node.get("protocol")).title,14,INK,true));
            space(f,6);f.addView(text("Choose a VPN user. This shares that user's existing connection.",13,MUTED,false));space(f,10);
            RadioGroup group=new RadioGroup(this);ArrayList<JSONObject> accounts=new ArrayList<>();
            if(draft.users!=null)for(int i=0;i<draft.users.length();i++){JSONObject user=draft.users.optJSONObject(i);if(user!=null&&!user.optString("login").isEmpty()&&user.optBoolean("enabled",true)&&!user.optBoolean("disabled",false))accounts.add(user);}
            accounts.sort(Comparator.comparing(u->collectionAccountLabel(u).toLowerCase(Locale.ROOT)));
            if(accounts.isEmpty()){draft.clear();AlertDialog empty=RookDialogs.builder(this).setTitle("No VPN users available").setMessage("Create a VPN user for this protocol, then select the connections to share.").setNegativeButton("Close",null).setPositiveButton("Open VPN users",(d,w)->openUsers(node)).create();collectionDialog(empty,null);return;}
            for(JSONObject user:accounts){RadioButton choice=new RadioButton(this);choice.setId(View.generateViewId());choice.setText(collectionAccountLabel(user));choice.setTag(user.optString("login"));choice.setTextSize(14);choice.setMinHeight(dp(52));choice.setButtonTintList(android.content.res.ColorStateList.valueOf(RED));group.addView(choice);if(user.optString("login").equals(draft.login))choice.setChecked(true);}
            f.addView(group);TextView ownKey=text("This phone uses this key. Sharing it can interrupt simultaneous connections. A separate VPN user works better.",13,MUTED,false);ownKey.setPadding(0,dp(12),0,0);f.addView(ownKey);
            AlertDialog dialog=RookDialogs.builder(this).setTitle("Choose a VPN user").setView(scrolling(f)).setNegativeButton("Cancel",(d,w)->draft.clear()).setPositiveButton("Use VPN user",null).create();collectionDialog(dialog,draft::clear);
            Button use=dialog.getButton(AlertDialog.BUTTON_POSITIVE);Runnable update=()->{use.setEnabled(!draft.login.isEmpty());ownKey.setVisibility(node.get("protocol").equals("awg")&&draft.login.equals(node.get("vpnLogin"))&&!draft.login.isEmpty()?View.VISIBLE:View.GONE);};update.run();
            group.setOnCheckedChangeListener((g,id)->{RadioButton checked=g.findViewById(id);draft.login=checked==null?"":(String)checked.getTag();update.run();});
            use.setOnClickListener(v->{if(draft.login.isEmpty())return;draft.phase="read-profile";dialog.dismiss();readCollectionProfile();});
        }catch(Exception e){collectionState.share.clear();error(e);}
    }
    private String collectionKnownPassword(Gateway node,String login){
        String instance=collectionState.share.instance;if(instance.isEmpty())return "";
        String known=instance.equals(node.get("serverInstance"))&&login.equals(node.get("vpnLogin"))?node.vpnPassword:"";
        return known.isEmpty()?newUserShare.recent.get(node.get("id"),instance,login):known;
    }
    private String collectionDisplayName(Gateway node){return ConnectionCollectionProfiles.displayName(node.get("protocol"),collectionState.share.login,ServerProtocols.name(node));}
    private void readCollectionProfile(){
        try{Gateway node=collectionNode();ConnectionCollectionState.ShareDraft draft=collectionState.share;if(draft.login.isEmpty())throw new IOException("Choose a VPN user first.");draft.phase="read-profile";
            collectionRead(node,json("action","profile","login",draft.login,"name",draft.login),"Preparing selected connection · "+SingleProtocols.from(node.get("protocol")).title,response->{
                if(!draft.active())return;try{JSONObject entry=ConnectionCollectionProfiles.complete(response,draft.login,collectionKnownPassword(node,draft.login),collectionDisplayName(node));appendCollectionProfile(entry);}
                catch(ConnectionCollectionProfiles.PasswordRequired required){draft.pendingProfile=response;draft.phase="password";collectionPassword();}
                catch(Exception e){draft.clear();error(e);}
            });
        }catch(Exception e){collectionState.share.clear();error(e);}
    }
    private void collectionPassword(){
        try{Gateway node=collectionNode();ConnectionCollectionState.ShareDraft draft=collectionState.share;LinearLayout f=form();
            f.addView(text(draft.login+" · "+SingleProtocols.from(node.get("protocol")).title,15,INK,true));space(f,10);EditText secret=field(f,"Existing VPN password","",true);
            f.addView(text("Include this user's current password. It is not changed on the server.",13,MUTED,false));
            AlertDialog dialog=RookDialogs.builder(this).setTitle("Include VPN password").setView(scrolling(f)).setNegativeButton("Cancel",(d,w)->draft.clear()).setPositiveButton("Continue",null).create();collectionDialog(dialog,draft::clear);secure(dialog);
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String password=secret.getText().toString();if(!InputRules.vpnPassword(password)){secret.setError("Enter this user's existing password");return;}try{JSONObject entry=ConnectionCollectionProfiles.complete(draft.pendingProfile,draft.login,password,collectionDisplayName(node));secret.setText("");dialog.dismiss();appendCollectionProfile(entry);}catch(Exception e){secret.setError("This password could not be included. Check the existing VPN-user password.");}});
        }catch(Exception e){collectionState.share.clear();error(e);}
    }
    private void appendCollectionProfile(JSONObject entry){
        ConnectionCollectionState.ShareDraft draft=collectionState.share;draft.profiles.add(entry);draft.pendingProfile=null;draft.users=null;draft.login="";draft.instance="";draft.step++;
        if(draft.step<draft.protocols.size()){draft.phase="read-users";readCollectionUsers();}
        else{draft.phase="prepare";collectionState.prepareExport(getApplicationContext(),draft.profiles);}
    }
    private void shareProtocolProfile(JSONObject profile){shareProtocolProfile(selected,profile);}
    private void shareProtocolProfile(Gateway source,JSONObject profile){
        try{String login=PasswordSignIn.login(profile),password=source!=null&&login.equals(source.get("vpnLogin"))?source.vpnPassword:"";if(password.isEmpty()&&source!=null)password=newUserShare.recent.get(source.get("id"),source.get("serverInstance"),login);sharePreparedProfile(profile,login,password);}catch(Exception e){error(e);}
    }
    private void shareScopedProfile(Gateway source,JSONObject object,JSONObject profile){
        try{String login=PasswordSignIn.login(profile);sharePreparedProfile(profile,login,newUserShare.recent.get(source.get("id"),object.optString("id"),login));}catch(Exception e){error(e);}
    }
    private void sharePreparedProfile(JSONObject profile,String login,String password){
        try{JSONObject prepared=PasswordSignIn.withKnownPassword(profile,login,password);String details=PasswordSignIn.share(prepared,password);
            if(details!=null){signInShareMenu(ConnectionExport.fromResponse(prepared),details);return;}
            if(PasswordSignIn.passwordBased(prepared)){shareExistingPassword(prepared,login);return;}
            connectionExportMenu(ConnectionExport.fromResponse(prepared));
        }catch(Exception e){error(e);}
    }
    private void shareExistingPassword(JSONObject profile,String login){
        LinearLayout f=form();f.addView(text(login+" · "+SingleProtocols.from(PasswordSignIn.protocol(profile)).title,16,INK,true));space(f,8);EditText secret=field(f,"Existing VPN password","",true);f.addView(text("Adds the password to shared details. Does not change it on the server.",14,MUTED,false));
        AlertDialog dialog=RookDialogs.builder(this).setTitle("Include the VPN password").setView(scrolling(f)).setNegativeButton("Cancel",null).setNeutralButton("File without password",(d,w)->{try{connectionExportMenu(ConnectionExport.fromResponse(profile));}catch(Exception e){error(e);}}).setPositiveButton("Continue",null).create();dialog.show();secure(dialog);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String password=secret.getText().toString();if(!InputRules.vpnPassword(password)){secret.setError("Enter the existing VPN password");return;}dialog.dismiss();sharePreparedProfile(profile,login,password);});
    }
    private void exportSavedNative(Gateway node){
        try{JSONObject saved=new NativeProfileStore(this).read(node.get("id"));ConnectionExport export=ConnectionExport.fromStored(node.get("id"),saved);String details=null;try{details=PasswordSignIn.share(new JSONObject(saved.getString("content")),node.vpnPassword);}catch(JSONException ignored){}if(details!=null)signInShareMenu(export,details);else connectionExportMenu(export);}catch(Exception e){error(e);}
    }
    private void signInShareMenu(ConnectionExport profile,String details){
        RookDialogs.builder(this).setTitle("Share VPN access").setItems(new String[]{"Share sign-in details","Copy sign-in details","Share connection file","Save connection file"},(d,w)->{try{if(w==0)startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,details),"Share VPN sign-in"));else if(w==1)copyConnection(details,"VPN sign-in","Sign-in details copied");else if(w==2)shareConnectionFile(profile);else saveProtocolProfile(profile.pending());}catch(Exception e){error(e);}}).setNegativeButton("Cancel",null).show();
    }
    private void connectionExportMenu(ConnectionExport profile){
        String copy=(profile.protocol.equals("xray")||profile.protocol.equals("xhttp"))?"Copy link":"Copy configuration";
        RookDialogs.builder(this).setTitle("Share connection").setItems(new String[]{"Share connection file","Share configuration text","Save connection file",copy},(d,w)->{
            try{
                if(w==0)shareConnectionFile(profile);
                else if(w==1)startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,profile.content),"Share VPN configuration"));
                else if(w==2)saveProtocolProfile(profile.pending());
                else copyConnection(profile.content);
            }catch(Exception e){error(e);}
        }).setNegativeButton("Cancel",null).show();
    }
    private void shareConnectionFile(ConnectionExport profile){
        Uri uri=ProfileExportProvider.issue(this,profile.name,profile.content);
        Intent share=new Intent(Intent.ACTION_SEND).setType(profile.mime()).putExtra(Intent.EXTRA_STREAM,uri);
        share.setClipData(ClipData.newRawUri("VPN profile",uri));share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivity(Intent.createChooser(share,"Share VPN profile"));
    }
    private void copyConnection(String content){copyConnection(content,"VPN configuration","Configuration copied");}
    private void copyConnection(String content,String label,String notice){
        ClipboardManager clipboard=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
        ClipData clip=ClipData.newPlainText(label,content);
        if(Build.VERSION.SDK_INT>=24){PersistableBundle extras=new PersistableBundle();extras.putBoolean("android.content.extra.IS_SENSITIVE",true);clip.getDescription().setExtras(extras);}
        clipboard.setPrimaryClip(clip);Toast.makeText(this,notice,Toast.LENGTH_SHORT).show();
        new Handler(Looper.getMainLooper()).postDelayed(()->{
            try{ClipData current=clipboard.getPrimaryClip();if(current!=null&&current.getItemCount()==1&&current.getDescription().getLabel()!=null&&current.getItemAt(0).getText()!=null&&label.contentEquals(current.getDescription().getLabel())&&content.contentEquals(current.getItemAt(0).getText())){
                if(Build.VERSION.SDK_INT>=28)clipboard.clearPrimaryClip();else clipboard.setPrimaryClip(ClipData.newPlainText("",""));
            }}catch(SecurityException ignored){}
        },60_000);
    }
    private void saveProtocolProfile(JSONObject profile)throws Exception{
        ConnectionExport export=ConnectionExport.fromResponse(profile);profileExport.set(export.pending());
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(export.mime()).putExtra(Intent.EXTRA_TITLE,export.documentName()),SAVE_PROFILE);
    }
    private void finishProfileExport(int result,Intent data){
        JSONObject profile=profileExport.take();if(result!=RESULT_OK)return;
        if(profile==null){error(new IOException("Export expired. Get the profile again."));return;}
        try{
            ConnectionExport export=ConnectionExport.fromResponse(profile);
            ProfileDocumentExport.Result saved=ProfileDocumentExport.save(getContentResolver(),data==null?null:data.getData(),export);
            AlertDialog.Builder notice=RookDialogs.builder(this).setTitle("File saved").setPositiveButton("Done",null);
            if(!saved.amneziaCompatible)notice.setMessage("Your connection file is saved and can be imported into Rookstride. This storage provider could not shorten its name. To import it into AmneziaWG, rename it to a short name such as family.conf first.");
            notice.show();
        }catch(Exception e){error(e);}
    }
    private void trust(Gateway requested,Ssh.HostTrust t,Runnable retry) {
        Gateway node=t.node==null?requested:t.node;
        if(t.changed) {
            String expected=node.get("fingerprint");
            try{String stored=new ServerIdentityPins(this).get(node);if(!stored.isEmpty())expected=stored;}catch(Exception problem){error(problem);return;}
            final String reviewed=expected;
            LinearLayout review=form();review.addView(text(node.get("host")+":"+node.port(),17,INK,true));space(review,10);
            review.addView(text("Sign-in stopped before credentials were sent. A replaced or reinstalled server may have a new SSH identity. Confirm the new fingerprint with your provider before trusting it.",14,INK,false));
            space(review,14);review.addView(text("Saved identity",12,MUTED,true));TextView old=text(reviewed,13,INK,false);old.setTextIsSelectable(true);review.addView(old);
            space(review,12);review.addView(text("New identity",12,MUTED,true));TextView fresh=text(t.fingerprint,13,INK,false);fresh.setTextIsSelectable(true);review.addView(fresh);
            CheckBox verified=new CheckBox(this);verified.setText("I verified this replacement server and its new fingerprint");verified.setMinHeight(dp(48));review.addView(verified);
            AlertDialog dialog=RookDialogs.builder(this).setTitle("Server identity changed").setView(scrolling(review)).setNegativeButton("Cancel",null).setPositiveButton("Trust replacement",null).create();dialog.show();
            Button accept=dialog.getButton(AlertDialog.BUTTON_POSITIVE);accept.setEnabled(false);verified.setOnCheckedChangeListener((v,on)->accept.setEnabled(on));
            accept.setOnClickListener(v->{try{new ServerIdentityPins(this).replaceReviewed(node,reviewed,t.fingerprint,gateways);recordActivity("Server identity replaced after review",node);dialog.dismiss();retry.run();}catch(Exception problem){dialog.dismiss();error(problem);}});return;
        }
        String previous=node.get("fingerprint");
        try{
            ServerIdentityPins pins=new ServerIdentityPins(this);String saved=pins.get(node);
            if(!saved.isEmpty()&&!saved.equals(t.fingerprint)){node.set("fingerprint",saved);trust(node,new Ssh.HostTrust(t.fingerprint,true,node),retry);return;}
            pins.remember(node,t.fingerprint);node.set("fingerprint",t.fingerprint);vault.write(gateways);retry.run();
        }catch(Exception e){node.set("fingerprint",previous);error(new IOException("Could not securely remember this server’s identity. Sign-in was stopped.",e));}
    }

    private EditText field(LinearLayout into,String label,String value,boolean password) {
        TextView l=text(label,12,MUTED,true);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.topMargin=dp(12);into.addView(l,lp);
        EditText e=new EditText(this);e.setSingleLine(true);e.setMinHeight(dp(48));boolean technical=!label.equals(t("Gateway name"))&&!label.equals(t("Person"))&&!label.equals(t("Device label"));e.setTextDirection(technical?View.TEXT_DIRECTION_LTR:View.TEXT_DIRECTION_FIRST_STRONG);if(technical)e.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);e.setTextSize(16);e.setText(value);e.setInputType(password?InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD:InputType.TYPE_CLASS_TEXT);
        e.setId(View.generateViewId());e.setSaveEnabled(false);e.setTag(label);l.setLabelFor(e.getId());
        if(password){
            e.setTypeface(Typeface.create("sans-serif",Typeface.NORMAL));LinearLayout input=row();input.setSaveEnabled(false);input.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);input.addView(e,new LinearLayout.LayoutParams(0,-2,1));
            ImageButton eye=new ImageButton(this);eye.setTag("password-visibility-"+label);eye.setSaveEnabled(false);eye.setImageResource(R.drawable.rook_eye);eye.setColorFilter(MUTED);eye.setPadding(dp(12),dp(12),dp(12),dp(12));eye.setBackground(touchFeedback(10));eye.setContentDescription("Show "+label.toLowerCase(Locale.ROOT));eye.setOnClickListener(v->{boolean visible=e.getTransformationMethod()!=null;int start=e.getSelectionStart(),end=e.getSelectionEnd();e.setTransformationMethod(visible?null:android.text.method.PasswordTransformationMethod.getInstance());if(start>=0&&end>=0)e.setSelection(Math.min(start,e.length()),Math.min(end,e.length()));eye.setImageResource(visible?R.drawable.rook_eye_off:R.drawable.rook_eye);eye.setSelected(visible);eye.setContentDescription((visible?"Hide ":"Show ")+label.toLowerCase(Locale.ROOT));});input.addView(eye,new LinearLayout.LayoutParams(dp(48),dp(48)));into.addView(input,new LinearLayout.LayoutParams(-1,-2));
        }else into.addView(e,new LinearLayout.LayoutParams(-1,-2));return e;
    }
    private LinearLayout form() {LinearLayout f=stack();f.setPadding(dp(22),dp(8),dp(22),dp(12));return f;}
    private LinearLayout advanced(LinearLayout parent){LinearLayout content=stack();content.setVisibility(View.GONE);Button options=fullButton(parent,"Connection options",false,()->{boolean open=content.getVisibility()!=View.VISIBLE;content.setVisibility(open?View.VISIBLE:View.GONE);});options.setContentDescription("Connection options: optional name, ports and private key");parent.addView(content);return content;}
    private ScrollView scrolling(LinearLayout f) {return RookDialogs.scrolling(this,f);}
    private void secure(AlertDialog dialog) {if(dialog.getWindow()!=null)dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);}
    private void passwordDialog(Gateway node,Runnable next) {
        LinearLayout f=form();f.setFocusableInTouchMode(true);f.requestFocus();f.addView(text(node.get("admin")+"@"+node.get("host"),15,INK,true));space(f,6);f.addView(text("Use the administrator password from your VPS provider. This signs in to the server over SSH.",14,MUTED,false));
        EditText p=field(f,"Server administrator password or key passphrase","",true);CheckBox remember=new CheckBox(this);remember.setText("Save server access on this phone");remember.setTextSize(14);remember.setMinHeight(dp(48));remember.setChecked(shouldRemember(node));f.addView(remember);f.addView(text("Stored encrypted so Refresh, users and server controls work next time.",13,MUTED,false));
        AlertDialog d=RookDialogs.builder(this).setTitle("Server sign-in").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Continue",null).create();d.show();secure(d);d.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE|WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{if(p.getText().length()==0&&node.privateKey.isEmpty()){p.setError("Enter your server administrator password");return;}node.sshPassword=p.getText().toString();try{ServerAccess.remember(gateways,node,remember.isChecked());}catch(Exception e){error(e);return;}save();d.dismiss();next.run();});
    }
    private void editGateway(Gateway node){editGateway(node,"");}
    private void editGateway(Gateway node,String nextAction){editGateway(node,nextAction,false);}
    private void editGateway(Gateway node,String nextAction,boolean serverOnly) {
        if(demo && node!=null){demoNotice();return;}if(vaultFailed){error(new IOException("Saved data is locked; preserve it before clearing app storage."));return;}
        Gateway parent=null;for(Gateway candidate:gateways)if(node!=null&&candidate.exit==node)parent=candidate;final Gateway pairParent=parent;
        SingleProtocols chosen=SingleProtocols.from(node==null?setupProtocol:node.get("protocol"));
        LinearLayout f=form();
        if(node==null&&nextAction.equals("install")&&!savedSetupServers().isEmpty()){fullButton(f,"Use a saved server",false,()->chooseSingleServer());space(f,12);f.addView(text("Or connect a new server",14,MUTED,false));}
        EditText host=field(f,"Server address",node==null?"":node.get("host"),false);
        EditText user=field(f,"Administrator login",node==null?"root":node.get("admin"),false);
        EditText password=field(f,"Server password (SSH)",node==null?"":node.sshPassword,true);password.setHint("From your VPS provider");
        CheckBox remember=new CheckBox(this);remember.setText("Save server access on this phone");remember.setTextSize(14);remember.setMinHeight(dp(48));remember.setChecked(shouldRemember(node));f.addView(remember);
        f.addView(text("Encrypted on this phone. You can turn this off here or in Settings.",12,MUTED,false));
        LinearLayout advanced=advanced(f);
        EditText name=field(advanced,serverOnly?"Server name":"VPN name",node==null?"":serverOnly&&(node.isPair()||pairParent!=null)?physicalName(node):node.isPair()||clientOnly(node)?node.get("name"):ServerProtocols.name(node),false);name.setHint("Use server address");
        EditText port=field(advanced,"SSH port",node==null?"22":String.valueOf(node.port()),false);port.setInputType(InputType.TYPE_CLASS_NUMBER);
        boolean installed=node!=null&&node.data.optJSONObject("snapshot")!=null&&node.data.optJSONObject("snapshot").has("services");
        boolean automaticPort=chosen!=SingleProtocols.IKEV2&&(node==null||node.data.optBoolean("vpnPortAuto",false))&&!installed;
        int configuredPort=node==null?chosen.port:installed?node.data.optJSONObject("snapshot").optInt("port",node.data.optInt("vpnPort",chosen.port)):node.data.optInt("vpnPort",chosen.port);
        EditText vpnPort=!serverOnly&&pairParent==null&&(node==null||!node.isPair())?field(advanced,chosen==SingleProtocols.IKEV2?"Phone VPN port":"VPN port",automaticPort?"":Integer.toString(configuredPort),false):null;
        if(vpnPort!=null)vpnPort.setHint(chosen==SingleProtocols.IKEV2?"500":"Automatic");
        if(vpnPort!=null){vpnPort.setInputType(InputType.TYPE_CLASS_NUMBER);if(node!=null&&otherProtocol(node)&&node.data.optJSONObject("snapshot")!=null&&node.data.optJSONObject("snapshot").has("services"))vpnPort.setEnabled(false);}
        keyField=field(advanced,"SSH private key",node==null?"":node.privateKey,true);keyField.setSingleLine(false);keyField.setMaxLines(3);
        fullButton(advanced,"Choose key file",false,()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),PICK_KEY));
        editor=RookDialogs.builder(this).setTitle(node==null?"Connect your server":"Server access").setView(scrolling(f)).setNegativeButton(t("Cancel"),null).setPositiveButton(node==null&&nextAction.equals("install")?"Install VPN":t("Save"),null).create();
        editor.show();secure(editor);
        editor.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            try {
                int p=port.getText().toString().trim().isEmpty()?22:Integer.parseInt(port.getText().toString().trim());String h=host.getText().toString().trim(),u=user.getText().toString().trim(),n=name.getText().toString().trim();if(n.isEmpty())n=h.substring(0,Math.min(80,h.length()));
                if(!InputRules.host(h)||!InputRules.port(p)||!InputRules.username(u)||n.isEmpty()||n.length()>80)throw new IllegalArgumentException("Check the name, address, port and administrator login.");
                boolean auto=vpnPort!=null&&chosen!=SingleProtocols.IKEV2&&vpnPort.getText().toString().trim().isEmpty();int vp=vpnPort==null||vpnPort.getText().toString().trim().isEmpty()?chosen.port:Integer.parseInt(vpnPort.getText().toString().trim());if(!InputRules.port(vp))throw new IllegalArgumentException("Check the VPN port.");if(node==null&&chosen==SingleProtocols.IKEV2&&vp!=500&&vp!=4500)throw new IllegalArgumentException("Use 500 or 4500 for IKEv2.");
                if(node!=null&&node.remember()&&!remember.isChecked()&&!Boolean.TRUE.equals(remember.getTag())){confirmForgetAccess(()->{remember.setTag(Boolean.TRUE);editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();});return;}
                Gateway target=node==null?new Gateway():node;ArrayList<Gateway> siblings=new ArrayList<>();if(node!=null)for(Gateway sibling:gateways)if(ServerProtocols.sameServer(target,sibling))siblings.add(sibling);
                boolean changedHost=!h.equals(target.get("host"))||p!=target.port();if(changedHost)target.set("fingerprint","");
                if(serverOnly&&(target.isPair()||pairParent!=null))target.set("serverName",n);else target.set("name",n);target.set("host",h);target.set("admin",u);target.data.put("port",p);target.data.put("remember",remember.isChecked());target.data.put("saveAccessChosen",true);target.sshPassword=password.getText().toString();target.privateKey=keyField.getText().toString();
                if(!target.isPair()&&pairParent==null&&!clientOnly(target)){target.set("serverName",n);for(Gateway sibling:siblings){if(changedHost)clearRemovedProtocol(sibling);sibling.set("host",h);sibling.set("admin",u);sibling.set("serverName",n);sibling.data.put("port",p);sibling.data.put("remember",remember.isChecked());sibling.data.put("saveAccessChosen",true);sibling.sshPassword=target.sshPassword;sibling.privateKey=target.privateKey;sibling.set("fingerprint",target.get("fingerprint"));if(sibling!=target)sibling.set("name",n+" · "+SingleProtocols.from(sibling.get("protocol")).title);}}
                if(vpnPort!=null){target.data.put("vpnPort",vp);target.data.put("vpnPortAuto",auto);if(!otherProtocol(target))applyPhonePort(target,vp);}
                if(node==null)gateways.add(target);selected=pairParent==null?target:pairParent;demo=false;target.set("setupIntent",nextAction);if(node==null)target.set("protocol",nextAction.equals("manage")?"":setupProtocol);save();editor.dismiss();if(nextAction.equals("manage"))openServer(target);else if(node==null||!nextAction.isEmpty())openScreen("VPN");else render();if(!nextAction.isEmpty())inspect(target);
            }catch(Exception e){Toast.makeText(this,t(e.getMessage()),Toast.LENGTH_LONG).show();}
        });
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==NATIVE_BATTERY){String id=pendingNativeId;pendingNativeId="";for(Gateway node:gateways)if(node.get("id").equals(id)){connectPhone(node);break;}return;}
        if(request==PREPARE_NATIVE_VPN){String id=pendingNativeId;pendingNativeId="";if(result==RESULT_OK)for(Gateway n:gateways)if(n.get("id").equals(id)){startNative(n);break;}return;}
        if(request==SAVE_PROFILE){finishProfileExport(result,data);return;}
        if(request==SAVE_COLLECTION){finishCollectionExport(result,data);return;}
        if(request==PICK_COLLECTION){if(result==RESULT_OK&&data!=null&&data.getData()!=null)collectionState.read(getApplicationContext(),data.getData());return;}
        if(request==SAVE_ADMIN_INVITATION){finishAdminInvitationExport(result,data);return;}
        if(request==PICK_PROFILE&&result==RESULT_OK&&data!=null){importProfile(data.getData());return;}
        if(request==SAVE_RECOVERY){finishRecoveryExport(result,data);return;}
        if(request==PICK_RECOVERY&&result==RESULT_OK&&data!=null){try(InputStream input=getContentResolver().openInputStream(data.getData())){byte[] envelope=read(input,2*1024*1024);Gateway target=null;for(Gateway node:gateways)if(node.get("id").equals(recoveryServerId))target=node;if(target==null)throw new IOException("Choose the matching saved Double VPN again.");decryptRecovery(target,envelope,recoveryPurpose);}catch(Exception e){error(e);}return;}
        if(request==PICK_ADMIN_INVITATION&&result==RESULT_OK&&data!=null){try(InputStream input=getContentResolver().openInputStream(data.getData())){reviewAdminInvitation(AdminAccess.parseInvitation(new String(read(input,65536),StandardCharsets.UTF_8)));}catch(Exception e){error(e);}return;}
        if(request==PICK_KEY && result==RESULT_OK && data!=null && keyField!=null)try(InputStream in=getContentResolver().openInputStream(data.getData())){keyField.setText(new String(read(in,65536),StandardCharsets.UTF_8));}catch(Exception e){error(e);}
    }
    private final java.util.Map<EditText,String> passwordWarnings=new java.util.WeakHashMap<>();
    private boolean acceptPasswordAdvice(EditText field, Runnable again){
        String value=field.getText().toString();
        if(!InputRules.weakVpnPassword(value)||value.equals(passwordWarnings.get(field)))return true;
        RookDialogs.builder(this).setTitle("Use this password?").setMessage("This password is easy to guess. We recommend at least 8 characters. You can use a longer passphrase, or keep your choice.").setNegativeButton("Change password",null).setPositiveButton("Use anyway",(d,w)->{passwordWarnings.put(field,value);again.run();}).show();return false;
    }
    private static String generatedPassword() {return InputRules.generatedVpnPassword();}
    private void confirm(String title,String copy,Runnable action) {RookDialogs.builder(this).setTitle(t(title)).setMessage(t(copy)).setNegativeButton(t("Cancel"),null).setPositiveButton(t("Continue"),(d,w)->action.run()).show();}
    private void installation(Gateway node,boolean enroll) {
        if(demo){demoNotice();return;}
        String login="this-phone",password=enroll?"":generatedPassword();
        JSONObject config=json("mode",enroll?"enroll":"install","server",vpnAddress(node),"login",enroll?"":login,"password",password,"statistics",node.data.optBoolean("statistics",true),"aliases",node.data.optJSONArray("ikeCertificateAliases"));
        if(!enroll){if(node.get("accessMode").isEmpty())node.set("accessMode","password");}
        if(!node.get("accessMode").isEmpty())try{config.put("access_mode",node.get("accessMode"));}catch(JSONException e){error(e);return;}
        if(!enroll){node.set("vpnLogin",login);node.vpnPassword=password;try{node.data.put("rememberVpn",true);}catch(JSONException e){error(e);return;}save();}
        startDeployment(node,enroll?"enroll":"single",config,false);
    }
    private void installIke(Gateway node){node.set("setupIntent","install");save();inspect(node);}
    private String physicalName(Gateway node){return node.get("serverName").isEmpty()?node.get("host"):node.get("serverName");}
    private void openPairServer(Gateway pair,Gateway part){selected=pair;pendingServerId=part.get("id");openScreen("PairServer");}
    private void pairServerScreen(){
        if(selected==null||!selected.isPair()){empty("Choose a Double VPN first.");return;}
        homeConnectionUpdates.clear();
        Gateway owner=selected,part=owner.exit.get("id").equals(pendingServerId)?owner.exit:owner;boolean entry=part==owner;
        serverTitle(part,true);LinearLayout c=card();c.addView(text("Double VPN · "+(entry?"Entry server":"Exit server"),18,RED,true));space(c,6);c.addView(text(owner.get("name"),15,INK,true));space(c,10);c.addView(text(SingleProtocols.from(owner.get(entry?"pairEntryProtocol":"pairExitProtocol")).title,20,INK,true));
        Button control=fullButton(c,entry?connectionAction(owner):"Open Double VPN",true,()->{if(entry)toggleConnection(owner);else openVpn(owner);});
        if(entry){control.setTag("pair-server-connection");Runnable update=()->updateConnectionAction(control,owner);homeConnectionUpdates.add(update);update.run();}
        fullButton(body,"Refresh server",false,()->refreshPair(owner));fullButton(body,"Server access",false,()->editGateway(part,"",true));
        fullButton(body,"VPN users",false,()->openUsers(owner));fullButton(body,"Server maintenance",false,()->openMaintenance(owner));
        List<Gateway> separate=independentConnections(part);if(!separate.isEmpty()){space(body,16);body.addView(text("Separate VPN connections",18,INK,true));for(Gateway node:separate)homeProtocolShortcut(body,node,node,SingleProtocols.from(node.get("protocol")),false);}
        if(entry&&canReviewSeparateVpn(owner))fullButton(body,"Add a separate VPN",false,()->reviewSeparateVpn(owner));
    }
    private boolean canReviewSeparateVpn(Gateway pair){return pair.isPair()&&PairController.modern(pair)&&pair.get("pairEntryProtocol").equals("awg")&&pair.get("pairId").matches("[a-f0-9]{32}")&&readyPhoneConnection(pair)&&!pair.data.optBoolean("pairNeedsPreparation");}
    private void reviewSeparateVpn(Gateway pair){
        if(!canReviewSeparateVpn(pair))return;
        for(Gateway existing:independentConnections(pair))if(existing.get("protocol").equals("openvpn")){openVpn(existing);return;}
        try{Gateway candidate=ServerProtocols.createCoexistingOpenVpn(pair);JSONObject request=json("action","plan","protocol","openvpn","server",vpnAddress(candidate),"sshPort",candidate.port(),"login","this-phone","coexist_pair",pair.get("pairId"));
            withSsh(pair,"Checking a separate VPN on the entry server",ssh->{try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,request);}},plan->{
                LinearLayout f=form();f.addView(text("OpenVPN on "+physicalName(pair),18,INK,true));space(f,10);f.addView(text("This connection reaches the internet directly through the entry server. Your existing Double VPN and its users keep their two-server route.",15,INK,false));space(f,10);f.addView(text("The server has checked a separate listener, address range and port. This option currently supports OpenVPN alongside an AmneziaWG Double VPN entry. No VPNs will be removed.",14,MUTED,false));
                RookDialogs.builder(this).setTitle("Add a separate VPN").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Install OpenVPN",(d,w)->{try{candidate.data.put("vpnPort",plan.getInt("port"));candidate.data.put("vpnPortAuto",false);gateways.add(candidate);selected=candidate;save();protocolInstallation(candidate);}catch(Exception e){error(e);}}).show();
            },"");
        }catch(Exception e){error(e);}
    }
    private boolean newPairDraft(){if(vaultFailed){error(new IOException("Saved VPN data is locked."));return false;}pairDraft.clear();pairDraft.open=true;pairDraft.remember=rememberServerAccess();pairDraft.put("password",generatedPassword());return true;}
    private void addPair(){if(newPairDraft())showPairStep();}
    private void draftServer(String role,Gateway node){
        hasAuth(node);pairDraft.put(role+"Remember",Boolean.toString(shouldRemember(node)));pairDraft.put(role+"Saved",node.get("id"));pairDraft.put(role+"Host",node.get("host"));pairDraft.put(role+"User",node.get("admin"));pairDraft.put(role+"Port",Integer.toString(node.port()));pairDraft.put(role+"Password",node.sshPassword);pairDraft.put(role+"Key",node.privateKey);
    }
    private void choosePairSshRoute(Gateway pair){
        String[] ids={"auto","direct","entry-via-exit","exit-via-entry"},labels={"Automatic · use the reachable server if needed","Direct only","Manage entry through exit","Manage exit through entry"};int current=0;for(int i=0;i<ids.length;i++)if(ids[i].equals(pair.get("sshRoute")))current=i;final int[] choice={current};
        LinearLayout f=form();f.addView(text("Choose how this phone reaches the servers for administration. Your VPN route stays the same.",14,MUTED,false));RadioGroup options=new RadioGroup(this);for(int i=0;i<ids.length;i++){RadioButton row=new RadioButton(this);row.setId(View.generateViewId());row.setTag(i);row.setText(labels[i]);row.setMinHeight(dp(48));options.addView(row);row.setChecked(i==current);}options.setOnCheckedChangeListener((group,id)->choice[0]=(Integer)group.findViewById(id).getTag());f.addView(options);
        RookDialogs.builder(this).setTitle("Server connection").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Save",(d,w)->{pair.set("sshRoute",ids[choice[0]]);pair.data.remove("resolvedSshRoute");pair.configureRelay();save();message="Server connection preference saved";render();}).show();
    }
    private void editPair(Gateway pair){if(!newPairDraft())return;draftServer("entry",pair);draftServer("exit",pair.exit);pairDraft.entry=pair.get("pairEntryProtocol").isEmpty()?"ikev2":pair.get("pairEntryProtocol");pairDraft.exit=pair.get("pairExitProtocol").isEmpty()?"awg":pair.get("pairExitProtocol");pairDraft.put("name",pair.get("name"));pairDraft.put("rebuild",pair.get("id"));pairDraft.put("relay",pair.get("sshRoute"));pairDraft.put("vpnPort",Integer.toString(pair.data.optInt("vpnPort",SingleProtocols.from(pairDraft.entry).port)));pairDraft.put("tunnelPort",Integer.toString(pair.data.optInt("tunnelPort",pairDraft.exit.equals("awg")?443:SingleProtocols.from(pairDraft.exit).port)));showPairStep();}
    private EditText pairField(LinearLayout target,String key,String label,String fallback,boolean secret){EditText input=field(target,label,pairDraft.get(key,fallback),secret);input.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int f){}public void onTextChanged(CharSequence s,int a,int b,int c){pairDraft.put(key,s.toString());}public void afterTextChanged(android.text.Editable s){}});return input;}
    private void choosePairServer(String role){
        LinearLayout choices=form();AlertDialog chooser=RookDialogs.builder(this).setTitle("Choose a saved server").setView(scrolling(choices)).setNegativeButton("Cancel",null).create();boolean any=false;String other=pairDraft.get((role.equals("entry")?"exit":"entry")+"Saved","");
        for(Gateway node:PairNodes.catalog(gateways))if(!clientOnly(node)&&!node.get("host").isEmpty()&&!node.get("id").equals(other)){
            any=true;Button option=button(physicalName(node)+"\n"+node.get("host"),false,()->{});option.setTag("saved-pair-server-"+node.get("id"));choices.addView(option,new LinearLayout.LayoutParams(-1,-2));space(choices,8);
            option.setOnClickListener(view->{draftServer(role,node);chooser.dismiss();if(pairWizard!=null)pairWizard.dismiss();showPairStep();});
        }
        if(!any)choices.addView(text("No other saved servers. Add the new server’s address below.",14,MUTED,false));
        chooser.show();
    }
    private void pairChoices(LinearLayout f,boolean entry){
        ArrayList<LinearLayout> cards=new ArrayList<>();ArrayList<RadioButton> radios=new ArrayList<>();
        for(SingleProtocols choice:setupProtocols()){String id=choice.id;
            SingleProtocols protocol=SingleProtocols.from(id);LinearLayout c=stack();c.setPadding(dp(14),dp(10),dp(14),dp(14));c.setTag("pair-choice-"+id);recommendation(c,protocol);RadioButton option=new RadioButton(this);option.setText(protocol.title);option.setTag(id);option.setMinHeight(dp(48));option.setButtonTintList(android.content.res.ColorStateList.valueOf(RED));LinearLayout heading=row();heading.addView(option,new LinearLayout.LayoutParams(0,-2,1));Button details=button("Details",false,()->protocolInfo(protocol));details.setTextColor(MUTED);details.setTextSize(13);details.setMinWidth(dp(64));details.setMinHeight(dp(48));details.setPadding(dp(8),0,dp(8),0);details.setBackground(touchFeedback(8));details.setContentDescription("Details about "+protocol.title);heading.addView(details,new LinearLayout.LayoutParams(-2,dp(48)));c.addView(heading);TextView copy=text(protocolUse(protocol),13,MUTED,false);copy.setPadding(dp(8),0,dp(4),0);c.addView(copy);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.bottomMargin=dp(10);f.addView(c,lp);cards.add(c);radios.add(option);
            Runnable choose=()->{if(entry){boolean changed=!id.equals(pairDraft.entry);pairDraft.entry=id;if(changed)pairDraft.put("vpnPort",Integer.toString(protocol.port));}else{boolean changed=!id.equals(pairDraft.exit);pairDraft.exit=id;if(changed)pairDraft.put("tunnelPort",Integer.toString(id.equals("awg")?443:protocol.port));}for(int i=0;i<cards.size();i++)stylePairChoice(cards.get(i),radios.get(i),(entry?pairDraft.entry:pairDraft.exit).equals(radios.get(i).getTag()));};
            heading.setOnClickListener(view->choose.run());c.setFocusable(true);c.setClickable(true);c.setOnClickListener(view->choose.run());copy.setOnClickListener(view->choose.run());option.setOnClickListener(view->choose.run());stylePairChoice(c,option,id.equals(entry?pairDraft.entry:pairDraft.exit));
        }
    }
    private void stylePairChoice(LinearLayout card,RadioButton radio,boolean selected){radio.setChecked(selected);GradientDrawable background=shape(selected?Color.rgb(255,245,245):Color.WHITE,12);background.setStroke(dp(selected?2:1),selected?RED:Color.rgb(215,215,224));card.setBackground(background);card.setForeground(touchFeedback(12));card.setContentDescription(radio.getText()+ (selected?", selected":""));}
    private void pairUserSettings(){
        LinearLayout f=form();EditText login=field(f,"VPN user name",pairDraft.get("login","this-phone"),false),password=field(f,"VPN password",pairDraft.get("password",""),true);
        AlertDialog d=RookDialogs.builder(this).setTitle("VPN user settings").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();d.show();secure(d);d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{if(!InputRules.username(login.getText().toString())||!InputRules.vpnPassword(password.getText().toString())){password.setError("Use a nonempty password, up to 127 UTF-8 bytes.");return;}if(!acceptPasswordAdvice(password,()->d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()))return;pairDraft.put("login",login.getText().toString());pairDraft.put("password",password.getText().toString());d.dismiss();});
    }
    private void showPairStep(){
        if(isFinishing()||isDestroyed()||!pairDraft.open)return;LinearLayout f=form();final int step=pairDraft.step;
        f.addView(text("Step "+(step+1)+" of 5",13,RED,true));space(f,8);ProgressBar bar=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);bar.setMax(5);bar.setProgress(step+1);bar.setProgressTintList(android.content.res.ColorStateList.valueOf(RED));f.addView(bar,new LinearLayout.LayoutParams(-1,dp(8)));space(f,16);
        String[] headings={"Phone → first server","First server → exit server","Entry server","Exit server","Review your Double VPN"};f.addView(text(headings[step],21,INK,true));space(f,8);
        if(step<2){f.addView(text(step==0?"Choose how your phone connects to the first server.":"Choose how the first server connects to the exit. Websites see the exit server’s address.",14,MUTED,false));space(f,12);pairChoices(f,step==0);}
        else if(step<4){String role=step==2?"entry":"exit";f.addView(text("Choose a saved server or enter a new one. Existing VPN software can be removed after you review it.",14,MUTED,false));fullButton(f,"Choose a saved server",false,()->choosePairServer(role));
            pairField(f,role+"Host",step==2?"Entry VPS address":"Exit VPS address","",false);pairField(f,role+"Password","Server administrator password","",true);LinearLayout extra=advanced(f);pairField(extra,role+"User","Administrator name","root",false);pairField(extra,role+"Port","SSH port","22",false);pairField(extra,role+"Key","Private key (optional)","",true).setSingleLine(false);CheckBox remember=new CheckBox(this);remember.setText("Save administrator passwords on this phone");remember.setChecked(Boolean.parseBoolean(pairDraft.get(role+"Remember",Boolean.toString(pairDraft.remember))));remember.setOnCheckedChangeListener((b,on)->pairDraft.put(role+"Remember",Boolean.toString(on)));f.addView(remember);
        }else{f.addView(text(SingleProtocols.from(pairDraft.entry).title+" → "+SingleProtocols.from(pairDraft.exit).title,17,INK,true));space(f,12);f.addView(text("Entry: "+pairDraft.get("entryHost","")+"\nExit: "+pairDraft.get("exitHost",""),14,INK,false));space(f,12);f.addView(text("Rookstride checks both servers, reviews existing VPNs before replacing them, then installs and verifies the new route. Ad blocking runs on the exit.",14,MUTED,false));fullButton(f,"Swap entry and exit servers",false,()->{pairDraft.swapServers();if(pairWizard!=null)pairWizard.dismiss();showPairStep();});
            LinearLayout extra=advanced(f);pairField(extra,"name","VPN name","My Double VPN",false);pairField(extra,"vpnPort","Phone VPN port",Integer.toString(SingleProtocols.from(pairDraft.entry).port),false);pairField(extra,"tunnelPort","Exit VPN port",pairDraft.exit.equals("awg")?"443":Integer.toString(SingleProtocols.from(pairDraft.exit).port),false);if(PasswordSignIn.supported(pairDraft.entry))fullButton(extra,"VPN user settings",false,this::pairUserSettings);
            f.addView(text("Server connection",15,INK,true));RadioGroup relay=new RadioGroup(this);f.addView(relay);for(String id:new String[]{"auto","direct","entry-via-exit","exit-via-entry"}){RadioButton option=new RadioButton(this);option.setId(View.generateViewId());option.setTag(id);option.setText(id.equals("auto")?"Automatic · use the reachable server if needed":id.equals("direct")?"Direct only":id.equals("entry-via-exit")?"Manage entry through exit":"Manage exit through entry");relay.addView(option);option.setChecked(id.equals(pairDraft.get("relay","auto")));}relay.setOnCheckedChangeListener((group,id)->pairDraft.put("relay",(String)group.findViewById(id).getTag()));
        }
        ScrollView scroll=scrolling(f);scroll.setVerticalScrollBarEnabled(true);scroll.setScrollbarFadingEnabled(false);AlertDialog d=RookDialogs.builder(this).setTitle("Double VPN").setView(scroll).setNegativeButton("Cancel",(a,w)->pairDraft.clear()).setPositiveButton(step==4?"Install":"Next",null).setNeutralButton(step>0?"Back":null,null).create();pairWizard=d;d.setCanceledOnTouchOutside(false);d.setOnCancelListener(a->pairDraft.clear());d.show();if(step==2||step==3)secure(d);
        d.getOnBackPressedDispatcher().addCallback(d,new androidx.activity.OnBackPressedCallback(true){public void handleOnBackPressed(){if(step>0){pairDraft.step--;d.dismiss();showPairStep();}else{pairDraft.clear();d.dismiss();}}});if(step>0)d.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(view->{pairDraft.step--;d.dismiss();showPairStep();});
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view->{try{
            if(step==2||step==3){String role=step==2?"entry":"exit",host=pairDraft.get(role+"Host","").trim();if(!InputRules.host(host)||!InputRules.username(pairDraft.get(role+"User","root"))||!InputRules.port(Integer.parseInt(pairDraft.get(role+"Port","22"))))throw new IOException("Check the server address and administrator.");if(pairDraft.get(role+"Password","").isEmpty()&&pairDraft.get(role+"Key","").isEmpty())throw new IOException("Enter the administrator password.");if(step==3&&host.equals(pairDraft.get("entryHost","")))throw new IOException("Use two different servers.");}
            if(step<4){android.view.inputmethod.InputMethodManager ime=(android.view.inputmethod.InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);if(d.getCurrentFocus()!=null&&ime!=null)ime.hideSoftInputFromWindow(d.getCurrentFocus().getWindowToken(),0);pairDraft.step++;d.dismiss();showPairStep();return;}
            Gateway a=pairDraftNode("entry"),b=pairDraftNode("exit");if(PairNodes.same(a,b))throw new IOException("Use two different servers.");a.exit=b;a.set("name",pairDraft.get("name","My Double VPN"));a.set("pairId",PairController.newId());a.set("pairEngine","native-v2");a.set("vpnLogin",pairDraft.get("login","this-phone"));a.vpnPassword=pairDraft.get("password","");a.data.put("rememberVpn",true);a.set("pairEntryProtocol",pairDraft.entry);a.set("pairExitProtocol",pairDraft.exit);a.set("protocol",pairDraft.entry);a.set("accessMode",PasswordSignIn.supported(pairDraft.entry)?pairDraft.get("accessMode","password"):"");b.set("protocol",pairDraft.exit);int vp=Integer.parseInt(pairDraft.get("vpnPort",Integer.toString(SingleProtocols.from(pairDraft.entry).port))),tp=Integer.parseInt(pairDraft.get("tunnelPort",pairDraft.exit.equals("awg")?"443":Integer.toString(SingleProtocols.from(pairDraft.exit).port)));if(!InputRules.port(vp)||!InputRules.port(tp)||!InputRules.vpnPassword(a.vpnPassword)||pairDraft.exit.equals("ikev2")&&tp!=500)throw new IOException("Check the optional ports and VPN user settings.");a.data.put("vpnPort",vp);a.data.put("tunnelPort",tp);a.data.put("pairStatistics",true);a.data.put("pairNeedsPreparation",true);a.set("sshRoute",pairDraft.get("relay","auto"));a.configureRelay();PairController.request(a,"entry");pairDraft.clear();d.dismiss();reviewPairChange(a,false);
        }catch(Exception e){Toast.makeText(this,e.getMessage(),Toast.LENGTH_LONG).show();}});
    }
    private Gateway pairDraftNode(String role)throws Exception{
        Gateway saved=PairNodes.find(gateways,pairDraft.get(role+"Saved",""));String host=pairDraft.get(role+"Host","").trim();int port=Integer.parseInt(pairDraft.get(role+"Port","22"));Gateway node=saved!=null&&saved.get("host").equals(host)&&saved.port()==port?PairNodes.copy(saved):new Gateway();String physical=saved==null?host:physicalName(saved);PairNodes.clearConnection(node);node.exit=null;node.set("serverName",physical);node.set("name",physical);node.set("host",host);node.set("admin",pairDraft.get(role+"User","root"));node.data.put("port",port);node.sshPassword=pairDraft.get(role+"Password","");node.privateKey=pairDraft.get(role+"Key","");node.data.put("remember",Boolean.parseBoolean(pairDraft.get(role+"Remember",Boolean.toString(pairDraft.remember))));node.data.put("saveAccessChosen",true);return node;
    }
    private void reviewedNodeSummary(LinearLayout into,Gateway node,String role,JSONObject review){
        space(into,12);into.addView(text(role+" · "+physicalName(node),17,INK,true));into.addView(text(node.get("host"),13,MUTED,false));JSONArray protocols=review.optJSONArray("protocols");ArrayList<String> names=new ArrayList<>();if(protocols!=null)for(int i=0;i<protocols.length();i++)names.add(SingleProtocols.from(protocols.optString(i)).title);into.addView(text(review.optString("kind").equals("fresh")?"No installed Rookstride VPNs to remove":String.join(", ",names)+(review.optBoolean("filtering")?" · ad blocking":""),14,INK,false));
        JSONArray files=review.optJSONArray("files");if(files!=null&&files.length()>0){LinearLayout detail=stack();detail.setVisibility(View.GONE);for(int i=0;i<files.length();i++){TextView path=text(files.optString(i).replace("/","/\u200b"),12,MUTED,false);detail.addView(path,new LinearLayout.LayoutParams(-1,-2));}fullButton(into,"Technical details",false,()->detail.setVisibility(detail.getVisibility()==View.GONE?View.VISIBLE:View.GONE));into.addView(detail);}
    }
    private void reviewPairChange(Gateway pair,boolean resetOnly){
        if(demo){demoNotice();return;}if(busy||DeploymentService.active())return;if(!hasAuth(pair)){passwordDialog(pair,()->reviewPairChange(pair,resetOnly));return;}if(!hasAuth(pair.exit)){passwordDialog(pair.exit,()->reviewPairChange(pair,resetOnly));return;}busy=true;message="Checking selected servers";if(!resetOnly)beginSetupCheck(pair,true,()->reviewPairChange(pair,false));else render();
        executor.execute(()->{try{JSONObject review=pairReviewSource.read(pair);handler.post(()->{
            if(isDestroyed()||isFinishing())return;busy=false;if(setupCheckProgress!=null){setupCheckProgress.finished=System.currentTimeMillis();setupCheckProgress.state="review";setupCheckProgress.phase="Review any existing VPN software before continuing.";}message="";render();Runnable accepted=()->{if(resetOnly)applyReviewedPairReset(pair,review);else beginReviewedPair(pair,review);};
            if(!resetOnly&&!PairPreparationController.removalNeeded(review)){accepted.run();return;}
            LinearLayout f=form();f.addView(text(resetOnly?"Remove the VPN setups on these two servers?":"Replace the existing VPN setups with this Double VPN?",18,INK,true));space(f,8);f.addView(text("VPN users, connection keys, ad blocking and usage data on the selected servers will be removed. Connected devices lose access. Ubuntu and administrator sign-in stay.",14,INK,false));reviewedNodeSummary(f,pair,"Entry server",review.optJSONObject("entry"));reviewedNodeSummary(f,pair.exit,"Exit server",review.optJSONObject("exit"));
            removalReview(resetOnly?"Remove both VPN setups?":"Replace VPN setups?",f,accepted);
        });}catch(Exception error){handler.post(()->{if(isDestroyed()||isFinishing())return;busy=false;if(setupCheckProgress!=null){setupCheckProgress.finished=System.currentTimeMillis();setupCheckProgress.state="needs-attention";setupCheckProgress.phase="Check both server addresses and administrator access, then try again.";}message="";render();if(error instanceof PairController.TrustNeeded){PairController.TrustNeeded t=(PairController.TrustNeeded)error;trust(t.node,t.issue,()->reviewPairChange(pair,resetOnly));}else error(error);});}});
    }
    private void beginReviewedPair(Gateway pair,JSONObject review){
        try{for(Gateway old:new ArrayList<>(gateways))if(PairNodes.same(old,pair)||PairNodes.same(old,pair.exit)||old.isPair()&&(PairNodes.same(old.exit,pair)||PairNodes.same(old.exit,pair.exit)))invalidatePhoneProfile(old);PairNodes.attach(gateways,pair);selected=pair;demo=false;save();startDeployment(pair,"pair",json("replacementReview",review),false);}catch(Exception e){error(e);}
    }
    private void applyReviewedPairReset(Gateway pair,JSONObject review){
        busy=true;message="Removing the reviewed VPN setups";render();executor.execute(()->{try{JSONObject reset=PairPreparationController.apply(pair,review,()->getAssets().open("gateway_bundle.zip"),()->getAssets().open("single_bundle.zip"),phase->handler.post(()->{message=phase;render();}),true);handler.post(()->{try{Gateway a=PairNodes.copy(pair),b=PairNodes.copy(pair.exit);boolean active=DeploymentService.active()||DeploymentService.needsLocalSave();PairNodes.clearAfterConfirmedReset(a,reset.getJSONObject("entry"),active);PairNodes.clearAfterConfirmedReset(b,reset.getJSONObject("exit"),active);invalidatePhoneProfile(pair);PairNodes.clearConnection(a);PairNodes.clearConnection(b);a.exit=null;b.exit=null;a.sshRelay=null;b.sshRelay=null;gateways.removeIf(n->n==pair||PairNodes.same(n,a)||PairNodes.same(n,b));gateways.add(a);gateways.add(b);DeploymentService.forget(this,pair);busy=false;selected=a;save();message="Both VPN setups removed. Your saved servers are ready.";openServer(a);}catch(Exception e){busy=false;error(e);}});}catch(Exception e){handler.post(()->{busy=false;message="Removal stopped. Review again to finish the remaining setup.";render();error(e);});}});
    }
    private void runPair(Gateway node,boolean resume){if(demo){demoNotice();return;}if(busy||DeploymentService.active())return;if(node.data.optBoolean("pairNeedsPreparation")){reviewPairChange(node,false);return;}if(!hasAuth(node)){passwordDialog(node,()->runPair(node,resume));return;}if(!hasAuth(node.exit)){passwordDialog(node.exit,()->runPair(node,resume));return;}startDeployment(node,"pair",null,resume);}
    private void refreshPair(Gateway node) {
        boolean modern=PairController.modern(node);
        pairRead(node,"Checking entry and exit servers",()->{try(PairSsh ssh=PairSsh.connect(node,this::pairReadProgress)){
            JSONObject entry=modern?ssh.entry.pair(json("command","health","pair",node.get("pairId"))):ssh.entry.admin(json("action","status"));JSONObject exit=modern?ssh.exit.pair(json("command","health","pair",node.get("pairId"))):ssh.exit.admin(json("action","status"));JSONObject result=json("entry",entry,"exit",exit);
            if(modern&&node.get("pairEntryProtocol").equals("awg"))try(InputStream bundle=getAssets().open("single_bundle.zip")){JSONObject inventory=ssh.entry.single(bundle,json("action","inspect"));result.put("entry_inventory",inventory);JSONObject coexist=inventory.optJSONObject("coexisting_protocols");if(coexist!=null&&node.get("pairId").equals(coexist.optString("openvpn")))result.put("entry_separate",ssh.entry.single(json("action","status","protocol","openvpn")));}catch(Exception unavailable){result.put("separate_check_unavailable",true);}
            return result;
        }},result->{try{
            for(Gateway changed:PairNodes.rememberHealth(node,result)){newUserShare.recent.forget(changed.get("id"));invalidatePhoneProfile(changed);}long checked=System.currentTimeMillis();node.data.put("checkedAt",checked);node.exit.data.put("checkedAt",checked);node.set("checked","Both nodes checked");
            JSONObject independent=result.optJSONObject("entry_separate"),inventory=result.optJSONObject("entry_inventory");
            if(inventory!=null){Gateway physical=PairNodes.copy(node);physical.exit=null;JSONObject probe=json("inventory",inventory);reconcileServerInventory(physical,probe,inventory);}
            if(independent!=null){Gateway separate=null;for(Gateway current:gateways)if(!current.isPair()&&PairNodes.same(current,node)&&current.get("protocol").equals("openvpn")){separate=current;break;}if(separate==null){separate=ServerProtocols.createCoexistingOpenVpn(node);gateways.add(separate);}separate.set("setupIntent","");separate.data.put("snapshot",independent);separate.set("serverInstance",independent.optString("instance"));separate.data.put("checkedAt",checked);if(inventory!=null)separate.data.put("probe",json("inventory",inventory));ServerProtocols.rememberConnection(gateways,separate,independent);}
            save();message="Double VPN checked · "+node.get("name")+"\nEntry "+node.get("host")+" → Exit "+node.exit.get("host")+"\nVPN service status updated on both servers"+(result.optBoolean("separate_check_unavailable")?"\nSeparate VPN inventory could not be checked.":"");recordActivity("Double VPN checked",node);
        }catch(JSONException e){error(e);}catch(Exception e){error(e);}});
    }

    private void resetPair(Gateway node) {
        reviewPairChange(node,true);
    }

    private void resetGateway(Gateway node) {
        if(demo){demoNotice();return;}
        if(pairNode(node)){resetServer(node);return;}
        withSsh(node,"Reviewing IKEv2 removal",ssh->{try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","plan"));}},plan->{
            LinearLayout f=form();f.addView(text("Remove IKEv2 accounts, certificates, configuration, its AdGuard settings and usage history from "+node.get("host")+". Other VPN protocols, Ubuntu, SSH and installed package binaries stay.",14,INK,false));
            removalReview("Uninstall IKEv2?",f,()->withSsh(node,"Removing IKEv2 setup",ssh->{try(InputStream bundle=getAssets().open("gateway_bundle.zip")){return ssh.reset(bundle,json("mode","apply","token",plan.getString("token"),"confirmation","DELETE VPN"));}},r->{
                try{ServerProtocols.recordRemoved(gateways,node);clearRemovedProtocol(node);node.set("checked","");save();message=r.optString("message");serverProtocols(node);}catch(Exception e){error(e);}
            }));
        });
    }
    private void pollJob(Gateway node) {
        if(demo){demoNotice();return;}if(node.get("job").isEmpty())return;
        startDeployment(node,otherProtocol(node)?(node.get("jobKind").equals("filter")?"filter":"protocol"):node.get("jobKind").equals("enroll")?"enroll":"single",new JSONObject(),true);
    }
    private boolean ensurePasswordPolicy(Gateway node){
        JSONObject policy=snapshot().optJSONObject("password_policy");if(policy!=null&&policy.optBoolean("advisory"))return true;
        RookDialogs.builder(this).setTitle("Update server management").setMessage("Update this server’s management helper to use the new password rules. Existing VPN accounts stay.").setNegativeButton("Cancel",null).setPositiveButton("Update",(d,w)->installation(node,true)).show();return false;
    }
    private String accountImpactAdvice(Gateway node,String operation){
        JSONObject snapshot=node.data.optJSONObject("snapshot"),impact=snapshot==null?null:snapshot.optJSONObject("account_updates");
        String mode=impact==null?(otherProtocol(node)?"restart":"live"):impact.optString(operation,"restart");
        if(mode.equals("restart"))return "Other connections to this protocol briefly reconnect while this change is applied.";
        if(mode.equals("targeted-or-restart"))return "Only this user’s sessions normally reconnect. If the server cannot end those sessions individually, other connections briefly reconnect too.";
        if(mode.equals("live-or-restart"))return "The server normally applies this without interrupting other users. A runtime restart may be needed if its live update is unavailable.";
        return "";
    }
    private void accountUpdateNotice(Gateway node,JSONObject receipt){if(receipt.optBoolean("listener_restarted")){recordActivity("VPN users updated · protocol restarted",node);Toast.makeText(this,"User updated. Other VPN connections may briefly reconnect.",Toast.LENGTH_LONG).show();}}
    private void changePassword(Gateway node,JSONObject user){
        if(!otherProtocol(node)&&!ensurePasswordPolicy(node))return;
        LinearLayout f=form();EditText password=field(f,"New password",generatedPassword(),true);String impact=accountImpactAdvice(node,"password");if(!impact.isEmpty())f.addView(text(impact,13,MUTED,false));
        AlertDialog d=RookDialogs.builder(this).setTitle("Change password").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Update",null).create();d.show();secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String value=password.getText().toString();if(!InputRules.vpnPassword(value)){password.setError("Use a nonempty password, up to 127 UTF-8 bytes");return;}if(!acceptPasswordAdvice(password,()->d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()))return;d.dismiss();
            command(node,json("action",otherProtocol(node)?"edit-user":"add-user","login",user.optString("login"),"password",value,"person",user.optString("person"),"device",user.optString("device"),"kind",user.optString("kind"),"replace",true),r->{accountUpdateNotice(node,r);newUserShare.recent.remember(node.get("id"),node.get("serverInstance"),user.optString("login"),value);if(user.optString("login").equals(node.get("vpnLogin"))){node.vpnPassword=value;if(otherProtocol(node))try{new NativeProfileStore(this).remove(node.get("id"));}catch(Exception e){error(e);}save();}credentials(user.optString("login"),value);inspect(node);});
        });
    }
    private void addUser(Gateway node) {
        if(demo){demoNotice();return;}
        if(newUserShare.pending){restoreCreatedUserShare();return;}
        if(!otherProtocol(node)&&!ensurePasswordPolicy(node))return;
        LinearLayout f=form();boolean passwordBased=passwordUsers(node);
        EditText person=field(f,passwordBased?"Name":"Device name","",false);
        EditText login=passwordBased?field(f,"VPN username","",false):null;
        EditText password=passwordBased?field(f,"VPN password",generatedPassword(),true):null;
        if(!passwordBased)f.addView(text("Connection keys are created automatically.",13,MUTED,false));
        String impact=accountImpactAdvice(node,"add");if(!impact.isEmpty())f.addView(text(impact,13,MUTED,false));
        AlertDialog d=RookDialogs.builder(this).setTitle("Add a VPN user").setView(scrolling(f)).setNegativeButton("Cancel",null).setPositiveButton("Create user",null).create();d.show();if(passwordBased)secure(d);
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String name=person.getText().toString().trim(),user=passwordBased?login.getText().toString().trim():name,secret=passwordBased?password.getText().toString():"";
            if(name.isEmpty()){person.setError("Enter a name");return;}
            if(passwordBased?!InputRules.username(user):!user.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,47}")){(passwordBased?login:person).setError(passwordBased?"Use letters, numbers, dots, underscores, @ or hyphens":"Use up to 48 letters, numbers, underscores or hyphens; start with a letter or number");return;}
            if(passwordBased&&!InputRules.vpnPassword(secret)){password.setError("Use a nonempty password, up to 127 UTF-8 bytes");return;}
            if(passwordBased&&!acceptPasswordAdvice(password,()->d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()))return;
            JSONObject request=passwordBased?json("action","add-user","login",user,"password",secret,"person",name,"device","Device","kind","device"):json("action","add-user","login",user);
            newUserDialog=d;d.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);d.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(false);d.setCancelable(false);loadingButton(d.getButton(AlertDialog.BUTTON_POSITIVE),RED);createUserAndShare(node,request,user,secret);
        });
    }
    private JSONObject userRequest(Ssh ssh,Gateway node,JSONObject request)throws Exception{
        if(otherProtocol(node)){request.put("protocol",node.get("protocol"));try(InputStream bundle=getAssets().open("single_bundle.zip")){return ssh.single(bundle,request);}}
        if(request.optString("action").equals("profile"))request.put("server",vpnAddress(node)).put("port",node.data.optInt("vpnPort",500));
        return ssh.admin(request);
    }
    private void loadCreatedProfile(Ssh ssh,Gateway node)throws Exception{
        JSONObject scoped=newUserShare.scopedObject;
        JSONObject profile=scoped==null?userRequest(ssh,node,json("action","profile","login",newUserShare.login,"name",newUserShare.login,"server",vpnAddress(node))):AdminAccessController.request(ssh,json("operation","users.profile","object_id",scoped.optString("id"),"parameters",json("login",newUserShare.login)));
        profile=PasswordSignIn.withKnownPassword(profile,newUserShare.login,newUserShare.password);
        ConnectionExport.fromResponse(profile);newUserShare.profile=profile;newUserShare.failureCode="";newUserShare.failureDetail="";
        if(scoped==null)try{newUserShare.snapshot=userRequest(ssh,node,json("action","status"));}catch(Exception ignored){/* Sharing remains available if usage/status is temporarily unavailable. */}
    }

    private void createUserAndShare(Gateway node,JSONObject request,String user,String secret){
        withSsh(node,"Creating VPN user",ssh->{
            newUserShare.begin(node.get("id"),user,secret);
            JSONObject receipt=new JSONObject();
            try{receipt=userRequest(ssh,node,request);newUserShare.confirmed=true;newUserShare.recent.remember(node.get("id"),node.get("serverInstance"),user,secret);loadCreatedProfile(ssh,node);}
            catch(Exception failure){rememberUserShareFailure(failure);/* Retain confirmation separately from profile retrieval. Never repeat a mutation. */}
            finally{newUserShare.loading=false;}
            return json("confirmed",newUserShare.confirmed,"listener_restarted",receipt.optBoolean("listener_restarted"));
        },result->{closeNewUserDialog();message="";accountUpdateNotice(node,result);if(result.optBoolean("confirmed"))recordActivity("VPN user created",node);restoreCreatedUserShare();},"");
    }
    private void rememberUserShareFailure(Exception failure){
        if(failure instanceof Ssh.ServerActionException){Ssh.ServerActionException server=(Ssh.ServerActionException)failure;newUserShare.failureCode=server.code;newUserShare.failureDetail=server.safeDetail;}
        else{newUserShare.failureCode="unconfirmed";newUserShare.failureDetail="The connection ended before the app could read a confirmed result.";}
    }
    private void reviewRequiredUserHelperUpdate(Gateway node){
        Gateway pair=managementPair(node);if(pair==null&&node.isPair())pair=node;
        if(pair==null||node.data.optBoolean("adminAccess")){RookDialogs.builder(this).setTitle("Owner update needed").setMessage("Ask this VPN’s owner to review its management update. VPN connections stay available.").setPositiveButton("Close",null).show();return;}
        final Gateway owner=pair;pairRead(owner,"Reviewing management helper versions",()->MaintenanceUpdates.review(owner,()->getAssets().open("gateway_bundle.zip"),this::pairReadProgress),review->reviewHelperUpdate(owner,review));
    }
    private void restoreCreatedUserShare(){
        if(!newUserShare.pending||newUserShare.loading||busy||isFinishing()||isDestroyed()||userShareDialog!=null&&userShareDialog.isShowing())return;
        Gateway node=null;for(Gateway saved:gateways)if(saved.get("id").equals(newUserShare.nodeId)){node=saved;break;}
        if(node==null){newUserShare.clear();return;}
        if(newUserShare.profile!=null){if(newUserShare.snapshot!=null){try{node.data.put("snapshot",newUserShare.snapshot);save();}catch(Exception ignored){/* Sharing does not depend on caching a server snapshot. */}newUserShare.snapshot=null;}showCreatedUserShare();return;}
        final Gateway server=node;
        if(newUserShare.failureCode.equals("pair_helper_update_required")){
            userShareDialog=RookDialogs.builder(this).setTitle("Management update needed").setMessage(newUserShare.confirmed?"The VPN user was created. Review the management update before reading its connection. Do not create the user again.":newUserShare.failureDetail).setNegativeButton("Close",(d,w)->newUserShare.clear()).setPositiveButton("Review update",(d,w)->{newUserShare.clear();reviewRequiredUserHelperUpdate(server);}).create();
        }else if(!newUserShare.confirmed){
            String detail=newUserShare.failureDetail.isEmpty()?"The server did not confirm the request.":newUserShare.failureDetail;
            userShareDialog=RookDialogs.builder(this).setTitle("Check VPN users").setMessage(detail+"\n\nCheck the user list before trying to create this user again.").setNegativeButton("Close",(d,w)->newUserShare.clear()).setPositiveButton("View users",(d,w)->{JSONObject scoped=newUserShare.scopedObject;newUserShare.clear();if(scoped!=null)scopedUsers(server,scoped);else openUsers(server);}).create();
        }else userShareDialog=RookDialogs.builder(this).setTitle("User created").setMessage("The account is saved on the server. Its connection could not be loaded yet. Retry sharing reads its existing connection without creating another user.").setNegativeButton("Later",(d,w)->newUserShare.clear()).setPositiveButton("Retry sharing",(d,w)->retrieveCreatedUserShare(server)).create();
        userShareDialog.setOnCancelListener(d->newUserShare.clear());userShareDialog.show();
    }
    private void retrieveCreatedUserShare(Gateway node){
        withSsh(node,"Preparing the new connection",ssh->{
            newUserShare.loading=true;
            try{loadCreatedProfile(ssh,node);}catch(Exception failure){rememberUserShareFailure(failure);/* Retry only this read operation. */}finally{newUserShare.loading=false;}
            return new JSONObject();
        },result->{message="";restoreCreatedUserShare();},"");
    }
    private void showCreatedUserShare(){
        try{ConnectionExport profile=ConnectionExport.fromResponse(newUserShare.profile);String signIn=PasswordSignIn.share(newUserShare.profile,newUserShare.password);LinearLayout f=form();f.addView(text(newUserShare.login+" · "+SingleProtocols.from(profile.protocol).title,16,INK,true));space(f,12);f.addView(text(signIn!=null?(profile.protocol.equals("ikev2")&&newUserShare.profile.optJSONObject("remote")!=null&&newUserShare.profile.optJSONObject("remote").has("cert")?"Share the sign-in details and connection file. This VPN uses a private server certificate, included in the file.":"Share the server address, username and password, or use a profile file."):profile.protocol.equals("ikev2")?"Import this .sswan file in strongSwan, then use the VPN username and password. It includes the server certificate needed to verify this VPN.":"Anyone with this connection can use the VPN. Share it with someone you trust.",14,MUTED,false));
            if(signIn!=null)fullButton(f,"Share sign-in details",true,()->startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,signIn),"Share VPN sign-in")));
            fullButton(f,"Share connection file",signIn==null,()->{try{shareConnectionFile(profile);}catch(Exception e){error(e);}});
            if(signIn!=null)fullButton(f,"Copy sign-in details",false,()->copyConnection(signIn,"VPN sign-in","Sign-in details copied"));
            else{fullButton(f,"Share configuration text",false,()->startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,profile.content),"Share VPN connection")));fullButton(f,"Copy configuration",false,()->copyConnection(profile.content));}
            fullButton(f,"Save connection file",false,()->{try{saveProtocolProfile(profile.pending());}catch(Exception e){error(e);}});
            userShareDialog=RookDialogs.builder(this).setTitle("Share connection").setView(scrolling(f)).setPositiveButton("Done",(d,w)->newUserShare.clear()).create();userShareDialog.setOnCancelListener(d->newUserShare.clear());userShareDialog.show();
        }catch(Exception e){
            userShareDialog=RookDialogs.builder(this).setTitle("Connection could not be prepared").setMessage("The user is saved. You can retry sharing without creating the account again.").setNegativeButton("Later",(d,w)->newUserShare.clear()).setPositiveButton("Retry sharing",(d,w)->{Gateway node=null;for(Gateway saved:gateways)if(saved.get("id").equals(newUserShare.nodeId)){node=saved;break;}newUserShare.profile=null;if(node!=null)retrieveCreatedUserShare(node);else newUserShare.clear();}).create();userShareDialog.setOnCancelListener(d->newUserShare.clear());userShareDialog.show();
        }
    }
    private void credentials(String user,String password) {
        RookDialogs.builder(this).setTitle(t("Access created")).setMessage(t("Login: ")+user+t("\nPassword: ")+password+t("\n\nSave the password now; it is not returned by the user list. Share the profile and password through a trusted channel."))
            .setPositiveButton(t("Done"),null).setNeutralButton(t("Copy password"),(d,w)->copySecret(password)).show().getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    private void copySecret(String password) {
        ClipData c=ClipData.newPlainText("VPN password",password);
        if(Build.VERSION.SDK_INT>=33){PersistableBundle extras=new PersistableBundle();extras.putBoolean("android.content.extra.IS_SENSITIVE",true);c.getDescription().setExtras(extras);}
        ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(c);Toast.makeText(this,t("Password copied"),0).show();
    }
    private void editUser(Gateway node,JSONObject user){
        if(!snapshot().optBoolean("edit_users")){RookDialogs.builder(this).setTitle("Update server management").setMessage("Update account management before editing names. Existing access stays.").setNegativeButton("Cancel",null).setPositiveButton("Update",(d,w)->{if(otherProtocol(node))inspect(node);else installation(node,true);}).show();return;}
        final AlertDialog[] accountDialog={null};LinearLayout f=form();EditText person=field(f,"Name",user.optString("person",user.optString("login")),false),device=field(f,"Device",user.optString("device",user.optString("login")),false);
        f.addView(text("Login: "+user.optString("login"),13,MUTED,false));
        fullButton(f,"Use on this phone",false,()->{if(accountDialog[0]!=null)accountDialog[0].dismiss();fetchForPhone(node,user.optString("login"));});
        if(passwordUsers(node))fullButton(f,"Change password",false,()->{if(accountDialog[0]!=null)accountDialog[0].dismiss();changePassword(node,user);});
        fullButton(f,"Delete account",false,()->{if(accountDialog[0]!=null)accountDialog[0].dismiss();removeUser(node,user);});
        AlertDialog d=RookDialogs.builder(this).setTitle("Edit account").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();accountDialog[0]=d;d.show();
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String p=person.getText().toString().trim(),label=device.getText().toString().trim();if(p.isEmpty()||p.length()>80||label.isEmpty()||label.length()>80){person.setError("Use 1–80 characters");return;}d.dismiss();command(node,json("action","edit-user","login",user.optString("login"),"person",p,"device",label),r->inspect(node));});
    }
    private void removeUser(Gateway node,JSONObject user){
        confirm("Delete account?",user.optString("login")+" will lose access on every device using this account."+(accountImpactAdvice(node,"revoke").isEmpty()?"":" "+accountImpactAdvice(node,"revoke")),()->command(node,json("action","remove-user","login",user.optString("login")),r->{accountUpdateNotice(node,r);try{newUserShare.recent.forget(node.get("id"),node.get("serverInstance"),user.optString("login"));if(user.optString("login").equals(node.get("vpnLogin"))){invalidatePhoneProfile(node);node.set("vpnLogin","");save();}inspect(node);}catch(Exception e){error(e);}}));
    }
    private void closeNewUserDialog(){if(newUserDialog!=null){newUserDialog.dismiss();newUserDialog=null;}}
    private void shareUserAccess(Gateway node,JSONObject user){
        if(demo){demoNotice();return;}String login=user.optString("login");if(otherProtocol(node))command(node,json("action","profile","login",login),profile->shareProtocolProfile(node,profile),"");else command(node,json("action","profile","login",login,"name",node.get("name")+" · "+user.optString("device")),profile->shareProtocolProfile(node,profile),"");
    }
    private void userActions(Gateway node,JSONObject user) {
        String login=user.optString("login");
        if(otherProtocol(node)){RookDialogs.builder(this).setTitle(login).setItems(new String[]{"Share connection","Use on this phone","Delete account"},(d,w)->{if(w==0)command(node,json("action","profile","login",login),profile->shareProtocolProfile(node,profile),"Connection prepared");else if(w==1)fetchForPhone(node,login);else removeUser(node,user);}).show();return;}
        RookDialogs.builder(this).setTitle(user.optString("person")+" · "+user.optString("device")).setItems(new String[]{"Share connection",t("Use on this phone"),t("Change password"),t("Revoke this login")},(d,w)->{
            if(demo){demoNotice();return;}
            if(w==0)command(node,json("action","profile","login",login,"name",node.get("name")+" · "+user.optString("device")),profile->shareProtocolProfile(node,profile),"Connection prepared");
            else if(w==1)fetchForPhone(node,login);
            else if(w==2)changePassword(node,user);
            else confirm(t("Revoke ")+login+"?",t("New logins will be denied and current sessions for this login will be disconnected. Other devices sharing it lose access too."),()->command(node,json("action","remove-user","login",login),r->{newUserShare.recent.forget(node.get("id"),node.get("serverInstance"),login);if(!r.optString("warning").isEmpty())RookDialogs.builder(this).setTitle(t("Login revoked")).setMessage(r.optString("warning")).setPositiveButton(t("Close"),null).show();inspect(node);}));
        }).show();
    }
    private void chooseLogin(Gateway node) {
        if(demo){demoNotice();return;}
        LinearLayout f=form();EditText user=field(f,t("VPN login"),node.get("vpnLogin"),false);
        RookDialogs.builder(this).setTitle(t("VPN on this phone")).setView(f).setNegativeButton(t("Cancel"),null).setPositiveButton(t("Get profile"),(d,w)->fetchForPhone(node,user.getText().toString().trim())).show();
    }
    private void fetchForPhone(Gateway node,String user) {
        if(!InputRules.username(user)){error(new IllegalArgumentException("Enter a valid VPN login."));return;}
        if(otherProtocol(node)){boolean same=user.equals(node.get("vpnLogin"));if(!same)node.vpnPassword="";node.set("vpnLogin",user);save();command(node,json("action","profile","login",user),r->{try{String content=r.getString("content");if(node.get("protocol").equals("openvpn")&&r.optString("access_mode").equals("password")){nativePassword(node,content,()->connectPhone(node));return;}new NativeProfileStore(this).save(node.get("id"),node.get("protocol"),node.get("name"),content);connectPhone(node);}catch(Exception e){error(e);}});return;}
        boolean sameLogin=user.equals(node.get("vpnLogin"));boolean known=sameLogin&&node.data.optBoolean("rememberVpn",false)&&!node.vpnPassword.isEmpty();
        command(node,json("action","profile","login",user,"name",node.get("name"),"server",vpnAddress(node)),p->{
            try {installProfile(node,p);node.set("vpnLogin",user);if(!sameLogin)node.vpnPassword="";save();if(known)connectPhone(node);else vpnPassword(node,()->connectPhone(node));}catch(Exception e){error(e);}
        });
    }
    private void nativePassword(Gateway node,String config,Runnable next)throws Exception{
        if(!node.get("vpnLogin").isEmpty()&&!node.vpnPassword.isEmpty()){new NativeProfileStore(this).save(node.get("id"),"openvpn",node.get("name"),PasswordSignIn.openVpn(config,node.get("vpnLogin"),node.vpnPassword).toString());next.run();return;}
        LinearLayout f=form();EditText user=field(f,"VPN username",node.get("vpnLogin"),false),password=field(f,"VPN password","",true);AlertDialog d=RookDialogs.builder(this).setTitle("OpenVPN sign-in").setView(f).setNegativeButton("Cancel",null).setPositiveButton("Continue",null).create();d.show();secure(d);d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{try{String login=user.getText().toString().trim(),secret=password.getText().toString();JSONObject wrapped=PasswordSignIn.openVpn(config,login,secret);new NativeProfileStore(this).save(node.get("id"),"openvpn",node.get("name"),wrapped.toString());node.set("vpnLogin",login);node.vpnPassword=secret;node.data.put("rememberVpn",true);save();d.dismiss();next.run();}catch(Exception e){password.setError(e.getMessage());}});
    }
    private void installProfile(Gateway node,JSONObject data) throws Exception {
        String alias=null;
        if(data.getJSONObject("remote").has("cert")){
            byte[] raw=java.util.Base64.getDecoder().decode(data.getJSONObject("remote").getString("cert"));
            X509Certificate certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(raw));
            KeyStore store=KeyStore.getInstance("LocalCertificateStore");store.load(null,null);store.setCertificateEntry(null,certificate);
            Enumeration<String> aliases=store.aliases();while(aliases.hasMoreElements()){String a=aliases.nextElement();if(certificate.equals(store.getCertificate(a)))alias=a;}
            if(alias==null)throw new IOException("Could not store the server certificate");TrustedCertificateManager.getInstance().reset();
        }
        VpnProfileDataSource source=new VpnProfileSource(this);source.open();
        try {
            VpnProfile p=node.get("profileUuid").isEmpty()?null:source.getVpnProfile(node.get("profileUuid"));boolean exists=p!=null;if(p==null)p=new VpnProfile();
            p.setName(node.get("name"));p.setGateway(data.getJSONObject("remote").getString("addr"));p.setRemoteId(data.getJSONObject("remote").optString("id",null));
            int remotePort=data.getJSONObject("remote").optInt("port",500);int phonePort=node.isPair()?remotePort:node.data.optInt("vpnPort",remotePort);p.setPort(phonePort==500?null:phonePort);
            p.setUsername(data.getJSONObject("local").getString("eap_id"));p.setVpnType(VpnType.IKEV2_EAP);p.setMTU(1280);p.setCertificateAlias(alias);p.setPassword(null);
            p.setSplitTunneling(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4|VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);p.setFlags(VpnProfile.FLAGS_SUPPRESS_CERT_REQS);
            if(exists)source.updateVpnProfile(p);else source.insertProfile(p);node.set("profileUuid",p.getUUID().toString());
        } finally {source.close();}
    }
    private void applyPhonePort(Gateway node,int port)throws Exception{
        if(node.get("profileUuid").isEmpty())return;
        VpnProfileDataSource source=new VpnProfileSource(this);source.open();
        try{VpnProfile p=source.getVpnProfile(node.get("profileUuid"));if(p!=null){p.setPort(port==500?null:port);source.updateVpnProfile(p);}}finally{source.close();}
    }
    private void vpnPassword(Gateway node,Runnable next) {
        LinearLayout f=form();EditText p=field(f,t("VPN password"),node.vpnPassword,true);
        AlertDialog d=RookDialogs.builder(this).setTitle(t("Connect as ")+node.get("vpnLogin")).setView(f).setNegativeButton(t("Cancel"),null).setPositiveButton(t("Continue"),(a,w)->{node.vpnPassword=p.getText().toString();save();next.run();}).create();d.show();secure(d);
    }
    private void nativeDetails(Gateway node){
        NativeVpn.Status status=NativeVpn.status(this,node.get("protocol"));boolean matches=status.id.equals(node.get("id"));
        String details="Rookstride "+org.strongswan.android.BuildConfig.VERSION_NAME+" · Android "+Build.VERSION.SDK_INT+"\n"+SingleProtocols.from(node.get("protocol")).title+"\n"+node.get("name")+"\n";
        details+=matches?status.state+(status.error.isEmpty()?"":"\n"+status.error)+"\n\n"+status.log:"No recent log for this connection. Connect this VPN to record a log.";
        final String shared=details;LinearLayout f=form();f.addView(text(details,13,INK,false));RookDialogs.builder(this).setTitle(SingleProtocols.from(node.get("protocol")).title+" log").setView(scrolling(f)).setNeutralButton("Share",(d,w)->startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT,shared),"Share connection details"))).setPositiveButton("Close",null).show();
    }
    private void nativeBatteryChoice(Gateway node){
        RookDialogs.builder(this).setTitle("Keep VPN running").setMessage("Allow background activity for a more reliable connection when the screen is off.")
            .setNegativeButton("Cancel",null).setNeutralButton("Connect now",(d,w)->{getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).apply();connectPhone(node);})
            .setPositiveButton("Allow background",(d,w)->{getSharedPreferences("rookstride-ui",0).edit().putBoolean("nativeBatteryAsked",true).apply();pendingNativeId=node.get("id");try{startActivityForResult(new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,Uri.parse("package:"+getPackageName())),NATIVE_BATTERY);}catch(ActivityNotFoundException e){pendingNativeId="";startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+getPackageName())));}}).show();
    }
    private void startNative(Gateway node){node.data.remove("dnsRefresh");save();if(vpn!=null)vpn.disconnect();beginConnectionTap(node,false);NativeVpn.start(this,node.get("protocol"),node.get("id"));}
    private void connectPhone(Gateway node) {
        if(otherProtocol(node)){
            if(!new NativeProfileStore(this).exists(node.get("id"))){if(clientOnly(node)){error(new IOException("Import this VPN profile again"));return;}if(!node.get("vpnLogin").isEmpty())fetchForPhone(node,node.get("vpnLogin"));else chooseLogin(node);return;}
            if(!getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName())&&!getSharedPreferences("rookstride-ui",0).getBoolean("nativeBatteryAsked",false)){nativeBatteryChoice(node);return;}
            Intent permission=android.net.VpnService.prepare(this);if(permission!=null){pendingNativeId=node.get("id");startActivityForResult(permission,PREPARE_NATIVE_VPN);}else startNative(node);return;
        }
        NativeVpn.disconnectAll(this);
        if(node.get("profileUuid").isEmpty()){if(!node.get("vpnLogin").isEmpty())fetchForPhone(node,node.get("vpnLogin"));else chooseLogin(node);return;}
        if(clientOnly(node)){Intent start=new Intent(this,VpnProfileControlActivity.class).setAction("org.strongswan.android.action.START_PROFILE").putExtra(VpnProfileControlActivity.EXTRA_VPN_PROFILE_UUID,node.get("profileUuid"));if(!node.vpnPassword.isEmpty())start.putExtra("rookstride.session_password",node.vpnPassword);beginConnectionTap(node,false);startActivity(start);return;}
        if(node.vpnPassword.isEmpty()){vpnPassword(node,()->connectPhone(node));return;}
        Intent i=new Intent(this,VpnProfileControlActivity.class).setAction("org.strongswan.android.action.START_PROFILE");
        i.putExtra(VpnProfileControlActivity.EXTRA_VPN_PROFILE_UUID,node.get("profileUuid"));i.putExtra("rookstride.session_password",node.vpnPassword);beginConnectionTap(node,false);startActivity(i);
    }
    private void share(JSONObject profile){shareProtocolProfile(profile);}
    private void enableFiltering(Gateway node){
        confirm("Enable ad blocking?","Install private DNS filtering and update this VPN. Existing accounts stay. The VPN may reconnect briefly. Set Android Private DNS to Automatic or Off for filtering.",()->{node.set("job","");try{node.data.put("dnsRefresh",NativeVpn.status(this,node.get("protocol")).active(node.get("id")));}catch(JSONException e){error(e);return;}save();startDeployment(node,"filter",json("protocol",node.get("protocol"),"filter_only",true),false);});
    }
    private void adguard(Gateway node) {
        if(node.isPair()){adguard(node.exit);return;}if(demo){demoNotice();return;}
        JSONObject status=node.data.optJSONObject("snapshot"),filter=status==null?null:status.optJSONObject("filtering");
        if(filter!=null&&filter.optBoolean("remote")){RookDialogs.builder(this).setTitle("Ad blocking runs on the exit server").setMessage("Open your saved two-server VPN to manage its exit’s ad blocker. This entry server forwards DNS through that connection.").setPositiveButton("Close",null).show();return;}
        command(node,json("action","adguard"),r->showAdguard(node,r));
    }
    private void showAdguard(Gateway node,JSONObject response){
        final AlertDialog[] dashboard={null};LinearLayout f=form();
        f.addView(text(response.optLong("blocked")+" blocked / "+response.optLong("queries")+" DNS requests",18,INK,true));space(f,8);
        if(response.has("protection_enabled"))f.addView(text(response.optBoolean("protection_enabled")?"Ad blocking is on":"Ad blocking is paused",14,response.optBoolean("protection_enabled")?RED:MUTED,true));
        f.addView(text("Settings are shared by VPNs using this ad blocker.",13,MUTED,false));space(f,12);
        f.addView(text("Blocking level",15,INK,true));space(f,8);String current=FilterPresets.selected(response);if(current.equals("custom")){f.addView(text("Current: custom filter selection",14,INK,true));JSONArray active=response.optJSONArray("filters");if(active!=null)for(int i=0;i<active.length();i++){JSONObject filter=active.optJSONObject(i);if(filter!=null&&filter.optBoolean("enabled"))f.addView(text(filter.optString("name"),13,MUTED,false));}}
        for(String[] level:FilterPresets.OPTIONS){
            boolean selected=level[0].equals(current);LinearLayout option=stack();option.setTag("filter-preset-"+level[0]);option.setSelected(selected);option.setPadding(dp(12),dp(10),dp(12),dp(10));GradientDrawable outline=shape(selected?Color.rgb(255,238,238):Color.WHITE,12);outline.setStroke(dp(selected?2:1),selected?RED:Color.rgb(222,222,228));option.setBackground(outline);
            option.addView(text(level[1]+(selected?"  ✓ Selected":""),16,selected?RED:INK,true));option.addView(text(level[2],13,MUTED,false));
            LinearLayout actions=row();Button details=browseButton("Details",()->filterDetails(level));actions.addView(details,new LinearLayout.LayoutParams(0,-2,1));Button use=button(selected?"Selected":"Use "+level[1],false,()->{if(dashboard[0]!=null)dashboard[0].dismiss();confirm("Use "+level[1]+" blocking?",level[3]+"\n\nThis affects every VPN sharing this ad blocker.",()->command(node,json("action","adguard","level",level[0]),a->showAdguard(node,a)));});use.setEnabled(!selected&&!busy&&!DeploymentService.active());LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);lp.leftMargin=dp(8);actions.addView(use,lp);option.addView(actions);LinearLayout.LayoutParams op=new LinearLayout.LayoutParams(-1,-2);op.bottomMargin=dp(10);f.addView(option,op);
        }
        if(response.has("protection_enabled"))fullButton(f,response.optBoolean("protection_enabled")?"Pause ad blocking":"Resume ad blocking",false,()->{if(dashboard[0]!=null)dashboard[0].dismiss();confirm("Change ad blocking?","This affects all VPNs sharing this ad blocker.",()->command(node,json("action","adguard","enabled",!response.optBoolean("protection_enabled")),a->showAdguard(node,a)));});
        dashboard[0]=RookDialogs.builder(this).setTitle("Ad blocking · AdGuard Home").setView(f).setPositiveButton("Close",null).create();dashboard[0].show();
    }
    private void filterDetails(String[] level){RookDialogs.builder(this).setTitle(level[1]+" blocking").setMessage(level[2]+"\n\n"+level[3]).setPositiveButton("Close",null).setNeutralButton("Official details",(d,w)->startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(level[4])))).show();}
    private void routingScreen(){
        title("Split tunneling","Choose which apps use the VPN");AppRouting.Policy policy;try{policy=AppRouting.read(this);}catch(Exception e){body.addView(text(e.getMessage(),14,RED,false));policy=new AppRouting.Policy("all",Collections.emptySet());}
        final java.util.TreeSet<String> chosen=new java.util.TreeSet<>(policy.packages);final String[] mode={policy.mode};
        RadioGroup modes=new RadioGroup(this);int checked=policy.mode.equals("all")?0:policy.mode.equals("only")?1:2;String[] labels={"All apps","Only selected apps","All except selected apps"};String[] values={"all","only","exclude"};
        for(int i=0;i<labels.length;i++){RadioButton option=new RadioButton(this);option.setText(labels[i]);option.setId(View.generateViewId());option.setMinHeight(dp(48));option.setButtonTintList(android.content.res.ColorStateList.valueOf(RED));modes.addView(option);if(i==checked)option.setChecked(true);}body.addView(modes);
        TreeMap<String,String> candidates=new TreeMap<>();android.content.pm.PackageManager pm=getPackageManager();Intent launch=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        for(android.content.pm.ResolveInfo result:pm.queryIntentActivities(launch,0)){String name=result.activityInfo.packageName;if(!name.equals(getPackageName()))candidates.put(name,result.loadLabel(pm).toString());}for(String name:chosen)if(!name.equals(getPackageName())&&!candidates.containsKey(name))candidates.put(name,name);
        Button picker=fullButton(body,"Choose apps · "+chosen.size()+" selected",false,()->AppSelectionDialog.show(this,candidates,chosen,selection->{chosen.clear();chosen.addAll(selection);Button control=body.findViewWithTag("choose-apps");if(control!=null)control.setText("Choose apps · "+chosen.size()+" selected");}));picker.setTag("choose-apps");picker.setVisibility(mode[0].equals("all")?View.GONE:View.VISIBLE);
        space(body,14);TextView explanation=text(routingExplanation(mode[0]),14,MUTED,false);explanation.setTag("routing-explanation");explanation.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);body.addView(explanation);
        modes.setOnCheckedChangeListener((group,id)->{int n=group.indexOfChild(group.findViewById(id));mode[0]=values[n];picker.setVisibility(n==0?View.GONE:View.VISIBLE);explanation.setText(routingExplanation(mode[0]));});
        fullButton(body,"Save",true,()->{try{AppRouting.Policy next=new AppRouting.Policy(mode[0],chosen);if(!next.mode.equals("all"))AppRouting.installed(this,next);AppRouting.save(this,next);message="Saved · reconnect to apply";noticeDeadline=0;recordActivity("VPN app selection updated",null);render();}catch(Exception e){error(e);}});
    }
    private String routingExplanation(String mode){
        if(mode.equals("all"))return "All apps use the VPN. Changes apply when you reconnect.";
        String choice=mode.equals("only")?"Only the apps you choose use the VPN. Other apps use your normal connection.":"The apps you choose use your normal connection. All other apps use the VPN.";
        return choice+" If Android’s “Block connections without VPN” setting is on, apps outside the VPN may not connect. Changes apply when you reconnect.";
    }
    private void recordCompletion(InstallationProgress p){
        String eventKey=p.kind+":"+p.gatewayId+":"+p.started;android.content.SharedPreferences prefs=getSharedPreferences("rookstride-ui",0);if(!eventKey.equals(prefs.getString("activityCompletion",""))){Gateway record=null;for(Gateway g:gateways)if(g.get("id").equals(p.gatewayId))record=g;ActivityHistory.Completion event=ActivityHistory.completion(maintenanceProgress(p)?"Maintenance complete":p.kind.equals("os")?"Ubuntu reinstalled":p.kind.equals("filter")?"Ad blocking installed":"VPN installed",p.started,p.finished,System.currentTimeMillis());recordActivity(event.title,record,event.time);prefs.edit().putString("activityCompletion",eventKey).apply();}
    }
    private JSONArray activityEvents(){try{return new JSONArray(getSharedPreferences("rookstride-ui",0).getString("activityHistory","[]"));}catch(JSONException e){return new JSONArray();}}
    private void recordActivity(String title,Gateway node){recordActivity(title,node,System.currentTimeMillis());}
    private void recordActivity(String title,Gateway node,long time){try{JSONArray history=ActivityHistory.append(activityEvents(),title,node==null?"":node.get("id"),node==null?"":node.get("protocol"),time);getSharedPreferences("rookstride-ui",0).edit().putString("activityHistory",history.toString()).putBoolean("activityUnread",true).apply();if(root!=null){View bell=root.findViewWithTag("activity-bell");if(bell instanceof ImageButton){((ImageButton)bell).setColorFilter(RED);bell.setContentDescription("Activity, new updates");}}}catch(JSONException ignored){}}
    private void activityScreen(){
        title("Activity","Recent actions on this phone");JSONArray events=activityEvents();if(events.length()==0)empty("No recent actions.");String previousDay="";LinearLayout list=null;
        java.text.SimpleDateFormat date=new java.text.SimpleDateFormat("MMM d, yyyy",Locale.ENGLISH),clock=new java.text.SimpleDateFormat("HH:mm",Locale.ENGLISH);
        for(int i=0;i<events.length();i++){JSONObject event=events.optJSONObject(i);if(event==null)continue;Date time=new Date(event.optLong("time"));String day=date.format(time);
            if(!day.equals(previousDay)){space(body,8);body.addView(text(day,13,MUTED,true));space(body,8);list=stack();list.setTag("activity-day");list.setBackground(surface(14));body.addView(list);space(body,12);previousDay=day;}
            if(list.getChildCount()>0){View divider=new View(this);divider.setBackgroundColor(LINE);LinearLayout.LayoutParams dividerParams=new LinearLayout.LayoutParams(-1,dp(1));dividerParams.leftMargin=dp(56);list.addView(divider,dividerParams);}
            LinearLayout item=row();item.setTag("activity-row");item.setPadding(dp(12),dp(12),dp(12),dp(12));item.setGravity(Gravity.TOP);ImageView icon=new ImageView(this);icon.setImageResource(activityIcon(event.optString("title")));icon.setColorFilter(RED);icon.setPadding(dp(7),dp(7),dp(7),dp(7));icon.setBackground(shape(Color.rgb(255,239,241),12));icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);item.addView(icon,new LinearLayout.LayoutParams(dp(32),dp(32)));
            LinearLayout words=stack();words.addView(text(event.optString("title"),15,INK,true));Gateway record=null;for(Gateway g:gateways){if(g.get("id").equals(event.optString("record")))record=g;else if(g.exit!=null&&g.exit.get("id").equals(event.optString("record")))record=g.exit;}
            String method="";for(SingleProtocols protocol:SingleProtocols.values())if(protocol.id.equals(event.optString("protocol")))method=protocol.title;
            if(record!=null||!method.isEmpty()){TextView metadata=text((record==null?"":ServerProtocols.name(record))+(method.isEmpty()?"":record==null?method:" · "+method),12,MUTED,false);metadata.setTag("activity-meta");words.addView(metadata);}words.addView(text(clock.format(time),12,MUTED,false));LinearLayout.LayoutParams wp=new LinearLayout.LayoutParams(0,-2,1);wp.leftMargin=dp(12);item.addView(words,wp);list.addView(item);
        }
        if(events.length()>0)fullButton(body,"Clear activity",false,()->RookDialogs.builder(this).setTitle("Clear activity?").setMessage("Delete the activity history on this phone? Your VPNs, users and servers stay unchanged.").setNegativeButton("Cancel",null).setPositiveButton("Clear",(d,w)->{getSharedPreferences("rookstride-ui",0).edit().remove("activityHistory").putBoolean("activityUnread",false).apply();render();}).show());
    }
    private int activityIcon(String title){String value=title.toLowerCase(Locale.ROOT);if(value.contains("failed")||value.contains("attention"))return R.drawable.rook_info;if(value.contains("refresh")||value.contains("check"))return R.drawable.rook_refresh;if(value.contains("remove")||value.contains("uninstall"))return R.drawable.rook_delete;if(value.contains("user"))return R.drawable.rook_users;if(value.contains("shar")||value.contains("export"))return R.drawable.rook_forward;if(value.contains("connect"))return R.drawable.rook_shield;return R.drawable.rook_activity;}
    private void confirmForgetAccess(Runnable accepted){LinearLayout f=form();f.addView(text("Without saved server access, Refresh, account changes, installs and removals will ask for the server administrator password or key again. Your VPN connections and exported profiles keep working.",15,INK,false));CheckBox consent=new CheckBox(this);consent.setText("I understand I will need to sign in again.");consent.setMinHeight(dp(48));f.addView(consent);AlertDialog d=RookDialogs.builder(this).setTitle("Stop saving server access?").setView(f).setNegativeButton("Keep saved",null).setPositiveButton("Continue",(x,w)->accepted.run()).create();d.show();d.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);consent.setOnCheckedChangeListener((v,c)->d.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(c));}
    private String documentName(String url){return url.endsWith("licenses.html")?"licenses.html":url.endsWith("guide-en-full.html")?"guide-en-full.html":"app-guide.html";}
    private void openDocument(String asset){guideDocument=asset;requestedDocument=asset;if(tab.equals("Guide")&&guideView!=null)guideView.loadUrl(OfflineDocuments.url(asset));else openScreen("Guide");}
    private String guideAsset(){return "app-guide.html";}
    private void openDemo() {
        try {
            selected=new Gateway();selected.set("name","Rook's gateway");selected.set("host","vpn.example.net");demo=true;
            JSONObject s=json("statistics_enabled",true,"services",json("strongswan-starter",true,"adguardhome",true,"unbound",true));
            s.put("users",new JSONArray().put(json("login","alex-phone","person","Alex","device","Phone","kind","device")).put(json("login","alex-laptop","person","Alex","device","Laptop","kind","device")).put(json("login","family","person","Family","device","Shared login","kind","shared")));
            s.put("monthly",new JSONArray().put(json("user","alex-phone","upload",1300000000L,"download",16800000000L)).put(json("user","alex-laptop","upload",2700000000L,"download",28400000000L)).put(json("user","family","upload",300000000L,"download",8100000000L)));
            s.put("connections",new JSONArray().put(json("id","41","user","alex-phone","endpoint","192.0.2.24","port",4500,"age",3720,"upload",44000000,"download",580000000,"vpn_addresses",new JSONArray().put("10.252.0.2"))).put(json("id","42","user","family","endpoint","198.51.100.18","port",53120,"age",840,"upload",15000000,"download",180000000,"vpn_addresses",new JSONArray().put("10.252.0.3"))));
            selected.data.put("snapshot",s);selected.set("checked","Sample snapshot");openScreen("VPN");
        }catch(Exception e){error(e);}
    }
}
