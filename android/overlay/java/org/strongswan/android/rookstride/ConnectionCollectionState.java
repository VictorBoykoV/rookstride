package org.strongswan.android.rookstride;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Retained, memory-only collection work. The import controller owns its durable journal. */
public final class ConnectionCollectionState extends ViewModel {
    public final MutableLiveData<Integer> changes=new MutableLiveData<>(0);
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private int version;
    public volatile boolean working,recoveryReady,recoveryAttempted,importReviewPending,exportReviewPending,documentSaved;
    public volatile String operation="",failure="",exportBundle;
    public volatile ConnectionBundleImport.Preview preview,exportPreview;
    public volatile ConnectionBundleImport.Result result;
    public final ShareDraft share=new ShareDraft();
    public static final class ShareDraft {
        public String serverId="",phase="",login="",instance="";
        public int step;
        public final ArrayList<String> protocols=new ArrayList<>();
        public final ArrayList<JSONObject> profiles=new ArrayList<>();
        public JSONObject pendingProfile;
        public JSONArray users;
        public boolean active(){return !serverId.isEmpty();}
        public void clear(){serverId="";phase="";login="";instance="";step=0;protocols.clear();profiles.clear();pendingProfile=null;users=null;}
    }
    private void changed(){main.post(()->changes.setValue(++version));}
    public synchronized void recover(Context context){
        if(working||recoveryAttempted||DeploymentService.active())return;
        recoveryAttempted=true;Context app=context.getApplicationContext();
        try{if(!ConnectionBundleImport.recoveryPending(app)){recoveryReady=true;return;}}
        catch(Exception invalid){failure="Saved connection import needs recovery. Existing connections were preserved. Reopen the import to try again.";changed();return;}
        working=true;operation="recovery";changed();
        worker.execute(()->{try{ConnectionBundleImport.recover(app);recoveryReady=true;}catch(Exception error){failure="Saved connection import needs recovery. Existing connections were preserved. Reopen the import to try again.";}finally{working=false;operation="";changed();}});
    }
    public synchronized void read(Context context,Uri uri){
        if(working)return;working=true;operation="read";failure="";preview=null;importReviewPending=false;Context app=context.getApplicationContext();changed();
        worker.execute(()->{try{
            requireIdle();recoveryReady=false;ConnectionBundleImport.recover(app);recoveryReady=true;recoveryAttempted=true;
            String text;try(InputStream input=app.getContentResolver().openInputStream(uri)){if(input==null)throw new IOException();text=decode(input);}
            preview=ConnectionBundleImport.preview(app,text);importReviewPending=true;
        }catch(Exception error){failure="The connection collection could not be opened. Choose a valid .rookbundle file. No connections were added.";}finally{working=false;operation="";changed();}});
    }
    public synchronized void apply(Context context){
        if(working||preview==null)return;working=true;operation="import";failure="";importReviewPending=false;Context app=context.getApplicationContext();ConnectionBundleImport.Preview reviewed=preview;changed();
        worker.execute(()->{try{requireIdle();result=ConnectionBundleImport.apply(app,reviewed);preview=null;if(result.cleanupPending){recoveryReady=false;recoveryAttempted=false;}}catch(Exception error){recoveryReady=false;recoveryAttempted=false;failure="Connection import could not finish. Existing connections were preserved. Reopen the import to recover and try again.";}finally{working=false;operation="";changed();}});
    }
    public synchronized void prepareExport(Context context,List<JSONObject> profiles){
        if(working)return;working=true;operation="export";failure="";Context app=context.getApplicationContext();List<JSONObject> selected=new ArrayList<>(profiles);changed();
        worker.execute(()->{try{requireIdle();String packed=ConnectionBundle.pack(selected);ConnectionBundleImport.Preview review=ConnectionBundleImport.preview(app,packed);exportBundle=packed;exportPreview=review;exportReviewPending=true;share.clear();}catch(Exception error){failure="The selected connections could not be prepared. Check the selected VPN users and their existing passwords.";}finally{working=false;operation="";changed();}});
    }
    public synchronized void save(Context context,Uri uri,String collection){
        if(working)return;working=true;operation="save";failure="";Context app=context.getApplicationContext();changed();
        worker.execute(()->{try{ConnectionCollectionDocument.save(app.getContentResolver(),uri,collection);clearExport();documentSaved=true;}catch(Exception error){exportReviewPending=exportBundle!=null;failure="The connection file could not be saved. Choose another destination and try again.";}finally{working=false;operation="";changed();}});
    }
    public void clearExport(){exportBundle=null;exportPreview=null;exportReviewPending=false;}
    public void clearImport(){preview=null;importReviewPending=false;}
    public String takeFailure(){String value=failure;failure="";return value;}
    public ConnectionBundleImport.Result takeResult(){ConnectionBundleImport.Result value=result;result=null;return value;}
    private static void requireIdle()throws IOException{if(DeploymentService.active())throw new IOException("Wait for the server operation to finish");}
    static String decode(InputStream input)throws IOException {
        ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count;
        while((count=input.read(buffer))!=-1){if(output.size()+count>ConnectionBundle.MAX_BYTES)throw new IOException("Connection collection is too large");output.write(buffer,0,count);}
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output.toByteArray())).toString();
    }
    @Override protected void onCleared(){clearExport();clearImport();share.clear();worker.shutdown();}
}
