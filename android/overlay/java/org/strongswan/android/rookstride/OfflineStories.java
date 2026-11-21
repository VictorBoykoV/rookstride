package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.Intent;
import android.content.ActivityNotFoundException;
import android.net.Uri;
import android.webkit.*;
import java.io.*;

/** Only bundled assets from an isolated synthetic origin; no external documents/scripts. */
public final class OfflineStories extends WebViewClient {
    public static final String LIBRARY="https://rookstride.invalid/stories/index.html";
    private final Context context;
    /** Historical five-world paths return to the current app library, never a missing page. */
    public static String location(String value){
        if(value==null)return LIBRARY;
        Uri u=Uri.parse(value);String fragment=u.getFragment();
        if(!allowed(u)||!"/stories/index.html".equals(u.getPath())||u.getQuery()!=null)return LIBRARY;
        if(fragment==null||fragment.isEmpty())return LIBRARY;
        return fragment.matches("(?:read|library)(?:/[a-z0-9]+(?:-[a-z0-9]+)*/(?:[1-9]|10)/[1-6]/(?:panel|page)(?:/end)?)?")?LIBRARY+"#"+fragment:LIBRARY;
    }
    public static void save(Context context,String value){
        // A tab can close before the first page commits. Blank/non-story URLs
        // must not erase the previous reading position during that window.
        if(value==null||!allowed(Uri.parse(value)))return;
        context.getSharedPreferences("rookstride-ui",0).edit().putString("storyUrl",location(value)).apply();
    }
    public OfflineStories(Context context){this.context=context.getApplicationContext();}
    @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){
        Uri u=request.getUrl();if(allowed(u)){
            if(request.isForMainFrame()&&!"/stories/index.html".equals(u.getPath())){view.loadUrl(LIBRARY);return true;}
            return false;
        }
        // External references open outside the privileged WebView, only on an actual tap.
        if(request.isForMainFrame()&&request.hasGesture()&&"https".equals(u.getScheme())&&u.getHost()!=null&&!u.getHost().equals("rookstride.invalid"))try{context.startActivity(new Intent(Intent.ACTION_VIEW,u).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));}catch(ActivityNotFoundException ignored){}
        return true;
    }
    @Override public void doUpdateVisitedHistory(WebView view,String url,boolean reload){save(context,url);}
    private static boolean allowed(Uri u){String path=u.getPath();return "https".equals(u.getScheme())&&"rookstride.invalid".equals(u.getHost())&&u.getPort()==-1&&path!=null&&path.startsWith("/stories/")&&!path.contains("..")&&!path.contains("\\")&&!path.contains("%")&&!path.contains("//");}
    @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest request){
        Uri u=request.getUrl();if(!allowed(u))return missing();
        String path=u.getPath().substring(1);if(path.endsWith("/"))path+="index.html";
        String type=path.endsWith(".html")?"text/html":path.endsWith(".js")?"application/javascript":path.endsWith(".css")?"text/css":path.endsWith(".json")?"application/json":path.endsWith(".svg")?"image/svg+xml":path.endsWith(".webp")?"image/webp":"application/octet-stream";
        try{return new WebResourceResponse(type,"UTF-8",context.getAssets().open(path));}catch(IOException e){return missing();}
    }
    private static WebResourceResponse missing(){return new WebResourceResponse("text/plain","UTF-8",404,"Not found",java.util.Collections.emptyMap(),new ByteArrayInputStream("Story page not found. Return to Stories and choose a chapter.".getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
}
