package org.strongswan.android.rookstride;

import android.content.*;
import android.net.Uri;
import android.webkit.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Stream only named bundled documents. No file access, remote subresources or JavaScript. */
public final class OfflineDocuments extends WebViewClient {
    public static final String ORIGIN="https://rookstride.invalid/docs/";
    private static final Set<String> PAGES=new HashSet<>(Arrays.asList("app-guide.html","guide-en-full.html","licenses.html"));
    private final Context context;
    public OfflineDocuments(Context context){this.context=context;}
    public static String url(String asset){if(!PAGES.contains(asset))throw new IllegalArgumentException("Unknown document");return ORIGIN+asset;}
    private static String asset(Uri uri){
        if(!"https".equals(uri.getScheme())||!"rookstride.invalid".equals(uri.getHost())||uri.getPort()!=-1||uri.getUserInfo()!=null||uri.getQuery()!=null)return null;
        String path=uri.getEncodedPath();if(path==null||!path.startsWith("/docs/"))return null;
        String name=path.substring(6);return PAGES.contains(name)?name:null;
    }
    @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){
        Uri uri=request.getUrl();if(asset(uri)!=null)return false;
        if(request.isForMainFrame()&&request.hasGesture()){
            String mapped=uri.toString().equals("rookstride:licenses")?"licenses.html":uri.toString().equals("rookstride:full-guide")?"guide-en-full.html":uri.toString().equals("rookstride:guide")?"app-guide.html":null;
            if(mapped!=null){view.loadUrl(url(mapped));return true;}
            if("https".equals(uri.getScheme())&&uri.getHost()!=null&&!"rookstride.invalid".equals(uri.getHost()))try{context.startActivity(new Intent(Intent.ACTION_VIEW,uri));}catch(ActivityNotFoundException ignored){}
        }
        return true;
    }
    @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest request){
        String name=asset(request.getUrl());
        if(name!=null)try{
            Map<String,String> headers=new HashMap<>();headers.put("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");headers.put("X-Content-Type-Options","nosniff");
            return new WebResourceResponse("text/html","UTF-8",200,"OK",headers,context.getAssets().open(name));
        }catch(IOException ignored){}
        return new WebResourceResponse("text/plain","UTF-8",404,"Not found",Collections.emptyMap(),new ByteArrayInputStream("This document is not available. Return to Help.".getBytes(StandardCharsets.UTF_8)));
    }
}
