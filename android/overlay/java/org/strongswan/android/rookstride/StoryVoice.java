package org.strongswan.android.rookstride;

import android.content.Context;
import android.os.*;
import android.speech.tts.*;
import android.webkit.*;
import org.json.*;
import java.util.*;

/** Offline installed device voices. No audio, story text or account data is uploaded. */
public final class StoryVoice implements AutoCloseable {
    private final WebView web;
    private final Handler main=new Handler(Looper.getMainLooper());
    private TextToSpeech tts;
    private volatile boolean ready=false,closed=false;
    private volatile String active="";
    public StoryVoice(Context context,WebView web){
        this.web=web;tts=new TextToSpeech(context.getApplicationContext(),status->{ready=status==TextToSpeech.SUCCESS;});
        tts.setOnUtteranceProgressListener(new UtteranceProgressListener(){
            public void onStart(String id){callback(id,"start",0,0);}
            public void onDone(String id){callback(id,"end",0,0);}
            public void onError(String id){callback(id,"error",0,0);}
            public void onRangeStart(String id,int start,int end,int frame){callback(id,"boundary",start,end);}
        });
    }
    private void callback(String id,String event,int start,int end){main.post(()->{if(closed||!active.equals(id))return;web.evaluateJavascript("window.rookNarrationEvent && window.rookNarrationEvent("+JSONObject.quote(id)+","+JSONObject.quote(event)+","+start+","+end+")",null);});}
    @JavascriptInterface public String voices(){
        JSONArray out=new JSONArray();if(ready&&!closed)try{Set<Voice> available=tts.getVoices();if(available!=null)for(Voice v:available)if(!v.isNetworkConnectionRequired()&&v.getLocale().getLanguage().equals("en"))out.put(new JSONObject().put("name",v.getName()).put("lang",v.getLocale().toLanguageTag()).put("localService",true));}catch(Exception ignored){}return out.toString();
    }
    @JavascriptInterface public void speak(String id,String text,String voice,float rate){
        if(id==null||!id.matches("[A-Za-z0-9_-]{1,80}")||text==null||text.length()>3500||closed)return;
        main.post(()->{if(!ready||closed){active=id;callback(id,"error",0,0);return;}
            Voice selected=null;Set<Voice> all=tts.getVoices();if(all!=null)for(Voice candidate:all)if(!candidate.isNetworkConnectionRequired()&&candidate.getLocale().getLanguage().equals("en")&&(selected==null||candidate.getName().equals(voice)))selected=candidate;
            active=id;if(selected==null){callback(id,"error",0,0);return;}tts.stop();tts.setVoice(selected);tts.setSpeechRate(Math.max(.7f,Math.min(1.3f,rate)));if(tts.speak(text,TextToSpeech.QUEUE_FLUSH,null,id)==TextToSpeech.ERROR)callback(id,"error",0,0);
        });
    }
    @JavascriptInterface public void stop(){active="";main.post(()->{if(!closed)tts.stop();});}
    @Override public void close(){active="";closed=true;ready=false;tts.stop();tts.shutdown();main.removeCallbacksAndMessages(null);}
}
