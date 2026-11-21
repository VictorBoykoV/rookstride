package io.rookstride.probe;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import org.json.JSONObject;
import java.net.*;
import java.io.*;

/** Independent application UID: verify traffic outside the administrator app. */
public class Main extends Activity {
 @Override public void onCreate(Bundle b){super.onCreate(b);TextView t=new TextView(this);t.setText("Testing VPN routing…");t.setTextSize(24);setContentView(t);new Thread(()->probe(t)).start();}
 private void probe(TextView t){
  JSONObject r=new JSONObject();String phase="network";
  try {
   if(getIntent().getBooleanExtra("socketOnly",false)) {
    boolean reachable=false;
    try(Socket socket=new Socket()){socket.connect(new InetSocketAddress("1.1.1.1",443),4000);reachable=true;}catch(IOException ignored){}
    // A userspace VPN can acknowledge SYN before its proxy reaches the peer.
    // A verified TLS/HTTP response is required to detect a real outage bypass.
    boolean https=false;String error="";
    // Use fresh requests to the same ordinary origins whose baseline browsing
    // was just verified, rather than depending on literal-IP website support.
    for(String origin:new String[]{"https://api.ipify.org/","https://example.com/"}){
     HttpURLConnection check=(HttpURLConnection)new URL(origin+"?rookstride="+android.os.SystemClock.elapsedRealtimeNanos()).openConnection();check.setUseCaches(false);check.setConnectTimeout(6000);check.setReadTimeout(6000);check.setRequestProperty("Connection","close");
     try{if(check.getResponseCode()==200){https=true;break;}}catch(IOException failure){error=failure.getClass().getSimpleName();}finally{check.disconnect();}
    }
    if(!https)r.put("httpsErrorType",error);
    r.put("tcpIpv4Reachable",reachable);r.put("httpsIpv4Reachable",https);r.put("ok",true);
    try(FileOutputStream out=openFileOutput("result.json",MODE_PRIVATE)){out.write(r.toString().getBytes("UTF-8"));}
    runOnUiThread(()->{t.setText(r.toString());if(getIntent().getBooleanExtra("finishAfter",false))finish();});return;
   }
   android.net.ConnectivityManager manager=getSystemService(android.net.ConnectivityManager.class);android.net.NetworkCapabilities network=manager.getNetworkCapabilities(manager.getActiveNetwork());r.put("vpnTransport",network!=null&&network.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN));
   phase="canary";String canary=getIntent().getStringExtra("canary");if(canary!=null){HttpURLConnection test=(HttpURLConnection)new URL(canary).openConnection();test.setConnectTimeout(6000);test.setReadTimeout(6000);try(InputStream in=test.getInputStream()){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[256];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>2048)throw new IOException("Oversized canary");}r.put("canary",out.toString("UTF-8").trim());}catch(IOException e){if(!getIntent().getBooleanExtra("negativeCanary",false))throw e;r.put("canaryUnavailable",true);}finally{test.disconnect();}}
   phase="https";
   HttpURLConnection c=(HttpURLConnection)new URL("https://api.ipify.org").openConnection();c.setConnectTimeout(20000);c.setReadTimeout(20000);
   try(InputStream in=c.getInputStream()){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[256];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>1024)throw new IOException("Oversized response");}r.put("ipv4Exit",out.toString("UTF-8").trim());}finally{c.disconnect();}
   phase="dns";boolean blocked=false;
   try{InetAddress[] addresses=InetAddress.getAllByName("doubleclick.net");blocked=true;for(InetAddress a:addresses)if(!a.isAnyLocalAddress()&&!a.isLoopbackAddress())blocked=false;}catch(UnknownHostException e){blocked=true;}
   r.put("dnsBlocked",blocked);
   phase="ipv6";boolean v6=false;try(Socket s=new Socket()){s.connect(new InetSocketAddress("2606:4700:4700::1111",443),2500);v6=true;}catch(IOException e){}
   r.put("ipv6Reachable",v6);r.put("ok",true);
  }catch(Exception e){try{r.put("ok",false);r.put("phase",phase);r.put("error",e.getClass().getSimpleName());String message=String.valueOf(e.getMessage());r.put("message",message.substring(0,Math.min(160,message.length())));}catch(Exception ignored){}}
  try(FileOutputStream out=openFileOutput("result.json",MODE_PRIVATE)){out.write(r.toString().getBytes("UTF-8"));}catch(Exception ignored){}
  runOnUiThread(()->{t.setText(r.toString());if(getIntent().getBooleanExtra("finishAfter",false))finish();});
 }
}
