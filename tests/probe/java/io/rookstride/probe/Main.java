package io.rookstride.probe;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import org.json.JSONObject;
import java.net.*;
import java.io.*;

/** Separate UID: strongSwan exempts the admin app itself from its VPN routes. */
public class Main extends Activity {
 @Override public void onCreate(Bundle b){super.onCreate(b);TextView t=new TextView(this);t.setText("Testing VPN routing…");t.setTextSize(24);setContentView(t);new Thread(()->probe(t)).start();}
 private void probe(TextView t){
  JSONObject r=new JSONObject();
  try {
   if(getIntent().getBooleanExtra("socketOnly",false)) {
    boolean reachable=false;
    try(Socket socket=new Socket()){socket.connect(new InetSocketAddress("1.1.1.1",443),4000);reachable=true;}catch(IOException ignored){}
    r.put("tcpIpv4Reachable",reachable);r.put("ok",true);
    try(FileOutputStream out=openFileOutput("result.json",MODE_PRIVATE)){out.write(r.toString().getBytes("UTF-8"));}
    runOnUiThread(()->t.setText(r.toString()));return;
   }
   HttpURLConnection c=(HttpURLConnection)new URL("https://api.ipify.org").openConnection();c.setConnectTimeout(20000);c.setReadTimeout(20000);
   try(InputStream in=c.getInputStream()){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[256];int n;while((n=in.read(b))!=-1){out.write(b,0,n);if(out.size()>1024)throw new IOException("Oversized response");}r.put("ipv4Exit",out.toString("UTF-8").trim());}finally{c.disconnect();}
   boolean blocked=false;
   try{InetAddress[] addresses=InetAddress.getAllByName("doubleclick.net");blocked=true;for(InetAddress a:addresses)if(!a.isAnyLocalAddress()&&!a.isLoopbackAddress())blocked=false;}catch(UnknownHostException e){blocked=true;}
   r.put("dnsBlocked",blocked);
   boolean v6=false;try(Socket s=new Socket()){s.connect(new InetSocketAddress("2606:4700:4700::1111",443),2500);v6=true;}catch(IOException e){}
   r.put("ipv6Reachable",v6);r.put("ok",true);
  }catch(Exception e){try{r.put("ok",false);r.put("error",e.getClass().getSimpleName());}catch(Exception ignored){}}
  try(FileOutputStream out=openFileOutput("result.json",MODE_PRIVATE)){out.write(r.toString().getBytes("UTF-8"));}catch(Exception ignored){}
  runOnUiThread(()->t.setText(r.toString()));
 }
}
