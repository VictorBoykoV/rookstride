import com.jcraft.jsch.SocketFactory;
import org.json.*;
import org.strongswan.android.rookstride.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Opt-in local disposable SSH fixture; never deploys or resets a server.
 * Args: private fixture JSON array, node index, expect-timeout|expect-success.
 * Compile with the actual app Ssh/Gateway/InputRules sources and pinned JSch/JSON.
 * Delays one encrypted response after authentication, without reading its content.
 */
public final class SlowSshChannelProbe {
 public static void main(String[] args)throws Exception {
  JSONObject fixture=new JSONArray(Files.readString(Path.of(args[0]))).getJSONObject(Integer.parseInt(args[1]));
  if(!fixture.optBoolean("disposable")||!fixture.getString("host").equals("127.0.0.1"))throw new IllegalArgumentException("Explicit local disposable fixture required");
  boolean expected=args[2].equals("expect-success");
  if(!expected&&!args[2].equals("expect-timeout"))throw new IllegalArgumentException("Choose the expected outcome");
  Gateway node=new Gateway(fixture);node.set("fingerprint","");
  try(Ssh ignored=new Ssh(node)){throw new AssertionError("Unpinned host key accepted");}
  catch(Ssh.HostTrust trust){
   boolean pinned=false;JSONArray pins=fixture.getJSONArray("pins");
   for(int i=0;i<pins.length();i++)if(pins.getString(i).equals(trust.fingerprint))pinned=true;
   if(!pinned)throw new AssertionError("Host key differs from trusted fixture");node.set("fingerprint",trust.fingerprint);
  }
  AtomicBoolean delay=new AtomicBoolean();
  Ssh.socketFactory=new SocketFactory(){
   public Socket createSocket(String host,int port)throws IOException{Socket s=new Socket();s.connect(new InetSocketAddress(host,port),12000);return s;}
   public OutputStream getOutputStream(Socket s)throws IOException{return s.getOutputStream();}
   public InputStream getInputStream(Socket s)throws IOException{return new FilterInputStream(s.getInputStream()){
    private void pause(int n)throws IOException{if(n>0&&delay.compareAndSet(true,false))try{Thread.sleep(12000);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("Test delay interrupted");}}
    @Override public int read(byte[] b,int off,int len)throws IOException{int n=in.read(b,off,len);pause(n);return n;}
    @Override public int read()throws IOException{int n=in.read();pause(n<0?-1:1);return n;}
   };}
  };
  boolean accepted=false;String failure="";long started;
  try(Ssh ssh=new Ssh(node)){
   delay.set(true);started=System.nanoTime();
   try{accepted=ssh.execute("id -u",null).equals("0");}catch(Exception e){failure=e.getClass().getSimpleName();}
   double elapsed=(System.nanoTime()-started)/1e9;
   if(accepted!=expected||elapsed<9||elapsed>45)throw new AssertionError("Unexpected slow-channel result");
   System.out.println(new JSONObject().put("response_delay_seconds",12).put("accepted",accepted).put("elapsed_seconds",elapsed).put("failure_class",failure));
  }finally{Ssh.socketFactory=null;}
 }
}
