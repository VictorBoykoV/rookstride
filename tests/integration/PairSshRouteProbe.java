import org.strongswan.android.rookstride.*;
import org.json.*;import java.io.*;import java.net.*;import java.nio.file.*;
/** Real SSH / forwarding against an explicitly supplied disposable fixture.
 * Logical direct reachability is fault-injected. This checks management transport,
 * not two distinct VPS deployment or Android's VpnService socket policy. */
public final class PairSshRouteProbe {
 static Gateway source;static boolean entryReachable,exitReachable;
 static Gateway node(String host)throws Exception{Gateway g=new Gateway(new JSONObject(source.persisted().toString()));g.set("id",java.util.UUID.randomUUID().toString());g.set("host",host);g.data.put("port",22);return g;}
 static Gateway pair()throws Exception{Gateway g=node("127.0.0.1");g.exit=node("localhost");g.set("sshRoute","auto");return g;}
 static void require(boolean v,String m)throws Exception{if(!v)throw new Exception(m);}
 static void check(String name,boolean a,boolean b,String route)throws Exception{
  entryReachable=a;exitReachable=b;Gateway g=pair();try(PairSsh s=PairSsh.connect(g,phase->{})){require(route.equals(g.get("resolvedSshRoute")),name+" selected wrong route");require("entry".equals(s.entry.execute("printf entry",null)),name+" entry read");require("exit".equals(s.exit.execute("printf exit",null)),name+" exit read");}System.out.println("PASS "+name);
 }
 public static void main(String[] args)throws Exception{
  source=new Gateway(new JSONObject(Files.readString(Path.of(args[0]))));require(!source.get("fingerprint").isEmpty(),"Pre-pin the fixture using independently attested keys");
  Ssh.socketFactory=new com.jcraft.jsch.SocketFactory(){
   public Socket createSocket(String host,int port)throws IOException{boolean entry=host.equals("127.0.0.1");if(!(entry?entryReachable:exitReachable))throw new ConnectException("Injected direct path unavailable");Socket s=new Socket();s.connect(new InetSocketAddress(source.get("host"),source.port()),6000);return s;}
   public InputStream getInputStream(Socket s)throws IOException{return s.getInputStream();}public OutputStream getOutputStream(Socket s)throws IOException{return s.getOutputStream();}
  };
  check("both direct",true,true,"direct");check("exit through entry",true,false,"exit-via-entry");check("entry through exit",false,true,"entry-via-exit");
  entryReachable=false;exitReachable=false;try(PairSsh s=PairSsh.connect(pair(),p->{})){throw new Exception("Neither path should open");}catch(IOException expected){require(expected.getMessage().contains("Neither"),"Wrong neither-path result");}System.out.println("PASS neither reachable");
  entryReachable=true;exitReachable=true;Gateway bad=pair();bad.exit.sshPassword="deliberately-wrong-fixture-password";try(PairSsh s=PairSsh.connect(bad,p->{})){throw new Exception("Wrong credentials accepted");}catch(Ssh.SignInRejected expected){}require(bad.get("resolvedSshRoute").isEmpty(),"Authentication error triggered fallback");System.out.println("PASS authentication stops fallback");
  bad=pair();bad.exit.set("fingerprint","SHA256:changed-fixture-identity");try(PairSsh s=PairSsh.connect(bad,p->{})){throw new Exception("Changed identity accepted");}catch(PairController.TrustNeeded expected){require(expected.issue.changed,"Key change was not identified");}System.out.println("PASS changed key stops fallback");
  entryReachable=true;exitReachable=false;Gateway g=pair();try(AdminConnection c=AdminConnection.open(g.exit,g,p->{})){require("once".equals(c.ssh.execute("printf once",null)),"Administrator command failed after rediscovery");require("exit-via-entry".equals(g.get("resolvedSshRoute")),"Ongoing admin discovery failed");}System.out.println("PASS ongoing admin route rediscovery");
  g=pair();g.set("sshRoute","direct");try(PairSsh s=PairSsh.connect(g,p->{})){throw new Exception("Explicit direct ignored");}catch(Ssh.Unreachable expected){}System.out.println("PASS explicit direct is honored");
 }
}
