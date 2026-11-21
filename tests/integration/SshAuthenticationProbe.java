import java.nio.file.*;
import org.json.*;
import org.strongswan.android.rookstride.*;

/** Explicit local fixture: delay a disposable account's PAM response beyond the
 * SSH timeout, then prove a genuine rejection remains a different error. Never
 * prints credentials, discovers servers or retries authentication. */
public final class SshAuthenticationProbe {
 public static void main(String[] args)throws Exception{
  JSONObject fixture=new JSONObject(Files.readString(Path.of(args[0])));
  if(!fixture.optBoolean("disposable"))throw new Exception("Disposable fixture required");
  Gateway node=new Gateway(fixture.getJSONObject("server"));
  if(node.get("fingerprint").isEmpty())throw new Exception("Independently pinned SSH identity required");
  String expected=fixture.getString("expected");long started=System.nanoTime();String actual;
  try(Ssh ssh=new Ssh(node)){throw new Exception("The negative authentication fixture unexpectedly connected");}
  catch(Ssh.Unreachable e){actual="network-timeout";}
  catch(Ssh.SignInRejected e){actual="bad-password";}
  if(!actual.equals(expected))throw new Exception("Expected "+expected+"; received "+actual);
  System.out.println(new JSONObject().put("expected",expected).put("actual",actual).put("seconds",(System.nanoTime()-started)/1_000_000_000.0));
 }
}
