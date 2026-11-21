import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.strongswan.android.rookstride.*;

/** Actual controller/SSH/forced-command acceptance on explicitly disposable nodes.
 * Usage: ScopedAccessProbe PRIVATE_FIXTURE.json; fixture has disposable, server,
 * bundle, optional peer (Gateway JSON). No addresses, keys or passwords printed.
 */
public final class ScopedAccessProbe {
 static JSONObject call(Ssh ssh,String op)throws Exception{return AdminAccessController.request(ssh,new JSONObject().put("operation",op));}
 static void require(boolean ok,String text)throws Exception{if(!ok)throw new Exception(text);}
 interface Action{void run()throws Exception;}
 static void denied(Action a)throws Exception{boolean rejected=false;try{a.run();}catch(IOException|com.jcraft.jsch.JSchException expected){rejected=true;}require(rejected,"An unauthorized request succeeded");}
 static JSONObject localObject(JSONObject caps,String serverId)throws Exception {JSONArray objects=caps.getJSONArray("objects");JSONObject fallback=null;for(int i=0;i<objects.length();i++)if(serverId.equals(objects.getJSONObject(i).getString("server_id"))){JSONObject object=objects.getJSONObject(i);if(object.getString("protocol").equals("awg"))return object;fallback=object;}if(fallback!=null)return fallback;throw new IOException("Local protocol was not discovered");}
 static void legacyUser(Ssh owner,JSONObject object,String action,String login,boolean pair)throws Exception {JSONObject request=new JSONObject().put("action",action).put("login",login);String command="sudo -n /usr/local/sbin/rookstride-admin";if(!object.getString("protocol").equals("ikev2")){request.put("protocol",object.getString("protocol"));command=pair?"sudo -n python3 /opt/rookstride-pair/single/run.py":"sudo -n python3 /opt/rookstride-single/current/single/run.py";}if(action.equals("add-user"))request.put("password","AccessLab-9!"+UUID.randomUUID());Ssh.response(owner.execute(command,request.toString()));}
 static void restrictedChannel(Ssh ssh,String kind)throws Exception {java.lang.reflect.Field field=Ssh.class.getDeclaredField("session");field.setAccessible(true);com.jcraft.jsch.Session session=(com.jcraft.jsch.Session)field.get(ssh);com.jcraft.jsch.Channel channel=session.openChannel(kind);if(channel instanceof com.jcraft.jsch.ChannelDirectTCPIP){com.jcraft.jsch.ChannelDirectTCPIP forward=(com.jcraft.jsch.ChannelDirectTCPIP)channel;forward.setHost("127.0.0.1");forward.setPort(22);forward.setOutputStream(new ByteArrayOutputStream());}try{channel.connect(10000);}finally{channel.disconnect();}}
 static JSONObject scope(JSONObject object,String kind)throws Exception{return new JSONObject().put("kind",kind).put("id",object.getString(kind.equals("protocol")?"id":kind+"_id")).put("users","own");}
 static JSONObject mutate(Ssh ssh,String op,JSONObject object,String login,String password)throws Exception {
  JSONObject req=new JSONObject().put("operation",op).put("object_id",object.getString("id")).put("expected_revision",call(ssh,"capabilities").getLong("revision")).put("operation_id",UUID.randomUUID().toString());
  JSONObject params=new JSONObject().put("login",login);if(password!=null)params.put("password",password);
  return AdminAccessController.request(ssh,req.put("parameters",params));
 }
 public static void main(String[] args)throws Exception{
  Path file=Path.of(args[0]);JSONObject fixture=new JSONObject(Files.readString(file));require(fixture.optBoolean("disposable"),"Disposable fixture required");Gateway owner=new Gateway(fixture.getJSONObject("server"));require(!owner.get("fingerprint").isEmpty(),"Pinned owner identity required");
  String deployment=fixture.optString("deployment_id","access-lab-"+UUID.randomUUID());String serverId=fixture.optString("server_id",owner.get("id"));JSONArray passed=new JSONArray();
  try(Ssh ssh=new Ssh(owner)){
   JSONObject config=new JSONObject().put("server_id",serverId).put("deployment_id",deployment).put("endpoint",new JSONObject().put("host",owner.get("host")).put("port",owner.port()).put("fingerprint",owner.get("fingerprint")));
   try(InputStream bundle=Files.newInputStream(Path.of(fixture.getString("bundle")))){AdminAccessController.enable(ssh,bundle,config);}passed.put("owner-enable-no-vpn-install");
   if(fixture.has("peer")){
    Gateway peer=new Gateway(fixture.getJSONObject("peer"));try(Ssh remote=new Ssh(peer)){
     config=new JSONObject().put("server_id",fixture.optString("peer_server_id",peer.get("id"))).put("deployment_id",deployment).put("endpoint",new JSONObject().put("host",peer.get("host")).put("port",peer.port()).put("fingerprint",peer.get("fingerprint")));
     try(InputStream bundle=Files.newInputStream(Path.of(fixture.getString("bundle")))){AdminAccessController.enable(remote,bundle,config);}
     AdminAccessController.linkPair(ssh,remote,serverId,deployment);passed.put("owner-linked-pinned-peer");
    }
   }
   JSONObject caps=call(ssh,"capabilities");JSONObject object=localObject(caps,serverId);JSONObject selectedScope=scope(object,fixture.has("peer")?"deployment":"protocol");
   JSONObject invite=AdminAccessController.createInvitation(ssh,"user_manager",selectedScope,600);Gateway device=AdminAccessController.deviceDraft(invite);
   Path draft=file.resolveSibling("access-device-private.json");Files.writeString(draft,device.persisted().toString());try{Files.setPosixFilePermissions(draft,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
   Gateway enrolled=AdminAccessController.accept(invite,device);Files.writeString(draft,enrolled.persisted().toString());passed.put("controller-device-key-auto-enrollment");
   require(!enrolled.privateKey.equals(invite.getJSONObject("bootstrap").getString("private_key")),"Recipient reused bootstrap key");
   Gateway other=AdminAccessController.deviceDraft(invite);denied(()->AdminAccessController.accept(invite,other));passed.put("second-device-replay-denied");
   try(Ssh delegated=new Ssh(enrolled)){
    JSONObject current=call(delegated,"capabilities");require(current.getString("role").equals("user_manager"),"Wrong assigned role");
    denied(()->AdminAccessController.request(delegated,new JSONObject().put("operation","invitations.create").put("role","owner").put("actor","@owner")));passed.put("forged-owner-denied");
    String arbitrary=delegated.execute("id; cat /etc/shadow; /bin/sh",new JSONObject().put("schema",1).put("operation","capabilities").toString());require(new JSONObject(arbitrary).getJSONObject("result").getString("role").equals("user_manager"),"Forced command was bypassed");passed.put("arbitrary-shell-command-forced-to-dispatcher");
    denied(()->restrictedChannel(delegated,"direct-tcpip"));call(delegated,"capabilities");passed.put("arbitrary-ssh-forwarding-denied");
    denied(()->restrictedChannel(delegated,"sftp"));call(delegated,"capabilities");passed.put("sftp-executable-upload-channel-denied");
    denied(()->AdminAccessController.request(delegated,new JSONObject().put("operation","users.list").put("object_id","unrelated-protocol")));passed.put("unknown-object-denied");
    String login="accesslab"+UUID.randomUUID().toString().replace("-","").substring(0,10);mutate(delegated,"users.create",object,login,"AccessLab-9!"+UUID.randomUUID());passed.put("actual-scoped-account-created");
    if(fixture.has("peer")){
     JSONObject remoteObject=null;JSONArray objects=current.getJSONArray("objects");
     for(int i=0;i<objects.length();i++)if(!objects.getJSONObject(i).getString("server_id").equals(serverId))remoteObject=objects.getJSONObject(i);
     require(remoteObject!=null,"Paired scope did not expose its remote protocol");
     mutate(delegated,"users.create",remoteObject,login+"peer","AccessLab-9!"+UUID.randomUUID());
     mutate(delegated,"users.revoke",remoteObject,login+"peer",null);passed.put("paired-proxy-actual-user-create-and-revoke");
    }
    JSONObject change=new JSONObject().put("operation","grants.update").put("grant_id",enrolled.get("adminGrantId")).put("role","viewer").put("scope",selectedScope).put("expected_revision",call(ssh,"capabilities").getLong("revision"));AdminAccessController.request(ssh,change);
    denied(()->mutate(delegated,"users.create",object,login+"x","AccessLab-9!"+UUID.randomUUID()));passed.put("role-change-effective-on-open-session");
    change.put("role","user_manager").put("expected_revision",call(ssh,"capabilities").getLong("revision"));AdminAccessController.request(ssh,change);mutate(delegated,"users.revoke",object,login,null);passed.put("actual-scoped-account-revoked");
    legacyUser(ssh,object,"add-user",login,fixture.has("peer"));
    denied(()->AdminAccessController.request(delegated,new JSONObject().put("operation","users.profile").put("object_id",object.getString("id")).put("parameters",new JSONObject().put("login",login))));
    denied(()->mutate(delegated,"users.revoke",object,login,null));
    legacyUser(ssh,object,"remove-user",login,fixture.has("peer"));passed.put("same-login-replacement-not-owned-by-former-issuer");
    AdminAccessController.request(ssh,new JSONObject().put("operation","devices.revoke").put("device_id",enrolled.get("adminDeviceId")).put("expected_revision",call(ssh,"capabilities").getLong("revision")));
    denied(()->call(delegated,"capabilities"));passed.put("revocation-effective-on-open-session");
   }
   denied(()->{try(Ssh rejected=new Ssh(enrolled)){call(rejected,"capabilities");}});passed.put("revoked-new-ssh-denied");
   JSONObject audit=call(ssh,"audit.read");require(!audit.toString().contains("PRIVATE KEY")&&!audit.toString().contains("AccessLab-9!"),"Secret entered audit");passed.put("audit-redacted");
  }
  System.out.println(new JSONObject().put("suite","scoped-access-real-ssh").put("passed",passed).put("count",passed.length()));
 }
}
