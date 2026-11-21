package org.strongswan.android.rookstride;

import org.json.JSONObject;
import org.json.JSONArray;
import java.io.InputStream;
import java.io.IOException;

/** Pinned SSH, one-use bootstrap, and per-device management credentials. */
public final class AdminAccessController {
    private AdminAccessController() {}
    // Fixed owner-only metadata reader. Opening SQLite in mode=ro never initializes
    // a missing database or invokes the restricted dispatcher's mutating audit.
    static final String OWNER_DISCOVERY_CODE=String.join("\n",
        "import hashlib,json,os,pathlib,sqlite3,stat",
        "def checked(path,maximum):",
        " s=path.lstat()",
        " if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_size>maximum: raise ValueError('Unsafe metadata')",
        " return path",
        "try:",
        " if os.geteuid()!=0: raise ValueError('Owner access required')",
        " machine=hashlib.sha256(checked(pathlib.Path('/etc/machine-id'),4096).read_bytes()).hexdigest()",
        " result={'schema':1,'machine':machine,'state':'absent','pair':None,'peers':[],'incoming':[]}",
        " manifest=pathlib.Path('/etc/rookstride-pair/manifest.json')",
        " if manifest.exists() or manifest.is_symlink():",
        "  value=json.loads(checked(manifest,1048576).read_text()); plan=value['plan']",
        "  result['pair']={'deployment_id':plan['pair'],'role':plan['role']}",
        " root=pathlib.Path('/var/lib/rookstride-access'); database=root/'authority.sqlite'",
        " if root.is_symlink(): raise ValueError('Unsafe metadata directory')",
        " if database.exists() or database.is_symlink():",
        "  checked(database,16777216)",
        "  with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5) as connection:",
        "   connection.execute('PRAGMA query_only=ON')",
        "   connection.execute('BEGIN')",
        "   row=connection.execute('SELECT value FROM records WHERE kind=? AND id=?',('meta','config')).fetchone()",
        "   if row is None or len(row[0])>65536: raise ValueError('Missing canonical identity')",
        "   value=json.loads(row[0]); endpoint=value['endpoint']",
        "   result.update(state='existing',authority={'server_id':value['server_id'],'deployment_id':value['deployment_id'],'fingerprint':endpoint['fingerprint'],'endpoint':{k:endpoint[k] for k in ('host','port','fingerprint')},'disabled':value.get('disabled',False)})",
        "   rows=list(connection.execute(\"SELECT id,value FROM records WHERE kind='peer' ORDER BY id LIMIT 65\"))",
        "   if len(rows)>64: raise ValueError('Too many authority peers')",
        "   for identity,raw in rows:",
        "    if len(raw)>65536: raise ValueError('Peer metadata is too large')",
        "    value=json.loads(raw); endpoint=value['endpoint']",
        "    result['peers'].append({'id':identity,'server_id':value['server_id'],'peer_id':value['peer_id'],'account':value['account'],'scope':value['scope'],'endpoint':{k:endpoint[k] for k in ('host','port','fingerprint')}})",
        "   rows=list(connection.execute(\"SELECT id,value FROM records WHERE kind='credential' ORDER BY id LIMIT 4097\"))",
        "   if len(rows)>4096: raise ValueError('Too many credentials')",
        "   for account,raw in rows:",
        "    if len(raw)>65536: raise ValueError('Credential metadata is too large')",
        "    value=json.loads(raw)",
        "    if value.get('kind')=='peer': result['incoming'].append({'account':account,'peer_id':value['peer_id'],'authority_id':value['authority_id'],'scope':value['scope'],'revoked':value.get('revoked',False)})",
        " print(json.dumps(result,separators=(',',':')))",
        "except Exception:",
        " print(json.dumps({'schema':1,'error':'Existing administrator metadata could not be read safely'})); raise SystemExit(1)");

    /** Read through the already pinned owner session before either enable or update.
     * For pairs, prepare both configurations before installing either module. */
    public static JSONObject ownerEnableConfig(Ssh ssh,Gateway node,String expectedPairDeployment)throws Exception {
        return ownerEnableConfig(node,ownerObservation(ssh,node),expectedPairDeployment);
    }
    private static JSONObject ownerObservation(Ssh ssh,Gateway node)throws Exception{
        if(node.data.optBoolean("adminAccess"))throw new IOException("Use the server owner's sign-in to manage administrator sharing");
        String prefix=ssh.execute("id -u",null).trim().equals("0")?"":"sudo -n ";
        return new JSONObject(ssh.execute(prefix+"python3 -I -c "+InputRules.quote(OWNER_DISCOVERY_CODE),null));
    }
    /** Canonical identity, never a phone cache, determines an existing module's IDs. */
    static JSONObject ownerEnableConfig(Gateway node,JSONObject observation,String expectedPairDeployment)throws Exception {
        if(node.data.optBoolean("adminAccess"))throw new IOException("Use the server owner's sign-in to manage administrator sharing");
        String pin=node.get("fingerprint"),machine=observation.optString("machine");
        if(observation.optInt("schema")!=1||observation.has("error")||!pin.matches("SHA256:[A-Za-z0-9+/]{43}")||!machine.matches("[0-9a-f]{64}"))throw new IOException("The server's administrator identity could not be verified. Refresh this server before trying again.");
        if(!node.get("machine").isEmpty()&&!node.get("machine").equals(machine))throw new IOException("This server's machine identity changed. Refresh and review its identity before enabling administrator sharing.");
        String deployment=expectedPairDeployment==null?"":expectedPairDeployment;
        JSONObject pair=observation.optJSONObject("pair");
        if(pair!=null){
            if(deployment.isEmpty()||!deployment.equals(pair.optString("deployment_id"))||!(node.isPair()?"entry":"exit").equals(pair.optString("role")))throw new IOException("Recognize the current Double VPN before managing its administrator sharing. The deployment identity or server role differs.");
        }else if(!deployment.isEmpty())throw new IOException("The server no longer belongs to the selected Double VPN. Inspect it before changing administrator sharing.");
        if(!deployment.isEmpty()&&!identity(deployment))throw new IOException("The Double VPN identity is invalid");
        String server;
        if(observation.optString("state").equals("existing")){
            JSONObject authority=observation.optJSONObject("authority");
            if(authority==null||!(authority.opt("server_id") instanceof String)||!(authority.opt("deployment_id") instanceof String)||!identity(authority.optString("server_id"))||!identity(authority.optString("deployment_id"))||!pin.equals(authority.optString("fingerprint"))||!(authority.opt("disabled") instanceof Boolean))throw new IOException("The retained administrator module belongs to a different or unverified server identity. Its grants were preserved.");
            if(!deployment.isEmpty()&&!deployment.equals(authority.optString("deployment_id")))throw new IOException("The retained administrator module belongs to a different deployment. Its grants were preserved; review it in Maintenance.");
            server=authority.getString("server_id");deployment=authority.getString("deployment_id");
        }else if(observation.optString("state").equals("absent")&&!observation.has("authority")){
            server=java.util.UUID.randomUUID().toString();
            if(deployment.isEmpty())deployment=java.util.UUID.randomUUID().toString();
        }else throw new IOException("The administrator module could not be inspected. Existing grants were preserved.");
        return new JSONObject().put("server_id",server).put("deployment_id",deployment).put("endpoint",new JSONObject().put("host",node.get("host")).put("port",node.port()).put("fingerprint",pin));
    }
    private static boolean identity(String value){return value.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}");}
    /** Call only after the explicit enable/update succeeds, never on discovery. */
    public static void rememberOwnerIdentity(Gateway node,JSONObject verifiedConfig)throws Exception {
        String server=verifiedConfig.getString("server_id"),deployment=verifiedConfig.getString("deployment_id");
        if(!identity(server)||!identity(deployment)||!node.get("fingerprint").equals(verifiedConfig.getJSONObject("endpoint").getString("fingerprint")))throw new IOException("The reviewed administrator identity changed");
        if(!node.get("adminServerId").equals(server)||!node.get("adminDeploymentId").equals(deployment))node.data.remove("adminSnapshot");
        node.set("adminServerId",server);node.set("adminDeploymentId",deployment);node.set("adminIdentityFingerprint",node.get("fingerprint"));
    }
    /** Reuse and verify an exact existing link; never mint another peer credential
     * merely because this phone lost its owner cache. A wrong/stale link needs
     * a separate reviewed repair, not replacement as an enable side effect. */
    public static JSONObject ensurePairLink(Ssh authority,Ssh peer,Gateway owner,Gateway exit,String deployment)throws Exception{
        JSONObject a=ownerObservation(authority,owner),b=ownerObservation(peer,exit);
        String mode=pairLinkDisposition(owner,exit,a,b,deployment);
        String authorityId=a.getJSONObject("authority").getString("server_id"),peerId=b.getJSONObject("authority").getString("server_id");
        if(mode.equals("create"))return linkPair(authority,peer,authorityId,deployment);
        JSONObject current=request(authority,new JSONObject().put("operation","capabilities"));
        // inventory.refresh proves the existing credential against the pinned peer
        // and its current server/deployment IDs; cached object names are not proof.
        JSONObject refreshed=request(authority,new JSONObject().put("operation","inventory.refresh").put("expected_revision",current.getLong("revision")));
        return new JSONObject().put("linked",true).put("reused",true).put("server_id",peerId).put("revision",refreshed.getLong("revision"));
    }
    static String pairLinkDisposition(Gateway owner,Gateway exit,JSONObject a,JSONObject b,String deployment)throws Exception{
        JSONObject authority=ownerEnableConfig(owner,a,deployment),peer=ownerEnableConfig(exit,b,deployment);
        if(!a.optString("state").equals("existing")||!b.optString("state").equals("existing"))throw new IOException("Enable both reviewed administrator modules before linking them");
        String authorityId=authority.getString("server_id"),peerId=peer.getString("server_id");
        if(authorityId.equals(peerId))throw new IOException("The two servers cannot share one physical administrator identity");
        JSONArray links=a.optJSONArray("peers"),incoming=b.optJSONArray("incoming");
        if(links==null||incoming==null||links.length()>1)throw pairLinkReview();
        if(links.length()==0){
            for(int i=0;i<incoming.length();i++){JSONObject credential=incoming.optJSONObject(i);if(credential==null)throw pairLinkReview();if(authorityId.equals(credential.optString("authority_id"))&&!Boolean.TRUE.equals(credential.opt("revoked")))throw pairLinkReview();}
            return "create";
        }
        JSONObject link=links.optJSONObject(0),canonicalEndpoint=b.getJSONObject("authority").optJSONObject("endpoint");
        if(link==null||!peerId.equals(link.optString("id"))||!peerId.equals(link.optString("server_id"))||!deploymentScope(link.optJSONObject("scope"),deployment)||!samePeerEndpoint(link.optJSONObject("endpoint"),canonicalEndpoint,exit.get("fingerprint")))throw pairLinkReview();
        for(int i=0;i<incoming.length();i++){
            JSONObject credential=incoming.optJSONObject(i);
            if(credential!=null&&Boolean.FALSE.equals(credential.opt("revoked"))&&authorityId.equals(credential.optString("authority_id"))&&identity(link.optString("peer_id"))&&link.optString("peer_id").equals(credential.optString("peer_id"))&&link.optString("account").matches("rsp[a-f0-9]{20}")&&link.optString("account").equals(credential.optString("account"))&&deploymentScope(credential.optJSONObject("scope"),deployment))return "reuse";
        }
        throw pairLinkReview();
    }
    private static boolean deploymentScope(JSONObject scope,String deployment){return scope!=null&&scope.optString("kind").equals("deployment")&&scope.optString("id").equals(deployment)&&scope.optString("users").equals("all");}
    private static boolean samePeerEndpoint(JSONObject actual,JSONObject expected,String pin){return actual!=null&&expected!=null&&InputRules.host(actual.optString("host"))&&actual.optString("host").equals(expected.optString("host"))&&InputRules.port(actual.optInt("port"))&&actual.optInt("port")==expected.optInt("port")&&pin.equals(actual.optString("fingerprint"))&&pin.equals(expected.optString("fingerprint"));}
    private static IOException pairLinkReview(){return new IOException("The retained administrator link needs a separate owner review. Existing peer credentials and grants were preserved; no replacement link was created.");}
    public static JSONObject enable(Ssh ssh,InputStream bundle,JSONObject config)throws Exception {
        config.put("schema",1).put("operation","enable");return ssh.access(bundle,config);
    }
    public static JSONObject request(Ssh ssh,JSONObject request)throws Exception {
        request.put("schema",1);
        // Forced SSH accounts ignore this command and invoke precisely the same
        // dispatcher. Root can execute it directly; sudo is fixed, without input.
        return Ssh.response(ssh.execute("sudo -n /usr/local/sbin/rookstride-access",request.toString()));
    }
    public static JSONObject createInvitation(Ssh ssh,String role,JSONObject scope,int ttl)throws Exception {
        JSONObject snapshot=request(ssh,new JSONObject().put("operation","capabilities"));
        return request(ssh,new JSONObject().put("operation","invitations.create").put("role",role).put("scope",scope).put("ttl_seconds",ttl).put("expected_revision",snapshot.getLong("revision"))).getJSONObject("invitation");
    }
    /** Optional labels are omitted when unknown, never sent as invalid empty values. */
    public static JSONObject newUserParameters(String protocol,String login,String password)throws Exception {
        return newUserParameters(protocol,PasswordSignIn.supported(protocol),login,password);
    }
    /** Native method names alone do not identify an installation's authentication mode. */
    public static boolean passwordUsers(JSONObject object){
        if(object==null)return false;String protocol=object.optString("protocol");
        return PasswordSignIn.supported(protocol)&&object.optString("access_mode").equals("password");
    }
    public static JSONObject newUserParameters(JSONObject object,String login,String password)throws Exception {
        String protocol=object.optString("protocol"),mode=object.optString("access_mode");
        if(PasswordSignIn.supported(protocol)&&!mode.equals("password")&&!mode.equals("profile"))throw new IOException("Refresh the administrator capabilities before adding users. The owner may need to update the management tools.");
        return newUserParameters(protocol,passwordUsers(object),login,password);
    }
    private static JSONObject newUserParameters(String protocol,boolean passwordBased,String login,String password)throws Exception {
        validateUser(protocol,login,passwordBased);
        JSONObject parameters=new JSONObject().put("login",login).put("person",login);
        if(passwordBased){
            if(!InputRules.vpnPassword(password))throw new IOException("Enter a nonempty VPN password, up to 127 UTF-8 bytes");
            parameters.put("password",password);
        }
        return parameters;
    }
    /** Empty optional edits mean keep the saved value; passwords are never trimmed. */
    public static JSONObject editUserParameters(String protocol,String login,String person,String device,String password)throws Exception {
        return editUserParameters(protocol,PasswordSignIn.supported(protocol),login,person,device,password);
    }
    public static JSONObject editUserParameters(JSONObject object,String login,String person,String device,String password)throws Exception {
        // Metadata-only edits remain safe on old helpers. Never present a
        // password editor without a confirmed password-capable installation.
        return editUserParameters(object.optString("protocol"),passwordUsers(object),login,person,device,password);
    }
    private static JSONObject editUserParameters(String protocol,boolean passwordBased,String login,String person,String device,String password)throws Exception {
        // Existing usernames can belong to a password installation whose old
        // helper has not yet reported its mode. Metadata editing grants no new
        // authentication capability; the server still validates the account.
        validateUser(protocol,login,true);JSONObject parameters=new JSONObject().put("login",login);
        optionalLabel(parameters,"person",person);optionalLabel(parameters,"device",device);
        if(password!=null&&!password.isEmpty()){
            if(!passwordBased)throw new IOException("This installation has no confirmed username/password sign-in. Share its connection file instead.");
            if(!InputRules.vpnPassword(password))throw new IOException("Enter a nonempty VPN password, up to 127 UTF-8 bytes");
            parameters.put("password",password);
        }
        return parameters;
    }
    private static void validateUser(String protocol,String login,boolean passwordBased)throws IOException {
        if(!SingleProtocols.from(protocol).id.equals(protocol))throw new IOException("Choose a supported VPN protocol");
        if(!InputRules.username(login))throw new IOException("Enter a valid VPN username");
        if(!passwordBased&&!login.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,47}"))throw new IOException("Use up to 48 letters, numbers, underscores or hyphens; start with a letter or number");
    }
    private static void optionalLabel(JSONObject parameters,String key,String value)throws Exception {
        String label=value==null?"":value.trim();if(label.isEmpty())return;
        if(label.codePointCount(0,label.length())>80||label.codePoints().anyMatch(c->Character.isISOControl(c)||c>=0xD800&&c<=0xDFFF))throw new IOException("Use a name of 1–80 printable characters");
        parameters.put(key,label);
    }
    /** Persist this draft in the encrypted vault BEFORE starting network enrollment. */
    public static Gateway deviceDraft(JSONObject invitation)throws Exception {
        invitation=AdminAccess.parseInvitation(invitation.toString());JSONObject key=AdminAccess.newDeviceKey();JSONObject endpoint=invitation.getJSONObject("endpoint");
        Gateway device=new Gateway();device.set("name","Administrator · "+endpoint.getString("host"));device.set("host",endpoint.getString("host"));device.data.put("port",endpoint.getInt("port"));device.set("fingerprint",endpoint.getString("fingerprint"));device.set("sshKeyType",endpoint.optString("host_key").split(" ")[0]);
        device.privateKey=key.getString("private_key");
        byte[] accountHash=java.security.MessageDigest.getInstance("SHA-256").digest(key.getString("public_key").getBytes(java.nio.charset.StandardCharsets.UTF_8));StringBuilder account=new StringBuilder("rsd");for(int i=0;i<10;i++)account.append(String.format(java.util.Locale.ROOT,"%02x",accountHash[i]&255));device.set("admin",account.toString());device.set("adminPublicKey",key.getString("public_key"));device.set("adminInvitationId",invitation.getString("invitation_id"));device.set("adminServerId",invitation.getString("server_id"));
        device.data.put("adminAccess",true).put("remember",true).put("saveAccessChosen",true).put("adminEnrollment",invitation);return device;
    }
    public static Gateway accept(JSONObject invitation,Gateway savedDevice)throws Exception {
        Gateway device=savedDevice==null?deviceDraft(invitation):savedDevice;
        if(savedDevice!=null&&!device.get("admin").isEmpty()) {
            try(Ssh existing=new Ssh(device)){JSONObject resumed=request(existing,new JSONObject().put("operation","enrollment.resume"));return finish(device,resumed);}
            catch(Ssh.SignInRejected notYetEnrolled){ /* Bootstrap is used only if this own key is not installed yet. */ }
        }
        invitation=AdminAccess.parseInvitation(invitation.toString());
        if(!device.get("adminInvitationId").equals(invitation.getString("invitation_id"))||device.privateKey.isEmpty())throw new IOException("Use this phone's saved enrollment draft to resume");
        JSONObject endpoint=invitation.getJSONObject("endpoint"),bootstrap=invitation.getJSONObject("bootstrap");
        Gateway temporary=new Gateway();temporary.set("host",endpoint.getString("host"));temporary.data.put("port",endpoint.getInt("port"));temporary.set("fingerprint",endpoint.getString("fingerprint"));temporary.set("sshKeyType",endpoint.optString("host_key").split(" ")[0]);temporary.set("admin",bootstrap.getString("account"));temporary.privateKey=bootstrap.getString("private_key");
        JSONObject result;
        try(Ssh ssh=new Ssh(temporary)) {
            JSONObject challenge=request(ssh,new JSONObject().put("operation","enrollment.challenge"));
            if(!challenge.getString("invitation_id").equals(invitation.getString("invitation_id"))||!challenge.getString("server_id").equals(invitation.getString("server_id")))throw new IOException("Server invitation identity differs");
            result=request(ssh,new JSONObject().put("operation","enrollment.accept").put("public_key",device.get("adminPublicKey")).put("signature",AdminAccess.prove(challenge,device.get("adminPublicKey"),device.privateKey)));
        }
        finish(device,result);
        try(Ssh ssh=new Ssh(device)){request(ssh,new JSONObject().put("operation","capabilities"));}
        return device;
    }
    private static Gateway finish(Gateway device,JSONObject result)throws Exception {
        device.set("admin",result.getString("account"));device.set("adminDeviceId",result.getString("device_id"));device.set("adminGrantId",result.getString("grant_id"));device.set("adminRole",result.getString("role"));device.data.put("adminScope",result.getJSONObject("scope")).put("adminPendingPeers",result.getJSONArray("pending_peers"));device.data.remove("adminEnrollment");return device;
    }
    /** Owner prelinks exact peers once; recipients never receive this credential. */
    public static JSONObject linkPair(Ssh authority,Ssh peer,String authorityId,String deploymentId)throws Exception {
        JSONObject current=request(peer,new JSONObject().put("operation","capabilities"));
        JSONObject prepared=request(peer,new JSONObject().put("operation","peers.prepare").put("authority_id",authorityId).put("scope",new JSONObject().put("kind","deployment").put("id",deploymentId).put("users","all")).put("expected_revision",current.getLong("revision")));
        current=request(authority,new JSONObject().put("operation","capabilities"));
        return request(authority,new JSONObject().put("operation","peers.link").put("link",prepared.getJSONObject("link")).put("expected_revision",current.getLong("revision")));
    }
}
