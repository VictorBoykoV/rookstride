package org.strongswan.android.rookstride;

import android.app.ActivityManager;
import android.content.Context;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.jcraft.jsch.SocketFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.rookstride.engine.AdminSocketFactory;
import org.strongswan.android.rookstride.engine.ProfileCipher;
import org.xmlpull.v1.XmlPullParser;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import static org.junit.Assert.*;

/** Opt-in export of existing authenticated phone evidence. No Activity, Vault
 * AtomicFile recovery, NativeProfileStore.file(), key creation or remote call.
 * A snapshot is not a constructor receipt or administrator enrollment. */
@RunWith(AndroidJUnit4.class)
public final class AcceptanceSnapshotIntegrationTest {
    private static final String CATALOG_ALIAS="rookstride.gateway.v1",PROFILE_ALIAS="rookstride.native-profile.v1";
    private static final Set<String> PENDING=new HashSet<>(Arrays.asList("job","helperUpdate","engineUpdate","lifecycleOperation","entryMigration","pairedOsOperation"));
    private static final Set<String> TERMINAL=new HashSet<>(Arrays.asList("accepted","rolled-back","cancelled","complete","completed","abandoned"));

    @Test public void exportCurrentAuthenticatedPhoneEvidenceWithoutRemoteAccess()throws Exception {
        PrivateAdministrationFixture f=PrivateAdministrationFixture.load("acceptance-snapshot","allow_read_only_snapshot");
        // The private request pins the Main APK and signer through load(); the
        // independently built test APK must be explicitly pinned there as well.
        assertEquals("Bind the actual test-only APK",f.request.getString("expected_test_apk_sha256"),f.binary.getString("test_apk_sha256"));
        assertTrue("Only local evidence export is authorized",f.request.getBoolean("no_remote_access"));
        assertTrue("Full authenticated catalog export needs explicit approval",f.request.getBoolean("allow_full_catalog_export"));
        boolean catalogOnly=f.request.optBoolean("catalog_only",false);
        if(catalogOnly){
            assertEquals("Catalog-only mode needs an explicit boolean selection",Boolean.TRUE,f.request.opt("catalog_only"));
            assertEquals("Catalog-only evidence needs separate authorization",Boolean.TRUE,f.request.opt("allow_catalog_only_snapshot"));
            assertFalse("Catalog-only evidence cannot claim constructor provenance",f.request.has("constructor_files"));
        }
        String observation=f.request.getString("observation_id");assertTrue("Use a fresh observation ID",observation.matches("[a-f0-9]{32}"));
        long now=System.currentTimeMillis(),expires=f.request.getLong("expires_at_ms");
        assertTrue("Use a current reviewed snapshot fixture",expires>=now&&expires-now<=300000);
        idle(f.context);
        File files=f.context.getFilesDir().getCanonicalFile(),data=files.getParentFile();
        // getNoBackupFilesDir() may create a missing directory. Require the
        // existing target-context location without asking storage APIs to repair it.
        File noBackup=new File(data,"no_backup"),profiles=new File(noBackup,"vpn-profiles");
        File progress=new File(data,"shared_prefs/rookstride-deployment.xml");
        secureDirectory(files);secureDirectory(noBackup);secureDirectory(profiles);secureDirectory(progress.getParentFile());
        byte[] fixture=read(new File(files,PrivateAdministrationFixture.FILE),2*1024*1024);
        assertEquals("The reviewed fixture changed after loading",f.request.toString(),new JSONObject(new String(fixture,StandardCharsets.UTF_8)).toString());
        String fixtureHash=PrivateAdministrationFixture.hash(fixture);Arrays.fill(fixture,(byte)0);
        SocketFactory previous=Ssh.socketFactory;
        assertTrue("Do not replace an unknown SSH socket policy",previous==null||previous instanceof AdminSocketFactory);
        AtomicInteger sockets=new AtomicInteger();
        SocketFactory deny=new SocketFactory(){
            public Socket createSocket(String host,int port)throws IOException{sockets.incrementAndGet();throw new IOException("Acceptance snapshot forbids every SSH socket");}
            public InputStream getInputStream(Socket socket)throws IOException{throw new IOException("Acceptance snapshot forbids SSH streams");}
            public OutputStream getOutputStream(Socket socket)throws IOException{throw new IOException("Acceptance snapshot forbids SSH streams");}
        };
        Ssh.socketFactory=deny;
        try{
            KeyStore keys=KeyStore.getInstance("AndroidKeyStore");keys.load(null);
            Map<String,String> aliases=aliases(keys),before=inputs(files,profiles,progress);
            requireCurrent(files,"gateways.enc");
            byte[] cipher=read(new File(files,"gateways.enc"),VaultCipher.MAX_FILE_BYTES),plain=null;
            JSONArray catalog;
            try{plain=VaultCipher.decrypt("gateways.enc",cipher,key(keys,CATALOG_ALIAS));catalog=new JSONArray(new String(plain,StandardCharsets.UTF_8));}
            finally{Arrays.fill(cipher,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
            assertTrue("Export the actual nonempty catalog",catalog.length()>0);
            String primary=f.request.getString("selected_gateway_id");
            JSONObject allowed=f.request.has("allowed_lifecycle")?f.request.getJSONObject("allowed_lifecycle"):null;
            Map<String,List<JSONObject>> nodes=new TreeMap<>();JSONArray pending=new JSONArray(),observedTasks=new JSONArray();AtomicInteger allowedCount=new AtomicInteger();
            for(int i=0;i<catalog.length();i++)walk(catalog.getJSONObject(i),nodes,pending,observedTasks,primary,allowed,true,allowedCount);
            if(allowed!=null)assertEquals("The exact reviewed active entry must occur once",1,allowedCount.get());
            byte[] xml=read(progress,2*1024*1024);reviewProgress(xml,nodes.keySet(),pending,observedTasks);
            JSONArray selected=f.request.getJSONArray("authorized_profile_gateway_ids");
            if(catalogOnly)assertEquals("Catalog-only evidence cannot export VPN profiles",0,selected.length());
            else assertTrue("Select the exact owner profiles to export",selected.length()>0&&selected.length()<=32);
            Set<String> selectedIds=new HashSet<>();Map<String,byte[]> outputs=new LinkedHashMap<>();JSONArray exported=new JSONArray();
            outputs.put("phone-catalog-private.json",utf8(catalog.toString()));outputs.put("phone-deployment-private.xml",xml);
            if(catalogOnly){
                assertEquals("Select a canonical actual owner ID",primary,UUID.fromString(primary).toString());
                List<JSONObject> copies=nodes.get(primary);assertNotNull("Selected owner is absent from the actual catalog",copies);
                JSONObject owner=copies.get(0);for(JSONObject copy:copies)assertEquals("Ambiguous owner records",owner.toString(),copy.toString());
                int topLevel=0;for(int i=0;i<catalog.length();i++)if(primary.equals(catalog.getJSONObject(i).getString("id")))topLevel++;
                assertEquals("Select exactly one existing top-level owner",1,topLevel);
                assertFalse("A client is not a server owner",owner.optBoolean("clientOnly"));
                assertFalse("Delegated access is not a root owner",owner.optBoolean("adminAccess"));
                assertEquals("Catalog-only recovery requires the actual root owner","root",owner.getString("admin"));
                outputs.put("selected-"+primary+"-gateway-private.json",utf8(owner.toString()));
            }
            for(int i=0;i<selected.length();i++){
                String id=selected.getString(i);assertTrue("Select a canonical actual owner ID",UUID.fromString(id).toString().equals(id));
                assertTrue("Duplicate selected profile owner",selectedIds.add(id));List<JSONObject> copies=nodes.get(id);assertNotNull("Selected profile owner is absent from the actual catalog",copies);
                JSONObject owner=copies.get(0);for(JSONObject copy:copies)assertEquals("Ambiguous owner records",owner.toString(),copy.toString());
                assertFalse("Select administrator-owned profiles only",owner.optBoolean("clientOnly"));
                requireCurrent(profiles,id+".enc");byte[] encoded=read(new File(profiles,id+".enc"),1024*1024),decoded=null;
                JSONObject saved;
                try{decoded=ProfileCipher.decrypt(id,encoded,key(keys,PROFILE_ALIAS));saved=new JSONObject(new String(decoded,StandardCharsets.UTF_8));}
                finally{Arrays.fill(encoded,(byte)0);if(decoded!=null)Arrays.fill(decoded,(byte)0);}
                assertEquals("A NativeProfileStore record has exactly its actual saved fields",new HashSet<>(Arrays.asList("protocol","name","content")),fields(saved));
                String protocol=saved.getString("protocol"),expected=owner.optString("pairEntryProtocol",owner.optString("protocol"));
                assertEquals("Selected profile protocol differs from its owner",expected,protocol);
                byte[] content=utf8(saved.getString("content"));assertTrue("The saved profile is empty",content.length>0);
                String prefix="selected-"+id;
                outputs.put(prefix+"-gateway-private.json",utf8(owner.toString()));outputs.put(prefix+"-profile-private.json",utf8(saved.toString()));outputs.put(prefix+"-client-private.conf",content);
                exported.put(new JSONObject().put("gateway_id",id).put("protocol",protocol).put("owner_path",prefix+"-gateway-private.json").put("profile_path",prefix+"-profile-private.json").put("client_path",prefix+"-client-private.conf").put("profile_sha256",PrivateAdministrationFixture.hash(content)).put("ciphertext_sha256",before.get("native/"+id+".enc")));
            }
            if(!catalogOnly)assertTrue("The primary profile must be explicitly authorized",selectedIds.contains(primary));
            byte[] primaryProfile=outputs.get("selected-"+primary+"-client-private.conf");
            Object constructorReceipt=JSONObject.NULL;
            if(f.request.has("constructor_files"))constructorReceipt=constructor(f,files,nodes.get(primary).get(0),primaryProfile,outputs);
            long observed=System.currentTimeMillis()/1000;
            JSONArray ids=new JSONArray();for(String id:nodes.keySet())ids.put(id);
            JSONObject phone=new JSONObject().put("schema",2).put("apk_sha256",f.binary.getString("apk_sha256")).put("test_apk_sha256",f.binary.getString("test_apk_sha256"))
                    .put("catalog_sha256",PrivateAdministrationFixture.hash(outputs.get("phone-catalog-private.json"))).put("constructor_receipt_sha256",constructorReceipt)
                    .put("constructor_profile_sha256",catalogOnly?JSONObject.NULL:PrivateAdministrationFixture.hash(primaryProfile)).put("pending_work_reviewed",true).put("pending_tasks",pending).put("checked_gateway_ids",ids)
                    .put("observed_at",observed).put("deployment_progress_sha256",PrivateAdministrationFixture.hash(xml));
            if(catalogOnly)phone.put("catalog_only",true).put("profile_exported",false).put("constructor_provenance_supplied",false);
            outputs.put("phone-observation-private.json",utf8(phone.toString()));
            idle(f.context);assertSame("The SSH deny policy changed during observation",deny,Ssh.socketFactory);assertEquals("No SSH connection may even be attempted",0,sockets.get());
            assertEquals("Snapshot changed existing ciphertext/progress files",before,inputs(files,profiles,progress));assertEquals("Snapshot changed Keystore aliases",aliases,aliases(keys));
            assertEquals("The reviewed fixture changed during collection",fixtureHash,PrivateAdministrationFixture.hash(read(new File(files,PrivateAdministrationFixture.FILE),2*1024*1024)));
            assertTrue("Snapshot fixture expired during collection",System.currentTimeMillis()<=expires);
            JSONObject hashes=new JSONObject();for(Map.Entry<String,byte[]> item:outputs.entrySet())hashes.put(item.getKey(),PrivateAdministrationFixture.hash(item.getValue()));
            JSONObject receipt=new JSONObject().put("schema",1).put("action","acceptance-snapshot").put("observation_id",observation).put("observed_at",observed).put("binary",new JSONObject(f.binary.toString()))
                    .put("fixture_sha256",fixtureHash).put("source","authenticated-current-phone-storage").put("selected_gateway_id",primary)
                    .put("storage",new JSONObject().put("files",files.getAbsolutePath()).put("native_profiles",profiles.getAbsolutePath()).put("deployment_progress",progress.getAbsolutePath()))
                    .put("exported_profiles",exported).put("file_sha256",hashes).put("input_sha256",new JSONObject(before)).put("keystore_alias_metadata",new JSONObject(aliases))
                    .put("ciphertexts_and_progress_unchanged",true).put("keystore_aliases_unchanged",true).put("ssh_socket_attempts",sockets.get()).put("no_remote_access",true)
                    .put("observed_tasks",observedTasks).put("blocking_or_unexpected_tasks",pending).put("allowed_lifecycle",allowed==null?JSONObject.NULL:allowed)
                    .put("constructor_provenance_supplied",constructorReceipt!=JSONObject.NULL).put("snapshot_is_constructor",false);
            if(catalogOnly)receipt.put("catalog_only",true).put("profile_exported",false).put("selected_gateway_path","selected-"+primary+"-gateway-private.json")
                    .put("selected_profile_sha256",JSONObject.NULL).put("constructor_receipt_sha256",JSONObject.NULL);
            File output=new File(files,"acceptance-snapshot-"+observation);assertFalse("Never reuse an observation directory",Files.exists(output.toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS));Os.mkdir(output.getAbsolutePath(),0700);
            // The final receipt is the commit marker. A partial output directory
            // after failure is preserved and must never be reused or auto-cleaned.
            for(Map.Entry<String,byte[]> item:outputs.entrySet())createPrivate(new File(output,item.getKey()),item.getValue());
            assertEquals(before,inputs(files,profiles,progress));assertEquals(aliases,aliases(keys));idle(f.context);assertSame(deny,Ssh.socketFactory);assertEquals(0,sockets.get());
            createPrivate(new File(output,"acceptance-snapshot-private.json"),utf8(receipt.toString(2)));
            for(byte[] value:outputs.values())Arrays.fill(value,(byte)0);
        }finally{assertSame("Do not silently replace a changed SSH policy",deny,Ssh.socketFactory);Ssh.socketFactory=previous;}
    }

    private static Set<String> fields(JSONObject value){Set<String> keys=new HashSet<>();for(Iterator<String> i=value.keys();i.hasNext();)keys.add(i.next());return keys;}
    private static byte[] utf8(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static boolean empty(Object value){return value==null||value==JSONObject.NULL||value.equals("")||value instanceof JSONObject&&((JSONObject)value).length()==0||value instanceof JSONArray&&((JSONArray)value).length()==0;}
    private static void task(JSONArray pending,String id,String field,Object value)throws Exception{pending.put(new JSONObject().put("gateway_id",id).put("field",field).put("value",value));}
    private static void walk(JSONObject node,Map<String,List<JSONObject>> nodes,JSONArray pending,JSONArray observed,String primary,JSONObject allowed,boolean topLevel,AtomicInteger allowedCount)throws Exception{
        String id=node.getString("id");assertFalse("Catalog owner has no host",node.getString("host").isEmpty());
        nodes.computeIfAbsent(id,k->new ArrayList<>()).add(node);
        for(Iterator<String> keys=node.keys();keys.hasNext();){String key=keys.next();Object value=node.get(key);
            if((PENDING.contains(key)||key.toLowerCase(Locale.ROOT).contains("pending")||key.endsWith("Update")||key.endsWith("Operation")||key.toLowerCase(Locale.ROOT).contains("reset")||key.equals("osReinstall")||key.equals("osReinstallState"))&&!empty(value))task(observed,id,key,value);
            if(key.startsWith("last")&&(key.endsWith("Operation")||key.endsWith("Update"))&&!empty(value)){
                if(!(value instanceof JSONObject)||!TERMINAL.contains(((JSONObject)value).optString("state")))task(pending,id,key,value);
            }else if(key.equals("lifecycleOperation")&&!empty(value)&&allowed!=null&&topLevel&&id.equals(primary)){
                reviewedLifecycle(node,allowed);assertEquals("Only one actual entry operation is authorized",1,allowedCount.incrementAndGet());
            }else if((PENDING.contains(key)||key.toLowerCase(Locale.ROOT).contains("pending")||key.endsWith("Update")||key.endsWith("Operation")||key.toLowerCase(Locale.ROOT).contains("reset"))&&!key.startsWith("last")&&!empty(value))task(pending,id,key,value);
        }
        Object os=node.opt("osReinstall");if(!empty(os)){
            JSONObject job=os instanceof JSONObject?(JSONObject)os:null;
            if(job==null||!node.optString("osReinstallState").equals("complete")||!job.optString("job").matches("[a-f0-9]{32}")||!job.optString("fingerprint").equals(node.optString("fingerprint")))task(pending,id,"osReinstall",os);
        }else if(!node.optString("osReinstallState").isEmpty()&&!node.optString("osReinstallState").equals("complete"))task(pending,id,"osReinstallState",node.get("osReinstallState"));
        if(node.has("pairExit")&&!node.isNull("pairExit"))walk(node.getJSONObject("pairExit"),nodes,pending,observed,primary,allowed,false,allowedCount);
    }
    private static void reviewedLifecycle(JSONObject owner,JSONObject allowed)throws Exception{
        assertEquals(new HashSet<>(Arrays.asList("operation","deployment","state","expected_revision","new_exit")),fields(allowed));
        assertTrue(allowed.getString("operation").matches("[a-f0-9]{32}"));assertTrue(allowed.getString("deployment").matches("[a-f0-9]{32}"));assertEquals("active",allowed.getString("state"));
        Object revision=allowed.get("expected_revision");assertTrue("Use the actual integral revision",revision instanceof Integer||revision instanceof Long);assertTrue(allowed.getLong("expected_revision")>=0);
        JSONObject operation=owner.getJSONObject("lifecycleOperation"),candidate=operation.getJSONObject("candidate"),request=operation.getJSONObject("request"),exit=owner.getJSONObject("pairExit");
        assertFalse("Actual signed18 does not persist top-level new_exit",operation.has("new_exit"));
        for(String field:new String[]{"operation","deployment","state","expected_revision"})assertEquals("The actual operation differs from the reviewed phase",allowed.get(field),operation.get(field));
        assertEquals(allowed.getString("deployment"),owner.getString("pairId"));assertEquals(allowed.getLong("expected_revision")+1,owner.getLong("deploymentRevision"));
        assertEquals("prepare-exit",request.getString("action"));for(String field:new String[]{"operation","deployment","expected_revision"})assertEquals(allowed.get(field),request.get(field));
        assertEquals(allowed.getString("new_exit"),candidate.getString("host"));assertEquals(candidate.getString("host"),request.getString("exit_host"));
        for(String field:new String[]{"id","host","fingerprint","machine"})assertEquals("Actual current exit differs from the staged candidate",candidate.get(field),exit.get(field));
        assertEquals(new Gateway(candidate).port(),new Gateway(exit).port());
    }
    private static void reviewProgress(byte[] xml,Set<String> ids,JSONArray pending,JSONArray observed)throws Exception{
        XmlPullParser parser=android.util.Xml.newPullParser();parser.setInput(new ByteArrayInputStream(xml),"UTF-8");assertEquals(XmlPullParser.START_TAG,parser.nextTag());assertEquals("map",parser.getName());assertEquals(0,parser.getAttributeCount());boolean seen=false;
        while(parser.nextTag()==XmlPullParser.START_TAG){assertFalse("Duplicate progress record",seen);seen=true;assertEquals("string",parser.getName());assertEquals(1,parser.getAttributeCount());assertEquals("name",parser.getAttributeName(0));assertEquals("progress",parser.getAttributeValue(0));JSONObject progress=new JSONObject(parser.nextText());
            if(progress.length()>0)task(observed,progress.optString("gateway"),"deployment_progress",progress);
            Set<String> kinds=new HashSet<>(Arrays.asList("single","pair","enroll","protocol","filter","engine-update","lifecycle-entry","lifecycle-exit","helper-update","paired-os","paired-restore","os"));
            if(progress.length()>0&&(!progress.optString("state").equals("complete")||!ids.contains(progress.optString("gateway"))||!kinds.contains(progress.optString("kind"))||!(progress.opt("started") instanceof Number)||!(progress.opt("finished") instanceof Number)||progress.optLong("started")<=0||progress.optLong("finished")<progress.optLong("started")))task(pending,progress.optString("gateway"),"deployment_progress",progress);
        }
        assertEquals("map",parser.getName());int tail=parser.next();while(tail==XmlPullParser.TEXT&&parser.isWhitespace())tail=parser.next();assertEquals(XmlPullParser.END_DOCUMENT,tail);
    }
    @SuppressWarnings("deprecation") private static void idle(Context context){
        assertNull("A DeploymentService coordinator exists",DeploymentService.current());assertFalse(DeploymentService.active());assertFalse(DeploymentService.needsLocalSave());
        ActivityManager manager=(ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);assertNotNull(manager);
        for(ActivityManager.RunningServiceInfo service:manager.getRunningServices(Integer.MAX_VALUE))assertNotEquals("DeploymentService is still running",DeploymentService.class.getName(),service.service.getClassName());
    }
    private static SecretKey key(KeyStore keys,String alias)throws Exception{assertTrue("Required existing phone key is unavailable",keys.containsAlias(alias));SecretKey key=(SecretKey)keys.getKey(alias,null);assertNotNull(key);return key;}
    private static Map<String,String> aliases(KeyStore keys)throws Exception{Map<String,String> result=new TreeMap<>();for(String alias:Collections.list(keys.aliases())){Date date=keys.getCreationDate(alias);java.security.cert.Certificate cert=keys.getCertificate(alias);result.put(alias,(date==null?"unknown":Long.toString(date.getTime()))+":"+(cert==null?"secret-key":PrivateAdministrationFixture.hash(cert.getEncoded())));}return result;}
    private static void secureDirectory(File path)throws Exception{StructStat s=Os.lstat(path.getAbsolutePath());assertTrue("Input directory must be app-owned and not a link",OsConstants.S_ISDIR(s.st_mode)&&s.st_uid==android.os.Process.myUid());}
    private static byte[] read(File file,int max)throws Exception{
        StructStat before=Os.lstat(file.getAbsolutePath());assertTrue("Input must be a bounded app-owned regular nonlinked file",OsConstants.S_ISREG(before.st_mode)&&before.st_uid==android.os.Process.myUid()&&before.st_nlink==1&&before.st_size>=0&&before.st_size<=max);
        java.io.FileDescriptor fd=Os.open(file.getAbsolutePath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW,0);
        try(FileInputStream in=new FileInputStream(fd);ByteArrayOutputStream out=new ByteArrayOutputStream()){
            StructStat opened=Os.fstat(fd);assertEquals(before.st_dev,opened.st_dev);assertEquals(before.st_ino,opened.st_ino);byte[] buffer=new byte[8192];int count;
            while((count=in.read(buffer))!=-1){out.write(buffer,0,count);assertTrue("Input grew during bounded read",out.size()<=max);}byte[] value=out.toByteArray();assertEquals(before.st_size,value.length);return value;
        }
    }
    private static void requireCurrent(File parent,String name){assertFalse("Do not recover or select an AtomicFile backup",Files.exists(new File(parent,name+".bak").toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS));assertFalse("An AtomicFile write is unfinished",Files.exists(new File(parent,name+".new").toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS));}
    private static Map<String,String> inputs(File files,File profiles,File progress)throws Exception{
        secureDirectory(files);secureDirectory(profiles);secureDirectory(progress.getParentFile());Map<String,String> result=new TreeMap<>();
        for(String name:new String[]{"gateways.enc","ssh-identities.enc"})for(String suffix:new String[]{"",".bak",".new"}){File file=new File(files,name+suffix);if(Files.exists(file.toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS))result.put(name+suffix,PrivateAdministrationFixture.hash(read(file,VaultCipher.MAX_FILE_BYTES)));}
        File[] nativeFiles=profiles.listFiles();assertNotNull(nativeFiles);for(File file:nativeFiles)result.put("native/"+file.getName(),PrivateAdministrationFixture.hash(read(file,1024*1024)));
        requireCurrent(progress.getParentFile(),progress.getName());result.put("deployment_progress",PrivateAdministrationFixture.hash(read(progress,2*1024*1024)));return result;
    }
    private static void createPrivate(File file,byte[] bytes)throws Exception{
        java.io.FileDescriptor fd=Os.open(file.getAbsolutePath(),OsConstants.O_CREAT|OsConstants.O_EXCL|OsConstants.O_WRONLY|OsConstants.O_NOFOLLOW,0600);
        try(FileOutputStream out=new FileOutputStream(fd)){out.write(bytes);out.getFD().sync();StructStat s=Os.fstat(fd);assertEquals(0600,s.st_mode&0777);assertEquals(android.os.Process.myUid(),s.st_uid);assertEquals(1,s.st_nlink);}
    }
    private static String constructor(PrivateAdministrationFixture f,File files,JSONObject owner,byte[] content,Map<String,byte[]> outputs)throws Exception{
        JSONObject bindings=f.request.getJSONObject("constructor_files");assertEquals(new HashSet<>(Arrays.asList("pair","receipt","client")),fields(bindings));Map<String,byte[]> actual=new HashMap<>();
        for(String kind:new String[]{"pair","receipt","client"}){JSONObject binding=bindings.getJSONObject(kind);assertEquals(new HashSet<>(Arrays.asList("path","sha256")),fields(binding));String name=binding.getString("path");assertTrue("Use an explicitly reviewed direct-child constructor file",name.matches("[a-zA-Z0-9_-]+\\.(json|conf)"));byte[] value=read(new File(files,name),2*1024*1024);assertEquals(binding.getString("sha256"),PrivateAdministrationFixture.hash(value));actual.put(kind,value);}
        JSONObject pair=new JSONObject(new String(actual.get("pair"),StandardCharsets.UTF_8)),receipt=new JSONObject(new String(actual.get("receipt"),StandardCharsets.UTF_8));
        assertEquals(2,receipt.getInt("schema"));assertEquals("actual-signed18-constructor",receipt.getString("source"));assertEquals(f.binary.getString("apk_sha256"),receipt.getString("apk_sha256"));assertEquals(f.binary.getString("test_apk_sha256"),receipt.getString("test_apk_sha256"));
        for(String field:new String[]{"id","host","fingerprint","machine","pairId","pairEntryProtocol","pairExitProtocol"})assertEquals("Constructor owner differs from the actual selected account",owner.get(field),pair.get(field));
        assertEquals(owner.getString("id"),receipt.getString("gateway_id"));assertEquals(owner.getString("pairId"),receipt.getString("deployment"));assertEquals(PrivateAdministrationFixture.hash(actual.get("pair")),receipt.getString("pair_sha256"));assertEquals(PrivateAdministrationFixture.hash(content),receipt.getString("profile_sha256"));assertArrayEquals("Current saved profile differs from the original constructor bytes",content,actual.get("client"));
        outputs.put("constructor-pair-private.json",actual.get("pair"));outputs.put("constructor-receipt-private.json",actual.get("receipt"));outputs.put("constructor-client-private.conf",actual.get("client"));return PrivateAdministrationFixture.hash(actual.get("receipt"));
    }
}
