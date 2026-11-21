package org.strongswan.android.rookstride;

import org.json.*;
import org.junit.Test;
import java.io.IOException;
import java.util.*;
import static org.junit.Assert.*;

/** Failure-boundary contracts; the Android adapter/Keystore remain separate device tests. */
public class ConnectionBundleImportTest {
    interface Checked{void run()throws Exception;}
    private void rejects(Checked action)throws Exception{try{action.run();fail("Failed import was reported successful");}catch(IOException expected){assertNotNull(expected.getMessage());}}
    private JSONObject entry(String user)throws Exception{return new JSONObject().put("format","ikev2").put("name","rookstride-"+user+".sswan").put("display_name",user+"’s VPN").put("content",PasswordSignIn.withKnownPassword(PasswordSignIn.definition("ikev2","vpn.example.net",user,"chosen-"+user,""),user,"chosen-"+user).toString());}
    private String bundle()throws Exception{return ConnectionBundle.pack(Arrays.asList(entry("mina"),entry("navid")));}
    private static Gateway copy(Gateway value)throws Exception{return new Gateway(new JSONObject(value.persisted().toString()));}
    private static final class Crash extends Error{}
    private static final class FakeStore implements ConnectionBundleImport.Store {
        ArrayList<Gateway> catalog=new ArrayList<>();Map<String,String> profiles=new HashMap<>();JSONObject journal;int stages,commits,writes,cleans,finishes;int failBeforeStage,failAfterStage,crashAfterStage;boolean failCommitBefore,failCommitAfter,failCatalog,failCatalogAfterStage,failClear,failCleanup,failFinish;Gateway lateWriter;
        @Override public ArrayList<Gateway> catalog()throws Exception{if(failCatalog)throw new IOException("Catalog cannot be decrypted");ArrayList<Gateway> result=new ArrayList<>();for(Gateway node:catalog)result.add(copy(node));return result;}
        @Override public boolean matches(Gateway node,JSONObject profile)throws Exception{return profile.getString("content").equals(profiles.get(node.get("id")));}
        @Override public ConnectionBundleImport.Asset describe(Gateway node,JSONObject profile)throws Exception{return new ConnectionBundleImport.Asset(node.get("id"),node.get("protocol"),"","",false,node.get("bundleImportId"));}
        @Override public void stage(Gateway node,JSONObject profile,ConnectionBundleImport.Asset asset)throws Exception{stages++;if(stages==failBeforeStage)throw new IOException("Injected pre-write failure");assertNotNull(journal);profiles.put(asset.id,profile.getString("content"));if(failCatalogAfterStage)failCatalog=true;if(stages==crashAfterStage)throw new Crash();if(stages==failAfterStage)throw new IOException("Injected post-write failure");}
        @Override public ArrayList<Gateway> append(List<Gateway> nodes)throws Exception{commits++;if(failCommitBefore)throw new IOException("Injected commit failure");if(lateWriter!=null)catalog.add(copy(lateWriter));for(Gateway node:nodes)catalog.add(copy(node));if(failCommitAfter)throw new IOException("Lost reply after durable commit");return catalog();}
        @Override public JSONObject journal()throws Exception{return journal==null?null:new JSONObject(journal.toString());}
        @Override public void journal(JSONObject value)throws Exception{writes++;journal=new JSONObject(value.toString());}
        @Override public void clearJournal()throws Exception{if(failClear)throw new IOException("Injected journal cleanup failure");journal=null;}
        @Override public void cleanup(ConnectionBundleImport.Asset asset,List<Gateway> references)throws Exception{for(Gateway node:references)if(asset.id.equals(node.get("id"))||asset.id.equals(node.get("profileUuid")))return;cleans++;if(failCleanup)throw new IOException("Injected cleanup failure");profiles.remove(asset.id);}
        @Override public void finishCleanup(List<ConnectionBundleImport.Asset> assets,List<Gateway> references)throws Exception{finishes++;for(ConnectionBundleImport.Asset asset:assets){boolean referenced=false;for(Gateway node:references)if(asset.id.equals(node.get("id")))referenced=true;assertTrue("Final certificate cleanup ran before profile cleanup",referenced||!profiles.containsKey(asset.id));}if(failFinish)throw new IOException("Injected final cleanup failure");}
        void seed(Gateway node,JSONObject entry)throws Exception{catalog.add(copy(node));profiles.put(node.get("id"),entry.getString("content"));}
    }
    private Gateway unrelated()throws Exception{Gateway node=new Gateway();node.set("host","other.example.net");node.set("name","Unrelated owner");node.data.put("remember",true);node.sshPassword="unrelated SSH secret";node.privateKey="unrelated key";return node;}

    @Test public void previewHasReadableMetadataAndNoStorageOrAuthorityEffects()throws Exception {
        FakeStore store=new FakeStore();ConnectionBundleImport.Preview p=ConnectionBundleImport.preview(store,bundle());assertEquals(2,p.toAdd);assertEquals(0,p.existing);assertEquals("mina",p.connections.get(0).account);assertEquals("vpn.example.net",p.connections.get(0).server);assertEquals("mina’s VPN",p.connections.get(0).displayName);assertEquals(0,store.stages);assertEquals(0,store.writes);assertTrue(store.catalog.isEmpty());
        try{p.connections.clear();fail("Preview summaries were mutable");}catch(UnsupportedOperationException expected){}
    }
    @Test public void invalidFinalEntryCannotWriteEvenARecoveryJournal()throws Exception {
        FakeStore store=new FakeStore();JSONObject bad=entry("navid").put("content","not a profile");String raw=new JSONObject().put("schema",1).put("kind",ConnectionBundle.KIND).put("connections",new JSONArray().put(entry("mina")).put(bad)).toString();rejects(()->ConnectionBundleImport.preview(store,raw));assertEquals(0,store.writes);assertEquals(0,store.stages);assertTrue(store.profiles.isEmpty());
    }
    @Test public void oneAppendPreservesAnUnrelatedConcurrentWriterAndProducesOnlyFreshClients()throws Exception {
        FakeStore store=new FakeStore();Gateway owner=unrelated();store.seed(owner,entry("other"));String unchanged=owner.persisted().toString();store.lateWriter=unrelated();ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));
        assertEquals(2,result.added);assertEquals(4,result.catalog.size());assertEquals(1,store.commits);assertEquals(unchanged,result.catalog.get(0).persisted().toString());assertNull(store.journal);
        for(int i=2;i<result.catalog.size();i++){Gateway node=result.catalog.get(i);assertTrue(node.data.getBoolean("clientOnly"));assertEquals(node.get("id"),node.get("profileUuid"));assertFalse(node.isPair());assertEquals("",node.sshPassword);assertEquals("",node.privateKey);assertFalse(node.remember());assertFalse(node.data.has("adminAccess"));assertTrue(node.vpnPassword.startsWith("chosen-"));}
    }
    @Test public void chosenIncomingUuidCannotOverwriteAnExistingOwnerProfile()throws Exception {
        FakeStore store=new FakeStore();Gateway owner=unrelated();JSONObject p=entry("mina"),content=new JSONObject(p.getString("content")).put("uuid",owner.get("id"));p.put("content",content.toString());store.seed(owner,p);ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,ConnectionBundle.pack(Collections.singletonList(p))));assertEquals(2,result.catalog.size());assertNotEquals(owner.get("id"),result.catalog.get(1).get("profileUuid"));assertEquals(content.toString(),store.profiles.get(owner.get("id")));
    }
    @Test public void failuresBeforeAndAfterEachAssetWriteRollBackOnlyNewData()throws Exception {
        for(boolean after:new boolean[]{false,true})for(int boundary=1;boundary<=2;boundary++){FakeStore store=new FakeStore();Gateway owner=unrelated();store.seed(owner,entry("other"));String original=store.profiles.get(owner.get("id"));if(after)store.failAfterStage=boundary;else store.failBeforeStage=boundary;rejects(()->ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle())));assertEquals(1,store.catalog.size());assertEquals(1,store.profiles.size());assertEquals(original,store.profiles.get(owner.get("id")));assertNull(store.journal);assertEquals(0,store.commits);}
    }
    @Test public void failedCatalogCommitCleansAllStagedAssetsAndKeepsTheOriginalCatalog()throws Exception {
        FakeStore store=new FakeStore();Gateway owner=unrelated();store.seed(owner,entry("other"));store.failCommitBefore=true;rejects(()->ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle())));assertEquals(1,store.catalog.size());assertEquals(1,store.profiles.size());assertEquals(1,store.commits);assertNull(store.journal);
    }
    @Test public void lostReplyAfterCommitRetainsConnectionsAndNeverReplaysTheInsertion()throws Exception {
        FakeStore store=new FakeStore();store.failCommitAfter=true;ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));assertEquals(2,result.added);assertEquals(2,result.catalog.size());assertEquals(2,store.profiles.size());assertEquals(1,store.commits);assertNull(store.journal);assertEquals(0,store.cleans);
    }
    @Test public void crashBeforeCommitLeavesOnlyIdentifiersAndRestartCleansUncommittedAssets()throws Exception {
        FakeStore store=new FakeStore();store.crashAfterStage=1;try{ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));fail("Crash was swallowed");}catch(Crash expected){}
        assertNotNull(store.journal);assertEquals(1,store.profiles.size());assertFalse(store.journal.toString().contains("chosen-"));assertFalse(store.journal.toString().contains("vpn.example.net"));assertFalse(store.journal.toString().contains("mina"));assertFalse(store.journal.toString().contains("sshPassword"));ConnectionBundleImport.recover(store);assertTrue(store.catalog.isEmpty());assertTrue(store.profiles.isEmpty());assertNull(store.journal);
    }
    @Test public void postCommitJournalCleanupCanFinishOnRestartWithoutDeletingAccess()throws Exception {
        FakeStore store=new FakeStore();store.failClear=true;ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));assertTrue(result.cleanupPending);assertNotNull(store.journal);store.failClear=false;ConnectionBundleImport.recover(store);assertEquals(2,store.catalog.size());assertEquals(2,store.profiles.size());assertNull(store.journal);assertEquals(1,store.commits);
    }
    @Test public void uncertainCatalogReadNeverTriggersDeletionOrFreshImport()throws Exception {
        FakeStore store=new FakeStore();store.failCatalogAfterStage=true;store.failAfterStage=1;rejects(()->ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle())));assertNotNull(store.journal);assertEquals(1,store.profiles.size());assertEquals(0,store.cleans);store.failCatalog=false;rejects(()->ConnectionBundleImport.preview(store,bundle()));ConnectionBundleImport.recover(store);assertTrue(store.profiles.isEmpty());assertNull(store.journal);
    }
    @Test public void interruptedCleanupKeepsTheJournalAndCanBeRepeatedWithoutInsertion()throws Exception {
        FakeStore store=new FakeStore();store.failAfterStage=1;store.failCleanup=true;rejects(()->ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle())));assertNotNull(store.journal);store.failCleanup=false;ConnectionBundleImport.recover(store);assertTrue(store.profiles.isEmpty());assertNull(store.journal);assertEquals(0,store.commits);ConnectionBundleImport.recover(store);
    }
    @Test public void reimportSkipsOnlyVerifiedExactClientAccessAndDoesNotRewriteIt()throws Exception {
        FakeStore store=new FakeStore();ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));int writes=store.writes,stages=store.stages;ConnectionBundleImport.Preview preview=ConnectionBundleImport.preview(store,bundle());assertEquals(0,preview.toAdd);assertEquals(2,preview.existing);ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,preview);assertEquals(0,result.added);assertEquals(2,result.existing);assertEquals(writes,store.writes);assertEquals(stages,store.stages);assertEquals(1,store.commits);
    }
    @Test public void matchingOwnerAndChangedClientAreNeverSilentlyReusedOrOverwritten()throws Exception {
        for(boolean owner:new boolean[]{true,false}){FakeStore store=new FakeStore();JSONObject entry=entry("mina");Gateway original=ConnectionBundleImport.client(entry,UUID.randomUUID().toString());if(owner)original.data.put("clientOnly",false);store.seed(original,entry);if(!owner)store.profiles.put(original.get("id"),"locally edited connection");String preserved=store.profiles.get(original.get("id"));ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,ConnectionBundle.pack(Collections.singletonList(entry))));assertEquals(1,result.added);assertEquals(2,result.catalog.size());assertEquals(preserved,store.profiles.get(original.get("id")));}
    }
    @Test public void hostileRecoveryIdentifiersFailBeforeAnyCleanup()throws Exception {
        FakeStore store=new FakeStore();store.crashAfterStage=1;try{ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));}catch(Crash expected){}store.journal.getJSONArray("assets").getJSONObject(0).put("id","../../an-owner-profile");rejects(()->ConnectionBundleImport.recover(store));assertEquals(0,store.cleans);assertNotNull(store.journal);assertEquals(1,store.profiles.size());
    }
    @Test public void identitiesAcquiredAfterPreviewAreRecheckedBeforeStaging()throws Exception {
        FakeStore store=new FakeStore();String text=ConnectionBundle.pack(Collections.singletonList(entry("mina")));ConnectionBundleImport.Preview first=ConnectionBundleImport.preview(store,text);ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,text));ConnectionBundleImport.Result replay=ConnectionBundleImport.apply(store,first);assertEquals(0,replay.added);assertEquals(1,replay.existing);assertEquals(1,store.commits);
    }
    @Test public void finalCleanupFailureKeepsCommittedAccessAndItsRecoveryJournal()throws Exception {
        FakeStore store=new FakeStore();store.failFinish=true;ConnectionBundleImport.Result result=ConnectionBundleImport.apply(store,ConnectionBundleImport.preview(store,bundle()));assertTrue(result.cleanupPending);assertNotNull(store.journal);assertEquals(2,store.profiles.size());store.failFinish=false;ConnectionBundleImport.recover(store);assertEquals(2,store.profiles.size());assertNull(store.journal);assertEquals(1,store.commits);
    }
    @Test public void nativeMetadataNeverUsesPrivateAccessMaterialAsTheDisplayAccount()throws Exception {
        String id="b74ab96c-a1db-4f4a-b10c-a784c92c5c21",uri="vless://"+id+"@vpn.example.net:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=www.example.net&sid=abcd";
        ConnectionBundleImport.Summary summary=ConnectionBundleImport.inspectMetadata("xray",uri);assertEquals("vpn.example.net",summary.server);assertEquals("Link access",summary.account);assertFalse(summary.displayName.contains(id));assertFalse(summary.displayName.contains("AAAAAAAA"));
        rejects(()->ConnectionBundleImport.inspectMetadata("unknown",uri));
    }
    private String metadataRoots()throws Exception{try(java.io.InputStream in=getClass().getResourceAsStream("/password-test-root.txt");java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream()){byte[] bytes=new byte[4096];for(int n;(n=in.read(bytes))!=-1;)out.write(bytes,0,n);return new String(out.toByteArray(),java.nio.charset.StandardCharsets.US_ASCII);}}
    private Gateway metadataClient(String protocol)throws Exception{Gateway node=new Gateway();node.set("protocol",protocol);node.set("name",SingleProtocols.from(protocol).title);node.data.put("clientOnly",true);return node;}
    private String metadataOpenVpn()throws Exception{return PasswordSignIn.definition("openvpn","vpn.example.net:1194","1","chosen secret",metadataRoots()).getString("config");}
    @Test public void nativeMetadataCoversEveryNativeMethodWithoutRevealingAccessKeys()throws Exception{
        Map<String,String> profiles=new LinkedHashMap<>();byte[] a=new byte[32],b=new byte[32];Arrays.fill(a,(byte)1);Arrays.fill(b,(byte)2);
        profiles.put("awg","[Interface]\nPrivateKey = "+Base64.getEncoder().encodeToString(a)+"\nAddress = 10.80.0.2/32\n[Peer]\nPublicKey = "+Base64.getEncoder().encodeToString(b)+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.net:51821\n");
        String link="vless://b74ab96c-a1db-4f4a-b10c-a784c92c5c21@vpn.example.net:8443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=www.example.net&sid=abcd";profiles.put("xray",link);profiles.put("xhttp",link.replace("type=tcp","type=xhttp&path=%2F"+String.join("",Collections.nCopies(48,"a"))+"&mode=auto"));
        for(String protocol:new String[]{"openvpn","hysteria2","trusttunnel","naive"})profiles.put(protocol,PasswordSignIn.definition(protocol,"vpn.example.net:8443","1","chosen secret",metadataRoots()).toString());
        for(String protocol:new String[]{"outline","shadowsocks"})profiles.put(protocol,new JSONObject().put("schema",1).put("protocol",protocol).put("server","vpn.example.net").put("port",9443).put("server_name","vpn.example.net").put("login","family").put("password","example-secret").put("certificate",metadataRoots()).put("method","chacha20-ietf-poly1305").put("path","/"+String.join("",Collections.nCopies(48,"a"))).toString());
        assertEquals(9,profiles.size());for(Map.Entry<String,String> entry:profiles.entrySet()){String original=entry.getValue();ConnectionBundleImport.Summary summary=ConnectionBundleImport.inspectMetadata(entry.getKey(),original);assertEquals("vpn.example.net",summary.server);assertEquals(entry.getKey().equals("awg")?51821:entry.getKey().equals("outline")||entry.getKey().equals("shadowsocks")?9443:8443,summary.port);assertFalse(summary.displayName.contains("chosen secret"));assertFalse(summary.displayName.contains("example-secret"));assertEquals(original,entry.getValue());}
        ConnectionBundleImport.Summary raw=ConnectionBundleImport.inspectMetadata("openvpn",metadataOpenVpn());assertEquals("vpn.example.net",raw.server);assertEquals(1194,raw.port);assertEquals("",raw.login);
    }
    @Test public void legacyImportedMetadataFillsMissingFieldsOnceAndPreservesProfileAndCredentials()throws Exception{
        Gateway node=metadataClient("openvpn");node.vpnPassword="existing phone secret";String id=node.get("id"),name=node.get("name"),config=metadataOpenVpn(),wrapped=PasswordSignIn.openVpn(config,"1","chosen secret").toString();
        assertTrue(ConnectionBundleImport.needsNativeMetadata(node));assertTrue(ConnectionBundleImport.populateNativeMetadata(node,wrapped));assertEquals("vpn.example.net",node.get("host"));assertEquals(1194,node.data.getInt("vpnPort"));assertEquals("1",node.get("vpnLogin"));assertEquals(id,node.get("id"));assertEquals(name,node.get("name"));assertEquals("existing phone secret",node.vpnPassword);assertEquals("",node.sshPassword);assertFalse(node.data.has("adminAccess"));assertFalse(ConnectionBundleImport.needsNativeMetadata(node));String before=node.persisted().toString();assertFalse(ConnectionBundleImport.populateNativeMetadata(node,wrapped));assertEquals(before,node.persisted().toString());assertEquals(config,new JSONObject(wrapped).getString("config"));assertEquals("chosen secret",new JSONObject(wrapped).getString("password"));
    }
    @Test public void metadataRepairNeverTouchesOwnersAdministratorsPairsOrIkeProfiles()throws Exception{
        Gateway owner=unrelated(),administrator=metadataClient("openvpn"),pair=metadataClient("openvpn"),ike=metadataClient("ikev2");administrator.data.put("adminAccess",true);pair.exit=new Gateway();
        for(Gateway node:Arrays.asList(owner,administrator,pair,ike)){String before=node.persisted().toString();assertFalse(ConnectionBundleImport.needsNativeMetadata(node));assertFalse(ConnectionBundleImport.populateNativeMetadata(node,"not a profile"));assertEquals(before,node.persisted().toString());}
    }
    @Test public void malformedMetadataIsAtomicAndKnownDisplayFieldsAreNeverOverwritten()throws Exception{
        Gateway missing=metadataClient("openvpn");String before=missing.persisted().toString();rejects(()->ConnectionBundleImport.populateNativeMetadata(missing,"not a profile"));assertEquals(before,missing.persisted().toString());assertTrue(ConnectionBundleImport.needsNativeMetadata(missing));
        Gateway named=metadataClient("openvpn");named.set("name","Mina’s personal VPN");named.set("host","kept.example.net");named.set("vpnLogin","kept-user");named.data.put("vpnPort",8443);assertFalse(ConnectionBundleImport.needsNativeMetadata(named));ConnectionBundleImport.populateNativeMetadata(named,PasswordSignIn.openVpn(metadataOpenVpn(),"1","chosen secret").toString());assertEquals("Mina’s personal VPN",named.get("name"));assertEquals("kept.example.net",named.get("host"));assertEquals("kept-user",named.get("vpnLogin"));assertEquals(8443,named.data.getInt("vpnPort"));
    }

}
