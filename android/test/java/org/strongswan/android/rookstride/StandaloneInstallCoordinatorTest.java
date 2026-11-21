package org.strongswan.android.rookstride;

import java.io.IOException;
import java.util.*;
import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;

/** Exercises the actual Service loop with real private-request persistence.
 * RPC replies and acknowledged catalog writes are local seams, not SSH/Android. */
public final class StandaloneInstallCoordinatorTest {
    private interface Checked {void run()throws Exception;}
    private static void rejects(Checked action)throws Exception{try{action.run();fail("The failed boundary was accepted");}catch(IOException expected){assertNotNull(expected.getMessage());}}
    private static String repeat(char value,int length){char[] chars=new char[length];Arrays.fill(chars,value);return new String(chars);}
    private static String job(char value){return repeat(value,32);}
    private static final class Memory implements StandaloneInstallRetry.Store {
        ArrayList<Gateway> values=new ArrayList<>();boolean failBefore,failAfter;int writes;
        public ArrayList<Gateway> read()throws Exception{ArrayList<Gateway> copy=new ArrayList<>();for(Gateway g:values)copy.add(new Gateway(new JSONObject(g.persisted().toString())));return copy;}
        public void write(ArrayList<Gateway> next)throws Exception{writes++;if(failBefore)throw new IOException("Private write unavailable");values=new ArrayList<>();for(Gateway g:next)values.add(new Gateway(new JSONObject(g.persisted().toString())));if(failAfter)throw new IOException("Private acknowledgement lost");}
        String snapshot()throws Exception{JSONArray a=new JSONArray();for(Gateway g:values)a.put(g.persisted());return a.toString();}
    }
    private static final class Journey implements StandaloneInstallCoordinator.Local,StandaloneInstallCoordinator.Rpc,StandaloneInstallCoordinator.Await {
        final Memory store=new Memory();final Gateway node=new Gateway();final List<JSONObject> calls=new ArrayList<>();
        final Map<String,JSONObject> remoteStarts=new HashMap<>(),remoteRetries=new HashMap<>();
        String catalogJob="",state="complete";int catalogAcks,awaits,workers,progress;boolean loseStartReply,loseRetryReply,failCatalogMarker,failCatalogJob,failPrivateAck,runningFirst,failChild;
        Journey()throws Exception{node.set("host","vpn.example.net");node.set("protocol","openvpn");node.set("fingerprint","SHA256:"+repeat('A',43));node.set("machine",repeat('b',64));}
        JSONObject original()throws Exception{return new JSONObject().put("action","start").put("protocol","openvpn").put("server",node.get("host")).put("port",1194).put("login","1").put("password","1").put("access_mode","password");}
        public boolean has()throws Exception{return !store.values.isEmpty();}
        public String recordedJob()throws Exception{return store.values.isEmpty()?"":store.read().get(0).get("job");}
        public JSONObject startRequest(JSONObject original)throws Exception{return StandaloneInstallRetry.startRequest(store,node,original);}
        public void rememberJob(JSONObject response)throws Exception{if(failPrivateAck){failPrivateAck=false;store.failAfter=true;try{StandaloneInstallRetry.rememberJob(store,node,response);}finally{store.failAfter=false;}}else StandaloneInstallRetry.rememberJob(store,node,response);}
        public JSONObject retryRequest(JSONObject failure)throws Exception{return StandaloneInstallRetry.retryRequest(store,node,failure);}
        public void saveJob(JSONObject response,boolean port)throws Exception{
            if(response==null&&failCatalogMarker){failCatalogMarker=false;throw new IOException("Catalog marker acknowledgement failed");}
            if(response!=null&&failCatalogJob){failCatalogJob=false;throw new IOException("Catalog job acknowledgement failed");}
            catalogAcks++;if(response!=null)catalogJob=response.getString("job");
        }
        public void progress(JSONObject status){progress++;}
        public void next(){awaits++;}
        JSONObject response(String id)throws Exception{
            JSONObject c=new JSONObject().put("schema",1).put("owner",node.get("id")).put("task",store.values.get(0).get("task")).put("request_digest",StandaloneInstallRetry.digest(original())).put("config_digest",repeat('c',64)).put("machine",node.get("machine")).put("source",repeat('d',64)).put("instance",repeat('e',32)).put("port",1194);
            return new JSONObject().put("job",id).put("plan",new JSONObject().put("port",1194)).put("bundle",c.getString("source")).put("install_context",c);
        }
        JSONObject failed(String id)throws Exception{
            JSONObject c=new JSONObject(store.values.get(0).data.getJSONObject("context").toString()).put("reason","acquisition-unavailable");
            return new JSONObject().put("job",id).put("state","failed").put("phase","Public acquisition unavailable").put("retryable",c).put("failed_receipt_sha256",repeat(id.equals(job('1'))?'f':'a',64));
        }
        public JSONObject request(JSONObject request,boolean bundled)throws Exception{
            calls.add(new JSONObject(request.toString()));String action=request.getString("action");
            if(action.equals("start")){
                assertTrue("A start must have its durable private request before any RPC",has());assertTrue("A catalog acknowledgement must precede a mutating RPC",catalogAcks>0);assertTrue(bundled);JSONObject saved=StandaloneInstallRetry.startRequest(store,node,new JSONObject());assertEquals(saved.toString(),request.toString());
                String task=request.getJSONObject("install_context").getString("task");JSONObject reply=remoteStarts.get(task);if(reply==null){reply=response(job('1'));remoteStarts.put(task,reply);workers++;}if(loseStartReply){loseStartReply=false;throw new IOException("First start reply lost");}return new JSONObject(reply.toString());
            }
            if(action.equals("retry")){
                assertTrue(bundled);JSONObject pending=store.values.get(0).data.getJSONObject("claim");assertEquals("The nonce must already be durable at RPC time",pending.getString("nonce"),request.getString("nonce"));assertEquals("Chosen secret must come from the original private request","1",request.getJSONObject("request").getString("password"));
                String key=request.getString("job")+":"+request.getString("nonce");JSONObject reply=remoteRetries.get(key);if(reply==null){reply=response(job('2')).put("retry_of",request.getString("job")).put("nonce",request.getString("nonce"));remoteRetries.put(key,reply);workers++;}if(loseRetryReply){loseRetryReply=false;throw new IOException("Linked retry reply lost");}return new JSONObject(reply.toString());
            }
            assertEquals("job",action);assertFalse("Polling must not upload/restart the installer",bundled);String id=request.getString("job");
            if(runningFirst){runningFirst=false;return new JSONObject().put("job",id).put("state","running");}
            if(state.equals("failed")&&(id.equals(job('1'))||failChild))return failed(id);
            return new JSONObject().put("job",id).put("state",state.equals("failed")?"complete":state);
        }
        JSONObject run(JSONObject config,boolean resume,boolean bound)throws Exception{return StandaloneInstallCoordinator.run(catalogJob,config,resume,bound,this,this,this);}
        long count(String action){return calls.stream().filter(c->c.optString("action").equals(action)).count();}
        void firstFailed()throws Exception{state="failed";rejects(()->run(original(),false,true));assertEquals(job('1'),catalogJob);assertEquals(1,workers);}
    }
    @Test public void failedPrivateWriteStopsBeforeEveryRpc()throws Exception{
        Journey j=new Journey();j.store.failBefore=true;rejects(()->j.run(j.original(),false,true));assertTrue(j.calls.isEmpty());assertEquals(0,j.workers);assertTrue(j.store.values.isEmpty());
    }
    @Test public void failedCatalogMarkerRetainsExactRequestAndStopsBeforeFirstRpc()throws Exception{
        Journey j=new Journey();j.failCatalogMarker=true;rejects(()->j.run(j.original(),false,true));assertTrue(j.calls.isEmpty());String task=j.store.values.get(0).get("task");assertEquals("complete",j.run(new JSONObject(),true,true).getString("state"));assertEquals(task,j.store.values.get(0).get("task"));assertEquals(1,j.workers);
    }
    @Test public void lostFirstReplyReconcilesTheSameTaskInsteadOfAllocatingAnotherInstaller()throws Exception{
        Journey j=new Journey();j.loseStartReply=true;rejects(()->j.run(j.original(),false,true));assertEquals("",j.catalogJob);String saved=j.store.snapshot();assertEquals("complete",j.run(new JSONObject(),true,true).getString("state"));assertEquals(2,j.count("start"));assertEquals(1,j.workers);assertEquals(j.calls.get(0).toString(),j.calls.get(1).toString());assertFalse(saved.isEmpty());
    }
    @Test public void lostPrivateJobAckReconcilesTheDurableJobBeforePolling()throws Exception{
        Journey j=new Journey();j.failPrivateAck=true;rejects(()->j.run(j.original(),false,true));assertEquals("",j.catalogJob);assertEquals(job('1'),j.recordedJob());assertEquals("complete",j.run(new JSONObject(),true,true).getString("state"));assertEquals(job('1'),j.catalogJob);assertEquals(1,j.count("start"));assertEquals(1,j.workers);
    }
    @Test public void failedCatalogJobSaveUsesPrivateAckWithoutResendingStart()throws Exception{
        Journey j=new Journey();j.failCatalogJob=true;rejects(()->j.run(j.original(),false,true));assertEquals("",j.catalogJob);assertEquals(job('1'),j.recordedJob());assertEquals("complete",j.run(new JSONObject(),true,true).getString("state"));assertEquals(1,j.count("start"));assertEquals(1,j.workers);
    }
    @Test public void lostLinkedReplyUsesTheSameDurableNonceAndOneChild()throws Exception{
        Journey j=new Journey();j.firstFailed();j.loseRetryReply=true;rejects(()->j.run(new JSONObject(),true,true));String nonce=j.store.values.get(0).data.getJSONObject("claim").getString("nonce");assertEquals(job('1'),j.catalogJob);j.node.vpnPassword="edited later";assertEquals("complete",j.run(new JSONObject(),true,true).getString("state"));assertEquals(2,j.count("retry"));assertEquals(2,j.workers);for(JSONObject call:j.calls)if(call.optString("action").equals("retry"))assertEquals(nonce,call.getString("nonce"));assertEquals(job('2'),j.catalogJob);
    }
    @Test public void failedNoncePersistenceStopsBeforeAnyRetryRpc()throws Exception{
        Journey j=new Journey();j.firstFailed();String before=j.store.snapshot();j.store.failBefore=true;rejects(()->j.run(new JSONObject(),true,true));assertEquals(0,j.count("retry"));assertEquals(before,j.store.snapshot());assertEquals(1,j.workers);
    }
    @Test public void aFreshFailedInstallNeverAutomaticallyRetries()throws Exception{
        Journey j=new Journey();j.firstFailed();assertEquals(0,j.count("retry"));assertEquals(job('1'),j.recordedJob());
    }
    @Test public void oneExplicitResumeAllocatesAtMostOneLinkedChild()throws Exception{
        Journey j=new Journey();j.firstFailed();j.failChild=true;rejects(()->j.run(new JSONObject(),true,true));assertEquals(1,j.count("retry"));assertEquals(2,j.workers);assertEquals(job('2'),j.catalogJob);assertEquals(job('2'),j.recordedJob());
    }
    @Test public void legacyUnboundWorkIsPolledButCannotClaimAnOwnedRetry()throws Exception{
        Journey j=new Journey();j.firstFailed();int calls=j.calls.size();rejects(()->StandaloneInstallCoordinator.run(job('1'),new JSONObject(),true,false,j,j,j));assertEquals(calls+1,j.calls.size());assertEquals(0,j.count("retry"));assertEquals(1,j.workers);
    }
    @Test public void runningAndUnknownStatesNeverReplayMutation()throws Exception{
        Journey j=new Journey();j.runningFirst=true;assertEquals("complete",j.run(j.original(),false,true).getString("state"));assertEquals(1,j.awaits);assertEquals(1,j.count("start"));assertEquals(2,j.count("job"));j.state="unknown";rejects(()->j.run(new JSONObject(),true,true));assertEquals(1,j.count("start"));assertEquals(0,j.count("retry"));assertEquals(1,j.workers);
    }
}
