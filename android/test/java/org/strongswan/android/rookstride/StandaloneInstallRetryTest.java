package org.strongswan.android.rookstride;

import org.json.*;
import org.junit.Test;
import java.io.IOException;
import java.util.*;
import static org.junit.Assert.*;

/** Phone persistence boundaries only; no SSH, Android Keystore or installer is executed. */
public class StandaloneInstallRetryTest {
    interface Attempt{void run()throws Exception;}
    private void reject(Attempt run)throws Exception{try{run.run();fail("An unbound retry was accepted");}catch(IOException|JSONException expected){assertNotNull(expected.getMessage());}}
    private static final class Memory implements StandaloneInstallRetry.Store {
        ArrayList<Gateway> values=new ArrayList<>();int writes;boolean failBefore,failAfter;
        public ArrayList<Gateway> read()throws Exception{ArrayList<Gateway> result=new ArrayList<>();for(Gateway value:values)result.add(new Gateway(new JSONObject(value.persisted().toString())));return result;}
        public void write(ArrayList<Gateway> next)throws Exception{writes++;if(failBefore)throw new IOException("Private storage unavailable");values=new ArrayList<>();for(Gateway value:next)values.add(new Gateway(new JSONObject(value.persisted().toString())));if(failAfter)throw new IOException("Lost write acknowledgement");}
        String snapshot()throws Exception{JSONArray result=new JSONArray();for(Gateway value:values)result.put(value.persisted());return result.toString();}
    }
    private Gateway node()throws Exception{Gateway n=new Gateway();n.set("host","vpn.example.net");n.set("protocol","openvpn");n.set("fingerprint","SHA256:"+String.join("",Collections.nCopies(43,"A")));n.set("machine",String.join("",Collections.nCopies(64,"b")));return n;}
    private JSONObject original()throws Exception{return new JSONObject().put("action","start").put("protocol","openvpn").put("server","vpn.example.net").put("login","1").put("password","  private chosen secret  ").put("sshPort",22).put("port",1194).put("access_mode","password");}
    private JSONObject response(Memory s,Gateway n,String job)throws Exception{Gateway r=s.values.get(0);JSONObject c=new JSONObject().put("schema",1).put("owner",n.get("id")).put("task",r.get("task")).put("request_digest",StandaloneInstallRetry.digest(original())).put("config_digest",String.join("",Collections.nCopies(64,"c"))).put("machine",n.get("machine")).put("source",String.join("",Collections.nCopies(64,"d"))).put("instance",String.join("",Collections.nCopies(32,"e"))).put("port",1194);return new JSONObject().put("job",job).put("plan",new JSONObject().put("port",1194)).put("bundle",c.getString("source")).put("install_context",c);}
    private String job(char c){return String.join("",Collections.nCopies(32,String.valueOf(c)));}
    private JSONObject failure(Memory s)throws Exception{Gateway r=s.values.get(0);JSONObject typed=new JSONObject(r.data.getJSONObject("context").toString()).put("reason","acquisition-unavailable");return new JSONObject().put("job",r.get("job")).put("state","failed").put("retryable",typed).put("failed_receipt_sha256",String.join("",Collections.nCopies(64,"f")));}
    private void started(Memory s,Gateway n)throws Exception{StandaloneInstallRetry.startRequest(s,n,original());StandaloneInstallRetry.rememberJob(s,n,response(s,n,job('1')));}
    @Test public void firstRequestIsSavedBeforeReturnAndColdStartKeepsItsExactTaskAndSecret()throws Exception{
        Memory s=new Memory();Gateway n=node();String clean=n.persisted().toString();JSONObject first=StandaloneInstallRetry.startRequest(s,n,original());assertEquals(1,s.writes);assertEquals(n.get("id"),first.getJSONObject("install_context").getString("owner"));String task=first.getJSONObject("install_context").getString("task");assertTrue(task.matches("[a-f0-9]{32}"));first.put("password","caller changed");JSONObject cold=StandaloneInstallRetry.startRequest(s,n,new JSONObject());assertEquals(task,cold.getJSONObject("install_context").getString("task"));assertEquals("  private chosen secret  ",cold.getString("password"));assertEquals(1,s.writes);assertEquals(clean,n.persisted().toString());assertFalse(n.data.toString().contains("private chosen secret"));
    }
    @Test public void unacknowledgedInitialWriteStopsBeforeAnyRequestCanBeSentAndReconcilesLostAck()throws Exception{
        Memory s=new Memory();Gateway n=node();s.failBefore=true;reject(()->StandaloneInstallRetry.startRequest(s,n,original()));assertTrue(s.values.isEmpty());s.failBefore=false;s.failAfter=true;reject(()->StandaloneInstallRetry.startRequest(s,n,original()));String task=s.values.get(0).get("task");s.failAfter=false;JSONObject recovered=StandaloneInstallRetry.startRequest(s,n,new JSONObject());assertEquals(task,recovered.getJSONObject("install_context").getString("task"));assertEquals(2,s.writes);
    }
    @Test public void changedRequestServerOrOwnerCannotReuseAStoredTask()throws Exception{
        Memory s=new Memory();Gateway n=node();StandaloneInstallRetry.startRequest(s,n,original());String saved=s.snapshot();reject(()->StandaloneInstallRetry.startRequest(s,n,original().put("password","different")));n.set("fingerprint","SHA256:"+String.join("",Collections.nCopies(43,"B")));reject(()->StandaloneInstallRetry.startRequest(s,n,new JSONObject()));assertEquals(saved,s.snapshot());Memory empty=new Memory();Gateway different=node();reject(()->StandaloneInstallRetry.startRequest(empty,different,new JSONObject()));assertTrue(empty.values.isEmpty());
    }
    @Test public void acknowledgementRequiresExactRequestMachinePortAndSourceAndDoesNotRewriteOnRepeat()throws Exception{
        Memory s=new Memory();Gateway n=node();StandaloneInstallRetry.startRequest(s,n,original());JSONObject good=response(s,n,job('1'));String saved=s.snapshot();JSONObject wrong=new JSONObject(good.toString());wrong.getJSONObject("install_context").put("machine",String.join("",Collections.nCopies(64,"a")));reject(()->StandaloneInstallRetry.rememberJob(s,n,wrong));assertEquals(saved,s.snapshot());JSONObject port=new JSONObject(good.toString());port.getJSONObject("plan").put("port",8443);reject(()->StandaloneInstallRetry.rememberJob(s,n,port));StandaloneInstallRetry.rememberJob(s,n,good);int writes=s.writes;StandaloneInstallRetry.rememberJob(s,n,good);assertEquals(writes,s.writes);
    }
    @Test public void retryNonceIsDurableReusedAndNeverReconstructsEditedGatewayCredentials()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);JSONObject failed=failure(s),retry=StandaloneInstallRetry.retryRequest(s,n,failed);int writes=s.writes;n.vpnPassword="edited later";JSONObject same=StandaloneInstallRetry.retryRequest(s,n,failed);assertEquals(retry.toString(),same.toString());assertEquals(writes,s.writes);assertEquals("  private chosen secret  ",retry.getJSONObject("request").getString("password"));retry.getJSONObject("request").put("password","caller edit");assertEquals("  private chosen secret  ",StandaloneInstallRetry.retryRequest(s,n,failed).getJSONObject("request").getString("password"));reject(()->StandaloneInstallRetry.startRequest(s,n,new JSONObject()));
    }
    @Test public void failedNonceWriteCannotReturnAnRpcAndTypedClaimsBindTheImmutableFailure()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);String saved=s.snapshot();s.failBefore=true;reject(()->StandaloneInstallRetry.retryRequest(s,n,failure(s)));assertEquals(saved,s.snapshot());s.failBefore=false;JSONObject retry=StandaloneInstallRetry.retryRequest(s,n,failure(s));JSONObject changed=failure(s).put("failed_receipt_sha256",String.join("",Collections.nCopies(64,"a")));reject(()->StandaloneInstallRetry.retryRequest(s,n,changed));assertEquals(retry.getString("nonce"),StandaloneInstallRetry.retryRequest(s,n,failure(s)).getString("nonce"));
    }
    @Test public void linkedChildAckCanBeReplayedReadOnlyAndNextExplicitFailureGetsANewNonce()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);JSONObject first=StandaloneInstallRetry.retryRequest(s,n,failure(s)),child=response(s,n,job('2')).put("retry_of",job('1')).put("nonce",first.getString("nonce"));JSONObject wrong=new JSONObject(child.toString()).put("nonce",job('9'));reject(()->StandaloneInstallRetry.rememberJob(s,n,wrong));StandaloneInstallRetry.rememberJob(s,n,child);assertEquals(job('2'),s.values.get(0).get("job"));int writes=s.writes;StandaloneInstallRetry.rememberJob(s,n,child);assertEquals(writes,s.writes);JSONObject second=StandaloneInstallRetry.retryRequest(s,n,failure(s));assertEquals(job('2'),second.getString("job"));assertNotEquals(first.getString("nonce"),second.getString("nonce"));
    }
    @Test public void onlyExactTypedFailedWorkCanClaimARetry()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);String original=s.snapshot();for(String state:new String[]{"running","complete","unknown"})reject(()->StandaloneInstallRetry.retryRequest(s,n,failure(s).put("state",state)));JSONObject generic=failure(s);generic.remove("retryable");reject(()->StandaloneInstallRetry.retryRequest(s,n,generic));JSONObject wrong=failure(s);wrong.getJSONObject("retryable").put("config_digest",String.join("",Collections.nCopies(64,"a")));reject(()->StandaloneInstallRetry.retryRequest(s,n,wrong));assertEquals(original,s.snapshot());
    }
    @Test public void forgettingIsOwnerScopedDurableAndDoesNotCreateAnEmptyStore()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);Gateway other=node();StandaloneInstallRetry.forgetOwner(s,other.get("id"));assertEquals(2,s.writes);s.failBefore=true;reject(()->StandaloneInstallRetry.forgetOwner(s,n.get("id")));assertEquals(1,s.values.size());s.failBefore=false;StandaloneInstallRetry.forgetOwner(s,n.get("id"));assertTrue(s.values.isEmpty());int writes=s.writes;StandaloneInstallRetry.forgetOwner(s,n.get("id"));assertEquals(writes,s.writes);
    }
    @Test public void canonicalRequestMatchesCrossLanguageUnicodeAndEscapingRules()throws Exception{
        JSONObject v=new JSONObject().put("z","</\\\"\n").put("a","Mina فارسی 😀").put("nested",new JSONObject().put("b",true).put("a",new JSONArray().put(22).put(JSONObject.NULL)));assertEquals("{\"a\":\"Mina فارسی 😀\",\"nested\":{\"a\":[22,null],\"b\":true},\"z\":\"</\\\\\\\"\\n\"}",StandaloneInstallRetry.canonical(v));reject(()->StandaloneInstallRetry.canonical(new JSONObject().put("float",1.5)));reject(()->StandaloneInstallRetry.canonical(new JSONObject().put("bad","\ud800")));
    }
    @Test public void failedAbandonMarkerCannotClearTheExactSavedRequestOrNonce()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);StandaloneInstallRetry.retryRequest(s,n,failure(s));String before=s.snapshot();int writes=s.writes;int[] calls={0};reject(()->StandaloneInstallRetry.abandonWithMarker(s,n,()->{calls[0]++;throw new IOException("Catalog acknowledgement failed");}));assertEquals(1,calls[0]);assertEquals(writes,s.writes);assertEquals(before,s.snapshot());
    }
    @Test public void privateCleanupFailureFollowsMarkerAckAndNeverLooksLikeSuccessfulAbandonment()throws Exception{
        Memory s=new Memory();Gateway n=node();started(s,n);String before=s.snapshot();boolean[] acknowledged={false};reject(()->StandaloneInstallRetry.abandonWithMarker(s,n,()->{acknowledged[0]=true;s.failBefore=true;}));assertTrue(acknowledged[0]);assertEquals(before,s.snapshot());s.failBefore=false;StandaloneInstallRetry.abandonWithMarker(s,n,()->acknowledged[0]=true);assertTrue(s.values.isEmpty());int writes=s.writes;acknowledged[0]=false;StandaloneInstallRetry.abandonWithMarker(s,n,()->acknowledged[0]=true);assertTrue(acknowledged[0]);assertEquals("A cold legacy abandonment must not create an empty private store",writes,s.writes);
    }

}
