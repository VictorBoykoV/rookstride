package org.strongswan.android.rookstride;

import org.json.JSONObject;
import java.io.IOException;

/** The Service's protocol loop; storage and transport remain with its real owner.
 * Explicit callbacks let local tests fail durable writes and lose RPC replies
 * without constructing a second implementation or opening a socket. */
final class StandaloneInstallCoordinator {
    interface Local {
        boolean has()throws Exception;
        String recordedJob()throws Exception;
        JSONObject startRequest(JSONObject original)throws Exception;
        void rememberJob(JSONObject response)throws Exception;
        JSONObject retryRequest(JSONObject failure)throws Exception;
        void saveJob(JSONObject response,boolean port)throws Exception;
        void progress(JSONObject status)throws Exception;
    }
    interface Rpc {JSONObject request(JSONObject request,boolean bundled)throws Exception;}
    interface Await {void next()throws Exception;}
    private StandaloneInstallCoordinator(){}

    static JSONObject run(String initialJob,JSONObject config,boolean resume,boolean bound,Local local,Rpc rpc,Await await)throws Exception {
        String job=initialJob;boolean retained=bound&&local.has();
        if(retained){String acknowledged=local.recordedJob();if(!acknowledged.isEmpty()&&!acknowledged.equals(job)){local.saveJob(new JSONObject().put("job",acknowledged),false);job=acknowledged;}}
        if(job.isEmpty()||retained&&local.recordedJob().isEmpty()){
            local.progress(new JSONObject().put("stage",1).put("phase","Inspecting the server and sending the installer"));
            JSONObject request=new JSONObject(config.toString());if(request.length()>0)request.put("action","start");
            if(bound)request=local.startRequest(request);else request.put("action","start");
            if(bound)local.saveJob(null,false);
            JSONObject started=rpc.request(request,true);
            if(bound){local.rememberJob(started);retained=true;}
            local.saveJob(started,true);job=started.getString("job");
        }
        boolean retried=false;long deadline=System.nanoTime()+5_400_000_000_000L;
        while(true){
            JSONObject status=rpc.request(new JSONObject().put("action","job").put("job",job),false);String state=status.optString("state");local.progress(status);
            if(state.equals("complete"))return status;
            if(state.equals("failed")){
                if(resume&&retained&&!retried&&status.optJSONObject("retryable")!=null){
                    // The real helper acknowledges the nonce before this RPC;
                    // only this explicit Check and resume may request a retry.
                    JSONObject request=local.retryRequest(status);local.saveJob(null,false);
                    JSONObject started=rpc.request(request,true);
                    local.rememberJob(started);local.saveJob(started,true);job=started.getString("job");retried=true;continue;
                }
                throw new IOException(status.optString("phase"));
            }
            if(!state.equals("starting")&&!state.equals("running"))throw new IOException("The recorded installer state is unknown. Inspect it before continuing.");
            if(System.nanoTime()>deadline)throw new IOException("Server setup is taking longer. Reopen its recorded installation to check progress.");
            await.next();
        }
    }
}
