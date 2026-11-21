package org.strongswan.android.rookstride;

import java.io.*;
import org.json.*;

/** Owner-only reviewed runtime updates; source pins are not arbitrary download URLs. */
public final class EngineUpdates {
    private EngineUpdates() {}
    private static JSONObject call(Ssh ssh,PairController.Bundle source,JSONObject request)throws Exception {
        try(InputStream in=source.open()){return ssh.engineUpdates(in,request);}
    }
    private static final class Sessions implements AutoCloseable {
        final PairSsh pair;final Ssh single;
        Sessions(Gateway gateway,PairController.Progress progress)throws Exception {
            pair=gateway.isPair()?PairSsh.connect(gateway,progress):null;single=pair==null?new Ssh(gateway):null;
        }
        String[] roles(){return pair==null?new String[]{"single"}:new String[]{"exit","entry"};}
        Ssh get(String role){return pair==null?single:role.equals("entry")?pair.entry:pair.exit;}
        public void close(){if(pair!=null)pair.close();if(single!=null)single.close();}
    }
    public static JSONObject inspect(Gateway gateway,PairController.Bundle source,PairController.Progress progress)throws Exception {
        JSONObject result=new JSONObject();
        try(Sessions sessions=new Sessions(gateway,progress)){
            for(String role:sessions.roles()){progress.update("Checking "+role+" runtime versions");result.put(role,call(sessions.get(role),source,new JSONObject().put("action","inspect")));}
        }return result;
    }
    public static JSONObject group(JSONObject inspection,String id){
        JSONArray groups=inspection.optJSONArray("groups");if(groups==null)return null;
        for(int i=0;i<groups.length();i++){JSONObject group=groups.optJSONObject(i);if(group!=null&&id.equals(group.optString("group")))return group;}
        return null;
    }
    public static boolean supports(JSONObject review,String id){
        for(String role:new String[]{"single","entry","exit"}){JSONObject item=review.optJSONObject(role);JSONObject candidate=item==null?null:group(item,id);if(candidate!=null&&candidate.optBoolean("supported"))return true;}
        return false;
    }
    private static JSONObject operation(Gateway gateway)throws IOException {
        JSONObject operation=gateway.data.optJSONObject("engineUpdate");if(operation==null)throw new IOException("No runtime update is recorded");return operation;
    }
    private static JSONObject waitFor(Ssh ssh,String id,PairController.Progress progress)throws Exception {
        long deadline=System.nanoTime()+1_800_000_000_000L;String last="";
        while(true){
            JSONObject status=ssh.engineUpdates(new JSONObject().put("action","status").put("operation",id));String state=status.optString("state"),phase=status.optString("phase");
            if(!phase.equals(last)){last=phase;progress.update(phase);}
            if(state.equals("prepared")||state.equals("verified")||state.equals("rolled-back")||state.equals("accepted")||state.equals("cancelled"))return status;
            if(state.equals("not-started"))throw new IOException("This runtime preparation has not started. Resume preparation before applying it.");
            if(state.endsWith("-failed"))throw new IOException(status.optString("error",phase));
            if(System.nanoTime()>deadline)throw new IOException("The runtime job is still recorded. Reopen this update to check and resume; it will not be replayed.");
            Thread.sleep(2000);
        }
    }
    public static JSONObject prepare(Gateway gateway,String group,JSONObject review,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
        progress.stage(0,"Reviewing runtime identities and saved client settings");
        JSONObject operation=gateway.data.optJSONObject("engineUpdate");
        if(operation==null){
            if(!supports(review,group))throw new IOException("This runtime has no compatible update adapter on this server");
            operation=new JSONObject().put("schema",1).put("group",group).put("review",review).put("state","preparing");
            for(String role:new String[]{"single","entry","exit"}){JSONObject node=review.optJSONObject(role);JSONObject candidate=node==null?null:group(node,group);if(candidate!=null&&candidate.optBoolean("supported"))operation.put(role,PairController.newId());}
            gateway.data.put("engineUpdate",operation);saved.save();
        }
        if(!operation.optString("group").equals(group)||!operation.optString("state").equals("preparing"))throw new IOException("Resume the recorded runtime update before preparing another");
        try(Sessions sessions=new Sessions(gateway,progress)){
            for(String role:sessions.roles()){
                if(!operation.has(role))continue;
                JSONObject candidate=group(operation.getJSONObject("review").getJSONObject(role),group);
                JSONObject started=call(sessions.get(role),source,new JSONObject().put("action","prepare").put("group",group).put("operation",operation.getString(role)).put("fingerprint",candidate.getString("fingerprint")));
                operation.put(role+"_status",started);saved.save();
            }
            progress.stage(1,"Preparing reviewed runtime files; current VPN unchanged");
            for(String role:sessions.roles())if(operation.has(role)){operation.put(role+"_status",waitFor(sessions.get(role),operation.getString(role),progress));saved.save();}
        }
        operation.put("state","prepared");saved.save();return operation;
    }
    public static JSONObject apply(Gateway gateway,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
        JSONObject operation=operation(gateway);String state=operation.optString("state");
        if(!state.equals("prepared")&&!state.equals("applying"))throw new IOException("Prepare and review the runtime update first");
        progress.stage(1,"Restarting the reviewed runtime while preserving client identities");
        operation.put("state","applying");saved.save();
        try(Sessions sessions=new Sessions(gateway,progress)){
            if(sessions.pair!=null){
                if(!operation.has("expected_exit_ip")){JSONObject overview=sessions.pair.exit.pair(new JSONObject().put("command","overview").put("pair",gateway.get("pairId")));operation.put("expected_exit_ip",overview.getString("exit_ip"));operation.put("filtering_enabled",call(sessions.pair.exit,source,new JSONObject().put("action","filter-policy")).getBoolean("enabled"));saved.save();}
                call(sessions.pair.entry,source,new JSONObject().put("action","guard").put("deployment",gateway.get("pairId")));
            }
            for(String role:sessions.roles())if(operation.has(role)){
                Ssh ssh=sessions.get(role);String id=operation.getString(role);JSONObject status=ssh.engineUpdates(new JSONObject().put("action","status").put("operation",id));
                if(status.optString("state").equals("prepared")||status.optString("state").equals("apply-failed"))ssh.engineUpdates(new JSONObject().put("action","apply").put("operation",id).put("confirmation","RESTART REVIEWED VPN RUNTIMES"));
                operation.put(role+"_status",waitFor(ssh,id,progress));saved.save();
            }
            verifyPair(gateway,operation,sessions,source,progress);
        }
        operation.put("state","verified");saved.save();return operation;
    }
    private static void verifyPair(Gateway gateway,JSONObject operation,Sessions sessions,PairController.Bundle source,PairController.Progress progress)throws Exception {
        progress.stage(2,"Checking the resulting VPN route");
        if(sessions.pair==null)return;
        progress.update("Verifying the complete Double VPN route and DNS");
        call(sessions.pair.entry,source,new JSONObject().put("action","verify-pair").put("deployment",gateway.get("pairId")).put("expected_exit_ip",operation.getString("expected_exit_ip")).put("filtering_enabled",operation.optBoolean("filtering_enabled",true)));
    }
    public static JSONObject abandon(Gateway gateway,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
        JSONObject operation=operation(gateway);progress.stage(0,"Closing the reviewed rollback record");
        try(Sessions sessions=new Sessions(gateway,progress)){for(String role:sessions.roles())if(operation.has(role)){JSONObject status=sessions.get(role).engineUpdates(new JSONObject().put("action","status").put("operation",operation.getString(role)));if(!status.optString("state").equals("not-started"))status=sessions.get(role).engineUpdates(new JSONObject().put("action","abandon").put("operation",operation.getString(role)).put("confirmation","ABANDON ENGINE ROLLBACK"));operation.put(role+"_status",status);saved.save();}}
        operation.put("state","abandoned");gateway.data.put("lastEngineUpdate",operation);gateway.data.remove("engineUpdate");saved.save();return operation;
    }
    public static JSONObject finish(Gateway gateway,boolean rollback,PairController.Bundle source,PairController.Progress progress,OsReinstall.Saved saved)throws Exception {
        JSONObject operation=operation(gateway);String state=operation.optString("state"),intent=rollback?"rolling-back":"accepting";
        if((state.equals("accepting")||state.equals("rolling-back"))&&!state.equals(intent))throw new IOException("Finish the recorded runtime completion direction first");
        if(!rollback&&!state.equals("verified")&&!state.equals("accepting"))throw new IOException("Verify the updated VPN before accepting it");
        operation.put("state",intent);saved.save();
        try(Sessions sessions=new Sessions(gateway,progress)){
            boolean changed=operation.has("expected_exit_ip");
            if(rollback&&sessions.pair!=null&&changed)call(sessions.pair.entry,source,new JSONObject().put("action","guard").put("deployment",gateway.get("pairId")));
            for(String role:sessions.pair==null?new String[]{"single"}:new String[]{"entry","exit"})if(operation.has(role)){
                Ssh ssh=sessions.get(role);String id=operation.getString(role);JSONObject status=ssh.engineUpdates(new JSONObject().put("action","status").put("operation",id));String remote=status.optString("state");
                if(rollback){
                    if(remote.equals("not-started")){operation.put(role+"_status",status);saved.save();continue;}
                    if(remote.equals("preparing")){status=waitFor(ssh,id,progress);remote=status.optString("state");}
                    if(remote.equals("prepared")||remote.equals("prepare-failed"))status=ssh.engineUpdates(new JSONObject().put("action","cancel").put("operation",id));
                    else if(!remote.equals("cancelled")&&!remote.equals("rolled-back")){
                        if(remote.equals("applying")||remote.equals("rolling-back"))status=waitFor(ssh,id,progress);
                        if(!status.optString("state").equals("rolled-back")){ssh.engineUpdates(new JSONObject().put("action","rollback").put("operation",id).put("confirmation","RESTART REVIEWED VPN RUNTIMES"));status=waitFor(ssh,id,progress);}
                    }
                }else status=ssh.engineUpdates(new JSONObject().put("action","accept").put("operation",id).put("confirmation","SAVED CLIENT TRAFFIC VERIFIED"));
                operation.put(role+"_status",status);saved.save();
            }
            if(rollback&&changed)verifyPair(gateway,operation,sessions,source,progress);
        }
        operation.put("state",rollback?"rolled-back":"accepted");gateway.data.put("lastEngineUpdate",operation);gateway.data.remove("engineUpdate");saved.save();return operation;
    }
}
