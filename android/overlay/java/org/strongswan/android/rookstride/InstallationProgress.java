package org.strongswan.android.rookstride;

import org.json.JSONObject;

/** Completed checkpoints, never a simulated byte/download percentage. */
public final class InstallationProgress {
    public static final String[] ENGINES={"Review installed runtime and identities","Prepare or restore reviewed engine files","Verify service, DNS and the complete route"};
    public static final String[] ENTRY={"Prepare the replacement entry","Connect an independent exit bridge","Restore entry identity and VPN users","Verify candidate routing, DNS and filtering"};
    public static final String[] HELPERS={"Update the exit management helper","Update the entry management helper","Verify routing and keep rollback available"};
    public static final String[] EXIT={"Check the current and replacement servers","Prepare the replacement exit","Verify isolated routing and DNS","Switch the guarded route"};
    public static final String[] PAIRED_OS={"First server · Start the reviewed reinstall","First server · Verify the Ubuntu image","First server · Prepare the boot installer","First server · Restart into the installer","First server · Wait for Ubuntu to return","First server · Verify OS and administrator access","Second server · Start the reviewed reinstall","Second server · Verify the Ubuntu image","Second server · Prepare the boot installer","Second server · Restart into the installer","Second server · Wait for Ubuntu to return","Second server · Verify OS and administrator access"};
    public static final String[] PAIRED_RESTORE={"First server · Start the reviewed reinstall","First server · Verify the Ubuntu image","First server · Prepare the boot installer","First server · Restart into the installer","First server · Wait for Ubuntu to return","First server · Verify OS and administrator access","Second server · Start the reviewed reinstall","Second server · Verify the Ubuntu image","Second server · Prepare the boot installer","Second server · Restart into the installer","Second server · Wait for Ubuntu to return","Second server · Verify OS and administrator access","Restore exit VPN identity","Restore entry VPN identity and users","Verify routing and DNS","Activate guarded forwarding"};
    public static final String[] OS={"Start the reviewed reinstall","Verify the Ubuntu image","Prepare the boot installer","Restart into the installer","Wait for Ubuntu to return","Verify OS and administrator access"};
    public static final String[] PAIR={"Prepare the selected servers","Install the exit VPN","Check exit ad blocking","Prepare the entry VPN","Join the exit bridge","Join the entry bridge","Check the complete route","Open client forwarding","Check connection monitoring","Read both VPN health reports"};
    public static final String[] SINGLE={"Verify server identity","Send the reviewed installer","Install VPN and private DNS","Prepare sign-in and usage tools","Read gateway health"};
    public static final String[] ENROLL={"Verify server identity","Send the management helper","Enroll management and usage history","Read gateway health"};
    public static final String[] PROTOCOL={"Connect to your server","Inspect server and ports","Prepare the protocol","Install ad blocking","Configure the protocol","Start the VPN","Check VPN and DNS"};
    public static final String[] FILTER={"Connect to your server","Review the existing VPN","Install private ad blocking","Update the VPN DNS route","Check VPN and DNS"};
    public final String kind, gatewayId;
    public final long started;
    public volatile long finished=0;
    public volatile int completed=0;
    public volatile String phase="Starting",state="running";
    public InstallationProgress(String kind,String gatewayId,long started){this.kind=kind;this.gatewayId=gatewayId;this.started=started;}
    public String[] steps(){return kind.equals("engine-update")?ENGINES:kind.equals("lifecycle-entry")?ENTRY:kind.equals("paired-restore")?PAIRED_RESTORE:kind.equals("helper-update")?HELPERS:kind.equals("lifecycle-exit")?EXIT:kind.equals("paired-os")?PAIRED_OS:kind.equals("os")?OS:kind.equals("pair")?PAIR:kind.equals("enroll")?ENROLL:kind.equals("protocol")?PROTOCOL:kind.equals("filter")?FILTER:SINGLE;}
    /** Stable semantic artwork keys: independent of translated phase/detail text. */
    public String illustration(){
        if(state.equals("complete"))return "celebrate";
        if(!state.equals("running"))return "wait";
        String[] poses=kind.equals("engine-update")?new String[]{"inspect","prepare","verify"}:kind.equals("lifecycle-entry")?new String[]{"prepare","bridge-entry","configure","verify"}:kind.equals("paired-restore")?new String[]{"inspect","send","prepare","start","wait","verify","inspect","send","prepare","start","wait","verify","exit","configure","verify","forward"}:kind.equals("helper-update")?new String[]{"exit","prepare","verify"}:kind.equals("lifecycle-exit")?new String[]{"inspect","exit","verify","forward"}:kind.equals("paired-os")?new String[]{"inspect","send","prepare","start","wait","verify","inspect","send","prepare","start","wait","verify"}:kind.equals("os")?new String[]{"inspect","send","prepare","start","wait","verify"}:kind.equals("pair")?new String[]{"inspect","exit","adblock","prepare","bridge-exit","bridge-entry","verify","forward","monitor","health"}:kind.equals("enroll")?new String[]{"inspect","send","monitor","health"}:kind.equals("protocol")?new String[]{"connect","inspect","prepare","adblock","configure","start","verify"}:kind.equals("filter")?new String[]{"connect","inspect","adblock","configure","verify"}:new String[]{"inspect","send","configure","monitor","health"};
        return poses[Math.max(0,Math.min(completed,poses.length-1))];
    }
    public static int singleStage(String kind,String phase){return kind.equals("enroll")?2:phase.contains("management")||phase.contains("trusted IKEv2")?3:2;}
    public int percent(){return Math.min(100,100*completed/steps().length);}
    public void stage(int index,String detail){completed=Math.max(0,Math.min(index,steps().length-1));phase=detail;state="running";}
    public void finish(){finishAt(0,System.currentTimeMillis());}
    public void finishAt(long serverCompletedAt,long now){
        if(state.equals("complete"))return;
        // A resumed server job may have finished long before the phone returned.
        // Ignore missing, future or pre-start server timestamps (including clock skew).
        finished=serverCompletedAt>=started&&serverCompletedAt>0&&serverCompletedAt<=now?serverCompletedAt:Math.max(started,now);
        completed=steps().length;state="complete";phase=kind.equals("engine-update")?"Runtime operation completed. Review its recorded status and verify an existing client before accepting.":kind.equals("lifecycle-entry")?"Candidate checks completed. Transfer the existing client endpoint and verify a saved client before finishing.":kind.equals("paired-restore")?"VPN identities restored. Verify saved clients on their actual networks.":kind.equals("helper-update")?"Management helpers checked. Verify existing clients before accepting the update.":kind.equals("lifecycle-exit")?"Server checks passed. Verify actual client traffic before accepting the replacement.":kind.equals("paired-os")?"Both servers are clean. New VPN setup and profiles are required.":kind.equals("os")?"Ubuntu reinstalled. You can now set up a VPN.":"Server checks passed. Test the VPN on your actual phone.";
    }
    public String remaining(){return (steps().length-completed)+" checkpoints remaining";}
    public String estimate(){
        if(state.equals("complete"))return "Setup finished";
        if(!state.equals("running"))return "Time estimate paused until you resume";
        // Planning ranges, not benchmarked promises. Network/reboot waits have no fixed ETA.
        if(kind.equals("paired-os")||kind.equals("paired-restore"))return "Allow about 20–60 minutes; two downloads and reboots vary";
        if(kind.equals("engine-update"))return "Allow about 2–30 minutes; verified downloads and runtime builds vary";
        if(kind.equals("helper-update"))return "Allow a few minutes for helper and route checks";
        if(kind.equals("lifecycle-exit")||kind.equals("lifecycle-entry"))return "Allow about 5–25 minutes; existing client traffic needs your final check";
        if(kind.equals("os"))return "Allow about 10–30 minutes; download and reboot times vary";
        int low=0,high=0;
        int[] mins=kind.equals("pair")?new int[]{0,2,0,2,0,0,0,0,0,0}:kind.equals("enroll")?new int[]{0,0,1,0}:kind.equals("filter")?new int[]{0,0,1,0,0}:kind.equals("protocol")?new int[]{0,0,1,1,0,0,0}:new int[]{0,0,2,1,0};
        int[] maxs=kind.equals("pair")?new int[]{3,20,2,20,2,2,3,1,2,2}:kind.equals("enroll")?new int[]{1,2,5,2}:kind.equals("filter")?new int[]{1,1,8,3,2}:kind.equals("protocol")?new int[]{1,1,15,8,3,1,2}:new int[]{1,2,20,5,2};
        for(int i=completed;i<steps().length;i++){low+=mins[i];high+=maxs[i];}
        return "Planning range: about "+Math.max(1,low)+"–"+high+" min for remaining stages";
    }
    public boolean elapsedKnown(){return !state.equals("complete")||finished>0;}
    public long elapsedSeconds(long now){return Math.max(0,((state.equals("complete")&&finished>0?finished:now)-started)/1000);}
    public String elapsed(long now){if(!elapsedKnown())return "Setup finished";long seconds=elapsedSeconds(now);return "Elapsed "+seconds/60+"m "+seconds%60+"s";}
    public JSONObject json(){try{return new JSONObject().put("pair_schema",2).put("kind",kind).put("gateway",gatewayId).put("started",started).put("finished",finished).put("completed",completed).put("phase",phase).put("state",state);}catch(Exception e){throw new IllegalStateException(e);}}
    public static InstallationProgress from(JSONObject data){InstallationProgress p=new InstallationProgress(data.optString("kind","single"),data.optString("gateway"),data.optLong("started"));int completed=data.optInt("completed");if(p.kind.equals("pair")&&data.optInt("pair_schema",1)<2)completed=new int[]{0,1,3,4,5,6,7,8,10}[Math.max(0,Math.min(8,completed))];p.completed=Math.max(0,Math.min(completed,p.steps().length));p.phase=data.optString("phase");p.state=data.optString("state","needs-attention");if(p.state.equals("complete"))p.completed=p.steps().length;long end=data.optLong("finished");p.finished=p.state.equals("complete")&&end>=p.started?Math.max(0,end):0;return p;}
}
