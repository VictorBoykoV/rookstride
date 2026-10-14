package org.strongswan.android.rookstride;

import org.json.JSONObject;

/** Completed checkpoints, never a simulated byte/download percentage. */
public final class InstallationProgress {
    public static final String[] PAIR={"Verify both identities","Prepare exit VPN and DNS","Prepare entry VPN","Join the exit bridge","Join the entry bridge","Check the complete server route","Open client forwarding","Read both gateway health reports"};
    public static final String[] SINGLE={"Verify server identity","Send the reviewed installer","Install VPN and private DNS","Add management and usage history","Read gateway health"};
    public static final String[] ENROLL={"Verify server identity","Send the management helper","Enroll management and usage history","Read gateway health"};
    public final String kind, gatewayId;
    public final long started;
    public volatile int completed=0;
    public volatile String phase="Starting",state="running";
    public InstallationProgress(String kind,String gatewayId,long started){this.kind=kind;this.gatewayId=gatewayId;this.started=started;}
    public String[] steps(){return kind.equals("pair")?PAIR:kind.equals("enroll")?ENROLL:SINGLE;}
    public int percent(){return Math.min(100,100*completed/steps().length);}
    public void stage(int index,String detail){completed=Math.max(0,Math.min(index,steps().length-1));phase=detail;state="running";}
    public void finish(){completed=steps().length;state="complete";phase="Server checks passed. Test the VPN on your actual phone.";}
    public String remaining(){return (steps().length-completed)+" checkpoints remaining";}
    public String estimate(){
        if(state.equals("complete"))return "Setup finished";
        if(!state.equals("running"))return "Time estimate paused until you resume";
        // Planning ranges, not benchmarked promises. Network/reboot waits have no fixed ETA.
        int low=0,high=0;
        int[] mins=kind.equals("pair")?new int[]{0,2,2,0,0,0,0,0}:kind.equals("enroll")?new int[]{0,0,1,0}:new int[]{0,0,2,1,0};
        int[] maxs=kind.equals("pair")?new int[]{1,20,20,2,2,3,1,2}:kind.equals("enroll")?new int[]{1,2,5,2}:new int[]{1,2,20,5,2};
        for(int i=completed;i<steps().length;i++){low+=mins[i];high+=maxs[i];}
        return "Planning range: about "+Math.max(1,low)+"–"+high+" min for remaining stages";
    }
    public String elapsed(long now){long seconds=Math.max(0,(now-started)/1000);return "Elapsed "+seconds/60+"m "+seconds%60+"s";}
    public JSONObject json(){try{return new JSONObject().put("kind",kind).put("gateway",gatewayId).put("started",started).put("completed",completed).put("phase",phase).put("state",state);}catch(Exception e){throw new IllegalStateException(e);}}
    public static InstallationProgress from(JSONObject data){InstallationProgress p=new InstallationProgress(data.optString("kind","single"),data.optString("gateway"),data.optLong("started"));p.completed=Math.max(0,Math.min(data.optInt("completed"),p.steps().length));p.phase=data.optString("phase");p.state=data.optString("state","needs-attention");return p;}
}
