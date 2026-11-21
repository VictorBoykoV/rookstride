package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;
public class InstallationProgressTest {
    @Test public void recipesHaveDistinctCheckpoints(){assertEquals(10,new InstallationProgress("pair","g",0).steps().length);assertEquals(5,new InstallationProgress("single","g",0).steps().length);assertEquals(4,new InstallationProgress("enroll","g",0).steps().length);}
    @Test public void waitsNeverInventCompletion(){InstallationProgress p=new InstallationProgress("pair","g",0);p.stage(1,"Downloading packages");assertEquals(10,p.percent());assertEquals(9,p.steps().length-p.completed);assertEquals(10,p.percent());assertTrue(p.estimate().contains("Planning range"));}
    @Test public void terminalAndRebootStatesDoNotCountAsDone(){InstallationProgress p=new InstallationProgress("pair","g",0);p.stage(2,"Preparing entry");p.state="awaiting-reboot";assertTrue(p.estimate().contains("paused"));assertEquals(20,p.percent());p.finish();assertEquals(100,p.percent());assertEquals("complete",p.state);}
    @Test public void savedProgressHasNoLoginOrHostSecrets(){InstallationProgress p=new InstallationProgress("single","random-id",1000);p.stage(3,"Adding management");String raw=p.json().toString();assertFalse(raw.contains("password"));assertFalse(raw.contains("host"));InstallationProgress q=InstallationProgress.from(p.json());assertEquals(3,q.completed);assertEquals(1000,q.started);assertEquals("Elapsed 1m 1s",q.elapsed(62000));}
    @Test public void completedElapsedStaysFrozenAfterHoursAndReload(){InstallationProgress p=new InstallationProgress("single","g",1000);p.finishAt(79000,80000);assertEquals("Elapsed 1m 18s",p.elapsed(90000000));assertEquals(78,p.elapsedSeconds(90000000));InstallationProgress q=InstallationProgress.from(p.json());assertEquals(79000,q.finished);assertEquals(p.elapsed(80000),q.elapsed(90000000));}
    @Test public void resumedCompletedServerJobUsesItsCompletionTime(){InstallationProgress p=new InstallationProgress("single","g",1000);p.finishAt(79000,172800000);assertEquals(78,p.elapsedSeconds(172800000));p.finishAt(900000,172800000);assertEquals(79000,p.finished);}
    @Test public void legacyCompleteRecordDoesNotInventAnElapsedDuration()throws Exception{InstallationProgress p=new InstallationProgress("single","g",1000);org.json.JSONObject old=p.json().put("state","complete").put("completed",5);old.remove("finished");InstallationProgress q=InstallationProgress.from(old);assertFalse(q.elapsedKnown());assertEquals("Setup finished",q.elapsed(172800000));}
    @Test public void invalidServerClockFallsBackToPhoneCompletion(){InstallationProgress p=new InstallationProgress("single","g",1000);p.finishAt(Long.MAX_VALUE,79000);assertEquals(78,p.elapsedSeconds(172800000));InstallationProgress q=new InstallationProgress("single","g",1000);q.finishAt(500,79000);assertEquals(79000,q.finished);}
 @org.junit.Test public void filteringHasItsOwnMilestonesAndLegacyCompletedCountsStayFinished()throws Exception{
  InstallationProgress filter=new InstallationProgress("filter","fixture",1000);org.junit.Assert.assertEquals(5,filter.steps().length);org.junit.Assert.assertTrue(filter.estimate().contains("min"));
  InstallationProgress old=InstallationProgress.from(new org.json.JSONObject().put("kind","protocol").put("gateway","fixture").put("started",1000).put("finished",2000).put("completed",6).put("state","complete"));org.junit.Assert.assertEquals(100,old.percent());org.junit.Assert.assertEquals(old.elapsedSeconds(3000),old.elapsedSeconds(99999));
 }
    @Test public void oldPairCheckpointsMigrateWithoutMarkingNewChecksAsDone()throws Exception{org.json.JSONObject old=new org.json.JSONObject().put("kind","pair").put("gateway","g").put("started",1).put("completed",2).put("state","needs-attention");InstallationProgress p=InstallationProgress.from(old);assertEquals(3,p.completed);assertEquals("Prepare the entry VPN",p.steps()[p.completed]);assertEquals(3,InstallationProgress.from(p.json()).completed);}
    @Test public void pairAdBlockingAndMonitoringAreRealNamedCheckpoints(){String all=java.util.Arrays.toString(new InstallationProgress("pair","g",0).steps());assertTrue(all.contains("ad blocking"));assertTrue(all.contains("monitoring"));}
    @Test public void everyRecipeHasDistinctPurposefulArtworkAndStableTerminalPoses(){
        for(String kind:new String[]{"single","protocol","filter","pair","enroll"}){
            InstallationProgress p=new InstallationProgress(kind,"fixture",0);java.util.Set<String> poses=new java.util.HashSet<>();
            for(int i=0;i<p.steps().length;i++){p.stage(i,p.steps()[i]);assertTrue(kind+" repeats "+p.illustration(),poses.add(p.illustration()));}
            p.phase="translated details do not select artwork";String before=p.illustration();assertEquals(before,p.illustration());p.state="needs-attention";assertEquals("wait",p.illustration());p.finish();assertEquals("celebrate",p.illustration());
        }
    }
    @Test public void trustedCertificatePreparationNeverMovesSingleSetupBackwards(){int previous=0;for(String phase:new String[]{"Installing StrongSwan, DNS and AdGuard Home","Adding management and monitoring","Preparing trusted IKEv2 sign-in"}){int stage=InstallationProgress.singleStage("single",phase);assertTrue(stage>=previous);previous=stage;}assertEquals(3,previous);assertEquals(2,InstallationProgress.singleStage("enroll","Adding management"));}

    @org.junit.Test public void maintenanceKindsKeepTheirOwnCheckpointCountsAndRecoveryCopy()throws Exception{
        for(String kind:new String[]{"lifecycle-exit","lifecycle-entry","paired-os","paired-restore","helper-update"}){
            InstallationProgress progress=new InstallationProgress(kind,"fixture-node",1000);progress.stage(1,"Fixture checkpoint");InstallationProgress restored=InstallationProgress.from(progress.json());org.junit.Assert.assertEquals(kind,restored.kind);org.junit.Assert.assertEquals(1,restored.completed);org.junit.Assert.assertFalse(restored.estimate().isEmpty());
            restored.finishAt(0,5000);org.junit.Assert.assertEquals(restored.steps().length,restored.completed);org.junit.Assert.assertFalse(restored.phase.contains("Server checks passed. Test the VPN"));
        }
    }
}
