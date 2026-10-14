package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;
public class InstallationProgressTest {
    @Test public void recipesHaveDistinctCheckpoints(){assertEquals(8,new InstallationProgress("pair","g",0).steps().length);assertEquals(5,new InstallationProgress("single","g",0).steps().length);assertEquals(4,new InstallationProgress("enroll","g",0).steps().length);}
    @Test public void waitsNeverInventCompletion(){InstallationProgress p=new InstallationProgress("pair","g",0);p.stage(1,"Downloading packages");assertEquals(12,p.percent());assertEquals(7,p.steps().length-p.completed);assertEquals(12,p.percent());assertTrue(p.estimate().contains("Planning range"));}
    @Test public void terminalAndRebootStatesDoNotCountAsDone(){InstallationProgress p=new InstallationProgress("pair","g",0);p.stage(2,"Preparing entry");p.state="awaiting-reboot";assertTrue(p.estimate().contains("paused"));assertEquals(25,p.percent());p.finish();assertEquals(100,p.percent());assertEquals("complete",p.state);}
    @Test public void savedProgressHasNoLoginOrHostSecrets(){InstallationProgress p=new InstallationProgress("single","random-id",1000);p.stage(3,"Adding management");String raw=p.json().toString();assertFalse(raw.contains("password"));assertFalse(raw.contains("host"));InstallationProgress q=InstallationProgress.from(p.json());assertEquals(3,q.completed);assertEquals(1000,q.started);assertEquals("Elapsed 1m 1s",q.elapsed(62000));}
}
