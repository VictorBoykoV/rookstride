package org.strongswan.android.rookstride;

import android.content.*;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** Synthetic network state only; no SSH or OS installer can run. */
@RunWith(AndroidJUnit4.class)
public final class OsWipeNetworkTest {
    @Test public void activeOrUnknownVpnCannotLaunchAnyDiskWipe()throws Exception{
        assertFalse(DeploymentService.active());DeploymentService.Session original=DeploymentService.current();OsWipeNetwork.Source source=OsWipeNetwork.source;
        AtomicInteger launches=new AtomicInteger();Context context=new ContextWrapper(InstrumentationRegistry.getInstrumentation().getTargetContext()){@Override public ComponentName startForegroundService(Intent intent){launches.incrementAndGet();return new ComponentName(getPackageName(),DeploymentService.class.getName());}};
        try{for(OsWipeNetwork.State network:new OsWipeNetwork.State[]{new OsWipeNetwork.State(true,false),new OsWipeNetwork.State(false,false),null}){
            OsWipeNetwork.source=ignored->network;
            for(String kind:new String[]{"os","paired-os","paired-restore"}){Gateway node=new Gateway();try{DeploymentService.launch(context,node,new ArrayList<>(),kind,new JSONObject(),false);fail("A disk wipe passed the network guard");}catch(IllegalStateException expected){assertTrue(expected.getMessage().contains("VPN")||expected.getMessage().contains("Connect directly"));}}
        }assertEquals("No foreground worker may start",0,launches.get());assertSame("No operation may be created",original,DeploymentService.current());}
        finally{OsWipeNetwork.source=source;java.lang.reflect.Field current=DeploymentService.class.getDeclaredField("current");current.setAccessible(true);current.set(null,original);}
    }
    @Test public void directNetworkPassesButOrdinaryManagementAndRecordedPollingAreUnaffected(){
        OsWipeNetwork.requireDirect(new OsWipeNetwork.State(false,true));
        OsWipeNetwork.Source source=OsWipeNetwork.source;AtomicInteger inspected=new AtomicInteger();
        try{OsWipeNetwork.source=context->{inspected.incrementAndGet();return new OsWipeNetwork.State(true,false);};
            for(String kind:new String[]{"protocol","pair","filter","lifecycle-entry","lifecycle-exit","helper-update"})OsWipeNetwork.beforeLaunch(null,kind,false);
            for(String kind:new String[]{"os","paired-os","paired-restore"})OsWipeNetwork.beforeLaunch(null,kind,true);
            assertEquals("Routine management and recorded polling need no direct-network guard",0,inspected.get());
        }finally{OsWipeNetwork.source=source;}
    }
}
