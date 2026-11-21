package org.strongswan.android.rookstride.engine;
import android.content.Context;
import android.os.Bundle;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class EngineJournalTest {
 @Test public void interruptedProcessRetainsDiagnosticsButNeverClaimsAConnection(){
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();String protocol="owned-test-fixture";
  try{
   EngineJournal journal=new EngineJournal(c,protocol);journal.desired("fixture-id");journal.save("fixture-id","connected","","Handshake established");
   EngineJournal recovered=new EngineJournal(c,protocol);assertEquals("fixture-id",recovered.desired());Bundle state=recovered.previous();
   assertEquals("interrupted",state.getString("state"));assertTrue(state.getBoolean("desired"));assertTrue(state.getString("log").contains("Handshake established"));assertTrue(state.getString("error").contains("Android stopped"));
   recovered.desired("");recovered.save("fixture-id","disconnected","","Disconnect requested");assertEquals("",new EngineJournal(c,protocol).desired());assertEquals("disconnected",new EngineJournal(c,protocol).previous().getString("state"));assertFalse(new EngineJournal(c,protocol).previous().getBoolean("desired"));
  }finally{c.getSharedPreferences("engine-journal-"+protocol,0).edit().clear().commit();}
 }
}
