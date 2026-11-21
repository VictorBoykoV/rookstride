package org.strongswan.android.rookstride;
import org.junit.Test;import org.json.JSONObject;import java.io.IOException;import static org.junit.Assert.*;

public class MaintenanceUpdatesTest {
 private Gateway operation(String state)throws Exception{Gateway pair=new Gateway();pair.data.put("helperUpdate",new JSONObject().put("state",state));return pair;}
 @Test public void preparedPairCannotCommitAcceptanceBeforeBothVerify()throws Exception{
  Gateway pair=operation("prepared");
  try{MaintenanceUpdates.finish(pair,false,()->{throw new AssertionError("No upload");},s->{},()->{throw new AssertionError("No state change");});fail();}
  catch(IOException e){assertTrue(e.getMessage().contains("Verify both"));}
  assertEquals("prepared",pair.data.getJSONObject("helperUpdate").getString("state"));
 }
 @Test public void partialAcceptanceCannotBeChangedToRollback()throws Exception{
  for(boolean rollback:new boolean[]{true,false}){
   Gateway pair=operation(rollback?"accepting":"rolling-back");
   try{MaintenanceUpdates.finish(pair,rollback,()->{throw new AssertionError("No upload");},s->{},()->{throw new AssertionError("No state change");});fail();}
   catch(IOException e){assertTrue(e.getMessage().contains("Resume the recorded"));}
  }
 }
 @Test public void partialCompletionCannotBeReapplied()throws Exception{
  Gateway pair=operation("accepting");
  try{MaintenanceUpdates.apply(pair,new JSONObject(),()->{throw new AssertionError("No upload");},s->{},()->{throw new AssertionError("No state change");});fail();}
  catch(IOException e){assertTrue(e.getMessage().contains("Resume the recorded"));}
 }
}
