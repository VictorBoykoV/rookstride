package org.strongswan.android.rookstride;
import org.junit.Test;
import org.json.*;
import static org.junit.Assert.*;
public class ActivityHistoryTest {
 @Test public void boundedNewestFirstMetadata()throws Exception{JSONArray h=new JSONArray();for(int i=0;i<70;i++)h=ActivityHistory.append(h,"Server refreshed","opaque-id","awg",i);assertEquals(50,h.length());assertEquals(69,h.getJSONObject(0).getLong("time"));assertEquals(20,h.getJSONObject(49).getLong("time"));assertEquals(4,h.getJSONObject(0).length());}
 private JSONObject event(String title,long time)throws Exception{return new JSONObject().put("title",title).put("time",time).put("untouched",new JSONObject().put("note","retained"));}
 @Test public void backdatedCompletionJoinsChronologyWithoutRewritingOldObjects()throws Exception{
  JSONObject newer=event("Newer action",300),older=event("Earlier action",100);JSONArray original=new JSONArray().put(newer).put(older);String before=original.toString();
  ActivityHistory.Completion completion=ActivityHistory.completion("VPN installed",90,200,1000);JSONArray result=ActivityHistory.append(original,completion.title,"opaque","awg",completion.time);
  assertEquals(before,original.toString());assertSame(newer,result.getJSONObject(0));assertEquals("VPN installed",result.getJSONObject(1).getString("title"));assertEquals(200,result.getJSONObject(1).getLong("time"));assertSame(older,result.getJSONObject(2));assertEquals("retained",older.getJSONObject("untouched").getString("note"));
 }
 @Test public void latestFiftyAreSelectedAcrossTheWholeUnsortedHistory()throws Exception{
  JSONArray original=new JSONArray();for(int i=1;i<=70;i++)original.put(event("Existing "+i,i));String before=original.toString();
  JSONArray result=ActivityHistory.append(original,"Old completed setup","opaque","awg",0);assertEquals(50,result.length());assertEquals(70,result.getJSONObject(0).getLong("time"));assertEquals(21,result.getJSONObject(49).getLong("time"));assertEquals(before,original.toString());
  for(int i=1;i<result.length();i++)assertTrue(result.getJSONObject(i-1).getLong("time")>=result.getJSONObject(i).getLong("time"));
 }
 @Test public void equalTimesKeepExistingOrderAndPutTheNewlyRecordedEventFirst()throws Exception{
  JSONObject first=event("First existing",100),second=event("Second existing",100);JSONArray old=new JSONArray().put(first).put(second);
  JSONArray result=ActivityHistory.append(old,"New same-millisecond event","opaque","awg",100);assertEquals("New same-millisecond event",result.getJSONObject(0).getString("title"));assertSame(first,result.getJSONObject(1));assertSame(second,result.getJSONObject(2));
 }
 @Test public void legacyInvalidTimestampObjectsArePreservedWithoutInventingCurrentTimes()throws Exception{
  JSONObject unknown=new JSONObject().put("title","Legacy unknown").put("time","unknown"),negative=event("Legacy negative",-5),missing=new JSONObject().put("title","Missing time");JSONArray old=new JSONArray().put(unknown).put(negative).put(missing);String before=old.toString();
  JSONArray result=ActivityHistory.append(old,"Current action","opaque","awg",100);assertEquals(4,result.length());assertEquals(100,result.getJSONObject(0).getLong("time"));assertSame(negative,result.getJSONObject(1));assertSame(unknown,result.getJSONObject(2));assertSame(missing,result.getJSONObject(3));assertEquals(before,old.toString());assertFalse(missing.has("time"));
 }
 @Test public void confirmedFinishTimeUsesTheServerResultInsteadOfFirstDisplayTime(){
  ActivityHistory.Completion result=ActivityHistory.completion("Maintenance complete",100,200,10000);assertEquals("Maintenance complete",result.title);assertEquals(200,result.time);
  assertEquals(100,ActivityHistory.completion("VPN installed",100,100,10000).time);assertEquals(10000,ActivityHistory.completion("VPN installed",100,10000,10000).time);
 }
 @Test public void missingPreStartOrFutureFinishBecomesAnExplicitDiscoveryAtNow(){
  for(long finish:new long[]{0,-1,99,1001,Long.MAX_VALUE}){ActivityHistory.Completion result=ActivityHistory.completion("VPN installed",100,finish,1000);assertEquals("Previous setup result found",result.title);assertEquals(1000,result.time);}
 }
 @Test public void timeComparisonDoesNotOverflowAndDoesNotRewriteHistoricalFutureEvents()throws Exception{
  assertEquals(Long.MAX_VALUE,ActivityHistory.completion("VPN installed",Long.MAX_VALUE-1,Long.MAX_VALUE,Long.MAX_VALUE).time);
  assertEquals("Previous setup result found",ActivityHistory.completion("VPN installed",Long.MAX_VALUE-1,Long.MAX_VALUE,Long.MAX_VALUE-1).title);
  JSONObject future=event("Historical future",Long.MAX_VALUE),past=event("Historical past",Long.MIN_VALUE);JSONArray old=new JSONArray().put(past).put(future);String before=old.toString();JSONArray result=ActivityHistory.append(old,"Current action","opaque","awg",1);assertSame(future,result.getJSONObject(0));assertEquals(1,result.getJSONObject(1).getLong("time"));assertSame(past,result.getJSONObject(2));assertEquals(before,old.toString());
 }
}
