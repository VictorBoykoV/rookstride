package org.strongswan.android.rookstride;
import org.json.*;import java.util.*;import org.junit.Test;import static org.junit.Assert.*;
public class QuickConnectionsTest {
 private Gateway ready(String id,boolean favorite)throws Exception{Gateway n=new Gateway();n.set("id",id);n.data.put("favorite",favorite);n.data.put("snapshot",new JSONObject().put("services",new JSONObject()));return n;}
 @Test public void favoritesAndRecentAreUniqueAndStableDuringStatusChanges()throws Exception{Gateway a=ready("a",true),b=ready("b",true),c=ready("c",false);List<Gateway> all=Arrays.asList(a,b,c);assertEquals(Arrays.asList(c,a,b),QuickConnections.list(all,c));assertEquals(Arrays.asList(a,b),QuickConnections.list(all,a));a.set("checked","now");assertEquals(Arrays.asList(b,a),QuickConnections.list(all,b));}
 @Test public void resetDoesNotKeepDeadFavoriteShortcuts()throws Exception{Gateway a=ready("a",true),b=ready("b",false);a.data.remove("snapshot");assertEquals(Collections.singletonList(b),QuickConnections.list(Arrays.asList(a,b),b));QuickConnections.forget(a);assertFalse(a.data.optBoolean("favorite"));a.data.put("snapshot",new JSONObject().put("services",new JSONObject()));assertEquals(Collections.singletonList(b),QuickConnections.list(Arrays.asList(a,b),b));}
 @Test public void deletedRecentIsNotReintroducedByAnOldReference()throws Exception{Gateway removed=ready("deleted",true),kept=ready("kept",true);assertEquals(Collections.singletonList(kept),QuickConnections.list(Collections.singletonList(kept),removed));}
 @Test public void recentUsesTheCurrentSavedRecordRatherThanAStaleSnapshot()throws Exception{Gateway old=ready("same",true),current=ready("same",false);current.data.remove("snapshot");assertTrue(QuickConnections.list(Collections.singletonList(current),old).isEmpty());}
 @Test public void restoredPairAndContextCheckedCachedProfilesRemainEligible()throws Exception{
  Gateway restored=new Gateway(),cached=new Gateway(),draft=new Gateway();restored.set("id","restored");cached.set("id","cached");draft.set("id","draft");restored.data.put("pairReady",true);cached.data.put("favorite",true);draft.data.put("favorite",true);
  List<Gateway> all=Arrays.asList(restored,cached,draft);assertEquals(Collections.singletonList(restored),QuickConnections.list(all,restored));
  assertEquals(Arrays.asList(restored,cached),QuickConnections.list(all,restored,n->QuickConnections.ready(n)||n.get("id").equals("cached")));
 }
}
