package org.strongswan.android.rookstride;
import org.json.*;
import java.util.*;
/** Bounded local activity metadata. No endpoints, credentials or raw server replies. */
public final class ActivityHistory {
 public static final class Completion {
  public final String title;public final long time;
  private Completion(String title,long time){this.title=title;this.time=time;}
 }
 /** A late discovery must not claim the earlier server operation happened now. */
 public static Completion completion(String title,long started,long finished,long now){
  boolean confirmed=finished>0&&finished>=started&&finished<=now;
  return new Completion(confirmed?title:"Previous setup result found",confirmed?finished:now);
 }
 public static JSONArray append(JSONArray old,String title,String record,String protocol,long time)throws JSONException{
  List<JSONObject> events=new ArrayList<>();events.add(new JSONObject().put("title",title).put("record",record).put("protocol",protocol).put("time",time));
  for(int i=0;i<old.length();i++){JSONObject previous=old.optJSONObject(i);if(previous!=null)events.add(previous);}
  // Stable sort keeps existing equal-time order. The newly recorded event wins
  // its tie, matching ordinary newest-first insertion. Never rewrite old data.
  events.sort((first,second)->Long.compare(second.optLong("time",Long.MIN_VALUE),first.optLong("time",Long.MIN_VALUE)));
  JSONArray out=new JSONArray();for(int i=0;i<Math.min(50,events.size());i++)out.put(events.get(i));return out;
 }
 private ActivityHistory(){}
}
