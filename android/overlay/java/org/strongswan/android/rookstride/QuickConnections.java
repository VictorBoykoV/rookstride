package org.strongswan.android.rookstride;
import java.util.*;
/** Stable favorite ordering; installing or resetting a protocol never exposes a stale shortcut. */
public final class QuickConnections {
 private QuickConnections(){}
 public static boolean ready(Gateway n){return n.data.optBoolean("clientOnly")||n.data.optBoolean("pairReady")||!n.get("profileUuid").isEmpty()||n.data.optJSONObject("snapshot")!=null&&n.data.optJSONObject("snapshot").has("services");}
 public static List<Gateway> list(List<Gateway> all,Gateway recent){return list(all,recent,QuickConnections::ready);}
 public static List<Gateway> list(List<Gateway> all,Gateway recent,java.util.function.Predicate<Gateway> eligible){
  LinkedHashMap<String,Gateway> out=new LinkedHashMap<>();if(recent!=null)for(Gateway n:all)if(n.get("id").equals(recent.get("id"))&&eligible.test(n)){out.put(n.get("id"),n);break;}for(Gateway n:all)if(n.data.optBoolean("favorite")&&eligible.test(n))out.put(n.get("id"),n);
  return new ArrayList<>(out.values());
 }
 /** Removal is durable: reinstalling a protocol does not silently star it again. */
 public static void forget(Gateway node){node.data.remove("favorite");}
}
