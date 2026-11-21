package org.strongswan.android.rookstride;
/** Retry only connection establishment. Never replay a user/server command. */
public final class AdminConnection implements AutoCloseable {
 public final Ssh ssh;private final PairSsh pair;
 private AdminConnection(Ssh ssh,PairSsh pair){this.ssh=ssh;this.pair=pair;}
 static boolean explicitRelay(Gateway node,Gateway parent){
  if(parent==null||!parent.isPair())return false;
  return parent.get("sshRoute").equals("entry-via-exit")&&PairNodes.same(node,parent)||parent.get("sshRoute").equals("exit-via-entry")&&PairNodes.same(node,parent.exit);
 }
 private static AdminConnection paired(Gateway node,Gateway parent,PairController.Progress progress)throws Exception{
  try{PairSsh sessions=PairSsh.connect(parent,progress);return new AdminConnection(PairNodes.same(node,parent)?sessions.entry:sessions.exit,sessions);}
  catch(PairController.TrustNeeded e){throw e.issue;}
 }
 public static AdminConnection open(Gateway node,Gateway parent,PairController.Progress progress)throws Exception{
  if(explicitRelay(node,parent))return paired(node,parent,progress);
  try{return new AdminConnection(new Ssh(node),null);}
  catch(Ssh.Unreachable failure){
   if(parent==null||!parent.isPair()||!PairNodes.same(node,parent)&&!PairNodes.same(node,parent.exit)||!parent.get("sshRoute").isEmpty()&&!parent.get("sshRoute").equals("auto"))throw failure;
   return paired(node,parent,progress);
  }
 }
 @Override public void close(){if(pair!=null)pair.close();else ssh.close();}
}
