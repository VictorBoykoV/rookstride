package org.strongswan.android.rookstride;
import java.io.IOException;
/** Read-only discovery. A retry may open SSH, never replay a server command. */
public final class PairSsh implements AutoCloseable {
 public final Ssh entry,exit;
 private PairSsh(Ssh a,Ssh b){entry=a;exit=b;a.artifactPeer=b;b.artifactPeer=a;}
 private static Ssh open(Gateway node)throws Exception{try{return new Ssh(node);}catch(Ssh.HostTrust e){throw new PairController.TrustNeeded(e.node==null?node:e.node,e);}}
 private static final class Attempt{Ssh ssh;Exception error;}
 private static Attempt attempt(Gateway node,java.util.concurrent.atomic.AtomicBoolean abandoned,java.util.concurrent.atomic.AtomicReferenceArray<Ssh> opened,int index){Attempt result=new Attempt();try{result.ssh=open(node);opened.set(index,result.ssh);if(abandoned.get()){result.ssh.close();result.ssh=null;}}catch(Exception e){result.error=e;}return result;}
 public static PairSsh connect(Gateway pair,PairController.Progress progress)throws Exception{
  if(pair.exit==null)throw new IOException("Add both servers first");
  if(!pair.get("sshRoute").isEmpty()&&!pair.get("sshRoute").equals("auto")){
   pair.configureRelay();Ssh a=open(pair);try{return new PairSsh(a,open(pair.exit));}catch(Exception e){a.close();throw e;}
  }
  pair.sshRelay=null;pair.exit.sshRelay=null;Ssh a=null,b=null;Ssh.Unreachable first=null,second=null;
  try{
   java.util.concurrent.ExecutorService checks=java.util.concurrent.Executors.newFixedThreadPool(2);
   java.util.concurrent.atomic.AtomicBoolean abandoned=new java.util.concurrent.atomic.AtomicBoolean(false);
   java.util.concurrent.atomic.AtomicReferenceArray<Ssh> opened=new java.util.concurrent.atomic.AtomicReferenceArray<>(2);
   java.util.concurrent.Future<Attempt> fa=checks.submit(()->attempt(pair,abandoned,opened,0)),fb=checks.submit(()->attempt(pair.exit,abandoned,opened,1));
   Attempt aa=null,bb=null;
   try{aa=fa.get(30,java.util.concurrent.TimeUnit.SECONDS);bb=fb.get(30,java.util.concurrent.TimeUnit.SECONDS);a=aa.ssh;b=bb.ssh;}
   finally{abandoned.set(true);checks.shutdownNow();if(aa==null||bb==null)for(int i=0;i<2;i++)if(opened.get(i)!=null)opened.get(i).close();}
   if(aa.error!=null){if(aa.error instanceof Ssh.Unreachable)first=(Ssh.Unreachable)aa.error;else throw aa.error;}
   if(bb.error!=null){if(bb.error instanceof Ssh.Unreachable)second=(Ssh.Unreachable)bb.error;else throw bb.error;}
   String route="direct";
   if(a==null&&b==null)throw new IOException("Neither server answered SSH. Check their addresses and your network, then try again.",first);
   if(a==null){progress.update("Connecting to entry through exit");pair.sshRelay=pair.exit;a=open(pair);route="entry-via-exit";}
   else if(b==null){progress.update("Connecting to exit through entry");pair.exit.sshRelay=pair;b=open(pair.exit);route="exit-via-entry";}
   pair.set("resolvedSshRoute",route);return new PairSsh(a,b);
  }catch(Exception e){if(a!=null)a.close();if(b!=null)b.close();throw e;}
 }
 /** Open a management node independently, falling back only on transport failure. */
 public static Ssh connectNode(Gateway node,Gateway relay,PairController.Progress progress)throws Exception{
  return connectNode(node,relay,progress,PairSsh::open);
 }
 /** This same connection-order seam is used by production and focused tests. */
 interface NodeOpener<T>{T open(Gateway node)throws Exception;}
 static <T> T connectNode(Gateway node,Gateway relay,PairController.Progress progress,NodeOpener<T> opener)throws Exception{
  Gateway direct=PairNodes.copy(node);direct.sshRelay=null;
  try{return openNode(direct,node,null,opener);}catch(Ssh.Unreachable failure){
   if(relay==null)throw failure;
   Gateway hop=PairNodes.copy(relay);hop.sshRelay=null;direct.sshRelay=hop;progress.update("Connecting through the pinned management relay");return openNode(direct,node,relay,opener);
  }
 }
 private static boolean sameAttempt(Gateway copy,Gateway original){
  return copy!=null&&original!=null&&!original.get("id").isEmpty()&&copy.get("id").equals(original.get("id"))&&copy.get("host").equalsIgnoreCase(original.get("host"))&&copy.port()==original.port()&&copy.get("admin").equals(original.get("admin"));
 }
 private static <T> T openNode(Gateway attempt,Gateway node,Gateway relay,NodeOpener<T> opener)throws Exception{
  try{return opener.open(attempt);}catch(PairController.TrustNeeded needed){
   Gateway presented=needed.issue.node==null?needed.node:needed.issue.node;
   Gateway original=sameAttempt(presented,node)?node:sameAttempt(presented,relay)?relay:null;
   if(original==null)throw new IOException("The SSH identity does not belong to this connection attempt",needed);
   // Pin the actual draft/member, not a temporary connection copy. Never adopt
   // the presented key here: the existing first-use/changed-key UI owns trust.
   throw new PairController.TrustNeeded(original,new Ssh.HostTrust(needed.issue.fingerprint,needed.issue.changed,original));
  }
 }
 @Override public void close(){exit.close();entry.close();}
}
