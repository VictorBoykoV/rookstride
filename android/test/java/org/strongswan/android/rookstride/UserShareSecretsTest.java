package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;

public class UserShareSecretsTest {
 @Test public void credentialsAreBoundToServerInstanceAndExactUser(){
  UserShareSecrets state=new UserShareSecrets();state.remember("node-a","instance-1","family","secret");
  assertEquals("secret",state.get("node-a","instance-1","family"));
  assertEquals("",state.get("node-a","instance-2","family"));
  assertEquals("",state.get("node-b","instance-1","family"));
  assertEquals("",state.get("node-a","instance-1","other"));
  state.remember("node-a","","family","unqualified");assertEquals("",state.get("node-a","","family"));
 }
 @Test public void deletingAnAccountOrServerForgetsOnlyItsPasswords(){
  UserShareSecrets state=new UserShareSecrets();state.remember("a","i","one","1");state.remember("a","i","two","2");state.remember("b","i","one","3");
  state.forget("a","i","one");assertEquals("",state.get("a","i","one"));assertEquals("2",state.get("a","i","two"));
  state.forget("a");assertEquals("",state.get("a","i","two"));assertEquals("3",state.get("b","i","one"));
  state.clear();assertEquals("",state.get("b","i","one"));
 }
 @Test public void cacheIsBoundedAndReplacementKeepsTheLatestKnownPassword(){
  UserShareSecrets state=new UserShareSecrets();for(int i=0;i<33;i++)state.remember("a","i","user"+i,"secret"+i);
  assertEquals("",state.get("a","i","user0"));assertEquals("secret32",state.get("a","i","user32"));
  state.remember("a","i","user32","changed");assertEquals("changed",state.get("a","i","user32"));
 }
}
