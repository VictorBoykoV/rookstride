package org.strongswan.android.rookstride;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
public class ServerOrderTest {
 private Gateway server(String host,String protocol)throws Exception{Gateway n=new Gateway();n.set("host",host);n.set("protocol",protocol);n.set("admin","root");return n;}
 @Test public void movingAServerKeepsAllProtocolRecordsAndCredentialsTogether()throws Exception{
  Gateway a=server("one.example.net","ikev2"),b=server("two.example.net","xray"),aa=ServerProtocols.create(a,SingleProtocols.AWG),c=server("three.example.net","openvpn");aa.sshPassword="fixture-only";
  ArrayList<Gateway> nodes=new ArrayList<>(Arrays.asList(a,b,aa,c));assertTrue(ServerOrder.move(nodes,a,c,true));assertEquals(Arrays.asList(b,c,a,aa),nodes);assertEquals("fixture-only",nodes.get(3).sshPassword);assertEquals(Arrays.asList(b,c,a),ServerProtocols.servers(nodes));
  assertTrue(ServerOrder.move(nodes,a,b,false));assertEquals(Arrays.asList(a,aa,b,c),nodes);
 }
 @Test public void importedAndPairedRecordsNeverBecomeOneServerBecauseHostsMatch()throws Exception{
  Gateway a=server("one.example.net","ikev2"),imported=server("one.example.net","ikev2"),pair=server("one.example.net","ikev2");imported.data.put("clientOnly",true);pair.exit=server("exit.example.net","ikev2");
  ArrayList<Gateway> nodes=new ArrayList<>(Arrays.asList(a,imported,pair));assertTrue(ServerOrder.move(nodes,pair,a,false));assertEquals(Arrays.asList(pair,a,imported),nodes);
 }
 @Test public void cancelledOrSameServerMovesDoNotLoseRecords()throws Exception{
  Gateway a=server("one.example.net","ikev2"),aa=ServerProtocols.create(a,SingleProtocols.AWG),absent=server("absent.example.net","xray");ArrayList<Gateway> nodes=new ArrayList<>(Arrays.asList(a,aa));
  assertFalse(ServerOrder.move(nodes,a,aa,true));assertFalse(ServerOrder.move(nodes,a,absent,false));assertEquals(Arrays.asList(a,aa),nodes);
 }
}
