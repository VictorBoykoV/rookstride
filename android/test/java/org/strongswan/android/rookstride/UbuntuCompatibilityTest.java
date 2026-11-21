package org.strongswan.android.rookstride;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;
public class UbuntuCompatibilityTest {
 @Test public void independentModernVersionsAndPointReleasesPass()throws Exception{
  for(String v:new String[]{"22.04","22.04.5","24.04","26.04","26.10","28.04"})UbuntuCompatibility.require(new JSONObject().put("os","ubuntu").put("version",v),true);
 }
 @Test public void malformedUnsupportedAndLegacyMixesStop()throws Exception{
  for(String[] v:new String[][]{{"debian","13"},{"ubuntu","20.04"},{"ubuntu","rolling"},{"ubuntu","22.99"},{"ubuntu","26.04;reboot"}})assertFalse(UbuntuCompatibility.eligible(v[0],v[1]));
  try{UbuntuCompatibility.require(new JSONObject().put("os","ubuntu").put("version","26.04"),false);fail();}catch(java.io.IOException expected){}
 }
 @Test public void explicitModernIkeToAwgKeepsLegacyRecordsSeparate()throws Exception{
  Gateway g=new Gateway();g.exit=new Gateway();g.set("pairId","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");g.set("host","entry.example.net");g.exit.set("host","exit.example.net");g.set("pairEntryProtocol","ikev2");g.set("pairExitProtocol","awg");
  assertFalse(PairController.modern(g));assertFalse(PairController.request(g,"entry").has("engine"));g.set("pairEngine","native-v2");assertTrue(PairController.modern(g));assertEquals("native-v2",PairController.request(g,"entry").getString("engine"));
 }
}
