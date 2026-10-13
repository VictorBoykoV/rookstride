package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.File;
import java.nio.file.Files;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in pair test; keys and credentials are supplied only through private test files. */
@RunWith(AndroidJUnit4.class)
public class PairIntegrationTest {
 @Test public void trustedTwoNodeInstallAndManagement() throws Exception {
  Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();
  File f=new File(c.getFilesDir(),"pair-integration.json");assumeTrue("No private pair fixture supplied",f.isFile());
  JSONObject fixture=new JSONObject(new String(Files.readAllBytes(f.toPath()),"UTF-8"));
  Gateway entry=new Gateway(fixture.getJSONObject("gateway"));
  for(Gateway node:new Gateway[]{entry,entry.exit}) {
   node.set("fingerprint","");String trusted="";
   try {new Ssh(node).close();fail("Unknown key accepted");}
   catch(Ssh.HostTrust e) {
    assertFalse(e.changed);JSONArray keys=fixture.getJSONArray(node==entry?"entryKeys":"exitKeys");
    for(int i=0;i<keys.length();i++)if(keys.getString(i).equals(e.fingerprint))trusted=e.fingerprint;
    assertFalse("Presented key was not verified through the VM console",trusted.isEmpty());
   }
   node.set("fingerprint","SHA256:wrong-key");
   try{new Ssh(node).close();fail("Changed key accepted");}catch(Ssh.HostTrust e){assertTrue(e.changed);}
   node.set("fingerprint",trusted);
  }
  if(fixture.optBoolean("fresh")) {
   try(Ssh a=new Ssh(entry);Ssh b=new Ssh(entry.exit)) {
    assertFalse(a.probe().getBoolean("existing"));assertFalse(b.probe().getBoolean("pair_helper"));
   }
   Gateway alias=new Gateway(new JSONObject(entry.data.toString()));alias.exit=new Gateway(new JSONObject(entry.data.toString()));alias.exit.privateKey=entry.privateKey;alias.privateKey=entry.privateKey;alias.vpnPassword=entry.vpnPassword;
   try {PairController.install(alias,()->c.getAssets().open("gateway_bundle.zip"),p->{},false);fail("Same machine accepted twice");}
   catch(java.io.IOException e){assertTrue(e.getMessage().contains("distinct machines"));}
  }
  JSONObject installed=PairController.install(entry,()->c.getAssets().open("gateway_bundle.zip"),p->{},true);
  assertTrue(installed.getJSONObject("entry").getBoolean("monitoring_available"));
  try(Ssh a=new Ssh(entry);Ssh b=new Ssh(entry.exit)) {
   assertTrue(a.pair(new JSONObject().put("command","overview").put("pair",entry.get("pairId"))).getBoolean("activated"));
   String login="pair-test-device";
   a.admin(new JSONObject().put("action","add-user").put("login",login).put("password",entry.vpnPassword).put("person","Test person").put("device","Emulator").put("kind","device"));
   try {
    JSONObject profile=a.admin(new JSONObject().put("action","profile").put("login",login));
    assertEquals(1280,profile.getInt("mtu"));assertEquals(entry.data.optInt("vpnPort",500),profile.getJSONObject("remote").optInt("port",500));
    assertTrue(profile.getJSONObject("split-tunneling").getBoolean("block-ipv6"));assertFalse(profile.toString().contains(entry.vpnPassword));
    b.admin(new JSONObject().put("action","adguard").put("level","strong"));
    assertTrue(b.admin(new JSONObject().put("action","adguard").put("level","standard")).getJSONArray("filters").length()>0);
   }finally{a.admin(new JSONObject().put("action","remove-user").put("login",login));}
   JSONObject profile=a.admin(new JSONObject().put("action","profile").put("login",entry.get("vpnLogin")));
   Files.write(new File(c.getFilesDir(),"vpn-test.json").toPath(),new JSONObject().put("profile",profile).put("vpnPassword",entry.vpnPassword).put("holdSeconds",100).toString().getBytes("UTF-8"));
  }
 }
}
