package org.strongswan.android.rookstride;
import org.json.*;import java.io.*;import java.nio.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.*;
import javax.crypto.*;import javax.crypto.spec.*;
/** Portable authenticated owner backup. No device Keystore dependency on restore. */
public final class OwnerRecovery {
 private OwnerRecovery(){}
 private static final byte[] MAGIC="ROOKREC1".getBytes(StandardCharsets.US_ASCII);
 private static final int ITERATIONS=250000,MAX=2*1024*1024,HEADER=40;
 private static byte[] derive(char[] password,byte[] salt)throws Exception{
  if(password==null||password.length<12)throw new IOException("Use an owner recovery password of at least 12 characters");
  PBEKeySpec spec=new PBEKeySpec(password,salt,ITERATIONS,256);try{return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();}finally{spec.clearPassword();}
 }
 private static Cipher cipher(int mode,byte[] secret,byte[] nonce,byte[] header)throws Exception{Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(mode,new SecretKeySpec(secret,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(header);return cipher;}
 public static byte[] encrypt(JSONObject archive,char[] password)throws Exception{
  validate(archive,archive.optString("deployment"));byte[] plain=archive.toString().getBytes(StandardCharsets.UTF_8);if(plain.length>MAX-HEADER-16)throw new IOException("Owner recovery package is too large");
  byte[] salt=new byte[16],nonce=new byte[12];SecureRandom random=new SecureRandom();random.nextBytes(salt);random.nextBytes(nonce);
  byte[] header=ByteBuffer.allocate(HEADER).put(MAGIC).putInt(ITERATIONS).put(salt).put(nonce).array(),secret=derive(password,salt);
  try{byte[] encrypted=cipher(Cipher.ENCRYPT_MODE,secret,nonce,header).doFinal(plain);ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(header);out.write(encrypted);return out.toByteArray();}finally{Arrays.fill(secret,(byte)0);Arrays.fill(plain,(byte)0);}
 }
 public static JSONObject decrypt(byte[] envelope,char[] password,String deployment)throws Exception{
  if(envelope.length<HEADER+16||envelope.length>MAX||!Arrays.equals(MAGIC,Arrays.copyOfRange(envelope,0,8))||ByteBuffer.wrap(envelope,8,4).getInt()!=ITERATIONS)throw new IOException("This is not a supported owner recovery package");
  byte[] header=Arrays.copyOfRange(envelope,0,HEADER),salt=Arrays.copyOfRange(envelope,12,28),nonce=Arrays.copyOfRange(envelope,28,40),secret=derive(password,salt),plain=null;
  try{plain=cipher(Cipher.DECRYPT_MODE,secret,nonce,header).doFinal(Arrays.copyOfRange(envelope,HEADER,envelope.length));JSONObject archive=new JSONObject(new String(plain,StandardCharsets.UTF_8));validate(archive,deployment);return archive;}finally{Arrays.fill(secret,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
 }
 public static void validate(JSONObject archive,String deployment)throws Exception{
  if(archive.optInt("schema")!=1||!archive.optString("purpose").equals("rookstride-owner-recovery")||!InputRules.job(archive.optString("deployment"))||!archive.optString("deployment").equals(deployment))throw new IOException("Owner recovery belongs to another deployment or file purpose");
  JSONObject nodes=archive.getJSONObject("nodes");for(String role:new String[]{"entry","exit"}){JSONObject node=nodes.getJSONObject(role);if(!node.optString("purpose").equals("rookstride-owner-recovery-node")||!node.optString("deployment").equals(deployment)||!node.optString("role").equals(role))throw new IOException("Owner recovery is missing a matching pair member");}
 }
 /** Rechecked locally on every resume, before opening an erase adapter. The
  * initial review also validates the complete bridge keys on the owner helper. */
 public static void validateRestore(Gateway pair,JSONObject archive)throws Exception{
  validate(archive,pair.get("pairId"));
  if(!PairController.modern(pair))throw new IOException("Recovery requires an owned native Double VPN");
  for(String role:new String[]{"entry","exit"}){
   JSONObject node=archive.getJSONObject("nodes").getJSONObject(role),state=node.getJSONObject("state"),initial=node.optJSONObject("initial_user"),plan=node.getJSONObject("plan");
   if(initial==null||!InputRules.username(initial.optString("login"))||initial.optString("password").isEmpty()||!initial.optString("login").equals(state.optString("initialLogin")))throw new IOException("Recovery is missing matching initial-user bootstrap metadata");
   String protocol=role.equals("entry")?pair.get("pairEntryProtocol"):pair.get("pairExitProtocol");if(!state.optString("protocol").equals(protocol)||(node.optInt("schema")!=1&&node.optInt("schema")!=2)||node.optInt("schema")==1&&!protocol.equals("awg")||node.optInt("schema")==2&&!node.optString("adapter").equals(protocol+"-identity-v1"))throw new IOException("This recovery file has no matching versioned protocol identity");
   JSONObject target=PairController.request(pair,role).put("client_pool","10.66.0.0/24").put("test_ip","10.249.255.254").put("entry_address","10.253.0.2/30").put("exit_address","10.253.0.1/30").put("route_table",51831);
   for(String field:new String[]{"pair","role","server","exit_host","vpn_port","tunnel_port","entry_protocol","exit_protocol","engine","access_mode","client_pool","test_ip","entry_address","exit_address","route_table"})if(!target.optString(field).equals(plan.optString(field)))throw new IOException("Recovery archive does not match the planned deployment endpoints, ports or protocol contract");
  }
 }
 public static JSONObject capture(Gateway pair,PairController.Bundle bundle,PairController.Progress progress)throws Exception{
  JSONObject nodes=new JSONObject();try(PairSsh sessions=PairSsh.connect(pair,progress)){
   for(String role:new String[]{"entry","exit"})try(InputStream in=bundle.open()){nodes.put(role,(role.equals("entry")?sessions.entry:sessions.exit).recovery(in,new JSONObject().put("action","export")));}
  }
  JSONObject archive=new JSONObject().put("schema",1).put("purpose","rookstride-owner-recovery").put("deployment",pair.get("pairId")).put("revision",pair.data.optInt("deploymentRevision",1)).put("created",System.currentTimeMillis()).put("nodes",nodes);validate(archive,pair.get("pairId"));return archive;
 }
 public static JSONObject rehearse(Gateway pair,JSONObject archive,PairController.Bundle bundle,PairController.Progress progress)throws Exception{
  validateRestore(pair,archive);JSONObject plans=new JSONObject();for(String role:new String[]{"entry","exit"})plans.put(role,PairController.request(pair,role));
  try(PairSsh sessions=PairSsh.connect(pair,progress);InputStream in=bundle.open()){return sessions.entry.recovery(in,new JSONObject().put("action","rehearse-pair").put("archive",archive).put("plans",plans));}
 }
}
