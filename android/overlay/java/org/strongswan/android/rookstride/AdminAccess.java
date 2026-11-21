package org.strongswan.android.rookstride;

import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** Administrative files are enrollment credentials, never VPN connection files. */
public final class AdminAccess {
    public static final int SCHEMA=1;
    public static final String PURPOSE="rookstride.admin.invitation";
    private AdminAccess() {}
    private static void require(boolean valid,String text)throws Exception{if(!valid)throw new java.io.IOException(text);}
    public static JSONObject parseInvitation(String text)throws Exception {
        require(text!=null&&text.getBytes(StandardCharsets.UTF_8).length<=65536,"Administrator invitation is too large");
        JSONObject value=new JSONObject(text);
        require(PURPOSE.equals(value.optString("purpose"))&&value.optInt("schema")==SCHEMA,"This is not a compatible administrator invitation");
        require(value.optString("invitation_id").matches("inv-[a-f0-9]{32}"),"Invalid invitation identity");
        require(value.optString("server_id").matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"),"Invalid server identity");
        require(value.optLong("expires")>System.currentTimeMillis()/1000,"This administrator invitation has expired");
        JSONObject endpoint=value.getJSONObject("endpoint");
        require(endpoint.optString("host").matches("[A-Za-z0-9][A-Za-z0-9.:-]{0,252}"),"Invalid administrator server address");
        require(endpoint.optInt("port")>0&&endpoint.optInt("port")<=65535,"Invalid administrator SSH port");
        require(endpoint.optString("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}"),"Administrator invitation requires a pinned SSH identity");
        JSONObject bootstrap=value.getJSONObject("bootstrap");
        require(bootstrap.optString("account").matches("rsb[a-f0-9]{20}"),"Invalid enrollment credential");
        String key=bootstrap.optString("private_key");
        require(key.length()<8192&&key.startsWith("-----BEGIN RSA PRIVATE KEY-----\n")&&key.trim().endsWith("-----END RSA PRIVATE KEY-----"),"Invalid enrollment private key");
        JSONObject scope=value.getJSONObject("scope");
        require(scope.optString("kind").matches("protocol|deployment|server")&&scope.optString("id").matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"),"Invalid invitation scope");
        require(value.optString("role").matches("infrastructure|user_manager|viewer"),"Unsupported administrator role");
        return value;
    }
    public static JSONObject newDeviceKey()throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
        KeyPair pair=generator.generateKeyPair();RSAPublicKey publicKey=(RSAPublicKey)pair.getPublic();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        field(out,"ssh-rsa".getBytes(StandardCharsets.US_ASCII));field(out,publicKey.getPublicExponent().toByteArray());field(out,publicKey.getModulus().toByteArray());
        String pem="-----BEGIN PRIVATE KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(pair.getPrivate().getEncoded())+"\n-----END PRIVATE KEY-----\n";
        return new JSONObject().put("private_key",pem).put("public_key","ssh-rsa "+Base64.getEncoder().encodeToString(bytes.toByteArray()));
    }
    private static void field(DataOutputStream stream,byte[] value)throws Exception{stream.writeInt(value.length);stream.write(value);}
    public static String fingerprint(String publicKey)throws Exception {
        byte[] wire=Base64.getDecoder().decode(publicKey.split(" ")[1]);
        return "SHA256:"+Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(wire));
    }
    public static String prove(JSONObject challenge,String publicKey,String privateKey)throws Exception {
        String message="rookstride-admin-enroll-v1\n"+challenge.getString("invitation_id")+"\n"+challenge.getString("server_id")+"\n"+challenge.getString("nonce")+"\n"+fingerprint(publicKey)+"\n";
        String base=privateKey.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replaceAll("\\s","");
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initSign(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base))));
        signature.update(message.getBytes(StandardCharsets.UTF_8));return Base64.getEncoder().encodeToString(signature.sign());
    }
}
