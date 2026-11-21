package org.strongswan.android.rookstride;
import org.json.JSONObject;
import org.strongswan.android.data.VpnProfile;
/** Exact stored client identity snapshot; used only in app-private acceptance data. */
final class IkeProfileIdentityTestSupport {
 static JSONObject snapshot(VpnProfile p)throws Exception{return new JSONObject().put("uuid",p.getUUID().toString()).put("gateway",p.getGateway()).put("username",p.getUsername()).put("password",p.getPassword()).put("type",p.getVpnType().getIdentifier()).put("ca",p.getCertificateAlias()==null?JSONObject.NULL:p.getCertificateAlias()).put("user_certificate",p.getUserCertificateAlias()==null?JSONObject.NULL:p.getUserCertificateAlias()).put("remote_id",p.getRemoteId()==null?JSONObject.NULL:p.getRemoteId()).put("local_id",p.getLocalId()==null?JSONObject.NULL:p.getLocalId()).put("port",p.getPort()==null?JSONObject.NULL:p.getPort()).put("mtu",p.getMTU()==null?JSONObject.NULL:p.getMTU()).put("flags",p.getFlags()==null?JSONObject.NULL:p.getFlags()).put("split",p.getSplitTunneling()==null?JSONObject.NULL:p.getSplitTunneling());}
 static boolean same(JSONObject a,JSONObject b){if(a.length()!=b.length())return false;java.util.Iterator<String> keys=a.keys();while(keys.hasNext()){String key=keys.next();if(!java.util.Objects.equals(a.opt(key),b.opt(key)))return false;}return true;}
}
