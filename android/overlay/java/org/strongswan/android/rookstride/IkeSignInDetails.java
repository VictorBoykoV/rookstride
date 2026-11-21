package org.strongswan.android.rookstride;
import org.json.JSONObject;
/** Human-readable account details preserve the distinction between public and private server trust. */
public final class IkeSignInDetails {
 private IkeSignInDetails(){}
 public static String from(JSONObject profile){
  if(profile==null||!profile.optString("type").equals("ikev2-eap"))return null;
  JSONObject remote=profile.optJSONObject("remote"),local=profile.optJSONObject("local");
  if(remote==null||local==null||!InputRules.host(remote.optString("addr"))||!InputRules.username(local.optString("eap_id"))||local.optString("shared_secret").isEmpty())return null;
  return "VPN type: IKEv2 EAP (Username/Password)\nServer: "+remote.optString("addr")+(remote.optInt("port",500)==500?"":"\nPort: "+remote.optInt("port"))+"\nUsername: "+local.optString("eap_id")+"\nPassword: "+local.optString("shared_secret")+
   (remote.has("cert")?"\nServer certificate: Import the accompanying .sswan connection file first. These details alone do not include the certificate needed to verify this VPN.":"\nCA certificate: Select automatically");
 }
}
