package org.strongswan.android.rookstride;
import android.content.Context;import org.strongswan.android.data.*;
/** Apply an SSH-verified private-to-public migration without discarding the VPN login. */
public final class IkeProfileTrust {
 private IkeProfileTrust(){}
 public static void usePublicCa(Context context,Gateway node)throws Exception{
  if(node.get("profileUuid").isEmpty())return;
  VpnProfileDataSource source=new VpnProfileSource(context);source.open();
  try{VpnProfile profile=source.getVpnProfile(node.get("profileUuid"));if(profile==null){node.set("profileUuid","");return;}profile.setCertificateAlias(null);profile.setRemoteId(null);source.updateVpnProfile(profile);}finally{source.close();}
 }
}
