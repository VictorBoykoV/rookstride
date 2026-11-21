package org.strongswan.android.rookstride;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;
public class ServerActionExceptionTest {
 @Test public void exactHelperPreflightHasSafeActionableCategory()throws Exception{
  String error="This Double VPN uses another installer version. Review its update before changing users or services.";
  try{Ssh.response(new JSONObject().put("ok",false).put("error",error).toString());fail();}catch(Ssh.ServerActionException value){assertEquals("pair_helper_update_required",value.code);assertTrue(value.rejectedBeforeMutation);assertTrue(value.safeDetail.contains("No account was created"));}
 }
 @Test public void otherRemoteFailuresDoNotPromiseNoMutationOrDisclosePayload(){
  Ssh.ServerActionException value=new Ssh.ServerActionException("worker failed after password=secret-fixture");assertFalse(value.rejectedBeforeMutation);assertEquals("server_action_failed",value.code);assertFalse(value.safeDetail.contains("secret-fixture"));assertTrue(value.safeDetail.contains("Check its current users"));
 }
}
