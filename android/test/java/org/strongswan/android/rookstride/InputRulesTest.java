package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;

public class InputRulesTest {
    @Test public void vpnPasswordsCountCharactersWithoutCompositionRules(){
        for(String value:new String[]{"1","short","1234567890123456","abcdefgh","12345678","abcdefghiJKLMNO","\"\\!@#$%^&*()","парольёж","😀😀😀😀😀😀😀😀"})assertTrue(value,InputRules.vpnPassword(value));
        for(String value:new String[]{"","abc\n12345","abc\r12345","abc\u000012345","abc\u202812345","abc\ud80012345"})assertFalse(InputRules.vpnPassword(value));
        assertFalse(InputRules.vpnPassword(null));
    }
    @Test public void generatedAccountPasswordsFitPolicyAndExistingSshSecretsRemainUnrestricted(){
        for(int i=0;i<25;i++){String value=InputRules.generatedVpnPassword();assertEquals(15,value.length());assertTrue(InputRules.vpnPassword(value));}
    }
    @Test public void rejectsShellAndPathInput() {
        assertFalse(InputRules.host("server;id"));assertFalse(InputRules.host("$(id)"));assertFalse(InputRules.host("-option"));
        assertFalse(InputRules.username("../root"));assertFalse(InputRules.username("alice\nroot"));
        assertTrue(InputRules.host("vpn.example.net"));assertTrue(InputRules.username("alex-phone"));
        assertFalse(InputRules.port(0));assertFalse(InputRules.port(65536));
        assertFalse(InputRules.stage("/tmp/rookstride-../root"));assertFalse(InputRules.job("a;id"));
    }
    @Test public void weakAdviceDoesNotRejectAChosenPassword(){
        assertTrue(InputRules.vpnPassword("1"));assertTrue(InputRules.weakVpnPassword("1"));
        assertTrue(InputRules.vpnPassword(new String(new char[64]).replace('\0','q')));
        assertFalse(InputRules.vpnPassword(new String(new char[128]).replace('\0','q')));
        assertFalse(InputRules.vpnPassword(new String(new char[32]).replace("\0","😀")));
        assertFalse(InputRules.weakVpnPassword("a longer passphrase is allowed"));
    }
    @Test public void passwordRememberChoiceIsRespected() throws Exception {
        Gateway g=new Gateway();g.sshPassword="private-administrator-secret";g.vpnPassword="private-vpn-secret";g.privateKey="private-key";
        assertFalse(g.persisted().toString().contains("private-"));
        g.data.put("remember",true);JSONObject value=g.persisted();assertEquals(g.sshPassword,value.getString("sshPassword"));
        g.data.put("remember",false);assertFalse(g.persisted().has("privateKey"));
    }
    @Test public void sshFingerprintIsStableAndUsesSha256() throws Exception {
        assertEquals("SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0",Ssh.fingerprint("abc".getBytes("UTF-8")));
    }
}
