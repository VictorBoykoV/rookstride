package org.strongswan.android.rookstride;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;

public class InputRulesTest {
    @Test public void rejectsShellAndPathInput() {
        assertFalse(InputRules.host("server;id"));assertFalse(InputRules.host("$(id)"));assertFalse(InputRules.host("-option"));
        assertFalse(InputRules.username("../root"));assertFalse(InputRules.username("alice\nroot"));
        assertTrue(InputRules.host("vpn.example.net"));assertTrue(InputRules.username("alex-phone"));
        assertFalse(InputRules.port(0));assertFalse(InputRules.port(65536));
        assertFalse(InputRules.stage("/tmp/rookstride-../root"));assertFalse(InputRules.job("a;id"));
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
