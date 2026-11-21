package org.strongswan.android.rookstride;

import android.content.Context;
import androidx.test.core.app.ActivityScenario;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.strongswan.android.ui.RookstrideActivity;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class AppFlowTest {
    @org.junit.Before public void englishFixture(){InstrumentationRegistry.getInstrumentation().runOnMainSync(()->androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(androidx.core.os.LocaleListCompat.forLanguageTags("en")));}
    @Test public void importedVpnNeedsNoAdministratorAndHasScopedSettings()throws Exception {
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        org.strongswan.android.data.VpnProfile profile=new org.strongswan.android.data.VpnProfile();profile.setName("Imported phone fixture");profile.setGateway("vpn.example.net");profile.setVpnType(org.strongswan.android.data.VpnType.IKEV2_EAP);profile.setUsername("fixture");
        org.strongswan.android.data.VpnProfileDataSource source=new org.strongswan.android.data.VpnProfileSource(context);source.open();source.insertProfile(profile);
        Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        try(ActivityScenario<RookstrideActivity> a=ActivityScenario.launch(RookstrideActivity.class)) {
            onView(withText("Imported phone fixture")).perform(scrollTo(),click());onView(withText("Connection preferences")).perform(scrollTo(),click());
            onView(withText("Edit connection")).check(matches(isDisplayed()));onView(withText("Server access")).check(androidx.test.espresso.assertion.ViewAssertions.doesNotExist());
            preview(context,"imported-settings");onView(withText("Remove VPN")).perform(scrollTo(),click());onView(withText("Continue")).perform(click());
            assertNull(source.getVpnProfile(profile.getUUID().toString()));onView(withText("Imported phone fixture")).check(androidx.test.espresso.assertion.ViewAssertions.doesNotExist());
            onView(withContentDescription("App settings")).perform(click());onView(withText("Help & FAQ")).perform(scrollTo(),click());onView(withText("How do I connect?  +")).perform(scrollTo(),click());onView(withText("Read technical guide")).perform(scrollTo(),click());onView(isAssignableFrom(android.webkit.WebView.class)).check(matches(isDisplayed()));
        }finally{source.deleteVpnProfile(profile);source.close();vault.write(original);}
    }
    private void preview(Context context,String name) {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        android.graphics.Bitmap bitmap=InstrumentationRegistry.getInstrumentation().getUiAutomation().takeScreenshot();
        if(bitmap!=null)try(java.io.FileOutputStream out=new java.io.FileOutputStream(new File(context.getFilesDir(),"preview-"+name+".png"))){bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out);}catch(java.io.IOException e){throw new AssertionError(e);}
    }
    @Test public void administratorSecretsAreEncryptedAtRest() throws Exception {
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
        Vault v=new Vault(context);ArrayList<Gateway> original=v.read();
        try {
            Gateway g=new Gateway();g.data.put("remember",true);g.sshPassword="test-only-secret-never-plaintext";
            ArrayList<Gateway> list=new ArrayList<>();list.add(g);v.write(list);
            byte[] data=Files.readAllBytes(new File(context.getFilesDir(),"gateways.enc").toPath());
            assertFalse(new String(data,java.nio.charset.StandardCharsets.UTF_8).contains(g.sshPassword));
            assertEquals(g.sshPassword,v.read().get(0).sshPassword);
        }finally{v.write(original);}
    }
    @Test public void savedVpnPasswordSurvivesWithoutRememberingAdministrator()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Vault vault=new Vault(context);ArrayList<Gateway> original=vault.read();
        try{
            Gateway node=new Gateway();node.data.put("rememberVpn",true);node.vpnPassword="generated-vpn-fixture";node.sshPassword="administrator-fixture";node.privateKey="key-fixture";
            ArrayList<Gateway> values=new ArrayList<>();values.add(node);vault.write(values);
            Gateway reloaded=new Vault(context).read().get(0);assertEquals(node.vpnPassword,reloaded.vpnPassword);assertEquals("",reloaded.sshPassword);assertEquals("",reloaded.privateKey);assertFalse(reloaded.remember());
            byte[] encrypted=Files.readAllBytes(new File(context.getFilesDir(),"gateways.enc").toPath());assertFalse(new String(encrypted,java.nio.charset.StandardCharsets.ISO_8859_1).contains(node.vpnPassword));
        }finally{vault.write(original);}
    }
}
