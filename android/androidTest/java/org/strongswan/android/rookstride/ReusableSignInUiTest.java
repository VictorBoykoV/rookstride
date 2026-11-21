package org.strongswan.android.rookstride;
import android.content.Context;
import android.widget.*;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.*;import org.junit.runner.RunWith;import org.json.*;
import org.strongswan.android.ui.RookstrideActivity;
import org.strongswan.android.data.*;
import java.util.*;
import static org.junit.Assert.*;
import static androidx.test.espresso.Espresso.*;
import static androidx.test.espresso.action.ViewActions.*;
import static androidx.test.espresso.matcher.ViewMatchers.*;
import static androidx.test.espresso.assertion.ViewAssertions.*;
import static org.hamcrest.Matchers.*;
@RunWith(AndroidJUnit4.class)
public class ReusableSignInUiTest {
 Context c;ArrayList<Gateway> before;
 @Before public void prepare()throws Exception{c=InstrumentationRegistry.getInstrumentation().getTargetContext();before=new Vault(c).read();new Vault(c).write(new ArrayList<>());c.getSharedPreferences("rookstride-deployment",0).edit().clear().commit();}
 @After public void restore()throws Exception{new Vault(c).write(before);}
 void call(RookstrideActivity a,String name,Class<?>[] types,Object... args)throws Exception{java.lang.reflect.Method m=RookstrideActivity.class.getDeclaredMethod(name,types);m.setAccessible(true);m.invoke(a,args);}
 @Test public void manualSignInNeedsOnlyVpnAddressAndUserDetails()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{call(a,"openScreen",new Class[]{String.class},"Import");}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Username and password")).perform(scrollTo()).check(matches(isCompletelyDisplayed())).perform(click());
   onView(withTagValue(is((Object)"VPN address (IP or domain)"))).perform(scrollTo(),replaceText("vpn.example.net"));
   onView(withTagValue(is((Object)"VPN username"))).perform(scrollTo(),replaceText("family.user"));
   onView(withTagValue(is((Object)"VPN password"))).perform(scrollTo(),replaceText("lettersOnly"));androidx.test.espresso.Espresso.closeSoftKeyboard();
   onView(withText("Save VPN")).check(matches(isCompletelyDisplayed())).perform(click());
   ArrayList<Gateway> saved=new Vault(c).read();assertEquals(1,saved.size());Gateway n=saved.get(0);assertTrue(n.data.getBoolean("clientOnly"));assertEquals("family.user",n.get("vpnLogin"));assertEquals("lettersOnly",n.vpnPassword);assertTrue(n.sshPassword.isEmpty());assertTrue(n.privateKey.isEmpty());
   VpnProfileDataSource source=new VpnProfileSource(c);source.open();try{VpnProfile p=source.getVpnProfile(n.get("profileUuid"));assertNotNull(p);assertNull(p.getCertificateAlias());assertNull("Password must stay in the encrypted app vault",p.getPassword());source.deleteVpnProfile(p);}finally{source.close();}ScreenshotProof.save(c,"manual-username-password-vpn");
  }
 }
 @Test public void allPasswordModesOfferChosenUsernameAndPasswordAtUserCreation()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   for(String id:new String[]{"ikev2","openvpn","hysteria2","trusttunnel","naive"}){
    screen.onActivity(a->{try{Gateway n=new Gateway();n.set("host","vpn.example.net");n.set("protocol",id);n.data.put("snapshot",new JSONObject().put("services",new JSONObject()).put("password_policy",new JSONObject().put("advisory",true)).put("manual_sign_in",true).put("access_mode","password"));call(a,"openVpn",new Class[]{Gateway.class},n);call(a,"addUser",new Class[]{Gateway.class},n);}catch(Exception e){throw new AssertionError(e);}});
    onView(withTagValue(is((Object)"VPN username"))).perform(scrollTo()).check(matches(isDisplayed()));onView(withTagValue(is((Object)"VPN password"))).perform(scrollTo()).check(matches(isDisplayed()));onView(withText("Create user")).check(matches(isCompletelyDisplayed()));onView(withText("Cancel")).perform(click());
   }
  }
 }
 @Test public void trustTunnelNewUserOffersReadableSharing()throws Exception{
  try(ActivityScenario<RookstrideActivity> screen=ActivityScenario.launch(RookstrideActivity.class)){
   screen.onActivity(a->{try{java.lang.reflect.Field f=RookstrideActivity.class.getDeclaredField("newUserShare");f.setAccessible(true);NewUserShareState state=(NewUserShareState)f.get(a);state.created("fixture","family.user","lettersOnly");state.profile=new JSONObject().put("format","trusttunnel").put("name","rookstride-family.rookvpn").put("content",new JSONObject().put("schema",1).put("protocol","trusttunnel").put("access_mode","password").put("server","vpn.example.net").put("port",443).put("login","family.user").put("password","lettersOnly").toString());call(a,"showCreatedUserShare",new Class[]{});}catch(Exception e){throw new AssertionError(e);}});
   onView(withText("Share sign-in details")).perform(scrollTo()).check(matches(isCompletelyDisplayed()));onView(withText("Copy sign-in details")).perform(scrollTo(),click());screen.onActivity(a->{android.content.ClipboardManager clipboard=(android.content.ClipboardManager)c.getSystemService(Context.CLIPBOARD_SERVICE);String text=clipboard.getPrimaryClip().getItemAt(0).getText().toString();assertTrue(text.contains("Username: family.user"));assertTrue(text.contains("Password: lettersOnly"));assertFalse(text.contains("BEGIN CERTIFICATE"));clipboard.setPrimaryClip(android.content.ClipData.newPlainText("",""));});onView(withText("Done")).perform(click());
  }
 }
}
