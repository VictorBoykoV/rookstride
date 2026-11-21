package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.AtomicFile;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Locale;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Opt-in fixture in app-private storage. Never embeds or discovers an operator server. */
final class PrivateAdministrationFixture {
    static final String FILE="major-administration-private.json";
    final Context context;
    final JSONObject request,binary;
    private PrivateAdministrationFixture(Context context,JSONObject request,JSONObject binary){this.context=context;this.request=request;this.binary=binary;}

    @SuppressWarnings("deprecation")
    static PrivateAdministrationFixture load(String action,String allowFlag)throws Exception {
        assumeTrue("This provider test needs an explicit action",action.equals(InstrumentationRegistry.getArguments().getString("rookstride_private_major_action","")));
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();File file=new File(context.getFilesDir(),FILE);
        assertTrue("Supply the reviewed fixture in app-private storage",file.isFile());
        JSONObject request=new JSONObject(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
        assertEquals(1,request.optInt("schema"));assertTrue("Disposable fixture authorization required",request.optBoolean("disposable"));assertTrue("This action is not authorized by the fixture",request.optBoolean(allowFlag));
        assertEquals("Use the signed release app",0,context.getApplicationInfo().flags&ApplicationInfo.FLAG_DEBUGGABLE);
        String apk=hash(new File(context.getApplicationInfo().sourceDir));
        assertTrue("The installed app differs from the explicitly reviewed APK",apk.equalsIgnoreCase(request.getString("expected_apk_sha256")));
        PackageInfo info=context.getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNATURES);
        assertEquals("Expected one app signing identity",1,info.signatures.length);String signer=hash(info.signatures[0].toByteArray());
        assertTrue("The APK signer differs from the fixture",signer.equalsIgnoreCase(request.getString("expected_signer_sha256")));
        JSONObject binary=new JSONObject().put("apk_sha256",apk).put("signer_sha256",signer).put("version",info.versionName).put("version_code",info.versionCode)
                .put("test_apk_sha256",hash(new File(InstrumentationRegistry.getInstrumentation().getContext().getApplicationInfo().sourceDir)));
        assertFalse("Finish the existing foreground operation first",DeploymentService.active());
        return new PrivateAdministrationFixture(context,request,binary);
    }
    Gateway pair()throws Exception {
        return pair(false);
    }
    /** The local replacement-exit lab uses a pinned passwordless-sudo owner.
     * Other provider/OS fixtures still require actual root password access. */
    Gateway acceptedEntryPair()throws Exception {
        return pair(true);
    }
    private Gateway pair(boolean acceptedEntry)throws Exception {
        Gateway pair=new Gateway(new JSONObject(request.getJSONObject("pair").toString()));
        assertTrue("An existing AWG/AWG pair is required",pair.isPair());assertEquals("awg",pair.get("pairEntryProtocol"));assertEquals("awg",pair.get("pairExitProtocol"));assertTrue(PairController.modern(pair));
        assertTrue(InputRules.job(pair.get("pairId")));assertFalse("Fixture servers must be distinct",ServerIdentityPins.sameEndpoint(pair,pair.exit));
        for(Gateway node:new Gateway[]{pair,pair.exit}){
            assertTrue("Independently pinned SSH identities required",node.get("fingerprint").matches("SHA256:[A-Za-z0-9+/]{43}"));
            if(node.get("admin").equals("root"))continue;
            assertTrue("Only the accepted-entry lab may use a reviewed sudo exit",acceptedEntry&&node==pair.exit&&request.optBoolean("allow_reviewed_sudo_exit"));
            JSONObject reviewed=request.getJSONObject("reviewed_sudo_exit");
            for(String field:new String[]{"host","admin","fingerprint"})assertEquals("The reviewed sudo owner differs",reviewed.getString(field),node.get(field));
            assertTrue(reviewed.getString("machine").matches("[a-f0-9]{64}"));
            try(PairSsh sessions=PairSsh.connect(pair,phase->{})){
                assertEquals("The reviewed owner has no passwordless root access","0",sessions.exit.execute("sudo -n id -u",null).trim());
                assertEquals("The independently observed lab machine differs",reviewed.getString("machine"),sessions.exit.probe().getString("machine"));
            }
        }
        return pair;
    }
    Gateway savedPair(ArrayList<Gateway> nodes)throws Exception {
        Gateway fixture=pair();for(Gateway node:nodes)if(node.get("id").equals(fixture.get("id"))){assertEquals(fixture.get("pairId"),node.get("pairId"));assertTrue(node.isPair());return node;}
        throw new AssertionError("The recorded pair is missing; do not start another wipe");
    }
    void verifyRecordedBinary(JSONObject metadata)throws Exception{
        String original=metadata.getJSONObject("binary").getString("apk_sha256");
        if(original.equals(binary.getString("apk_sha256")))return;
        assertTrue("A changed app requires explicit review before resuming recorded OS jobs",request.optBoolean("allow_recorded_job_apk_migration"));
        assertEquals("Only the explicitly reviewed previous app may own these recorded jobs",request.getString("previous_apk_sha256"),original);
        metadata.put("reviewed_resume_binary",new JSONObject(binary.toString()));
    }
    File file(String name){return new File(context.getFilesDir(),name);}
    void checkpoint(Gateway pair)throws Exception{atomic(file("paired-restore-gateway-private.json"),pair.persisted().toString().getBytes(StandardCharsets.UTF_8));}
    void receipt(String name,JSONObject values)throws Exception {values.put("binary",new JSONObject(binary.toString()));atomic(file(name),values.toString().getBytes(StandardCharsets.UTF_8));}
    static void atomic(File target,byte[] bytes)throws Exception {AtomicFile file=new AtomicFile(target);FileOutputStream out=file.startWrite();try{out.write(bytes);file.finishWrite(out);}catch(Exception e){file.failWrite(out);throw e;}}
    static String hash(File file)throws Exception {MessageDigest digest=MessageDigest.getInstance("SHA-256");try(InputStream in=new FileInputStream(file)){byte[] buffer=new byte[65536];int read;while((read=in.read(buffer))!=-1)digest.update(buffer,0,read);}return hex(digest.digest());}
    static String hash(byte[] bytes)throws Exception {return hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String hash(String text)throws Exception {return hash(text.getBytes(StandardCharsets.UTF_8));}
    private static String hex(byte[] value){StringBuilder result=new StringBuilder();for(byte b:value)result.append(String.format(Locale.ROOT,"%02x",b&255));return result.toString();}
}
