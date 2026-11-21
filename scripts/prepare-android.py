#!/usr/bin/env python3
"""Apply the independently maintained admin UI to pinned strongSwan sources."""
import json
import os
import html
import re
import shutil
import zipfile
from pathlib import Path

def write_text(path,value):
    if not path.exists() or path.read_text()!=value: path.write_text(value)

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'.tools/strongswan-source/src/frontends/android'
APP=SOURCE/'app'
if not APP.exists(): raise SystemExit('Prepare pinned strongSwan sources first; see docs/BUILD.md')
import subprocess
subprocess.run(['python3',str(ROOT/'scripts/prepare-rook-poses.py')],check=True)
subprocess.run(['python3',str(ROOT/'scripts/compile-locales.py')],check=True)
# Journal has no published endpoint yet. Keep authoring masters in source; do not
# embed the historical comic reader or its images in this app edition.
packed_stories=ROOT/'android/overlay/assets/stories'
if packed_stories.exists():shutil.rmtree(packed_stories)
overlay=ROOT/'android/overlay'
main=APP/'src/main'
# A previous website build may have packed historical worlds. The app has its own edition.
if (main/'assets/stories').exists(): shutil.rmtree(main/'assets/stories')
legacy_voice=main/'java/org/strongswan/android/rookstride/StoryVoice.java'
if legacy_voice.exists(): legacy_voice.unlink()
for src,dest in [('java','java'),('res','res'),('assets','assets')]:
    shutil.copytree(overlay/src,main/dest,dirs_exist_ok=True)
from license_page import render as render_licenses
write_text(main/'assets/licenses.html',render_licenses(ROOT))

with zipfile.ZipFile(main/'assets/gateway_bundle.zip','w',zipfile.ZIP_DEFLATED) as z:
    for folder in ('gateway','server','twohop','single'):
        for p in sorted((ROOT/folder).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.log'):
                z.write(p,p.relative_to(ROOT))

# Single adapters include the exact owned IKEv2 reset helper for whole-server VPN cleanup.
with zipfile.ZipFile(main/'assets/single_bundle.zip','w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted((ROOT/'single').rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':z.write(p,p.relative_to(ROOT))

    z.write(ROOT/'server/reset.py','server/reset.py')
    z.write(ROOT/'server/ike_packages.py','server/ike_packages.py')

# OS replacement is a separate, explicitly destructive adapter.
with zipfile.ZipFile(main/'assets/reinstall_bundle.zip','w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted((ROOT/'reinstall').rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':z.write(p,p.relative_to(ROOT))

# Check the exact real installer, including nested file ordering, in the JVM suite.
import importlib.util
spec=importlib.util.spec_from_file_location('rook_pair_digest',ROOT/'server/pair.py')
pair_digest=importlib.util.module_from_spec(spec);spec.loader.exec_module(pair_digest)
write_text(main/'assets/gateway_bundle.sha256',pair_digest.source_digest(ROOT)+'\n')

gradle=APP/'build.gradle'
text=gradle.read_text()
text=text.replace('applicationId "org.strongswan.android"','applicationId "io.rookstride.android"')
text=text.replace('minSdkVersion 21','minSdkVersion 26')
release=json.loads((ROOT/'release.json').read_text())
text=re.sub(r'versionCode\s+\d+', 'versionCode '+str(release['code']),text,count=1)
text=re.sub(r'versionName\s+"[^"]+"', 'versionName "'+release['name']+'"',text,count=1)
if 'rookstride-overlay' not in text:
    text+='''
// rookstride-overlay
android {
    buildFeatures { buildConfig true }
    defaultConfig {
        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64' }
    }
    packaging { resources { excludes += ['META-INF/versions/**', 'META-INF/*.kotlin_module'] } }
    signingConfigs {
        rookstride {
            if (System.getenv('ROOKSTRIDE_KEYSTORE')) {
                storeFile file(System.getenv('ROOKSTRIDE_KEYSTORE'))
                storePassword System.getenv('ROOKSTRIDE_SIGNING_PASSWORD')
                keyAlias 'rookstride'
                keyPassword System.getenv('ROOKSTRIDE_SIGNING_PASSWORD')
            }
        }
    }
    buildTypes { release { if (System.getenv('ROOKSTRIDE_KEYSTORE')) signingConfig signingConfigs.rookstride } }
}
dependencies {
    implementation 'com.github.mwiede:jsch:2.28.8'
    implementation 'org.bouncycastle:bcprov-jdk18on:1.86'
    testImplementation 'org.json:json:20250517'
    androidTestImplementation 'androidx.test:runner:1.7.0'
    androidTestImplementation 'androidx.test.ext:junit:1.3.0'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.7.0'
    androidTestImplementation 'androidx.test.uiautomator:uiautomator:2.3.0'
}
'''
if 'androidx.test.uiautomator:uiautomator:' not in text:
    text+="\ndependencies { androidTestImplementation 'androidx.test.uiautomator:uiautomator:2.3.0' }\n"
if 'rookstride-test-build-type' not in text:
    text+='\n// rookstride-test-build-type: opt in to tests against the signed release.\nandroid { testBuildType providers.gradleProperty("rookstrideTestBuildType").getOrElse("debug") }\n'
write_text(gradle,text)
gradle_properties=SOURCE/'gradle.properties'
properties=gradle_properties.read_text()
if 'org.gradle.jvmargs=' not in properties:write_text(gradle_properties,properties+'\norg.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=512m\norg.gradle.workers.max=2\n')
# English-only app edition. Shared website catalogs are retained independently.
if 'rookstride-english-only' not in text:
    text+='\n// rookstride-english-only\nandroid { defaultConfig { resourceConfigurations += ["en"] } }\n'
write_text(gradle,text)
write_text(main/'res/xml/rookstride_locales.xml','<?xml version="1.0" encoding="utf-8"?>\n<locale-config xmlns:android="http://schemas.android.com/apk/res/android"><locale android:name="en"/></locale-config>\n')
nativemk=main/'jni/Android.mk'
native=nativemk.read_text().replace('openssl/include','openssl/$(TARGET_ARCH_ABI)/include')
if '-DHAVE_SIGWAITINFO' not in native:
    native=native.replace('-DHAVE_PRCTL', '-DHAVE_SIGWAITINFO \\\n\t-DHAVE_PRCTL')
shutil.copytree(overlay/'jni/rook-files',main/'jni/rook-files',dirs_exist_ok=True)
if '\trook-files \\\n' not in native:
    anchor='strongswan_BUILD := \\\n'
    if native.count(anchor)!=1:raise SystemExit('Upstream native module list changed')
    native=native.replace(anchor,anchor+'\trook-files \\\n',1)
write_text(nativemk,native)
appmk=main/'jni/Application.mk'
application=appmk.read_text().replace('android-21','android-26')
if '-Wl,-z,common-page-size=16384' not in application:
    # NDK r27's flexible-page flag sets max-page-size but not RELRO's common-page-size.
    application+='\n# rookstride: align LOAD and RELRO segments for 16-KiB Android devices.\nAPP_LDFLAGS += -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384\n'
write_text(appmk,application)

manifest=main/'AndroidManifest.xml'
text=manifest.read_text().replace('@mipmap/ic_launcher','@drawable/rook_icon')
text=text.replace('org.strongswan.android.content.log','io.rookstride.android.content.log')
launcher='''            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>'''
if '.ui.RookstrideActivity' not in text:
    if launcher not in text: raise SystemExit('Upstream launcher manifest changed')
    text=text.replace(launcher,'',1)
    text=text.replace('        <activity\n', '''        <activity android:name=".ui.RookstrideActivity" android:theme="@style/RookstrideTheme" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
        </activity>
        <provider android:name="androidx.core.content.FileProvider" android:authorities="${applicationId}.files" android:exported="false" android:grantUriPermissions="true">
            <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/rookstride_file_paths"/>
        </provider>
        <activity\n''',1)
write_text(manifest,text)

# Rookstride diagnostics must not preaddress private logs to upstream support.
log_activity=main/'java/org/strongswan/android/ui/LogActivity.java'
log_source=log_activity.read_text()
log_source=re.sub(r'^\s*intent\.putExtra\(Intent\.EXTRA_EMAIL, new String\[\]\{MainActivity\.CONTACT_EMAIL\}\);\n','\n',log_source,flags=re.M)
write_text(log_activity,log_source)

# Return imported VPNs to Rookstride rather than the upstream profile list.
import_activity=main/'java/org/strongswan/android/ui/VpnProfileImportActivity.java'
import_source=import_activity.read_text().replace('new Intent(this, MainActivity.class)', 'new Intent(this, RookstrideActivity.class)')
write_text(import_activity,import_source)

# Separate, user-started installation polling, not the VPN foreground service.
text=manifest.read_text()
for permission in ('FOREGROUND_SERVICE_DATA_SYNC','POST_NOTIFICATIONS'):
    if 'android.permission.'+permission not in text:
        text=text.replace('<application','<uses-permission android:name="android.permission.'+permission+'"/>\n    <application',1)
# Older preparation runs may have inserted this upstream permission twice.
seen_notifications=False
for match in list(re.finditer(r'<uses-permission\s+android:name="android.permission.POST_NOTIFICATIONS"\s*/>',text))[::-1]:
    if seen_notifications:text=text[:match.start()]+text[match.end():]
    seen_notifications=True
if 'android.permission.WAKE_LOCK' not in text:
    text=text.replace('<application', '<uses-permission android:name="android.permission.WAKE_LOCK"/>\n    <application',1)
if '.rookstride.DeploymentService' not in text:
    text=text.replace('</application>', '<service android:name=".rookstride.DeploymentService" android:exported="false" android:foregroundServiceType="dataSync"/>\n    </application>')
if '<queries>' not in text:
    text=text.replace('<application','<queries></queries>\n    <application',1)
# The current story reader has no audio/narration feature.
text=re.sub(r'<intent><action android:name="android.intent.action.TTS_SERVICE"\s*/></intent>', '', text)
for package in ('org.amnezia.awg','com.v2ray.ang','de.blinkt.openvpn'):
    query='<package android:name="'+package+'"/>'
    if query not in text:text=text.replace('</queries>',query+'</queries>')
if '.rookstride.ProfileExportProvider' not in text:
    text=text.replace('</application>', '<provider android:name=".rookstride.ProfileExportProvider" android:authorities="${applicationId}.profiles" android:exported="false" android:grantUriPermissions="true"/></application>')
# Native Android 13 language settings and AppCompat persistence on Android 8–12.
if 'android:localeConfig=' not in text:text=text.replace('<application', '<application android:localeConfig="@xml/rookstride_locales" android:supportsRtl="true"',1)
if 'androidx.appcompat.app.AppLocalesMetadataHolderService' not in text:
    text=text.replace('</application>', '<service android:name="androidx.appcompat.app.AppLocalesMetadataHolderService" android:enabled="false" android:exported="false"><meta-data android:name="autoStoreLocales" android:value="true"/></service>\n</application>')
write_text(manifest,text)

control=main/'java/org/strongswan/android/ui/VpnProfileControlActivity.java'
text=control.read_text()
needle='''\t\tif (profile != null)
\t\t{
\t\t\tstartVpnProfile(profile);'''
if 'rookstride.session_password' not in text:
    if needle not in text: raise SystemExit('Upstream VPN control changed')
    text=text.replace(needle,'''\t\tif (profile != null)
\t\t{
            // Rookstride supplies the password for this session; do not store it in the profile DB.
            String sessionPassword = intent.getStringExtra("rookstride.session_password");
            if (sessionPassword != null) { profile.setPassword(sessionPassword); }
\t\t\tstartVpnProfile(profile);''',1)
write_text(control,text)

for p in (main/'res').glob('values*/strings.xml'):
    s=p.read_text()
    import re
    s=re.sub(r'(<string name="app_name"[^>]*>).*?(</string>)',r'\1Rookstride\2',s)
    s=re.sub(r'(<string name="main_activity_name"[^>]*>).*?(</string>)',r'\1Rookstride VPN profiles\2',s)
    write_text(p,s)
colors=main/'res/values/colors.xml'
s=colors.read_text()
import re
for name,value in [('primary','#141418'),('primary_dark','#141418'),('accent','#EE3038')]:
    s=re.sub(r'(<color name="'+name+r'">).*?(</color>)',r'\g<1>'+value+r'\2',s)
write_text(colors,s)
for p in (main/'java').rglob('*.java'):
    s=p.read_text().replace('org.strongswan.android.content.log','io.rookstride.android.content.log')
    s=s.replace('R.mipmap.ic_launcher','R.drawable.rook_icon')
    write_text(p,s)

for src in ('test','androidTest'):
    if (ROOT/'android'/src).exists(): shutil.copytree(ROOT/'android'/src,APP/'src'/src,dirs_exist_ok=True)
write_text(SOURCE/'local.properties','sdk.dir='+str(Path(os.environ.get('ROOKSTRIDE_SDK', str(ROOT/'.tools/sdk'))).resolve())+'\n')
application_source=main/'java/org/strongswan/android/logic/StrongSwanApplication.java'
application_text=application_source.read_text()
if 'AdminSocketFactory.install' not in application_text:
    application_text=application_text.replace('super.onCreate();','super.onCreate();\n        org.strongswan.android.rookstride.engine.AdminSocketFactory.install(this);',1)
write_text(application_source,application_text)
if 'RuntimeComponents.install' not in application_text:
    application_text=application_text.replace('super.onCreate();','super.onCreate();\n        org.strongswan.android.rookstride.RuntimeComponents.install(this);',1)
write_text(application_source,application_text)

# Source-built protocol engines; each Go runtime stays in its own service process.
subprocess.run(['python3',str(ROOT/'scripts/prepare-engines.py')],check=True)
text=gradle.read_text()
if 'rookstride-native-engines' not in text:
    text+="\n// rookstride-native-engines\ndependencies { implementation files('rookstride-libs/libxray.aar'); implementation 'com.google.code.findbugs:jsr305:3.0.2' }\n"
if 'rookstride-selected-abis' not in text:
    text+="""
// rookstride-selected-abis: optional smaller APK from the same app sources.
android {
    def requested = providers.gradleProperty('rookstrideAbis').orNull
    if (requested != null) {
        def abis = requested.split(',').toList()
        if (abis.isEmpty() || !['arm64-v8a','armeabi-v7a','x86_64'].containsAll(abis)) throw new GradleException('Unsupported Rookstride ABI')
        defaultConfig.ndk.abiFilters.clear()
        defaultConfig.ndk.abiFilters.addAll(abis)
    }
}
"""
write_text(gradle,text)
text=gradle.read_text()
if 'rookstride-executable-worker' not in text:
    text=text.replace('jniLibs { useLegacyPackaging = true }','jniLibs { useLegacyPackaging = true; keepDebugSymbols += [\"**/librook-routes.so\"] }')
    text+='\n// rookstride-executable-worker\nandroid { packaging { jniLibs { useLegacyPackaging = true; keepDebugSymbols += ["**/librook-routes.so"] } } }\n'
text=text.replace('jniLibs { useLegacyPackaging = true }','jniLibs { useLegacyPackaging = true; keepDebugSymbols += [\"**/librook-routes.so\"] }')
write_text(gradle,text)
text=manifest.read_text()
text=re.sub(r'android:extractNativeLibs="false"','android:extractNativeLibs="true"',text)
if 'android:extractNativeLibs=' not in text:text=text.replace('<application','<application android:extractNativeLibs="true"',1)
if '.rookstride.engine.ConnectionKeeper' not in text:
    text=text.replace('</application>','<service android:name=".rookstride.engine.ConnectionKeeper" android:exported="false" android:foregroundServiceType="specialUse"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="Keeps a user-started VPN connected"/></service></application>')
for protocol,service,provider in [('awg','AwgVpnService','Awg'),('xray','XrayVpnService','Xray'),('openvpn','OpenVpnService','OpenVpn'),('routes','RoutesVpnService','Routes')]:
    name='.rookstride.engine.'+service
    if name not in text:
        entry='<service android:name="'+name+'" android:process=":rook_'+protocol+'" android:exported="false" android:foregroundServiceType="specialUse" android:permission="android.permission.BIND_VPN_SERVICE"><intent-filter><action android:name="android.net.VpnService"/></intent-filter><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="VPN connection"/><meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="false"/></service>'
        entry+='<provider android:name=".rookstride.engine.EngineStatusProvider$'+provider+'" android:process=":rook_'+protocol+'" android:authorities="${applicationId}.engine.'+protocol+'" android:exported="false"/>'
        text=text.replace('</application>',entry+'</application>')
write_text(manifest,text)
print('Prepared Rookstride Android overlay and offline gateway bundle')

# Apply the same saved phone routing policy to the embedded IKEv2 client.
charon=main/'java/org/strongswan/android/logic/CharonVpnService.java'
text=charon.read_text()
marker='SelectedAppsHandling appHandling = profile.getSelectedAppsHandling();'
if '// rookstride-app-routing' not in text:
    if marker not in text:raise SystemExit('Upstream app-routing boundary changed')
    text=text.replace(marker,'// rookstride-app-routing\n            if (org.strongswan.android.rookstride.AppRouting.configured(CharonVpnService.this)) {\n                org.strongswan.android.rookstride.AppRouting.Policy policy = org.strongswan.android.rookstride.AppRouting.read(CharonVpnService.this);\n                profile.setSelectedApps(org.strongswan.android.rookstride.AppRouting.installed(CharonVpnService.this, policy));\n                profile.setSelectedAppsHandling(policy.mode.equals("only") ? SelectedAppsHandling.SELECTED_APPS_ONLY : policy.mode.equals("exclude") ? SelectedAppsHandling.SELECTED_APPS_EXCLUDE : SelectedAppsHandling.SELECTED_APPS_DISABLE);\n            }\n            SelectedAppsHandling appHandling = profile.getSelectedAppsHandling();',1)
write_text(charon,text)
text=manifest.read_text()
query='<intent><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent>'
if query not in text:text=text.replace('</queries>',query+'</queries>')
write_text(manifest,text)
