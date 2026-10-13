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
overlay=ROOT/'android/overlay'
main=APP/'src/main'
for src,dest in [('java','java'),('res','res'),('assets','assets')]:
    shutil.copytree(overlay/src,main/dest,dirs_exist_ok=True)
license_files=[ROOT/'NOTICE.md',ROOT/'LICENSE']+sorted((ROOT/'licenses').glob('*'))+[ROOT/'gateway/LICENSE',ROOT/'twohop/LICENSE']
license_html='<html><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font:14px sans-serif;padding:18px}pre{white-space:pre-wrap;word-break:break-word}</style><h1>Rookstride licenses</h1><a href="rookstride:guide">Back to guide</a>'
for p in license_files:
    license_html+='<h2>'+html.escape(p.name)+'</h2><pre>'+html.escape(p.read_text())+'</pre>'
write_text(main/'assets/licenses.html',license_html+'</html>')

with zipfile.ZipFile(main/'assets/gateway_bundle.zip','w',zipfile.ZIP_DEFLATED) as z:
    for folder in ('gateway','server','twohop'):
        for p in sorted((ROOT/folder).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.log'):
                z.write(p,p.relative_to(ROOT))

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
}
'''
write_text(gradle,text)
nativemk=main/'jni/Android.mk'
native=nativemk.read_text().replace('openssl/include','openssl/$(TARGET_ARCH_ABI)/include')
if '-DHAVE_SIGWAITINFO' not in native:
    native=native.replace('-DHAVE_PRCTL', '-DHAVE_SIGWAITINFO \\\n\t-DHAVE_PRCTL')
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
print('Prepared Rookstride Android overlay and offline gateway bundle')
