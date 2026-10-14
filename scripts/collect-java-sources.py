#!/usr/bin/env python3
"""Collect exact resolved release-library source JARs and published Maven metadata."""
import hashlib,json,os,subprocess,urllib.error,urllib.request,zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'.build';BUILD.mkdir(exist_ok=True)
TARGET=ROOT/'.tools/dependency-sources';TARGET.mkdir(parents=True,exist_ok=True)
inventory=BUILD/'release-java-inventory.json'
init=BUILD/'java-source-inventory.gradle'
init.write_text('''
allprojects {
    afterEvaluate { project ->
        if (project.path == ':app') {
            tasks.register('rookstrideSourceInventory') {
                doLast {
                    def artifacts = configurations.releaseRuntimeClasspath.resolvedConfiguration.resolvedArtifacts.collect {
                        [group:it.moduleVersion.id.group, name:it.moduleVersion.id.name, version:it.moduleVersion.id.version]
                    }.unique().sort { a,b -> "${a.group}:${a.name}:${a.version}" <=> "${b.group}:${b.name}:${b.version}" }
                    new File(System.getenv('ROOKSTRIDE_SOURCE_INVENTORY')).text = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(artifacts))
                }
            }
        }
    }
}
''')
env=dict(os.environ,ROOKSTRIDE_SOURCE_INVENTORY=str(inventory))
result=subprocess.run(['./gradlew','-I',str(init),':app:rookstrideSourceInventory','--offline','--no-daemon','--console=plain'],cwd=ROOT/'.tools/strongswan-source/src/frontends/android',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
if result.returncode:raise SystemExit('Dependency inventory failed; run the documented Android build first.\n'+result.stdout)
records=[]
for item in json.loads(inventory.read_text()):
    group,name,version=item['group'],item['name'],item['version']
    relative=group.replace('.','/')+'/'+name+'/'+version+'/'
    base=('https://dl.google.com/dl/android/maven2/' if group.startswith('androidx.') or group=='com.google.android.material' else 'https://repo.maven.apache.org/maven2/')+relative
    directory=TARGET/relative;directory.mkdir(parents=True,exist_ok=True)
    files=[]
    for suffix in ('-sources.jar','.pom','.module'):
        filename=name+'-'+version+suffix;url=base+filename;path=directory/filename
        try:
            if not path.is_file():
                with urllib.request.urlopen(url,timeout=90) as response:payload=response.read()
                temporary=path.with_suffix(path.suffix+'.part');temporary.write_bytes(payload);temporary.replace(path)
        except urllib.error.HTTPError as error:
            if suffix=='.module' and error.code==404:continue
            raise
        if suffix=='-sources.jar':
            with zipfile.ZipFile(path) as archive:assert archive.testzip() is None,'Corrupt source archive: '+filename
        files.append({'path':path.relative_to(TARGET).as_posix(),'url':url,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    records.append(dict(item,files=files))
manifest={'configuration':'releaseRuntimeClasspath','repositories':['Google Maven','Maven Central'],'modules':records}
(TARGET/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Collected exact Java/Kotlin source and Maven metadata for',len(records),'release modules')
