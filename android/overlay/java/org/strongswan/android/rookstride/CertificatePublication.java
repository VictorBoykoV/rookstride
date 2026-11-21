package org.strongswan.android.rookstride;

import android.content.Context;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.AtomicFile;
import org.json.JSONObject;
import org.strongswan.android.security.LocalCertificateStore;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;

/** Publishes complete private trust without replacing any existing alias.
 * A private durable proof survives the move, including a crash before SQL commit.
 * The caller serializes import/recovery and supplies current SQL/catalog references. */
final class CertificatePublication {
    interface Publisher {int move(File source,File target)throws Exception;}
    private final File files,staging;
    private final Publisher publisher;
    CertificatePublication(Context context)throws IOException{this(context,CertificatePublication::publishNative);}
    CertificatePublication(Context context,Publisher publisher)throws IOException{
        files=context.getFilesDir().getCanonicalFile();staging=context.getNoBackupFilesDir().getCanonicalFile();this.publisher=publisher;
    }
    private static final class Native {static{System.loadLibrary("rook-files");}}
    private static native int nativeRenameNoReplace(String source,String target);
    static int publishNative(File source,File target)throws IOException{
        try{new Native();return nativeRenameNoReplace(source.getAbsolutePath(),target.getAbsolutePath());}
        catch(LinkageError unavailable){throw new IOException("This phone cannot safely publish new private VPN trust",unavailable);}
    }
    private File folder(ConnectionBundleImport.Asset asset){return new File(new File(staging,"connection-import-certificates"),asset.operation);}
    File temporary(ConnectionBundleImport.Asset asset){return new File(folder(asset),asset.id+".der");}
    File proofFile(ConnectionBundleImport.Asset asset){return new File(folder(asset),asset.id+".ownership.json");}
    File target(ConnectionBundleImport.Asset asset)throws IOException{if(!asset.protocol.equals("ikev2")||!asset.certificateAlias.matches("local:[a-f0-9]{40}")||!asset.certificateHash.matches("[a-f0-9]{64}"))throw new IOException("Invalid private trust publication");return new File(files,"certificate-"+asset.certificateAlias.substring(6));}
    private static boolean exists(File file){try{Os.lstat(file.getPath());return true;}catch(ErrnoException error){return error.errno!=OsConstants.ENOENT;}}
    private static boolean artifacts(File file){return exists(file)||exists(new File(file+".bak"))||exists(new File(file+".new"));}
    private static boolean ownedMode(StructStat state){return state.st_uid==Process.myUid()&&(state.st_mode&0002)==0&&((state.st_mode&0020)==0||state.st_gid==Process.myUid());}
    private static void directory(File file,boolean create)throws Exception{
        if(!exists(file)){if(!create)return;if(!file.mkdir())throw new IOException("Could not create private trust recovery storage");Os.chmod(file.getPath(),0700);}
        StructStat state=Os.lstat(file.getPath());if(!OsConstants.S_ISDIR(state.st_mode)||!ownedMode(state)||!file.getCanonicalFile().equals(file.getAbsoluteFile()))throw new IOException("Unexpected private trust recovery directory");
    }
    private void directories(ConnectionBundleImport.Asset asset,boolean create)throws Exception{
        directory(staging,false);directory(files,false);directory(folder(asset).getParentFile(),create);directory(folder(asset),create);
    }
    private static void syncDirectory(File file)throws Exception{FileDescriptor fd=Os.open(file.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);try{StructStat state=Os.fstat(fd);if(!OsConstants.S_ISDIR(state.st_mode)||!ownedMode(state))throw new IOException("Unexpected private trust recovery directory");Os.fsync(fd);}finally{Os.close(fd);}}
    private static final class Read {
        final StructStat state;final byte[] bytes;
        Read(StructStat state,byte[] bytes){this.state=state;this.bytes=bytes;}
    }
    private static Read read(File file,int limit)throws Exception{
        FileDescriptor fd=Os.open(file.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
        try(FileInputStream in=new FileInputStream(fd)){
            StructStat state=Os.fstat(fd);if(!OsConstants.S_ISREG(state.st_mode)||!ownedMode(state)||state.st_size<=0||state.st_size>limit)throw new IOException("Unexpected private trust recovery file");
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int count;while((count=in.read(buffer))!=-1){if(out.size()+count>limit)throw new IOException("Private trust recovery file is too large");out.write(buffer,0,count);}return new Read(state,out.toByteArray());
        }
    }
    private static String hash(byte[] bytes)throws Exception{return ConnectionBundleImport.hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void freshAtomic(File file,byte[] bytes)throws Exception{
        if(artifacts(file))throw new IOException("Private trust staging already exists; recover the recorded import");
        AtomicFile atomic=new AtomicFile(file);FileOutputStream out=atomic.startWrite();try{out.write(bytes);out.getFD().sync();atomic.finishWrite(out);}catch(Exception failure){atomic.failWrite(out);throw failure;}
        Os.chmod(file.getPath(),0600);if(!Arrays.equals(bytes,read(file,Math.max(4096,bytes.length)).bytes))throw new IOException("Private trust recovery write could not be verified");
    }
    private JSONObject proof(ConnectionBundleImport.Asset asset,Read source)throws Exception{return new JSONObject().put("schema",1).put("operation",asset.operation).put("id",asset.id).put("alias",asset.certificateAlias).put("sha256",asset.certificateHash).put("dev",source.state.st_dev).put("inode",source.state.st_ino).put("uid",source.state.st_uid);}
    private JSONObject loadProof(ConnectionBundleImport.Asset asset)throws Exception{
        File file=proofFile(asset);if(!artifacts(file))return null;
        File backup=new File(file+".bak");File candidate=exists(backup)?backup:file;read(candidate,4096); // validate before AtomicFile recovery can rename anything
        JSONObject value=new JSONObject(new String(new AtomicFile(file).readFully(),StandardCharsets.UTF_8));Set<String> allowed=new HashSet<>(Arrays.asList("schema","operation","id","alias","sha256","dev","inode","uid"));for(Iterator<String> keys=value.keys();keys.hasNext();)if(!allowed.contains(keys.next()))throw new IOException("Invalid private trust recovery proof");
        for(String name:new String[]{"schema","dev","inode","uid"})if(!(value.get(name) instanceof Integer)&&!(value.get(name) instanceof Long))throw new IOException("Invalid private trust proof number");
        if(value.length()!=allowed.size()||value.getInt("schema")!=1||!asset.operation.equals(value.getString("operation"))||!asset.id.equals(value.getString("id"))||!asset.certificateAlias.equals(value.getString("alias"))||!asset.certificateHash.equals(value.getString("sha256"))||value.getInt("uid")!=Process.myUid()||value.getLong("inode")==0)throw new IOException("Private trust recovery proof does not match this import");return value;
    }
    private boolean matchesProof(File file,JSONObject proof,String expectedHash)throws Exception{
        if(!exists(file))return false;StructStat state=Os.lstat(file.getPath());if(!OsConstants.S_ISREG(state.st_mode)||state.st_uid!=Process.myUid())return false;Read actual=read(file,450000);
        return actual.state.st_dev==proof.getLong("dev")&&actual.state.st_ino==proof.getLong("inode")&&hash(actual.bytes).equals(expectedHash);
    }
    private boolean exactCertificate(File file,byte[] encoded)throws Exception{
        if(!exists(file))return false;StructStat state=Os.lstat(file.getPath());if(!OsConstants.S_ISREG(state.st_mode)||state.st_uid!=Process.myUid())return false;return Arrays.equals(encoded,read(file,450000).bytes);
    }
    boolean existingMatches(ConnectionBundleImport.Asset asset,X509Certificate certificate)throws Exception{return exactCertificate(target(asset),certificate.getEncoded());}
    void stage(ConnectionBundleImport.Asset asset,X509Certificate certificate)throws Exception{
        File target=target(asset);if(!asset.newCertificate||!asset.certificateAlias.equals(new LocalCertificateStore().getCertificateAlias(certificate)))throw new IOException("Private trust plan changed");byte[] encoded=certificate.getEncoded();if(encoded.length>450000||!hash(encoded).equals(asset.certificateHash))throw new IOException("Private trust plan changed");
        directories(asset,true);File temporary=temporary(asset),proofFile=proofFile(asset);if(artifacts(temporary)||artifacts(proofFile))throw new IOException("Recover the staged private trust before importing again");
        freshAtomic(temporary,encoded);Read source=read(temporary,450000);JSONObject proof=proof(asset,source);freshAtomic(proofFile,proof.toString().getBytes(StandardCharsets.UTF_8));syncDirectory(folder(asset));syncDirectory(folder(asset).getParentFile());syncDirectory(staging);
        int error=publisher.move(temporary,target);
        if(error==OsConstants.EEXIST){if(!exactCertificate(target,encoded))throw new IOException("Saved certificate trust changed during import");return;}
        if(error!=0)throw new IOException("This phone could not safely publish the VPN certificate ("+OsConstants.errnoName(error)+")");
        syncDirectory(folder(asset));syncDirectory(files);if(!matchesProof(target,proof,asset.certificateHash)||exists(temporary))throw new IOException("Published private trust ownership could not be verified");
    }
    /** False/missing/mismatched ownership never authorizes deleting an alias. */
    void cleanup(ConnectionBundleImport.Asset asset,boolean referenced)throws Exception{
        if(!asset.newCertificate||asset.certificateAlias.isEmpty())return;File target=target(asset);directories(asset,false);File temporary=temporary(asset);JSONObject proof=loadProof(asset);
        if(!referenced){
            boolean owned=proof!=null&&matchesProof(target,proof,asset.certificateHash);
            // Compatibility with a retained older hard-link journal; new imports
            // never create links and cannot acquire ownership from equal bytes.
            if(proof==null&&exists(temporary)&&exists(target)){Read old=read(temporary,450000);JSONObject legacy=proof(asset,old);owned=hash(old.bytes).equals(asset.certificateHash)&&matchesProof(target,legacy,asset.certificateHash);}
            if(owned&&matchesProof(target,proof==null?proof(asset,read(temporary,450000)):proof,asset.certificateHash)){Os.remove(target.getPath());syncDirectory(files);}
        }
        if(artifacts(temporary)){Read staged=read(exists(new File(temporary+".bak"))?new File(temporary+".bak"):temporary,450000);if(!hash(staged.bytes).equals(asset.certificateHash)||proof!=null&&(staged.state.st_dev!=proof.getLong("dev")||staged.state.st_ino!=proof.getLong("inode")))throw new IOException("Private staged trust ownership changed");new AtomicFile(temporary).delete();if(artifacts(temporary))throw new IOException("Could not remove staged private trust");}
        if(proof!=null){new AtomicFile(proofFile(asset)).delete();if(artifacts(proofFile(asset)))throw new IOException("Could not remove private trust proof");}
        File directory=folder(asset);if(directory.isDirectory()){String[] names=directory.list();if(names!=null&&names.length==0&&!directory.delete())throw new IOException("Could not remove private trust recovery directory");}
    }
}
