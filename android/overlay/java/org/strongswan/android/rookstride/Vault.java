package org.strongswan.android.rookstride;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import org.json.JSONArray;
import java.io.*;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Administrator and saved VPN secrets are encrypted with an Android Keystore key. */
public final class Vault {
    private final AtomicFile file;
    private final Object fileLock;
    // AtomicFile provides crash recovery, not concurrent reader/writer exclusion.
    // Instances share these locks because Activity, workers and services each
    // construct Vault objects. This is process-local, not a catalog merge API.
    private static final java.util.concurrent.ConcurrentHashMap<String,Object> FILE_LOCKS=new java.util.concurrent.ConcurrentHashMap<>();
    private static final Object KEY_LOCK=new Object();
    private static final String ALIAS="rookstride.gateway.v1";
    interface AtomicFileFactory {AtomicFile create(File base);}
    public Vault(Context context) { this(context,"gateways.enc"); }
    Vault(Context context,String name) {this(context,name,AtomicFile::new);}
    Vault(Context context,String name,AtomicFileFactory factory) {
        if(!name.equals("gateways.enc")&&!name.equals("ssh-identities.enc")&&!name.equals("standalone-installs.enc"))throw new IllegalArgumentException("Unknown vault");
        File path;try{path=new File(context.getFilesDir(),name).getCanonicalFile();}catch(IOException failure){throw new IllegalStateException("Saved phone storage could not be resolved",failure);}
        file=factory.create(path);
        if(file==null||!file.getBaseFile().equals(path))throw new IllegalArgumentException("Unexpected saved phone storage path");
        fileLock=FILE_LOCKS.computeIfAbsent(path.getAbsolutePath(),ignored->new Object());
    }
    private SecretKey key(boolean create) throws Exception {
        synchronized(KEY_LOCK){return keyLocked(create);}
    }
    private SecretKey keyLocked(boolean create) throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (!store.containsAlias(ALIAS)) {
            if(!create)throw new IOException("The saved phone key is unavailable. Existing encrypted data was preserved.");
            for(String name:new String[]{"gateways.enc","ssh-identities.enc","standalone-installs.enc"})for(String suffix:new String[]{"",".bak",".new"})if(new File(file.getBaseFile().getParentFile(),name+suffix).exists())throw new IOException("The saved phone key is unavailable. Existing encrypted data was preserved.");
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build());
            generator.generateKey();
        }
        return (SecretKey)store.getKey(ALIAS,null);
    }
    public ArrayList<Gateway> read() throws Exception {
        synchronized(fileLock){return readLocked();}
    }
    private ArrayList<Gateway> readLocked() throws Exception {
        ArrayList<Gateway> nodes=new ArrayList<>();
        byte[] bytes;
        File backup=new File(file.getBaseFile().getPath()+".bak"),readable=backup.exists()?backup:file.getBaseFile();
        if(readable.exists()&&readable.length()>VaultCipher.MAX_BYTES)throw new IOException("Saved gateway data is too large and was preserved");
        try{bytes=file.readFully();}
        catch(FileNotFoundException missing){
            // API 26 can retain only .bak after a crash. Let AtomicFile recover
            // that first; only a genuinely absent store means an empty catalog.
            if(!file.getBaseFile().exists()&&!new File(file.getBaseFile().getPath()+".bak").exists())return nodes;
            throw missing;
        }
        byte[] plaintext=null;
        try{
            plaintext=VaultCipher.decrypt(file.getBaseFile().getName(),bytes,key(false));
            JSONArray values=new JSONArray(new String(plaintext,java.nio.charset.StandardCharsets.UTF_8));
            for(int i=0;i<values.length();i++)nodes.add(new Gateway(values.getJSONObject(i)));
            return nodes;
        }finally{java.util.Arrays.fill(bytes,(byte)0);if(plaintext!=null)java.util.Arrays.fill(plaintext,(byte)0);}
    }
    public void write(ArrayList<Gateway> nodes) throws Exception {
        synchronized(fileLock){writeLocked(nodes);}
    }
    /** Append freshly staged ordinary clients to the latest catalog under one
     * shared read/merge/write lock. Never replace an existing owner record. */
    public ArrayList<Gateway> appendClientRecords(List<Gateway> additions)throws Exception {
        synchronized(fileLock){
            if(!file.getBaseFile().getName().equals("gateways.enc"))throw new IOException("Client import requires the VPN catalog");
            ArrayList<Gateway> current=readLocked();if(additions.isEmpty())return current;
            Set<String> ids=new HashSet<>();for(Gateway node:current){ids.add(node.get("id"));if(node.exit!=null)ids.add(node.exit.get("id"));}
            Set<String> allowed=new HashSet<>(java.util.Arrays.asList("id","protocol","host","name","clientOnly","bundleImportId","importedConnectionHash","profileUuid","vpnLogin","accessMode","rememberVpn","vpnPort"));
            for(Gateway node:additions){
                if(!node.data.optBoolean("clientOnly")||node.exit!=null||node.sshRelay!=null||!node.sshPassword.isEmpty()||!node.privateKey.isEmpty()||node.remember()||!node.get("importedConnectionHash").matches("[a-f0-9]{64}"))throw new IOException("Only new ordinary client access can be imported");
                for(java.util.Iterator<String> fields=node.data.keys();fields.hasNext();)if(!allowed.contains(fields.next()))throw new IOException("Unexpected administrator data in client import");
                for(String key:new String[]{"id","bundleImportId"})if(!java.util.UUID.fromString(node.get(key)).toString().equals(node.get(key)))throw new IOException("Invalid imported connection identity");
                if(!ids.add(node.get("id")))throw new IOException("The imported connection identifier is already in use");
                current.add(new Gateway(node.persisted()));
            }
            writeLocked(current);return current;
        }
    }
    private void writeLocked(ArrayList<Gateway> nodes) throws Exception {
        JSONArray values=new JSONArray();for(Gateway node:nodes)values.put(node.persisted());
        byte[] plaintext=values.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),encrypted=null,verified=null;
        try{
            if(plaintext.length>VaultCipher.MAX_PLAINTEXT_BYTES)throw new IOException("The phone’s saved VPN catalog is full. Existing data was preserved.");
            SecretKey wrapping=key(true);encrypted=VaultCipher.encrypt(file.getBaseFile().getName(),plaintext,wrapping);
            verified=VaultCipher.decrypt(file.getBaseFile().getName(),encrypted,wrapping);
            if(!java.security.MessageDigest.isEqual(plaintext,verified))throw new IOException("Saved phone storage could not be verified. Existing data was preserved.");
            FileOutputStream stream=file.startWrite();boolean finishInvoked=false;
            try(FileOutputStream owned=stream){
                try{
                    owned.write(encrypted);owned.getFD().sync();
                    finishInvoked=true;file.finishWrite(owned);
                    syncParent(file.getBaseFile().getParentFile());
                    VaultCommit.verify(file.getBaseFile(),encrypted,VaultCipher.MAX_BYTES);
                }catch(Exception failure){if(!finishInvoked)file.failWrite(owned);throw failure;}
            }
        }finally{java.util.Arrays.fill(plaintext,(byte)0);if(encrypted!=null)java.util.Arrays.fill(encrypted,(byte)0);if(verified!=null)java.util.Arrays.fill(verified,(byte)0);}
    }
    private static void syncParent(File parent)throws IOException {
        java.io.FileDescriptor descriptor=null;
        try{
            descriptor=android.system.Os.open(parent.getAbsolutePath(),android.system.OsConstants.O_RDONLY,0);
            if(!android.system.OsConstants.S_ISDIR(android.system.Os.fstat(descriptor).st_mode))throw new IOException("Saved phone storage parent is not a directory. Existing files were preserved.");
            android.system.Os.fsync(descriptor);
        }catch(android.system.ErrnoException failure){throw new IOException("Saved phone storage directory could not be synced. Existing files were preserved.",failure);}
        finally{if(descriptor!=null)try{android.system.Os.close(descriptor);}catch(android.system.ErrnoException failure){throw new IOException("Saved phone storage directory could not be closed. Existing files were preserved.",failure);}}
    }
}
