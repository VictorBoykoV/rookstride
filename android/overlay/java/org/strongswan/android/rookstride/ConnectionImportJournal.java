package org.strongswan.android.rookstride;

import android.content.Context;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Short, shared serialization of AtomicFile operations in the UI process. */
final class ConnectionImportJournal {
    // AtomicFile does not lock: openRead can restore a backup or remove a new
    // file while another instance is writing. Never hold this across an import.
    private static final Object JOURNAL_LOCK=new Object();
    private static final int MAX_BYTES=32768;
    private final AtomicFile file;
    ConnectionImportJournal(Context context){this(new AtomicFile(new File(context.getApplicationContext().getNoBackupFilesDir(),"connection-import.json")));}
    /** Isolated Android storage tests use a real AtomicFile with controlled scheduling. */
    ConnectionImportJournal(AtomicFile file){this.file=file;}
    JSONObject read()throws Exception{
        synchronized(JOURNAL_LOCK){
            byte[] bytes;
            try{bytes=readBytes();}
            catch(FileNotFoundException missing){if(!exists("")&&!exists(".bak")&&!exists(".new"))return null;throw missing;}
            JSONObject value=new JSONObject(new String(bytes,StandardCharsets.UTF_8));ConnectionBundleImport.assets(value);return value;
        }
    }
    void write(JSONObject value)throws Exception{
        ConnectionBundleImport.assets(value);byte[] bytes=value.toString().getBytes(StandardCharsets.UTF_8);if(bytes.length>MAX_BYTES)throw new IOException("Connection import recovery record is too large");
        synchronized(JOURNAL_LOCK){
            FileOutputStream out=file.startWrite();
            try{out.write(bytes);file.finishWrite(out);out=null;if(!Arrays.equals(bytes,readBytes()))throw new IOException("Could not verify connection import recovery record");}
            catch(Exception failed){if(out!=null)file.failWrite(out);throw failed;}
        }
    }
    void clear()throws Exception{
        synchronized(JOURNAL_LOCK){file.delete();if(exists("")||exists(".bak")||exists(".new"))throw new IOException("Connection import cleanup is waiting");}
    }
    private boolean exists(String suffix){return new File(file.getBaseFile().getPath()+suffix).exists();}
    /** Called only while holding JOURNAL_LOCK, including post-write verification. */
    private byte[] readBytes()throws Exception{
        try(InputStream in=file.openRead();ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[4096];for(int n;(n=in.read(buffer,0,Math.min(buffer.length,MAX_BYTES+1-out.size())))!=-1;){out.write(buffer,0,n);if(out.size()>MAX_BYTES)throw new IOException("Connection import recovery needs attention");}return out.toByteArray();
        }
    }
}
