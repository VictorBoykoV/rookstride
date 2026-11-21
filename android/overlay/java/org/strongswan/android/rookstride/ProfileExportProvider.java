package org.strongswan.android.rookstride;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.OpenableColumns;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

/** Explicit, short-lived read grants. Private VPN profiles are never cached on disk. */
public final class ProfileExportProvider extends ContentProvider {
    private static final long LIFETIME=300_000;
    private static final Map<String,Entry> ENTRIES=new HashMap<>();
    private static final class Entry {
        final String name;final byte[] bytes;final long expires;
        Entry(String name,byte[] bytes){this.name=name;this.bytes=bytes;expires=SystemClock.elapsedRealtime()+LIFETIME;}
    }
    private static synchronized void prune(long now){
        Iterator<Entry> iterator=ENTRIES.values().iterator();
        while(iterator.hasNext()){Entry value=iterator.next();if(value.expires<=now){Arrays.fill(value.bytes,(byte)0);iterator.remove();}}
    }
    public static void validateName(String filename){
        if(filename==null||!filename.matches("(?:rookstride-[A-Za-z0-9_-]+\\.(?:conf|ovpn|txt|sswan|rookvpn|rookadmin|rookbundle)|rook-[a-f0-9]{10}\\.conf)"))throw new IllegalArgumentException("Unexpected profile name");
    }
    public static synchronized Uri issue(Context context,String filename,String content){
        validateName(filename);
        if(content==null)throw new IllegalArgumentException("Connection data is unavailable");
        byte[] bytes=content.getBytes(StandardCharsets.UTF_8);
        boolean collection=filename.endsWith(ConnectionBundle.EXTENSION);
        if(bytes.length>(collection?ConnectionBundle.MAX_BYTES:512000))throw new IllegalArgumentException("Connection profile is too large");
        if(collection)try{ConnectionBundle.parse(content);}catch(Exception rejected){throw new IllegalArgumentException("The connection collection is invalid");}
        prune(SystemClock.elapsedRealtime());
        if(ENTRIES.size()>=8)throw new IllegalStateException("Close previous profile exports and try again shortly");
        String token=UUID.randomUUID().toString();ENTRIES.put(token,new Entry(filename,bytes));
        new Handler(Looper.getMainLooper()).postDelayed(()->prune(SystemClock.elapsedRealtime()),LIFETIME+100);
        return new Uri.Builder().scheme("content").authority(context.getPackageName()+".profiles").appendPath(token).appendPath(filename).build();
    }
    private static synchronized Entry find(Uri uri)throws FileNotFoundException{
        prune(SystemClock.elapsedRealtime());
        if(uri.getPathSegments().size()!=2)throw new FileNotFoundException("Profile is unavailable");
        Entry entry=ENTRIES.get(uri.getPathSegments().get(0));
        if(entry==null||!entry.name.equals(uri.getLastPathSegment()))throw new FileNotFoundException("Profile expired. Export it again.");
        return entry;
    }
    @Override public boolean onCreate(){return true;}
    @Override public String getType(Uri uri){String name=uri.getLastPathSegment()==null?"":uri.getLastPathSegment();return name.endsWith(ConnectionBundle.EXTENSION)?ConnectionBundle.MIME:ConnectionExport.mimeForName(name);}
    @Override public Cursor query(Uri uri,String[] columns,String selection,String[] args,String sort){
        try{
            Entry entry=find(uri);String[] names=columns==null?new String[]{OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE}:columns;
            MatrixCursor cursor=new MatrixCursor(names,1);Object[] row=new Object[names.length];
            for(int i=0;i<names.length;i++)row[i]=OpenableColumns.DISPLAY_NAME.equals(names[i])?entry.name:OpenableColumns.SIZE.equals(names[i])?entry.bytes.length:null;
            cursor.addRow(row);return cursor;
        }catch(FileNotFoundException e){return null;}
    }
    @Override public ParcelFileDescriptor openFile(Uri uri,String mode)throws FileNotFoundException{
        if(!"r".equals(mode))throw new FileNotFoundException("Read access only");
        final byte[] bytes;
        synchronized(ProfileExportProvider.class){bytes=find(uri).bytes.clone();}
        return openPipeHelper(uri,getType(uri),null,bytes,(output,u,mime,options,data)->{
            try(FileOutputStream stream=new FileOutputStream(output.getFileDescriptor())){stream.write(data);}catch(IOException ignored){}finally{Arrays.fill(data,(byte)0);}
        });
    }
    @Override public Uri insert(Uri uri,ContentValues values){throw new UnsupportedOperationException("Read access only");}
    @Override public int update(Uri uri,ContentValues values,String selection,String[] args){throw new UnsupportedOperationException("Read access only");}
    @Override public int delete(Uri uri,String selection,String[] args){throw new UnsupportedOperationException("Read access only");}
}
