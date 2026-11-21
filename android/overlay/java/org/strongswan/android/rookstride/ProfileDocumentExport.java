package org.strongswan.android.rookstride;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Writes only the document selected by the user. The document display name is
 * not a configuration-validation boundary; providers may add collision suffixes. */
public final class ProfileDocumentExport {
    private ProfileDocumentExport(){}
    public static final class Result {
        public final Uri uri;public final String name;public final boolean amneziaCompatible;
        Result(Uri uri,String name,boolean compatible){this.uri=uri;this.name=name;amneziaCompatible=compatible;}
    }
    public static boolean amneziaName(String name){
        return name!=null&&name.toLowerCase(Locale.ROOT).endsWith(".conf")&&name.substring(0,name.length()-5).matches("[a-zA-Z0-9_=+.-]{1,15}");
    }
    private static String name(ContentResolver resolver,Uri uri){
        try(Cursor cursor=resolver.query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
            if(cursor!=null&&cursor.moveToFirst())return cursor.getString(0);
        }catch(Exception ignored){}
        return "";
    }
    public static Result save(ContentResolver resolver,Uri uri,ConnectionExport export)throws IOException{
        if(uri==null||!"content".equals(uri.getScheme()))throw new IOException("Choose a document location.");
        // Save first: a provider-generated filename must never turn a successful
        // CREATE_DOCUMENT into an empty file containing none of the access data.
        try(OutputStream stream=resolver.openOutputStream(uri,"wt")){
            if(stream==null)throw new IOException("Could not open the document");
            stream.write(export.content.getBytes(StandardCharsets.UTF_8));
        }
        String filename=name(resolver,uri);
        if(!export.protocol.equals("awg")||amneziaName(filename))return new Result(uri,filename,true);
        try{
            Uri renamed=DocumentsContract.renameDocument(resolver,uri,ConnectionExport.freshAmneziaName());
            if(renamed!=null&&"content".equals(renamed.getScheme())&&java.util.Objects.equals(uri.getAuthority(),renamed.getAuthority())){
                uri=renamed;filename=name(resolver,uri);
            }
        }catch(Exception ignored){/* A complete file remains usable in Rookstride. */}
        return new Result(uri,filename,amneziaName(filename));
    }
}
