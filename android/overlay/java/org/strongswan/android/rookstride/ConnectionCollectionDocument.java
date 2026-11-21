package org.strongswan.android.rookstride;

import android.content.ContentResolver;
import android.net.Uri;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Complete ordinary connections written only to the user's chosen document. */
public final class ConnectionCollectionDocument {
    private ConnectionCollectionDocument(){}
    public static void save(ContentResolver resolver,Uri uri,String content)throws Exception {
        if(uri==null||!"content".equals(uri.getScheme()))throw new IOException("Choose a document location");
        ConnectionBundle.parse(content);
        byte[] encoded=content.getBytes(StandardCharsets.UTF_8);
        try(OutputStream stream=resolver.openOutputStream(uri,"wt")){
            if(stream==null)throw new IOException("The selected document could not be opened");
            stream.write(encoded);stream.flush();
        }finally{java.util.Arrays.fill(encoded,(byte)0);}
    }
}
