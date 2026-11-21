package org.strongswan.android.rookstride;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.*;

/** Android's trusted authorities; never a server leaf downloaded without verification. */
public final class PublicTrustRoots {
    private PublicTrustRoots(){}
    public static String read()throws Exception{
        KeyStore store=KeyStore.getInstance("AndroidCAStore");store.load(null,null);ArrayList<String> aliases=Collections.list(store.aliases());Collections.sort(aliases);StringBuilder out=new StringBuilder();
        for(String alias:aliases){Certificate certificate=store.getCertificate(alias);if(certificate==null)continue;out.append("-----BEGIN CERTIFICATE-----\n").append(java.util.Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(certificate.getEncoded())).append("\n-----END CERTIFICATE-----\n");}
        if(out.length()==0||out.length()>450000)throw new java.io.IOException("The phone’s trusted certificate store is unavailable");return out.toString();
    }
}
