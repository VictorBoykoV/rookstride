package org.strongswan.android.rookstride.engine;
import android.content.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.*;

public class EngineStatusProvider extends ContentProvider {
    public boolean onCreate(){return true;}
    @Override public Bundle call(String method,String arg,Bundle extras){
        if(Binder.getCallingUid()!=android.os.Process.myUid())throw new SecurityException("Private VPN state");
        if(method.equals("protect")){
            EngineVpnService service=EngineVpnService.current;
            if(service!=null&&service.nativeStopping())service=null;
            Bundle answer=new Bundle();ParcelFileDescriptor fd=extras==null?null:extras.getParcelable("socket");
            // prepare() is an ownership-changing operation for a pre-consented
            // VPN. Never call it while checking administrator transport state.
            // protect() only succeeds for the current owner and never prepares us.
            try{
                boolean owner=service!=null&&fd!=null&&service.protect(fd.getFd());
                answer.putBoolean("present",owner);
                if(owner){answer.putBoolean("protected",service.bindProtectedSocket(fd.getFd()));answer.putParcelable("network",service.underlying);}
            }finally{if(fd!=null)try{fd.close();}catch(java.io.IOException ignored){}}
            return answer;
        }
        String protocol=this instanceof Awg?"awg":this instanceof Xray?"xray":this instanceof Routes?"routes":"openvpn";
        if(method.equals("disconnect")){EngineVpnService s=EngineVpnService.current;if(s!=null){new EngineJournal(getContext(),protocol).desired("");s.requestStop();}else{EngineJournal journal=new EngineJournal(getContext(),protocol);Bundle prior=journal.previous();journal.desired("");journal.save(prior.getString("id",""),"disconnected","",prior.getString("log","")+"\nDisconnect requested");}}
        if(method.equals("recheck")){EngineVpnService s=EngineVpnService.current;if(s!=null)s.verifyTraffic();}
        return EngineVpnService.status(getContext(),protocol);
    }
    public Cursor query(Uri u,String[] p,String s,String[] a,String order){throw new UnsupportedOperationException();}
    public String getType(Uri u){return null;}
    public Uri insert(Uri u,ContentValues v){throw new UnsupportedOperationException();}
    public int delete(Uri u,String s,String[] a){throw new UnsupportedOperationException();}
    public int update(Uri u,ContentValues v,String s,String[] a){throw new UnsupportedOperationException();}
    public static final class Awg extends EngineStatusProvider{}
    public static final class Xray extends EngineStatusProvider{}
    public static final class OpenVpn extends EngineStatusProvider{}
    public static final class Routes extends EngineStatusProvider{}
}
