package org.strongswan.android.rookstride;

import android.content.Context;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Locale;
import java.util.List;
import java.util.IdentityHashMap;
import java.util.Map;

/** Durable first-use identities, including servers still in a setup draft. No passwords. */
public final class ServerIdentityPins {
    private static final Object LOCK=new Object();
    private final Vault vault,servers;
    public ServerIdentityPins(Context context){vault=new Vault(context,"ssh-identities.enc");servers=new Vault(context);}
    public static boolean sameEndpoint(Gateway a,Gateway b){return a.port()==b.port()&&a.get("host").equalsIgnoreCase(b.get("host"));}
    private static String merge(Gateway node,Gateway saved,String known)throws IOException{
        if(saved==null||saved.data.optBoolean("clientOnly")||!sameEndpoint(node,saved)||saved.get("fingerprint").isEmpty())return known;
        String pin=saved.get("fingerprint");
        if(!known.isEmpty()&&!known.equals(pin))throw new IOException("Saved SSH identities disagree; review the server identity before signing in.");
        return pin;
    }
    public String get(Gateway node)throws Exception{synchronized(LOCK){
        String known="";
        for(Gateway saved:vault.read())known=merge(node,saved,known);
        // Existing installations already pinned their identity in the gateway vault.
        // A new draft for that endpoint must not downgrade it to first use.
        for(Gateway saved:servers.read()){known=merge(node,saved,known);known=merge(node,saved.exit,known);}
        return known;
    }}
    public void remember(Gateway node,String fingerprint)throws Exception{synchronized(LOCK){
        if(!fingerprint.matches("SHA256:[A-Za-z0-9+/]{43}"))throw new IOException("Invalid SSH identity");
        String known=get(node);if(!known.isEmpty()&&!known.equals(fingerprint))throw new IOException("Server SSH identity changed; review the replacement before signing in.");
        ArrayList<Gateway> records=vault.read();
        for(Gateway saved:records)if(sameEndpoint(saved,node)){
            if(!saved.get("fingerprint").equals(fingerprint))throw new IOException("Server SSH identity changed; review the replacement before signing in.");
            return;
        }
        if(records.size()>=512)throw new IOException("Saved SSH identity limit reached; remove unused server identities first.");
        Gateway record=new Gateway();record.set("host",node.get("host").toLowerCase(Locale.ROOT));record.data.put("port",node.port());record.set("fingerprint",fingerprint);records.add(record);vault.write(records);
    }}
    public void forget(Gateway node)throws Exception{synchronized(LOCK){
        ArrayList<Gateway> records=vault.read();records.removeIf(saved->sameEndpoint(saved,node));vault.write(records);
    }}
    /** Removing the last administrator record retires only that physical endpoint's pin. */
    public void forgetIfUnreferenced(Gateway removed,List<Gateway> remaining)throws Exception{synchronized(LOCK){
        for(Gateway record:remaining)if(references(record,removed)||references(record.exit,removed))return;
        forget(removed);
    }}
    private static boolean references(Gateway record,Gateway endpoint){return record!=null&&!record.data.optBoolean("clientOnly")&&sameEndpoint(record,endpoint);}
    /** The owner reviewed both complete fingerprints. Pin replacement is compare-and-set,
     * never a one-time authentication bypass; the retry must match the new pin. */
    public void replaceReviewed(Gateway node,String expected,String replacement,List<Gateway> active)throws Exception{synchronized(LOCK){
        if(!expected.matches("SHA256:[A-Za-z0-9+/]{43}")||!replacement.matches("SHA256:[A-Za-z0-9+/]{43}")||expected.equals(replacement))throw new IOException("Review a different, valid server identity.");
        if(!get(node).equals(expected))throw new IOException("The saved server identity changed during this review. Check it again before signing in.");
        ArrayList<Gateway> pins=vault.read();boolean found=false;
        for(Gateway pin:pins)if(sameEndpoint(pin,node)){if(!pin.get("fingerprint").equals(expected))throw new IOException("Saved SSH identities disagree. Sign-in was stopped.");pin.set("fingerprint",replacement);found=true;}
        if(!found){if(pins.size()>=512)throw new IOException("Saved SSH identity limit reached");Gateway pin=new Gateway();pin.set("host",node.get("host").toLowerCase(Locale.ROOT));pin.data.put("port",node.port());pin.set("fingerprint",replacement);pins.add(pin);}
        IdentityHashMap<Gateway,String> previous=new IdentityHashMap<>();
        for(Gateway record:active){reviewReplacement(record,node,expected,replacement,previous);reviewReplacement(record.exit,node,expected,replacement,previous);}
        reviewReplacement(node,node,expected,replacement,previous);
        for(Gateway record:previous.keySet())record.set("fingerprint",replacement);
        try{servers.write(new ArrayList<>(active));vault.write(pins);}
        catch(Exception failure){for(Map.Entry<Gateway,String> old:previous.entrySet())old.getKey().set("fingerprint",old.getValue());try{servers.write(new ArrayList<>(active));}catch(Exception rollback){failure.addSuppressed(rollback);}throw new IOException("Could not save the reviewed identity. Sign-in was stopped.",failure);}
    }}
    private static void reviewReplacement(Gateway record,Gateway endpoint,String expected,String next,IdentityHashMap<Gateway,String> previous)throws IOException{
        if(!references(record,endpoint)||previous.containsKey(record))return;
        String old=record.get("fingerprint");if(!old.isEmpty()&&!old.equals(expected))throw new IOException("Another saved connection has a different server identity. Sign-in was stopped.");
        previous.put(record,old);
    }
    /** Only the already-verified OS job may replace its exact old SSH identity.
     * Ordinary first-use/update paths still reject every changed key. */
    public void replaceVerifiedOsIdentity(Gateway node)throws Exception{synchronized(LOCK){
        org.json.JSONObject plan=node.data.optJSONObject("osReinstall");String previous=node.get("osPreviousFingerprint"),next=node.get("fingerprint");
        if(!node.get("osReinstallState").equals("complete")||plan==null||!next.equals(plan.optString("fingerprint"))||previous.equals(next)||!previous.matches("SHA256:[A-Za-z0-9+/]{43}")||!next.matches("SHA256:[A-Za-z0-9+/]{43}"))throw new IOException("The completed OS job has no verified SSH identity replacement");
        ArrayList<Gateway> records=vault.read();boolean found=false;
        for(Gateway record:records)if(sameEndpoint(record,node)){
            String pin=record.get("fingerprint");if(!pin.equals(previous)&&!pin.equals(next))throw new IOException("The saved SSH identity changed outside this OS job. Verify it before continuing.");
            record.set("fingerprint",next);found=true;
        }
        if(!found){if(records.size()>=512)throw new IOException("Saved SSH identity limit reached");Gateway record=new Gateway();record.set("host",node.get("host").toLowerCase(Locale.ROOT));record.data.put("port",node.port());record.set("fingerprint",next);records.add(record);}
        vault.write(records);
    }}
}
