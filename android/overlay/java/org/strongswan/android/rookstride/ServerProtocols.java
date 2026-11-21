package org.strongswan.android.rookstride;

import java.util.*;
import org.json.*;

/** Server identity and per-protocol records; imported profiles never gain admin access. */
public final class ServerProtocols {
    private ServerProtocols(){}
    public static List<Gateway> servers(List<Gateway> nodes){
        List<Gateway> result=new ArrayList<>();
        for(Gateway node:nodes){boolean found=false;for(Gateway existing:result)if(sameServer(existing,node)){found=true;break;}if(!found)result.add(node);}
        return result;
    }
    public static String name(Gateway server){String value=server.get("serverName");return !value.isEmpty()?value:!server.get("name").isEmpty()?server.get("name"):server.get("host");}
    /** Local physical-server label; connection names, identities and credentials stay independent. */
    public static void rename(List<Gateway> nodes,Gateway server,String input){
        String value=input==null?"":input.trim();
        if(value.isEmpty()||value.length()>80||value.codePoints().anyMatch(c->Character.isISOControl(c)||c==0x2028||c==0x2029))throw new IllegalArgumentException("Enter a server name of 1–80 characters.");
        if(server==null||server.data.optBoolean("clientOnly"))throw new IllegalArgumentException("Choose a managed server.");
        ArrayList<Gateway> matches=new ArrayList<>();
        for(Gateway root:nodes)for(Gateway part:root.isPair()?Arrays.asList(root,root.exit):Collections.singletonList(root))if(PairNodes.same(part,server))matches.add(part);
        if(matches.isEmpty())throw new IllegalArgumentException("This server is no longer saved.");
        for(Gateway part:matches)part.set("serverName",value);
    }
    public static List<SingleProtocols> ordered(Set<String> installed,boolean present){
        List<SingleProtocols> result=new ArrayList<>();for(SingleProtocols p:SingleProtocols.values())if(installed.contains(p.id)==present)result.add(p);
        result.sort(Comparator.comparing(p->p.title.toLowerCase(Locale.ROOT)));return result;
    }
    public static boolean sameServer(Gateway a,Gateway b){
        if(a==null||b==null||a.isPair()||b.isPair()||a.data.optBoolean("clientOnly")||b.data.optBoolean("clientOnly"))return false;
        String ap=a.get("fingerprint"),bp=b.get("fingerprint");
        if(!ap.isEmpty()&&!bp.isEmpty()&&!ap.equals(bp))return false;
        if(!a.get("machine").isEmpty()&&a.get("machine").equals(b.get("machine"))&&!ap.isEmpty()&&ap.equals(bp))return true;
        return !a.get("host").isEmpty()&&a.get("host").equalsIgnoreCase(b.get("host"))&&a.port()==b.port();
    }
    public static Gateway find(List<Gateway> nodes,Gateway server,String protocol){
        for(Gateway node:nodes)if(hasProtocolRecord(node)&&sameServer(server,node)&&SingleProtocols.from(node.get("protocol")).id.equals(protocol))return node;
        return null;
    }
    private static boolean hasProtocolRecord(Gateway node){
        if(!node.get("protocol").isEmpty()||!node.get("profileUuid").isEmpty())return true;
        // Early IKEv2 records predate the explicit protocol field. An empty
        // managed VPS has neither a phone profile nor an IKE service snapshot.
        JSONObject snapshot=node.data.optJSONObject("snapshot"),services=snapshot==null?null:snapshot.optJSONObject("services");
        return services!=null&&services.has("strongswan-starter");
    }
    public static Set<String> installed(List<Gateway> nodes,Gateway server){
        Set<String> ids=new LinkedHashSet<>();
        for(Gateway node:nodes)if(sameServer(server,node)){
            JSONObject probe=node.data.optJSONObject("probe"),inventory=probe==null?null:probe.optJSONObject("inventory");
            if(probe!=null&&probe.optBoolean("gateway"))ids.add("ikev2");
            JSONArray values=inventory==null?null:inventory.optJSONArray("installed_protocols");
            if(values!=null)for(int i=0;i<values.length();i++){String id=values.optString(i);for(SingleProtocols protocol:SingleProtocols.values())if(protocol.id.equals(id))ids.add(id);}
            if(inventory==null&&node.data.optJSONObject("snapshot")!=null&&node.data.optJSONObject("snapshot").has("services"))ids.add(SingleProtocols.from(node.get("protocol")).id);
        }
        return ids;
    }
    public static void recordInstalled(List<Gateway> nodes,Gateway installed,String instance)throws JSONException{
        String protocol=SingleProtocols.from(installed.get("protocol")).id;
        for(Gateway node:nodes)if(sameServer(installed,node)){
            JSONObject previous=node.data.optJSONObject("probe");if(previous==null)continue;JSONObject probe=new JSONObject(previous.toString());
            if(protocol.equals("ikev2"))probe.put("gateway",true);
            else{
                JSONObject inventory=probe.optJSONObject("inventory");if(inventory==null){inventory=new JSONObject();probe.put("inventory",inventory);}
                JSONArray ids=inventory.optJSONArray("installed_protocols");if(ids==null){ids=new JSONArray();inventory.put("installed_protocols",ids);}boolean found=false;for(int i=0;i<ids.length();i++)if(protocol.equals(ids.optString(i)))found=true;if(!found)ids.put(protocol);
                if(!instance.isEmpty()){JSONObject instances=inventory.optJSONObject("installed_instances");if(instances==null){instances=new JSONObject();inventory.put("installed_instances",instances);}instances.put(protocol,instance);}
            }
            node.data.put("probe",probe);
        }
    }
    public static boolean changedInstance(Gateway node,String instance){return !instance.isEmpty()&&!node.get("serverInstance").isEmpty()&&!instance.equals(node.get("serverInstance"));}
    public static void recordRemoved(List<Gateway> nodes,Gateway removed)throws JSONException{
        String protocol=SingleProtocols.from(removed.get("protocol")).id;
        for(Gateway node:nodes)if(sameServer(removed,node)){
            JSONObject previous=node.data.optJSONObject("probe");if(previous==null)continue;
            JSONObject probe=new JSONObject(previous.toString());
            if(protocol.equals("ikev2")){probe.put("gateway",false);probe.remove("status");}
            else{
                JSONObject inventory=probe.optJSONObject("inventory");
                if(inventory!=null){JSONArray old=inventory.optJSONArray("installed_protocols"),keep=new JSONArray();if(old!=null)for(int i=0;i<old.length();i++)if(!protocol.equals(old.optString(i)))keep.put(old.get(i));inventory.put("installed_protocols",keep);JSONObject instances=inventory.optJSONObject("installed_instances");if(instances!=null)instances.remove(protocol);}
            }
            node.data.put("probe",probe);
        }
    }
    /** Only an authenticated report linked to the exact preceding private identity may migrate a cached pin. */
    public static boolean publicCertificateMigration(Gateway node,JSONObject status,String instance){
        if(node.isPair()||node.data.optBoolean("clientOnly")||SingleProtocols.from(node.get("protocol"))!=SingleProtocols.IKEV2)return false;
        JSONObject cert=status==null?null:status.optJSONObject("certificate");String old=node.get("serverInstance");
        return cert!=null&&cert.optString("trust").equals("public")&&instance.matches("public-[a-f0-9]{32}")&&old.matches("[a-f0-9]{64}")&&old.equals(cert.optString("previous_instance"));
    }
    /** Retain verified public hostnames across a managed VPN reset on this phone. */
    public static void rememberIkeCertificateNames(List<Gateway> nodes,Gateway server,JSONObject status)throws JSONException{
        JSONObject certificate=status==null?null:status.optJSONObject("certificate");if(certificate==null||!certificate.optString("trust").equals("public"))return;
        JSONArray original=certificate.optJSONArray("aliases"),names=original==null?new JSONArray():new JSONArray(original.toString());String identity=certificate.optString("identity");if(!identity.isEmpty()&&!identity.matches("[0-9.]+")&&InputRules.host(identity)){boolean found=false;for(int i=0;i<names.length();i++)if(identity.equals(names.optString(i)))found=true;if(!found)names.put(identity);}if(names.length()>5)return;for(int i=0;i<names.length();i++)if(!InputRules.host(names.optString(i)))return;
        for(Gateway node:nodes)if(sameServer(server,node))node.data.put("ikeCertificateAliases",new JSONArray(names.toString()));
    }
    public static void rememberConnection(List<Gateway> nodes,Gateway source,JSONObject status)throws JSONException{
        rememberCoexistence(source,status.optString("coexist_pair"));
        String protocol=SingleProtocols.from(source.get("protocol")).id;int port=status.optInt("port",source.data.optInt("vpnPort",SingleProtocols.from(protocol).port));
        source.data.put("vpnPort",port);source.data.put("vpnPortAuto",false);
        if(status.optBoolean("manual_sign_in"))source.set("accessMode","password");
        for(Gateway sibling:nodes)if(sameServer(source,sibling)){
            JSONObject ports=sibling.data.optJSONObject("lastVpnPorts");if(ports==null)ports=new JSONObject();ports.put(protocol,port);sibling.data.put("lastVpnPorts",ports);
        }
    }
    /** Only an authenticated server report may recover selective pair coexistence ownership. */
    public static void rememberCoexistence(Gateway node,String pair){
        if(!node.isPair()&&!node.data.optBoolean("clientOnly")&&node.get("protocol").equals("openvpn")&&pair!=null&&pair.matches("[a-f0-9]{32}"))node.set("coexistPair",pair);
        else node.data.remove("coexistPair");
    }
    public static Gateway createCoexistingOpenVpn(Gateway pair)throws JSONException{
        if(!pair.isPair()||!PairController.modern(pair)||!pair.get("pairEntryProtocol").equals("awg")||!pair.get("pairId").matches("[a-f0-9]{32}"))throw new IllegalArgumentException("This separate VPN requires an AmneziaWG Double VPN entry.");
        Gateway base=PairNodes.copy(pair);PairNodes.clearConnection(base);base.set("serverName",name(pair));base.set("vpnServer",pair.get("vpnServer"));
        Gateway node=create(base,SingleProtocols.OPENVPN);node.set("coexistPair",pair.get("pairId"));return node;
    }
    public static Gateway create(Gateway server,SingleProtocols protocol)throws JSONException{
        if(server.isPair()||server.data.optBoolean("clientOnly"))throw new IllegalArgumentException("Choose a single server with administrator access");
        Gateway node=new Gateway();for(String key:new String[]{"host","admin","fingerprint","machine","sshKeyType"})node.set(key,server.get(key));
        if(server.data.optJSONArray("ikeCertificateAliases")!=null)node.data.put("ikeCertificateAliases",new JSONArray(server.data.getJSONArray("ikeCertificateAliases").toString()));
        if(server.data.optJSONObject("lastVpnPorts")!=null)node.data.put("lastVpnPorts",new JSONObject(server.data.getJSONObject("lastVpnPorts").toString()));
        if(!server.get("vpnServer").isEmpty())node.set("vpnServer",server.get("vpnServer"));
        String name=name(server);node.set("serverName",name);node.set("name",name+" · "+protocol.title);
        node.set("protocol",protocol.id);node.set("setupIntent","install");node.data.put("port",server.port());node.data.put("vpnPort",protocol.port);node.data.put("vpnPortAuto",protocol!=SingleProtocols.IKEV2);
        JSONObject ports=server.data.optJSONObject("lastVpnPorts");if(ports!=null&&InputRules.port(ports.optInt(protocol.id,0))){node.data.put("vpnPort",ports.getInt(protocol.id));node.data.put("vpnPortAuto",false);}
        node.data.put("remember",server.remember());if(server.data.has("saveAccessChosen"))node.data.put("saveAccessChosen",server.data.getBoolean("saveAccessChosen"));node.sshPassword=server.sshPassword;node.privateKey=server.privateKey;
        if(server.data.optJSONObject("probe")!=null)node.data.put("probe",new JSONObject(server.data.getJSONObject("probe").toString()));
        return node;
    }
}
