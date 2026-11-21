package org.strongswan.android.rookstride;

import android.content.Context;
import org.json.*;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.StrongSwanApplication;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.security.LocalCertificateStore;
import org.strongswan.android.rookstride.engine.NativeProfileStore;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.*;

/** Android storage adapter; only freshly allocated client assets are ever staged or removed. */
final class ConnectionBundleAndroidStore implements ConnectionBundleImport.Store {
    private final Context context;private final Vault vault;private final NativeProfileStore nativeProfiles;private final ConnectionImportJournal importJournal;
    ConnectionBundleAndroidStore(Context context){this.context=context.getApplicationContext();vault=new Vault(this.context);nativeProfiles=new NativeProfileStore(this.context);importJournal=new ConnectionImportJournal(this.context);}
    @Override public ArrayList<Gateway> catalog()throws Exception{return vault.read();}
    @Override public ArrayList<Gateway> append(List<Gateway> nodes)throws Exception{return vault.appendClientRecords(nodes);}
    @Override public JSONObject journal()throws Exception{return importJournal.read();}
    @Override public void journal(JSONObject value)throws Exception{importJournal.write(value);}
    @Override public void clearJournal()throws Exception{importJournal.clear();}
    private VpnProfileDataSource sql(){return new VpnProfileSqlDataSource().open();}
    private boolean nativeExists(String id){File file=new File(new File(context.getNoBackupFilesDir(),"vpn-profiles"),id+".enc");return file.exists()||new File(file.getPath()+".bak").exists()||new File(file.getPath()+".new").exists();}

    @Override public ConnectionBundleImport.Asset describe(Gateway node,JSONObject envelope)throws Exception{
        String id=node.get("id"),protocol=envelope.getString("format");if(nativeExists(id))throw new IOException("A new connection identifier is already in use");
        VpnProfileDataSource source=sql();try{if(source.getVpnProfile(id)!=null)throw new IOException("A new VPN profile identifier is already in use");}finally{source.close();}
        if(!protocol.equals("ikev2"))return new ConnectionBundleImport.Asset(id,protocol,"","",false,node.get("bundleImportId"));
        JSONObject profile=new JSONObject(envelope.getString("content"));ManagedConfiguration policy=StrongSwanApplication.getInstance().getManagedConfigurationService().getManagedConfiguration();
        if(!policy.isAllowProfileCreation()||!policy.isAllowProfileImport()||!policy.isAllowExistingProfiles()||profile.getJSONObject("remote").has("cert")&&!policy.isAllowCertificateImport())throw new IOException("This phone’s administrator does not allow importing this VPN");
        X509Certificate cert=certificate(profile);if(cert==null)return new ConnectionBundleImport.Asset(id,protocol,"","",false,node.get("bundleImportId"));
        LocalCertificateStore store=new LocalCertificateStore();String alias=store.getCertificateAlias(cert);X509Certificate previous=store.getCertificate(alias);
        ConnectionBundleImport.Asset asset=new ConnectionBundleImport.Asset(id,protocol,alias,certificateHash(cert),previous==null,node.get("bundleImportId"));
        if(previous!=null&&(!Arrays.equals(previous.getEncoded(),cert.getEncoded())||!new CertificatePublication(context).existingMatches(asset,cert)))throw new IOException("This certificate conflicts with trust already saved on this phone. Import it separately.");
        return asset;
    }
    @Override public void stage(Gateway node,JSONObject envelope,ConnectionBundleImport.Asset asset)throws Exception{
        if(!node.get("id").equals(asset.id)||!node.get("protocol").equals(asset.protocol))throw new IOException("Connection import plan changed");
        if(!asset.protocol.equals("ikev2")){if(nativeExists(asset.id))throw new IOException("A staged connection identifier is already in use");nativeProfiles.save(asset.id,asset.protocol,node.get("name"),envelope.getString("content"));if(!matches(node,envelope))throw new IOException("Could not verify the staged VPN connection");return;}
        JSONObject definition=new JSONObject(envelope.getString("content"));X509Certificate cert=certificate(definition);VpnProfileDataSource source=sql();
        try{
            if(source.getVpnProfile(asset.id)!=null)throw new IOException("A staged VPN profile identifier is already in use");
            if(cert!=null){LocalCertificateStore store=new LocalCertificateStore();X509Certificate previous=store.getCertificate(asset.certificateAlias);
                if(previous!=null&&(!certificateHash(previous).equals(asset.certificateHash)||!new CertificatePublication(context).existingMatches(asset,cert)))throw new IOException("Saved certificate trust changed during import");
                if(previous==null){if(!asset.newCertificate)throw new IOException("Saved certificate trust changed during import");new CertificatePublication(context).stage(asset,cert);X509Certificate actual=store.getCertificate(asset.certificateAlias);if(actual==null||!certificateHash(actual).equals(asset.certificateHash))throw new IOException("Could not verify the saved VPN server certificate");TrustedCertificateManager.getInstance().reset();}
            }
            if(source.insertProfile(ike(node,definition,asset.certificateAlias))==null)throw new IOException("Could not save the IKEv2 connection");
        }finally{source.close();}
        if(!matches(node,envelope))throw new IOException("Could not verify the staged IKEv2 connection");
    }
    private static X509Certificate certificate(JSONObject definition)throws Exception{JSONObject remote=definition.getJSONObject("remote");return !remote.has("cert")?null:(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(remote.getString("cert"))));}
    private static String certificateHash(X509Certificate cert)throws Exception{return ConnectionBundleImport.hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));}
    private static VpnProfile ike(Gateway node,JSONObject definition,String alias)throws Exception{
        JSONObject remote=definition.getJSONObject("remote"),local=definition.getJSONObject("local");VpnProfile profile=new VpnProfile();profile.setUUID(UUID.fromString(node.get("profileUuid")));profile.setName(node.get("name"));profile.setGateway(remote.getString("addr"));profile.setRemoteId(remote.optString("id",null));int port=remote.optInt("port",500);profile.setPort(port==500?null:port);profile.setUsername(local.getString("eap_id"));profile.setVpnType(VpnType.IKEV2_EAP);profile.setMTU(1280);profile.setCertificateAlias(alias.isEmpty()?null:alias);profile.setPassword(null);profile.setSplitTunneling(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4|VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);profile.setFlags(VpnProfile.FLAGS_SUPPRESS_CERT_REQS);return profile;
    }
    @Override public boolean matches(Gateway node,JSONObject envelope)throws Exception{
        if(!node.data.optBoolean("clientOnly"))return false;
        if(!envelope.getString("format").equals("ikev2")){try{JSONObject saved=nativeProfiles.read(node.get("id"));return envelope.getString("format").equals(saved.getString("protocol"))&&envelope.getString("content").equals(saved.getString("content"));}catch(Exception unavailable){return false;}}
        JSONObject definition=new JSONObject(envelope.getString("content"));if(!node.vpnPassword.equals(definition.getJSONObject("local").getString("shared_secret")))return false;
        X509Certificate cert=certificate(definition);String alias=cert==null?"":new LocalCertificateStore().getCertificateAlias(cert);
        if(cert!=null){X509Certificate saved=new LocalCertificateStore().getCertificate(alias);if(saved==null||!Arrays.equals(saved.getEncoded(),cert.getEncoded()))return false;}
        VpnProfileDataSource source=sql();try{VpnProfile saved=source.getVpnProfile(node.get("profileUuid"));if(saved==null)return false;VpnProfile wanted=ike(node,definition,alias);
            return saved.getVpnType()==wanted.getVpnType()&&Objects.equals(saved.getGateway(),wanted.getGateway())&&Objects.equals(saved.getUsername(),wanted.getUsername())&&Objects.equals(saved.getRemoteId(),wanted.getRemoteId())&&Objects.equals(saved.getPort(),wanted.getPort())&&Objects.equals(saved.getCertificateAlias(),wanted.getCertificateAlias())&&Objects.equals(saved.getMTU(),wanted.getMTU())&&Objects.equals(saved.getSplitTunneling(),wanted.getSplitTunneling())&&Objects.equals(saved.getFlags(),wanted.getFlags())&&empty(saved.getIkeProposal())&&empty(saved.getEspProposal())&&empty(saved.getLocalId())&&empty(saved.getDnsServers())&&empty(saved.getProxyHost());
        }finally{source.close();}
    }
    private static boolean empty(String value){return value==null||value.isEmpty();}
    private boolean referenced(ConnectionBundleImport.Asset asset,List<Gateway> nodes){for(Gateway node:nodes)if(asset.id.equals(node.get("id"))||asset.id.equals(node.get("profileUuid"))||node.exit!=null&&(asset.id.equals(node.exit.get("id"))||asset.id.equals(node.exit.get("profileUuid"))))return true;return false;}
    @Override public void cleanup(ConnectionBundleImport.Asset asset,List<Gateway> references)throws Exception{
        if(referenced(asset,references))return;
        if(!asset.protocol.equals("ikev2")){nativeProfiles.remove(asset.id);if(nativeExists(asset.id))throw new IOException("A staged VPN connection could not be removed");return;}
        VpnProfileDataSource source=sql();try{VpnProfile profile=source.getVpnProfile(asset.id);if(profile!=null&&!source.deleteVpnProfile(profile))throw new IOException("A staged IKEv2 connection could not be removed");}finally{source.close();}
    }
    @Override public void finishCleanup(List<ConnectionBundleImport.Asset> assets,List<Gateway> references)throws Exception{
        boolean any=false;for(ConnectionBundleImport.Asset asset:assets)if(asset.newCertificate)any=true;if(!any)return;
        Set<String> used=new HashSet<>();VpnProfileDataSource source=sql();try{for(VpnProfile profile:source.getAllVpnProfiles())used.add(profile.getCertificateAlias());}finally{source.close();}
        source=new VpnProfileSource(context).open();try{for(VpnProfile profile:source.getAllVpnProfiles())used.add(profile.getCertificateAlias());}finally{source.close();}
        for(ConnectionBundleImport.Asset asset:assets)if(!asset.certificateAlias.isEmpty()&&referenced(asset,references))used.add(asset.certificateAlias);
        CertificatePublication publication=new CertificatePublication(context);for(ConnectionBundleImport.Asset asset:assets)publication.cleanup(asset,used.contains(asset.certificateAlias));TrustedCertificateManager.getInstance().reset();
    }
    JSONObject savedConnection(Gateway node)throws Exception{
        String protocol=SingleProtocols.from(node.get("protocol")).id;JSONObject envelope;
        if(!protocol.equals("ikev2")){JSONObject saved=nativeProfiles.read(node.get("id"));if(!protocol.equals(saved.getString("protocol")))throw new IOException("The saved connection method differs");envelope=ConnectionExport.fromStored(node.get("id"),saved).pending();envelope.put("content",saved.getString("content"));}
        else{
            VpnProfileDataSource source=new VpnProfileSource(context).open();try{VpnProfile p=source.getVpnProfile(node.get("profileUuid"));if(p==null||p.getVpnType()!=VpnType.IKEV2_EAP)throw new IOException("Choose an IKEv2 username/password connection");
                if(!empty(p.getIkeProposal())||!empty(p.getEspProposal())||!empty(p.getLocalId())||!empty(p.getDnsServers())||!empty(p.getProxyHost())||p.getNATKeepAlive()!=null)throw new IOException("Share this advanced IKEv2 profile separately");
                String password=node.vpnPassword.isEmpty()?p.getPassword():node.vpnPassword;if(!InputRules.vpnPassword(password))throw new IOException("Include the existing VPN password before sharing these connections");
                JSONObject remote=new JSONObject().put("addr",p.getGateway()).put("port",p.getPort()==null?500:p.getPort()).put("certreq",false);if(!empty(p.getRemoteId()))remote.put("id",p.getRemoteId());
                if(!empty(p.getCertificateAlias())){X509Certificate cert=new LocalCertificateStore().getCertificate(p.getCertificateAlias());if(cert==null)throw new IOException("The saved VPN certificate is unavailable");remote.put("cert",Base64.getEncoder().encodeToString(cert.getEncoded()));}
                int split=p.getSplitTunneling()==null?0:p.getSplitTunneling();JSONObject definition=new JSONObject().put("uuid",p.getUUID().toString()).put("name",p.getName()).put("type","ikev2-eap").put("remote",remote).put("local",new JSONObject().put("eap_id",p.getUsername()).put("shared_secret",password)).put("mtu",p.getMTU()==null?1280:p.getMTU()).put("split-tunneling",new JSONObject().put("block-ipv4",(split&VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4)!=0).put("block-ipv6",(split&VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6)!=0));envelope=ConnectionExport.fromResponse(definition).pending();
            }finally{source.close();}
        }
        if(!node.get("name").isEmpty())envelope.put("display_name",node.get("name"));ConnectionBundle.pack(Collections.singletonList(envelope));return envelope;
    }
}
