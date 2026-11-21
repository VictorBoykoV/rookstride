// Copyright 2026 Rookstride contributors. SPDX-License-Identifier: GPL-3.0-or-later
// JNI adapter to OpenVPN 3's public ClientAPI; the core retains its own license.
#include <jni.h>
#include <client/ovpncli.hpp>
#include <mutex>
#include <memory>
using namespace openvpn::ClientAPI;
namespace {
JavaVM* vm;
std::mutex guard;
struct Client;
Client* active=nullptr;
struct Env {
 JNIEnv* e=nullptr; bool attached=false;
 Env(){if(vm->GetEnv((void**)&e,JNI_VERSION_1_6)!=JNI_OK){vm->AttachCurrentThread(&e,nullptr);attached=true;}}
 ~Env(){if(attached)vm->DetachCurrentThread();}
};
struct Client:OpenVPNClient {
 jobject service; jclass cls;
 Client(JNIEnv* e,jobject s){service=e->NewGlobalRef(s);cls=(jclass)e->NewGlobalRef(e->GetObjectClass(s));}
 ~Client(){Env x;x.e->DeleteGlobalRef(service);x.e->DeleteGlobalRef(cls);}
 bool call(const char* method){Env x;auto m=x.e->GetMethodID(cls,method,"()Z");return m&&x.e->CallBooleanMethod(service,m)&&!x.e->ExceptionCheck();}
 bool address(const char* method,const std::string& a,int prefix){Env x;auto m=x.e->GetMethodID(cls,method,"(Ljava/lang/String;I)Z");auto s=x.e->NewStringUTF(a.c_str());bool ok=m&&x.e->CallBooleanMethod(service,m,s,prefix)&&!x.e->ExceptionCheck();x.e->DeleteLocalRef(s);return ok;}
 bool tun_builder_new() override{return call("openvpnNew");}
 bool tun_builder_set_layer(int l) override{return l==3;}
 bool tun_builder_set_remote_address(const std::string&,bool) override{return true;}
 bool tun_builder_set_session_name(const std::string&) override{return true;}
 bool tun_builder_set_mtu(int mtu) override{Env x;return x.e->CallBooleanMethod(service,x.e->GetMethodID(cls,"openvpnMtu","(I)Z"),mtu);}
 bool tun_builder_add_address(const std::string& a,int p,const std::string&,bool,bool) override{return address("openvpnAddress",a,p);}
 bool tun_builder_add_route(const std::string& a,int p,int,bool) override{return address("openvpnRoute",a,p);}
 // Full-device routing is deliberate; do not silently bypass local networks.
 bool tun_builder_exclude_route(const std::string&,int,int,bool) override{return false;}
 bool tun_builder_reroute_gw(bool v4,bool v6,unsigned int) override{return (!v4||address("openvpnRoute","0.0.0.0",0))&&(!v6||address("openvpnRoute","::",0));}
 bool tun_builder_set_dns_options(const openvpn::DnsOptions& dns) override{
  for(const auto& pair:dns.servers)for(const auto& a:pair.second.addresses)if(!address("openvpnDns",a.address,0))return false;
  return true;
 }
 int tun_builder_establish() override{Env x;return x.e->CallIntMethod(service,x.e->GetMethodID(cls,"openvpnEstablish","()I"));}
 bool socket_protect(openvpn_io::detail::socket_type fd,std::string,bool) override{Env x;return x.e->CallBooleanMethod(service,x.e->GetMethodID(cls,"protectSocket","(I)Z"),(jint)fd);}
 bool pause_on_connection_timeout() override{return false;}
 void event(const Event& event) override{Env x;auto n=x.e->NewStringUTF(event.name.c_str());x.e->CallVoidMethod(service,x.e->GetMethodID(cls,"openvpnEvent","(Ljava/lang/String;Z)V"),n,(jboolean)(event.error||event.fatal));x.e->DeleteLocalRef(n);}
 void log(const LogInfo&) override{}
 void acc_event(const AppCustomControlMessageEvent&) override{}
 void external_pki_cert_request(ExternalPKICertRequest& r) override{r.error=true;r.errorText="External PKI is not supported";}
 void external_pki_sign_request(ExternalPKISignRequest& r) override{r.error=true;r.errorText="External PKI is not supported";}
};
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* v,void*){vm=v;return JNI_VERSION_1_6;}
extern "C" JNIEXPORT jstring JNICALL Java_org_strongswan_android_rookstride_engine_OpenVpnNative_run(JNIEnv* e,jclass,jobject service,jstring config,jstring username,jstring password){
 try{
  auto client=std::make_unique<Client>(e,service);const char* text=e->GetStringUTFChars(config,nullptr);
  Config c;c.content=text;c.connTimeout=40;c.tunPersist=false;c.info=false;c.compressionMode="no";c.disableClientCert=e->GetStringLength(username)>0;e->ReleaseStringUTFChars(config,text);
  auto eval=client->eval_config(c);
  if(eval.error)return e->NewStringUTF(eval.message.c_str());
  if(eval.externalPki&&!c.disableClientCert)return e->NewStringUTF("External client keys are not supported");
  if(!eval.autologin){
   auto utf8=[&](jstring value){auto encoding=e->NewStringUTF("UTF-8");auto stringClass=e->FindClass("java/lang/String");auto method=e->GetMethodID(stringClass,"getBytes","(Ljava/lang/String;)[B");auto bytes=(jbyteArray)e->CallObjectMethod(value,method,encoding);if(e->ExceptionCheck()||!bytes)throw std::runtime_error("Could not prepare VPN sign-in");std::string result(e->GetArrayLength(bytes),'\0');e->GetByteArrayRegion(bytes,0,result.size(),reinterpret_cast<jbyte*>(&result[0]));e->DeleteLocalRef(bytes);e->DeleteLocalRef(stringClass);e->DeleteLocalRef(encoding);return result;};
   ProvideCreds credentials;credentials.username=utf8(username);credentials.password=utf8(password);
   if(credentials.username.empty()||credentials.password.empty())return e->NewStringUTF("Enter the VPN username and password");
   auto supplied=client->provide_creds(credentials);if(supplied.error)return e->NewStringUTF("VPN credentials could not be prepared");
  }
  {std::lock_guard<std::mutex> lock(guard);if(client->call("nativeStopping"))return e->NewStringUTF("");active=client.get();}
  auto result=client->connect();
  {std::lock_guard<std::mutex> lock(guard);active=nullptr;}
  return e->NewStringUTF(result.error?result.message.c_str():"");
 }catch(const std::exception& ex){std::lock_guard<std::mutex> lock(guard);active=nullptr;return e->NewStringUTF(ex.what());}
}
extern "C" JNIEXPORT void JNICALL Java_org_strongswan_android_rookstride_engine_OpenVpnNative_stop(JNIEnv*,jclass){std::lock_guard<std::mutex> lock(guard);if(active)active->stop();}

extern "C" JNIEXPORT void JNICALL Java_org_strongswan_android_rookstride_engine_OpenVpnNative_reconnect(JNIEnv*,jclass){std::lock_guard<std::mutex> lock(guard);if(active)active->reconnect(0);}
