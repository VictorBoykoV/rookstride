package org.strongswan.android.rookstride;

/** A server recipe and a phone engine are separate capabilities. */
public enum SingleProtocols {
    IKEV2("ikev2","IKEv2",500,"Rookstride",""),
    AWG("awg","AmneziaWG 3.1",51820,"AmneziaWG","org.amnezia.awg"),
    XRAY("xray","VLESS · REALITY (TCP)",443,"v2rayNG","com.v2ray.ang"),
    OPENVPN("openvpn","OpenVPN",1194,"OpenVPN for Android","de.blinkt.openvpn"),
    XHTTP("xhttp","VLESS · XHTTP / REALITY",443,"Rookstride",""),
    HYSTERIA2("hysteria2","Hysteria 2",443,"Rookstride",""),
    OUTLINE("outline","Outline · Shadowsocks / WSS",443,"Rookstride",""),
    SHADOWSOCKS("shadowsocks","Shadowsocks · v2ray-plugin / WSS",443,"Rookstride",""),
    TRUSTTUNNEL("trusttunnel","TrustTunnel · HTTP/2",443,"Rookstride",""),
    NAIVE("naive","NaïveProxy · HTTP/2",443,"Rookstride","");
    public final String id,title,client,packageName;public final int port;
    SingleProtocols(String id,String title,int port,String client,String packageName){this.id=id;this.title=title;this.port=port;this.client=client;this.packageName=packageName;}
    public String downloadUrl(){switch(this){case AWG:return "https://github.com/amnezia-vpn/amneziawg-android/releases";case XRAY:return "https://github.com/2dust/v2rayNG/releases";case OPENVPN:return "https://github.com/schwabe/ics-openvpn/releases";default:return "https://github.com/VictorBoykoV/rookstride";}}
    public boolean embedded(){return true;}
    public boolean worker(){return this==HYSTERIA2||this==OUTLINE||this==SHADOWSOCKS||this==TRUSTTUNNEL||this==NAIVE;}
    public String documentation(){switch(this){case AWG:return "https://github.com/amnezia-vpn/amneziawg-go";case XRAY:case XHTTP:return "https://xtls.github.io/en/config/";case OPENVPN:return "https://openvpn.net/community/";case HYSTERIA2:return "https://v2.hysteria.network/";case OUTLINE:return "https://developers.google.com/outline";case SHADOWSOCKS:return "https://github.com/shadowsocks/v2ray-plugin";case TRUSTTUNNEL:return "https://github.com/TrustTunnel/TrustTunnel";case NAIVE:return "https://github.com/klzgrad/naiveproxy";default:return "https://docs.strongswan.org/";}}
    public static SingleProtocols from(String id){for(SingleProtocols value:values())if(value.id.equals(id))return value;return IKEV2;}
}
