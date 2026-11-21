package org.strongswan.android.rookstride;

public final class InputRules {
    private InputRules() {}
    public static boolean vpnPassword(String value) {
        if(value==null)return false;int count=value.codePointCount(0,value.length());if(count<1||count>127)return false;
        for(int i=0;i<value.length();){int c=value.codePointAt(i);if(c<32||c>=127&&c<=159||c==0x2028||c==0x2029||c>=0xD800&&c<=0xDFFF)return false;i+=Character.charCount(c);}return value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=127;
    }
    /** Advice is evaluated at account creation, never while joining a VPN. */
    public static boolean weakVpnPassword(String value){
        if(!vpnPassword(value))return false;
        return value.codePointCount(0,value.length())<8 || value.codePoints().distinct().count()==1 ||
            "01234567890123456789".contains(value) || "12345678901234567890".contains(value) || "abcdefghijklmnopqrstuvwxyz".contains(value.toLowerCase(java.util.Locale.ROOT));
    }
    public static String generatedVpnPassword(){
        byte[] bytes=new byte[15];new java.security.SecureRandom().nextBytes(bytes);String alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(alphabet.charAt(b&63));return out.toString();
    }
    public static boolean host(String value) { return value!=null && value.matches("[A-Za-z0-9.-]{1,253}") && !value.startsWith("-"); }
    public static boolean username(String value) { return value!=null && value.matches("[A-Za-z0-9_.@-]{1,64}"); }
    public static boolean port(int value) { return value>0 && value<=65535; }
    public static boolean stage(String value) { return value!=null && value.matches("/tmp/rookstride-[a-f0-9]{32}"); }
    public static boolean job(String value) { return value!=null && value.matches("[a-f0-9]{32}"); }
    public static String quote(String value) { return "'"+value.replace("'","'\\''")+"'"; }
}
