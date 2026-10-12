package org.strongswan.android.rookstride;

public final class InputRules {
    private InputRules() {}
    public static boolean host(String value) { return value!=null && value.matches("[A-Za-z0-9.-]{1,253}") && !value.startsWith("-"); }
    public static boolean username(String value) { return value!=null && value.matches("[A-Za-z0-9_.@-]{1,64}"); }
    public static boolean port(int value) { return value>0 && value<=65535; }
    public static boolean stage(String value) { return value!=null && value.matches("/tmp/rookstride-[a-f0-9]{32}"); }
    public static boolean job(String value) { return value!=null && value.matches("[a-f0-9]{32}"); }
    public static String quote(String value) { return "'"+value.replace("'","'\\''")+"'"; }
}
