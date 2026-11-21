package org.strongswan.android.rookstride.engine;
public final class OpenVpnNative {
    public static native String run(OpenVpnService service,String profile,String username,String password);
    public static native void stop();
    public static native void reconnect();
}
