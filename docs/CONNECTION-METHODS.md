# Choosing a connection method

Rookstride installs the selected method from your phone over pinned SSH. Normal
setup asks for a server address and administrator password; `root` is the default
administrator. The app creates the VPN access, selects a free port, configures
private DNS/ad blocking, and prepares its embedded client. You can add a different
method to the same single-server VPN later. A different server address can help
when the address itself is blocked.

This document describes the private alpha18 implementation. Check the [dated test report](ADDITIONAL-METHODS-TESTING.md) before treating a new method or Double VPN combination as accepted. These
are connection methods: some share an underlying protocol or implementation.

## What each choice changes

| Menu choice | Connection from your phone | Useful first test | Main dependency |
| --- | --- | --- | --- |
| AmneziaWG 3.1 | Obfuscated WireGuard-derived UDP | A fast everyday VPN where UDP works | UDP reaches the VPS |
| IKEv2 | IPsec with a pinned certificate and user login | Ordinary networks and IPsec compatibility | UDP 500/4500 |
| OpenVPN | TCP with individual device certificates | Compatibility or a familiar exported `.ovpn` file | The TCP VPN handshake is allowed |
| VLESS · REALITY (TCP) | VLESS TCP with REALITY and Vision | A TCP alternative when ordinary VPN traffic is filtered | A reachable REALITY target and VPS |
| VLESS · XHTTP / REALITY | VLESS using XHTTP requests with REALITY | A different transport when the original VLESS TCP path fails | Compatible XHTTP client/server; its profile differs from TCP/Vision |
| Hysteria 2 | QUIC/UDP with Salamander | Fast or lossy connections with available UDP | UDP/QUIC is allowed; this is not fake TCP |
| Outline · Shadowsocks / WSS | Outline SDK, Shadowsocks and TLS WebSockets | An alternative secure WebSocket transport | WSS reaches the VPS; Rookstride packet extension carries UDP |
| Shadowsocks · v2ray-plugin / WSS | Compatible Shadowsocks WebSocket TCP path plus Rookstride UDP extension | Compatibility with the Shadowsocks/WSS family | Not an independent blocking breakthrough compared with Outline/WSS |
| TrustTunnel · HTTP/2 | Official endpoint and Rookstride's HTTP/2 client adapter | Another authenticated TCP/HTTPS transport | SNI, certificate validation and HTTP/2 reachability |
| NaïveProxy · HTTP/2 | Chromium/Cronet HTTP/2 with authenticated forwarding | A different client networking implementation | Larger native component; HTTP/2 reachability |

The original VLESS choice retains **TCP + Vision**. The new one uses **XHTTP**
and omits Vision's TCP flow setting. Their names, profile validation and server
services are separate. Existing saved TCP profiles remain usable.

The two Shadowsocks choices share most of their implementation. Generic
v2ray-plugin TCP framing (`mux=0` in the tested interoperability preset) and Outline's packet framing are separate capabilities;
a generic SIP003 link does not describe Rookstride's UDP extension.

## Starting tests by network and location

These are engineering recommendations for the first tests, **not measured country
success rankings**. Russia, China and Iran contain many different fixed/mobile
networks, and behavior changes. Rookstride has not completed in-country field
acceptance of these six additions.

| User/network situation | First choices to compare | Why |
| --- | --- | --- |
| Russia; ordinary VPN handshakes appear filtered | AWG 3.1 versus VLESS TCP/REALITY; then XHTTP | Compare a disguised UDP method with two distinct TCP transports |
| China; direct UDP VPNs fail | VLESS TCP/REALITY versus XHTTP; then NaïveProxy HTTP/2 | Prioritize working TCP/HTTPS paths and implementation diversity |
| Iran; intermittent mobile data or UDP restrictions | AWG when UDP works; otherwise VLESS/XHTTP or NaïveProxy | Test availability on the actual carrier; a TCP choice covers a different failure mode |
| UDP works but packet loss hurts | Hysteria 2 versus AWG | Compare QUIC congestion behavior with the existing datagram VPN |
| TCP/HTTPS works, but a VLESS method fails | NaïveProxy, Outline/WSS or TrustTunnel | Change framing/client implementation; compare actual browsing and sustained transfers |
| All protocols fail to one IP, while another server works | Another reachable VPS/provider | Changing a protocol cannot make an unreachable IP reachable |
| Only approved destinations are reachable or internet service is withdrawn | No universal single-VPS recommendation | A reachable relay/carrier and a different topology may be required |

Primary references:
[REALITY](https://github.com/XTLS/REALITY), [Xray transports](https://xtls.github.io/en/config/transports/),
[Hysteria](https://v2.hysteria.network/), [Outline SDK](https://github.com/Jigsaw-Code/outline-sdk),
[v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin),
[TrustTunnel](https://github.com/TrustTunnel/TrustTunnel),
[NaïveProxy](https://github.com/klzgrad/naiveproxy).

## Profiles, modules and trust

All new methods connect inside Rookstride. XHTTP shares a
`vless://` link. The five new worker methods use a self-contained `.rookvpn` JSON
profile, shareable as text or a file, with VPN access and the verified server
certificate authority. It contains no SSH administrator access. This Rookstride
format must not be described as a native Outline Manager, AmneziaVPN, Hysteria or
TrustTunnel configuration file.

Worker methods use a private authority transported through verified SSH, never
`insecure` TLS. Leaves last 30 days; the VPS checks renewal daily and replaces a
complete certificate generation before reloading. This avoids a user-owned domain
requirement, but differs from a publicly trusted website certificate. IP-only
public ACME certificates, renewal and each engine's exact acceptance remain a
separate improvement. TrustTunnel's IP-only recipe generates a private `.internal`
TLS name because the upstream endpoint requires SNI; it does not require public
DNS or send credentials to another domain owner.

Ad blocking is shared by native methods on one VPS; Double VPN uses the exit's
resolver. IKEv2 retains its separate existing filtering recipe. Statistics are
operational estimates scoped to the current daemon generation. TCP/UDP session
counts are not a count of physical devices; Xray byte counters do not establish
concurrent-user presence. Changing blocking strength affects every method sharing
that resolver.

Transport sockets and SSH sockets bypass Android's VPN individually. App traffic
and tunneled DNS do not get a direct fallback. The NaïveProxy adapter restricts
Chromium transport dials to the chosen endpoint; unrelated background probes are
rejected. The official TrustTunnel endpoint forwards through a private worker
which enforces DNS redirection, private-destination restrictions and IPv6 rejection.
Its own private metrics listener is restricted to root-owned local processes.
