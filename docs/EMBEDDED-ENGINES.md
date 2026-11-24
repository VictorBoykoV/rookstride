# Embedded Android connection engines

Installation, import and connection are separate operations within the Android
app. The engine notes on this page began with the private 0.3.0-alpha18
candidate. See the release and test guides for the current signed APK and its
verified scope. [Connection methods](CONNECTION-METHODS.md) · [Release tests](TESTING.md)

| Protocol | Phone implementation | Initial connected state |
| --- | --- | --- |
| IKEv2 | Existing strongSwan/Charon service | Upstream established IKE/CHILD state |
| AmneziaWG 3.1 | Pinned native Android configuration API and AWG Go v3 JNI backend | Actual peer handshake |
| VLESS / REALITY | Pinned Amnezia libXray/core plus tun2socks, with original in-memory config adapter | HTTPS traffic check through the installed VPN |
| OpenVPN | Pinned OpenVPN 3 Core public ClientAPI and original JNI bridge | Core CONNECTED event |
| VLESS XHTTP / REALITY | Existing Xray process, separate validated XHTTP transport | HTTPS through the installed VPN |
| Hysteria2 | Protected Go worker, sing-box QUIC/Salamander | HTTPS through the installed VPN |
| Outline / WSS and Shadowsocks WSS | Protected Outline SDK TCP/packet adapter and private WSS relay | HTTPS through the installed VPN |
| TrustTunnel HTTP/2 | Original verified HTTP/2 adapter; official Rust endpoint on the VPS | HTTPS through the installed VPN |
| NaïveProxy HTTP/2 | Protected worker with upstream Cronet library | HTTPS through the installed VPN |

See [method comparison and trust](CONNECTION-METHODS.md). The two Shadowsocks
menu presets share code; the compatibility test uses official v2ray-plugin 1.4.0
with `tls;host=...;path=.../tcp;mux=0`. That tests TCP interoperability, not a
generic plugin UDP format. All ten choices connect inside Rookstride.

### Building the additional worker

Keep the existing engine/crypto bootstrap. For this worker, use Go 1.26.8 and
Android NDK **30.0.16248370** (older engines keep their existing NDK). Run:

```sh
python3 scripts/bootstrap-routes.py
python3 scripts/build-routes.py android linux
python3 scripts/collect-route-sources.py
python3 scripts/prepare-android.py
```

Install that exact NDK through the Android SDK manager first. The worker build
produces Android PIE executables for arm64-v8a, armeabi-v7a and x86_64, plus
x86_64/aarch64 Linux worker/library payloads. The app uploads the appropriate
hash-verified Linux archive through pinned SSH; it does not ask the user to
install a runtime separately. Worker source, module sums, binary hashes, 16KiB
alignment and packaged server payloads are audited before distribution.


Linux server builds require the `with_gvisor` tag for the bridge's TUN packet
stack; `rook-routes features` exposes the capability and pair setup refuses a
worker without it. Android uses its existing packet adapter instead. Packaged
server archives use the neutral asset name `runtime.bin` because Android's asset
merger automatically decompresses `.gz` filenames. The uploaded gzip bytes must
still match their recorded archive length/hash, checked inside the signed APK.

The Go adapters are built from source. Cronet's static Android/shared Linux
libraries remain **upstream prebuilts**, identified by exact Go module sums and
output hashes. `build-pins.json` records the Go toolchain and NaïveProxy commit;
the source collector retains its archive and notices. The pinned cronet-go
module contains `cmd/build-naive` and its platform build instructions; its
NaïveProxy submodule is commit `72a06c9fca0e2d228588c7f3074bf7efff3ff686`.
Chromium build/toolchain/DEPS retrieval is substantial and has not been repeated
locally or established as bit-for-bit reproduction of the supplied Cronet libs.
Do not describe this candidate as a locally source-built Chromium distribution.

The worker owns only explicitly registered outbound/TUN/DNS components. Only
outer VPN transport descriptors use the private protection channel. Cronet
HTTP/2 transport is limited to the selected literal endpoint, so unrelated
background dials cannot become a direct-traffic bypass. Raw native messages are
not retained in the app's log because they can contain sensitive destinations.

The root `android/engines/pins.json` records source archive identities. Go
modules are fixed by upstream go.mod/go.sum, verified by Go and preserved with
checksums by `collect-go-sources.py`. `prepare-engines.py` packages compiled
libraries and their source manifest; release artifacts include corresponding
sources and notices. Server/runtime pins remain in `single/pins.json`.

## Lifecycle and ownership

Each engine family has a separate private service process. The five new worker
methods share the private Routes process, with one connection active at a time.
AWG and Xray
therefore do not load independent Go runtimes into the same process. Services
use Android's VPN consent, a foreground notification with Disconnect, private
same-UID status/control providers, and service-owned worker lifecycles. Normal
screen navigation, backgrounding and Activity recreation do not own the tunnel.

Only one VPN is active. Starting another connection first stops the previous
engine; request generation prevents an obsolete delayed start. Android revoke
and notification disconnect close the engine and TUN. An Android sticky restart can recover the most recently user-started encrypted
profile; an intentional disconnect or permission revoke clears that request. A
private structural event journal survives process death. Force-stop, reboot and
OEM power policies can still prevent recovery.
New-service always-on is explicitly disabled pending a unified, tested recovery
contract. Do not infer lockdown/always-on acceptance from a foreground pass.

During AWG/OpenVPN reconnection an extra TUN descriptor retains the interface
while the engine replaces its descriptor. Network callbacks select a physical
underlay, rebind protected transport sockets and trigger engine reconnection.
These mechanisms require actual OEM/carrier transition testing before claiming
universal recovery or leak prevention.

## Credentials and administrator access

Profiles live in `noBackupFilesDir/vpn-profiles`, encrypted with a dedicated
Android Keystore AES-GCM key. Intents contain an opaque profile ID. Profiles do
not enter saved-instance state, logs, notifications or status bundles. Imported
VPNs require no SSH credential. Removing a saved VPN deletes its local key file;
server reset/revocation and sharing are separate deliberate operations.

Xray configuration is constructed from a validated VLESS/TCP/REALITY link and
passed to the engine in memory. Its local SOCKS endpoint listens only on
127.0.0.1 and uses random credentials. Socket protection failures abort transport.
OpenVPN imports require self-contained inline keys/certificates and server
verification; scripts, plugins and external file references are rejected.

SSH sockets use an injected JSch SocketFactory. A private provider receives a
duplicated socket descriptor, protects/binds it before connection and returns
the selected underlay for hostname resolution. This preserves administrator
access when the managed VPN is reset. Credentials still follow SSH host-key
verification. The protection channel is restricted to the app UID; other apps
cannot ask it to bypass VPN routing.

## Routing and diagnostics

Connected publication waits for Android to expose the active VPN network as well
as the engine event. This closes the asynchronous route-registration interval
observed on API26 reconnects. Xray waits before sending its HTTPS check.

New engines route IPv4 through the TUN and keep Android's IPv6 family blocked.
They do not exclude the whole Rookstride app from VPN routing; only protected
protocol and administrator sockets use the physical underlay. New server recipes
share a private AdGuard resolver; traffic history remains separate. IKEv2 retains its existing AdGuard/Unbound route.

Connection details show a bounded stage/error history and can be shared by the
user. Keys, imported configuration and administrator credentials are excluded.
Failure to connect is distinct from installation completion and from the local
Android VPN indicator. Ordinary HTTP/DNS and a separate-UID test app must be
checked independently of engine startup.

## Verification

`NativeProfilesTest` checks profile boundaries. The opt-in
`NativeEngineIntegrationTest` uses root-only, synthetic fixture profiles from a
disposable Ubuntu VM. It establishes actual engines, checks a private VPN-only
canary and separate-app HTTPS/egress, verifies protected SSH, exercises screen
lifecycle and disconnects. No operator VPS credentials are compiled into the APK.
Read the exact artifact's report for actual completed APIs/checks; this document
is an implementation contract, not a claim that all Android/OEM gates passed.

## Connection checks and diagnostics

Xray tries HTTPS at two independent origins through Android's VPN Network. A
single unavailable test page cannot force a disconnect. If neither succeeds,
"Check internet access" retains the VPN interface and offers Retry connection
check; Connected still requires a successful HTTPS check. No administrator socket
or physical-network connection is used for that test. Native View log can share
sanitized state, interrupted-process/recovery events, battery restriction status,
underlay changes and AWG handshake/rekey events. It never includes profile keys.
AWG has no configured account/session duration; after a stale handshake it can
rebuild transport. A foreground service is not a guarantee against OEM shutdown.

The alpha6 physical-phone incident still needs a fresh log after an unexpected
shutdown. Emulator recovery/long-session checks, server health and user-network
availability are separate measurements.

The first native connection offers an optional Android battery-exemption choice,
matching the purpose of upstream IKEv2's power prompt. Connect now declines that
change; Cancel does not connect. Background connection in Settings reopens the
system app settings. Android grants the exemption only after the user's own
permission. This does not override manufacturer-specific power policies.

## Connection lifecycle in private alpha7

A small foreground ConnectionKeeper in the app process records only the desired
opaque encrypted-profile ID and protocol. Native workers stay in separate
processes. The keeper checks worker presence and can restart an unexpectedly
stopped worker; Disconnect, revoke and terminal engine failures clear intent.
Replacement connections wait until service cleanup completes. The keeper and
worker share a single ongoing VPN notification with a Disconnect action.

The private structural journal records startup, renewed AWG handshakes and
process interruption without profile contents, passwords or endpoints. The app
offers Android's optional battery-exemption choice; declining does not prevent
connection. Force-stop, reboot, OEM battery policy and always-on/lockdown remain
separate acceptance gates. See the exact candidate report for tested versions.

Xray checks two HTTPS origins through Android's VPN Network. An inconclusive
check retains the tunnel and offers Retry rather than disconnecting it.
