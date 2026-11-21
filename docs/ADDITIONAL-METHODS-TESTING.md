# Alpha18 — additional connection methods

Date: 23 October 2026. Private development candidate, Android 8/API26 minimum,
Ubuntu 24.04 x86_64/aarch64 server payloads. Website/public promotion is outside
this iteration. See [the comparison](CONNECTION-METHODS.md) for method names,
profile formats and network-first recommendations.

## Implemented scope

Six additions: VLESS XHTTP/REALITY, Hysteria 2, Outline/WSS,
Shadowsocks/v2ray-plugin WSS, TrustTunnel HTTP/2 and NaïveProxy HTTP/2.
All connect inside Rookstride, install through pinned SSH with automatic defaults,
create/revoke/export users, expose private AdGuard and available statistics,
and support owned removal/reinstallation. Original VLESS remains TCP/REALITY/Vision.
The two WSS presets share implementation; they are not two independently proven
censorship-resistance techniques.

The original four methods remain available. Ten choices on each Double VPN leg
produce one hundred selectable combinations; acceptance below names the routes
actually exercised rather than claiming one hundred full deployments.

## Acceptance record

Accepted server/application-controller checks:

| Check | Result |
| --- | --- |
| Python tests | 161 passed |
| JVM tests | 157 passed |
| Internal/export tests | 17 passed |
| Go race tests on Linux | 8 passed, including required packet-stack capability |
| Independent CI lifecycle | 12 clean single-method rounds, six methods × two |
| Android8/API26 and Android9/API28 x86_64 emulator traffic | Six methods per API; debug acceptance before the signed packaging fix, same final native worker bytes |
| Exact signed API26 UI/packaging | 19 normal cases plus all-ten-card selection at 320×480dp/130% text |
| Double VPN Java-controller/Linux-client | 12 clean both-node deployments; six routes with physical roles reversed |
| Certificates/reboot | Five forced-due leaf renewals; all six services restored after a fixture reboot |
| Compatibility | Official v2ray-plugin1.4 TCP/WSS mux=0; 30 independent TrustTunnel HTTPS requests |

Paired route cohorts:

| Phone → entry method | Entry → exit method | Machines |
| --- | --- | --- |
| Hysteria2 | XHTTP/REALITY | A→B and B→A |
| XHTTP/REALITY | NaïveProxy | A→B and B→A |
| NaïveProxy | Outline/WSS | A→B and B→A |
| Outline/WSS | TrustTunnel | A→B and B→A |
| TrustTunnel | Shadowsocks/WSS | A→B and B→A |
| Shadowsocks/WSS | Hysteria2 | A→B and B→A |

Each paired run verifies encrypted HTTPS, an integrity-checked 1MiB transfer,
exit-only canary, TCP/UDP exit-side filtered DNS, actual entry traffic counters,
no HTTPS/canary/DNS fallback while the bridge is stopped, normal entry-host
Internet/main-route preservation and recovery after bridge restart. The app's
production Java SSH/preparation/deployment/reset controllers configure both nodes.

The exact signed universal APK also completed a fresh **Hysteria2 → NaïveProxy**
both-node deployment on API26. Stories navigation and Activity recreation did
not cancel it. A separate app verified HTTPS, the unique exit-only canary,
expected exit, filtered DNS and blocked IPv6 socket. Fresh HTTPS succeeded before
the bridge stop, failed during the outage, and recovered after restart. User
creation/export/removal worked after disconnecting the phone VPN. The first
inconclusive literal-IP-baseline attempt is excluded; this is the clean repeat.

The exact signed universal APK then passed **all six single-server embedded
methods** on API26 after a final managed cleanup and coexisting six-method
installation through production app SSH code. Each method passed own-app HTTPS,
separate-UID HTTPS/egress/canary/filtered DNS/IPv6-socket checks, protected SSH,
Activity recreation/background, explicit disconnect without keeper restart,
SSH surviving teardown, and a fresh reconnect/canary. API28's earlier final-
worker debug cohort is recorded separately; it is not relabeled as signed.

## Signed artifact identity

App `0.3.0-alpha18`, versionCode25, minimum API26/target API36. Product code
checkpoint `5a4c8fe104c5f749d464087d35d5965a1645a0dd`; subsequent acceptance
test/documentation changes do not alter the retained APK. Both packages are
non-debuggable and use the retained signing certificate:
`751386cf7143ba92c88084a0b26dfeac86128b2fe0d5277821ee4c67a92ae7ba`.

| Artifact | SHA-256 |
| --- | --- |
| Universal APK | `f68fd04172c97f71c41826b59c08f0c5a21a7ab8bba4585e15369ad45c7e05bf` |
| ARM64 APK | `616ba838a9bd0aa6019a28e8850715cae4b7aeca876bad7dfc8f8fa4ec8fda9f` |

The universal contains 36 native libraries; ARM64 contains 12. Their 167 common
DEX/assets/ARM64 native entries match exactly. ZIP/LOAD/RELRO static 16KiB audits,
embedded source/runtime hashes, version, signer and non-debuggable checks pass.
Corresponding source is supplied separately with checksums and exact 69 Java
source modules, 71 new-worker modules, the earlier engines' module sources,
Go source, pinned NaïveProxy/TrustTunnel source and notices. Source hashes belong
in the accompanying checksum file rather than a self-referencing archive.

Private CI at this product checkpoint is green for source/boundaries, the
original-method lab and the additional-method lab. The commands below can be run
independently against explicitly disposable environments.

## Regressions found and fixed

- Meter wrappers must preserve upstream handshake/headroom and EOF contracts.
  Hysteria TCP and Naïve UDP exposed these errors. WSS must send a normal close
  after its final payload rather than reset a completed stream.
- The Linux worker needs the gVisor packet stack for a Double VPN exit bridge.
  Build tags, an explicit capability preflight and a Linux test enforce this.
- Android AssetMerger expands `.gz` assets and strips their extension. Neutral
  `runtime.bin` assets retain the exact signed/pinned gzip stream. Static APK
  audits and an on-device packaged-byte test catch transformations/stale assets.
- TrustTunnel's official endpoint needs SNI with the IP-only recipe and HTTP1
  configuration for its private metrics handler. Its generation is the endpoint
  InvocationID; session estimates are not inferred physical-device counts.
- Thirty-day private TLS leaves satisfy the selected client constraints, with
  immutable complete-generation renewal. Private CA trust remains verified through
  SSH; certificate validation is never disabled.
- Helper units/timers must use immutable enrolled source, not a temporary upload
  directory. Read-only inspections do not enroll helpers or activate services.
- The old CI coexistence test installed only three native methods but iterated
  the expanded registry. Its cohort now matches the methods actually installed.

## Reproducible checks

- `python3 -m unittest discover -s tests -v`
- `go test -race -tags with_quic,with_naive_outbound,with_utls,with_purego,with_gvisor -count=1 -v ./...`
  from `android/engines/routes` on Linux. Android does not use that server TUN stack.
- `tests/integration/routes_lifecycle_lab.py`: explicit disposable-root opt-in,
  six methods × two fresh lifecycle rounds; HTTPS, private/filtered DNS,
  revocation, counters, no-user shutdown, first-user recovery and scoped resets.
- `NativeEngineIntegrationTest`: opt-in synthetic fixture, actual embedded
  tunnels plus a separate-UID probe, exact exit/canary/DNS/IPv6-socket checks,
  protected SSH, Activity lifecycle and deliberate disconnect/reconnect.
- `NativePairIntegrationTest`: actual bundled Android both-node installation,
  browse Stories/recreate during deployment, encrypted first leg, exit-only
  traffic, bridge outage/recovery and account mutation while disconnected.
- `scripts/verify-apk.py`: signed identity/version, non-debuggable release,
  exact bundled server source/payload hashes, all selected ABIs and static
  ZIP/LOAD/RELRO 16KiB alignment. Exact source/module notices are retained.

Tests use two disposable VZ Ubuntu nodes and owned Android emulators, not an
operator's working VPN. The underlay uses an explicit test-only SSH-TUN link and
local emulator port forwarding; root in the emulator prepares this fixture, while
the installed app and VPN engine remain unprivileged. A unique exit-only canary
is mandatory because both guests share the host's public egress.

A first APK-driven pair attempt installed and browsed successfully but could not
establish the separate literal-IP HTTPS outage baseline. It is not counted as
outage acceptance. The probe now requires a positive control through fresh HTTPS
requests to ordinary website origins and rejects both during the outage; a raw
TCP connect is insufficient because a userspace packet stack may acknowledge SYN.

Ubuntu mirror HTTP metadata once failed its signed hash check in the test
fixture. It was preserved as a rejected run; both guests now use the official
HTTPS mirrors with signature/hash checking retained. A reboot removed a lab-only
default route, and changed test SSH keys were rejected until independently
verified through the console and re-enrolled. These fixture repairs do not weaken
production checks and are not counted as uninterrupted accepted runs.

## Limits

- No in-country carrier testing establishes success rates for Russia, China or
  Iran. Endpoint blocking, allow-only networks and loss of Internet reachability
  are different problems from identifying a protocol.
- ARM phone variants and the Linux aarch64 payload are built and statically audited;
  this cohort executes native clients/servers on x86_64.
- Real phone/OEM power management, mobile/Wi-Fi transitions, force-stop/reboot,
  always-on/lockdown, full dual-stack privacy, sustained low-memory load and
  actual 16KiB-page devices remain separate gates. A blocked IPv6 socket in a
  local emulator is not a complete privacy audit.
- The Android16 emulator failed to reach a usable framework, including after
  fresh disposable userdata. No Android16 native traffic result is claimed.
- Five methods export a Rookstride `.rookvpn` profile, not falsely labeled
  generic Outline/SIP003/Hysteria files. The official v2ray-plugin interoperability
  check covers TCP/WSS `mux=0`; Rookstride packet/UDP framing is separate.
- Statistics are current-daemon estimates with generation IDs, not monthly
  billing or a physical-device count. TrustTunnel uses the official endpoint
  with an original Rookstride client adapter; this is not the official AdGuard app.
- Cronet libraries are pinned upstream prebuilts. Go adapters, exact modules,
  notices and pinned NaïveProxy source are retained; a local Chromium build or
  bit-for-bit reproduction of those supplied libraries is not established.
- Managed cleanup preserves Ubuntu, SSH and unrelated files. Whole-OS rebuild,
  public IP ACME, stock-Android fake TCP and automatic domain/CDN setup are not
  silently promised by this iteration.
