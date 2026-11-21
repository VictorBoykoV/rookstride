# Single-server protocol adapters

Private 0.3.0-alpha19 development candidate. Protocol adapters share lifecycle and
module contracts, with separate native engines and the existing IKEv2 recipe.
Read the exact candidate's test report before publishing support claims.

| Choice | Server runtime | Phone client in this edition |
| --- | --- | --- |
| IKEv2 | Existing strongSwan, AdGuard Home and Unbound recipe | Rookstride's embedded strongSwan |
| AmneziaWG 3.1 | Official userspace binaries in an isolated container | Embedded AmneziaWG 3.1 |
| Xray / VLESS / REALITY | Verified upstream Xray binary and owned systemd service | Embedded Xray and tun2socks |
| OpenVPN | Isolated runtime; username/password or legacy device certificates | Embedded OpenVPN 3 Core |
| VLESS / XHTTP / REALITY | Xray service with XHTTP transport | Embedded Xray and tun2socks |
| Hysteria 2 | Owned worker with QUIC transport | Embedded routing worker |
| Outline / Shadowsocks WSS | Outline SDK TCP/UDP payload over private TLS WebSocket | Embedded routing worker |
| Shadowsocks / v2ray-plugin WSS | SIP003-compatible WSS transport plus Rookstride UDP path | Embedded routing worker |
| TrustTunnel HTTP/2 | Official endpoint and owned local adapter | Embedded routing worker |
| NaïveProxy HTTP/2 | Owned Cronet-based worker | Embedded routing worker |

The choices install servers, create/revoke device access, export profiles and
connect inside Rookstride. Other VPN applications are optional recipients of
shared profiles. Native adapters share private AdGuard Home filtering and expose
available current-generation statistics; durable cross-restart history remains
separate work. See [operations](OPERATIONS.md) for exact counter scopes and
[maintenance](PROTOCOL-MAINTENANCE.md) for shared dependencies.
A running server service is separate from an established phone tunnel; consult
the exact candidate's test report for verified environments.

## App journeys

Returning users see the active VPN and Disconnect first, or their last connected VPN with Connect. Below it are their saved servers. A server opens its installed protocols alphabetically, then protocols available to install alphabetically. Connect/Disconnect belongs to each installed protocol. Imported phone profiles remain separate from managed servers. **Add
VPN** opens the setup/import/manage choices separately. After removing the last
VPN, the returning home stays an empty VPN list with Add VPN available.

Back returns to the previous page or setup step. From home only, Stay/Leave app
protects against an accidental exit; leaving backgrounds the task. Navigation
does not cancel an installation or disconnect a VPN. Long dialogs scroll their
content independently of fixed Cancel/Install controls, including with the keyboard
open. These are UI behavior contracts; see the exact candidate's device evidence.

- **Set up a VPN** → one server → protocol → SSH access → inspect → install.
- **Import a VPN** → profile type → file → saved VPN → Connect. No administrator
  access is needed. Supported inputs are .sswan, native AWG .conf, self-contained
  certificate .ovpn and VLESS/REALITY link files.
- **Manage a server** → SSH identity/access → detected Rookstride VPN → controls.

Server access asks for the address, administrator login (prefilled `root`) and
password. SSH defaults to port22. VPN names, custom SSH/VPN ports, SSH keys are optional Advanced controls. Blank VPN names use the
server address. Initial VPN credentials are generated without asking the user
to invent a second password.
New IKEv2 setup saves that VPN credential in the encrypted vault, separately from
the administrator-access preference. Server SSH access is saved encrypted on the phone by default and reused across matching protocol records; an explicit opt-out stays visible in the sign-in form. Existing entries without stored credentials need one server sign-in. Known initial logins are
used directly when fetching the phone profile.

AWG, Xray and OpenVPN automatically choose a port after inspecting server
listeners, preferring the protocol's normal port and preserving existing services.
An explicit Advanced port is respected and rejected if occupied; it is never
silently replaced. IKEv2 uses its fixed UDP500/4500 transport. Custom SSH access
and provider firewall rules remain the operator's settings; this is not remote
SSH-port discovery or a promise of public reachability.

People, connection information, server settings and reset belong to the selected
VPN. Unavailable measurements/actions are hidden. Application language is English
in this edition. Website/catalog sources are retained separately.

## Account passwords and keys

Generated VPN account passwords contain 15 random characters. For manually chosen passwords, 8–15 is advice rather than a limit: short choices require confirmation and longer passphrases are accepted (up to 127 UTF-8 bytes, without control characters). Letters alone, numbers
alone, symbols or any combination are accepted; control/newline characters are
rejected. The default generated account password has 15 random characters.
Existing VPN passwords continue to authenticate, and SSH administrator passwords
keep their existing rules. Updating an older IKEv2 management helper is an
explicit action; it keeps existing accounts.

New app installations offer reusable username/password mode for IKEv2, OpenVPN,
Hysteria 2, TrustTunnel and NaïveProxy. See [reusable sign-in](REUSABLE-SIGN-IN.md).
OpenVPN also retains its legacy device-certificate mode. AmneziaWG keeps generated
peer keys, and VLESS keeps generated identifiers/REALITY keys; they do not acquire
an artificial account password or shorter cryptographic keys. Administration uses verified encrypted SSH; phone
credentials stay in the Keystore-encrypted vault. Current IKEv2 EAP secrets are
root-only server files, not bcrypt password hashes.

## Protocols on one server

Open a managed server to see its protocols. **Refresh server** reads the current inventory through pinned SSH. With saved administrator access this inspection also happens on open when the cached inventory is over 30 minutes old. An empty inventory clears matching cached phone profiles and installed state while retaining the server record. Installed protocols are marked
and can be selected; another protocol can be installed later. Each protocol keeps
its own connection profile and device access. Selecting an installed protocol
reuses its saved record rather than creating a duplicate. Android has one active
VPN at a time; connect using the selected protocol to change it.

Protocol installation preserves the other protocols and unrelated applications.
Inactive owned protocols reserve their configured ports too. Existing arbitrary
VPNs are not silently adopted; two-hop nodes keep their separate management route.
SSH success alone does not identify the reason for a VPN connection failure.

Left swipes reveal a trash button; tap it and confirm. Forgetting a server removes
its local records while leaving the VPS running. Removing an installed protocol
opens the server uninstall review. Users have direct Edit/Connection actions and
confirmed deletion; editing a display name keeps its keys and login identity.

## Ad blocking

All nine native methods share one private AdGuard Home
instance. For an existing native installation, open the protocol → **Ad blocking** →
**Enable ad blocking for this protocol**. The detached job preserves device keys and exported
profiles; reconnect afterward to clear the phone's old DNS cache.

**Server tools → Shared ad blocking** offers Standard, Strong and Strict presets and
aggregate query/blocked counts. This resolver serves native protocols
on that server. IKEv2's existing AdGuard Home/Unbound route remains independent.
Native DNS uses an authenticated loopback administration API, private DNS address
and encrypted Quad9 upstream. It adds no public DNS service or dashboard.
AWG/OpenVPN intercept TCP/UDP port53 within the owned container; Xray routes port53
through its private DNS outbound. Encrypted DNS inside another application remains
outside domain-filter interception. Native filtering declines external DoT/DoQ on port853 so Android Automatic Private DNS falls back to the in-tunnel filter. An explicitly selected strict/custom Private DNS provider must be changed to Automatic or Off. Query history is disabled; counts are aggregate.

An individual protocol uninstall keeps shared DNS for the other protocols.
**Remove all VPN setups** reviews and removes the shared component last. An incomplete,
unreferenced filter installation has its own reviewed cleanup in Server settings, keeping
working VPN accounts. Arbitrary server files are never inferred to be owned.

## Existing servers

Ubuntu 22.04+ with working root/passwordless administrator SSH is assessed. See [Ubuntu compatibility](UBUNTU-COMPATIBILITY.md) for eligibility versus deployment evidence.
Inventory checks existing VPN files, listeners and owned installations. Compatible
used servers can keep their applications and use a free VPN port; arbitrary
existing VPN installations are not adopted as managed Rookstride installations.
The IKEv2 route retains its DNS/configuration conflict guard.

**Protocol settings → Uninstall this protocol** removes one setup.
**Server tools → Remove VPN setups** removes all recognized Rookstride
VPNs. **Wipe server & reinstall Ubuntu** is the separate system-disk replacement action
on compatible full virtual machines. See [Server management](SERVER-MANAGEMENT.md).
Only recognized, owned VPN components can be reset. Reset reviews a state hash,
expires after five minutes and requires the checkbox confirmation in the app. It removes that protocol's
service/container, configuration and credentials. It keeps Ubuntu, SSH access,
administrator credentials, downloaded packages/images and unrelated applications.
This is not an OS reinstall. Removing all Rookstride VPNs requires a combined state review. The API retains its `DELETE VPN` / `DELETE ALL VPNS` confirmation values, supplied by the app after the checkbox review.
A changed account/configuration or expired review requires a new confirmation.
Partial removal stops and requires review of the remaining protocols. The app
clears matching local managed profiles after a successful server reset.

For a fresh OS on a supported full VM, use **Wipe server & reinstall Ubuntu** and
review its complete disk scope. Unsupported layouts need the provider's
Rebuild/Reinstall control; save its resulting access details and verify the new SSH
identity when adding the server again. Provider/rescue API integration and unsupported
boot recovery remain separate from the reviewed SSH reimage adapter.

Host/provider firewalls and network reachability remain separate checks. Do not
assume a successful SSH connection proves that a VPN transport is reachable.
Xray's REALITY destination must be reachable and support the required TLS behavior;
the current default was verified in the disposable transport lab.

## Implementation boundaries

- `single/run.py`: bounded JSON-over-SSH API; detached root-only systemd jobs;
  immutable source releases; progress/recovery; reviewed owned reset.
- `single/inspect_server.py`: read-only compatibility/listener inventory.
- `single/model.py`: validated request/config/profile construction.
- `single/runtime.py`: argv-based operations, private state and lifecycle.
- `single/filtering.py`: shared private AdGuard lifecycle, health, presets and reviewed cleanup.
- `single/pins.json` and Dockerfiles: exact runtime inputs and provenance.
- `single_bundle.zip`: Android asset produced separately from `gateway_bundle.zip`.

API actions are `inspect`, `plan`, `start`, `job`, `status`, `profile`, `add-user`,
`remove-user`, `edit-user`, `adguard`, `filter-reset-plan`, `filter-reset-apply`, `reset-plan`, `reset-apply`, `reset-server-plan` and `reset-server-apply`. All values travel as JSON over pinned
SSH; user values are not concatenated into remote shell commands. The single bundle includes the exact `server/reset.py` dependency for owned IKEv2
cleanup; its digest covers that helper. The shared password-policy change updates
the IKEv2/pair bundle identity without changing the pair routing design.
An existing native protocol can use `start` with `filter_only: true`; it never creates new device keys.
Omitting `port` in a new-adapter `plan`/`start` requests automatic selection.
`start` persists exactly the selected plan port; `status` returns the configured
port. Existing requests containing a port retain their exact-port behavior.

AWG exports MTU 1280, matching 3.1 header protection/transport parameters,
per-device keys, full IPv4/IPv6 routes and server-side IPv6 forwarding block.
Legacy OpenVPN connection-file mode uses per-device certificates, tls-crypt, server identity validation and
IPv6 blocking. Xray exports only public connection material, not its server key.
Client settings and privacy behavior still depend on the compatible Android app.

### Share or save a connection

Open **VPNs → server → installed protocol → VPN accounts → account → Connection →
Export connection**. Choose **Share file**, **Share as text**, **Save file**, or
**Copy configuration** (**Copy link** for Xray). Imported AWG, OpenVPN and Xray
connections also offer **Protocol settings → Export connection**, without SSH access.

| Protocol | File | Text / clipboard |
| --- | --- | --- |
| AmneziaWG 3.1 | Native `.conf` for a compatible AmneziaWG client | Same complete configuration, including AWG 3.1 parameters |
| OpenVPN | Reusable trusted-CA `.ovpn` plus username/password; legacy mode includes a device key | Same complete configuration |
| Xray VLESS / REALITY | `.txt` containing a `vless://` link | Same connection link |
| IKEv2 | strongSwan `.sswan` with automatic public CA selection in trusted mode, or a pinned certificate in private mode | Same JSON; enter the VPN password separately |

AmneziaWG export does not generate an AmneziaVPN `vpn://` connection or app backup.
SSH/root credentials are never included. Device configuration contains connection
credentials; someone receiving it can use that account. Copy marks the clipboard
as sensitive and attempts to clear the unchanged copy after one minute while
Android permits access. It does not overwrite a subsequent clipboard item.

The Android profile provider shares private material through temporary,
read-only in-memory content grants. It expires after five minutes or process
termination; no private profile export is written to the app's disk cache.
A user-requested file save uses Android's document picker and retains a copy at
the chosen location. Pending export keys stay in memory across rotation and are
not serialized into saved-instance state. AmneziaWG imports through its own file
picker; the inspected official 3.1 app has no external VIEW/import Activity.
AWG filenames have a 15-character basename compatible with that client's limit.
A recipient deliberately importing/sharing a profile can retain its own copy.

## Runtime provenance and license work

AWG binaries come from the pinned official `amneziavpn/amneziawg-go` image; its
older Alpine runtime is replaced with a pinned supported Alpine base. Xray ZIP
size/SHA256 are verified before extracting the binary. OpenVPN uses the pinned
Ubuntu base and Ubuntu signed package repositories; package versions are not a
snapshot-pinned reproducible build. Preserve upstream licensing/notices when
redistributing runtime images or embedding additional native engines.

The new Android engine source pins are independent of the server pins. See
[embedded engine architecture](EMBEDDED-ENGINES.md), [build instructions](BUILD.md)
and `android/engines/pins.json`. Each engine's private service process owns its
TUN and foreground lifecycle. Connection keys are encrypted in Android Keystore
storage; SSH sockets use a same-UID protection channel so administration can
survive a VPN disconnect. Ordinary application traffic stays in the VPN.

The new services use full-device IPv4 and leave Android's IPv6 family blocked.
Always-on/lockdown and OEM/network-transition acceptance remain separate gates;
this candidate does not enable new-service always-on support. Physical network
reachability depends on the actual client/server path.

## Verification

Local protocol boundary tests live in `tests/test_single_protocols.py`.
`tests/integration/single_protocol_lab.py` is restricted to disposable root Ubuntu
runners using `ROOKSTRIDE_DISPOSABLE_LAB=yes`. The private CI matrix repeats install,
real tunnel-bound HTTPS, device create/revoke and owned reset, preserving an
unrelated sentinel. This is Linux transport/backend evidence, not a physical-phone
or provider deployment through the Android SSH wrapper.

## Server list, accounts and cleanup

Alpha6 groups managed servers on Home. Inside a server, Installed protocols and
Not installed protocols are each alphabetical. Refresh server inspects recognized
Rookstride inventory and invalidates stale connection caches after a reset or
instance replacement. Account display labels can be edited without rotating their
cryptographic identity; login names remain immutable. IKEv2 management enrollment
must be updated explicitly for new account features. Native management requests
use the current bundled helper over pinned SSH.

Swiping left reveals a trash control; it never deletes directly. Removing a server
from the phone leaves it running. An installed protocol's trash opens reviewed
uninstallation. Remove all VPN setups removes all recognized Rookstride VPNs and keys,
retaining Ubuntu, SSH, packages and unrelated software. How to reinstall Ubuntu
opens provider instructions. Rookstride’s SSH cleanup is limited to recognized, owned VPN components.

OpenVPN's pinned runtime build bootstraps public roots from the pinned Alpine
image and fetches signed Ubuntu indexes/packages over HTTPS with strict update
errors. It never bypasses hash verification after a mirror/download failure.

## Shared filtering acceptance

Shared filtering is implemented in private alpha8. See **Ad blocking** above for
new and existing installations. Its acceptance checks include blocked/allowed
DNS through each embedded Android engine, private authenticated administration,
protocol coexistence, individual removal and all-VPN cleanup/reinstall. IKEv2's
independent AdGuard/Unbound installation is preserved. Exact environments and
remaining physical-device gates belong to the candidate's test report.

## App, server and protocol scope

The fixed header keeps Rook, the name and the Activity bell. Clickable ancestor
breadcrumbs live in the scrolling page. Android Back follows the previous screen;
choosing an ancestor removes the child from that path. App preferences are in the
Settings tab. **Add VPN** sits below the Home heading and quick connections.
Setup offers **Single-server VPN** and **Double VPN**. Protocol cards select a
method; only Details opens its explanation and official documentation.

A server cog opens that server's page. **Refresh** checks its inventory; **Server
access** edits saved administrator sign-in. Compact server tools expose shared
ad blocking and **Remove VPN setups**. Shared native filtering and IKEv2 filtering
remain distinct. Double VPN manages filtering on its exit.

A protocol row's name/body or settings cog opens its own controls. Connect and
Disconnect remain separate actions. Inside it, VPN users, Logs, Usage and Ad
blocking refer to that protocol; uninstall removes only its recognized setup.
VPN users have **Edit** and **Share access**. Editing also offers Use on this phone.
These are VPN accounts, not Linux/root accounts. Sharing exports that user's
connection file/text; it is not another connection button.

A star on a protocol page adds a Home favorite. The compact red carousel contains
favorites and the active/recent connection. Swipe between cards; each has one
connection action. State changes update existing views without rebuilding Home
or moving its scroll position. The current connection is never inferred from a
server installation check alone.

Settings avoids duplicate Split/Activity links and offers an expanding native FAQ.
Help, licenses and Journal remain browsable during a service-owned installation.
The Journal placeholder makes no network requests. Server removal still requires
the configuration-bound review/confirmation and keeps Ubuntu, SSH and unrelated
files. It is not an OS rebuild.

## Private alpha11 installation and feedback

An existing-server protocol card opens its details without starting setup. Its
**Install VPN** button starts once, using `this-phone` and generated credentials.
The separate first-device/REALITY-name dialog is removed. Before a new IKEv2 install, its Protocol settings retain the optional usage-history switch. New VLESS installations
select a certificate-verified TLS1.3/h2 target from the VPS automatically; an
explicit CLI `sni` stays explicit and is also checked. Before completing setup,
a temporary loopback VLESS client must authenticate and carry certificate-verified
HTTPS through the installed server. A target can pass ordinary TLS and still fail
REALITY; automatic installs try the next compatible target in that case. Failed
traffic checks cannot mark the setup complete. The temporary client/configuration
is removed, and existing installations are not silently rotated. This server test
does not establish the phone's network path.

The web check uses two HTTPS test sites through Android's VPN network. DNS
lookup failure has a separate explanation. An inconclusive check leaves the
VPN routes on and offers Disconnect and retry, rather than labeling the engine
failed or silently exposing direct traffic.

The IKEv2 readiness check decodes actual listener addresses, including all IPv4
loopback addresses and IPv6 loopback. Ubuntu's 127.0.0.54 resolver no longer
causes a false conflict. Genuine files/ports are listed rather than overwritten.
Repeated cleanup/reinstall labs must test this preflight as well as deploy.py.

Long hold reorders servers locally and keeps their protocol records together.
A substantial left swipe reveals Delete, followed by an explicit confirmation.
Short server actions show a prominent waiting/result panel. Installation finishes
on a distinct screen with fixed Open VPN/Done actions and a result notification. Protocol Install/Connect/Disconnect actions also stay in a fixed row outside scrolling content.
Help/license documents stream offline from a restricted origin; they never open
the generic upstream client screen.
