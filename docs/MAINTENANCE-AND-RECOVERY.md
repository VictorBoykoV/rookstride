# Maintain a VPN without starting over

The private 0.4 development edition separates three tasks: connect to a VPN,
manage its users, and maintain its servers. **VPNs** keeps quick connections and
collapsible connection groups. **Servers** lists machines you can administer.
**Manage** opens installed protocols and their users;
**Maintenance** contains server access, administration, recovery and destructive
changes. A VPN connection is not required for ordinary SSH management.

Server administrator passwords are saved in the encrypted phone vault by
default. An explicit choice not to save them is respected. Removing the final
administrator record for an address and SSH port also removes its saved SSH pin.
If a still-saved server changes identity, review its old and new fingerprints in
the error dialog before choosing **Trust replacement**. The subsequent connection
must match that newly saved identity; this is not a one-time verification bypass.

## Choose the right action

| Task | What stays | What changes |
| --- | --- | --- |
| Add an existing Double VPN | Its services, users, keys and routing | The phone attaches a verified record of the two owned members |
| Replace exit | Entry address, client listener and users | A verified new inter-server route and public exit address |
| Replace entry | Compatible VPN identity and existing exit | The entry machine; either transfer the endpoint or explicitly share an updated connection |
| Update helpers | VPN engines, accounts, client identities and configuration | Reviewed management code, with a previous copy retained |
| VPN runtime updates | Compatible accounts, configuration and protocol identities | A reviewed runtime version, with supported rollback retained until acceptance |
| Remove VPN setups | Ubuntu, administrator SSH and unrelated applications | The reviewed owned VPN components and their data |
| Clean OS rebuild | Provider account and external backups | Both selected system disks, their apps and identities |
| Rebuild and restore | Only the identities, users and policy in the selected recovery package | System disks, SSH identities and administrator enrollment |
| Remove from this phone | The running servers and everyone else's VPN access | Local records, saved access and unreferenced SSH pins |

Each server mutation begins with a review. A failed reply is not permission to
repeat an erase. Resume uses the recorded operation and node jobs. Installation
and maintenance continue in a foreground service while you use another tab;
closing the app can leave a detached server job running, but a subsequent disk
erase waits for the coordinator to resume and verify its prerequisites.

## Replace an exit

Select a different reachable server and review its preparation. The current
adapter retains the selected entry and exit protocol kinds. Rookstride builds
a separate candidate link, checks exit DNS and routing, then switches the entry
while keeping a direct Internet fallback blocked. Keep the old exit until an
unchanged saved VPN profile has successfully opened websites through the new one.
You can then accept the change, or roll back while the old exit is available.
Changing the public exit address can interrupt existing website sessions.

Protocol-aware adapters cover the installed connection methods, but installation,
migration and live-client qualification have separate compatibility matrices.
An unsupported identity, custom route or runtime layout is not silently
reinstalled. Replacing a server is distinct from switching to another protocol.

## Replace an entry

To keep the user's connection unchanged, entry replacement needs a stable
endpoint. A domain can be pointed
to the new server, or an eligible provider IP can be transferred. A saved client
using the old literal IP cannot follow an unrelated DNS change. Rookstride stages
the replacement identity and a separate exit peer first. It checks the destination's
planned SSH key and machine identity before retiring the previous entry, and asks
for saved-client verification. Sharing an Internet egress IP is not proof that
the client endpoint moved. Provider DNS/IP transfer is not performed by this
adapter; keep both entries until the transfer and client check succeed.

Alternatively choose the explicit **new address** path. Existing accounts and
compatible identities are retained, but users receive a connection with the new
endpoint. Verify that connection before accepting the replacement. Public
certificate staging for an unchanged domain is not supported by this adapter;
the app must refuse that path rather than claim an unverified transfer. Accepted
entry replacement is final; going back afterward requires a new reviewed move.

## Owner recovery and a full rebuild

Export an encrypted `.rookrecovery` package before a destructive change. Use a
separate recovery password and keep both available. The package contains VPN
secrets; it is different from a normal VPN profile or administrator invitation.
Checking a package validates its encryption, deployment and required material.
Only a successful disposable restore demonstrates that it works end to end.

Protocol-aware restore retains reviewed peer/client keys, certificates or native
account identities, users and supported filtering presets/enabled state.
It does not copy extra standalone protocols, arbitrary custom DNS rules, traffic
history, administrator grants or unrelated files. Unsupported policy is rejected
before erasure. New traffic counters have a new generation and are not added to
old totals as if they were continuous.
Recovery reads the effective accepted exit route. A prior exit replacement must
not be silently restored as the old topology. Archive checks validate the actual
key pairs, certificate names and enabled/revoked account data before erase;
valid archive data alone is not proof of a successful live restore.

For two servers, the app checks the management path and erases one node at a
time. The only usable SSH relay is kept until the other node returns with its
planned SSH identity and requested Ubuntu version. Exit services and DNS are
restored before entry forwarding activates. Whole-disk replacement requires an
independent management/rescue path and a compatible VM layout; it is separate
from routine VPN removal. See [OS replacement](SERVER-MANAGEMENT.md).

## Share administration separately

**Share VPN connection** gives someone ordinary VPN access in a compatible
client. **Invite administrator** gives an expiring, one-use `.rookadmin` invitation
for a role and exact scope. Opening it in Rookstride automatically enrolls that
phone's own management key. There is no second owner-approval step.

Changing or revoking an administrative role does not change that person's
ordinary VPN login or profile. New devices require a fresh invitation. Server
checks enforce scope on every request, including requests from a modified client.
The initial infrastructure role does not delegate OS erasure, protocol installation
or topology mutations; those remain owner operations. See the complete
[administration contract](SCOPED-ADMINISTRATION.md).

## Update boundaries

Reviewed helper updates do not download a new VPN engine. Engine binaries retain
their tested pins. Both nodes stage the reviewed source before either is changed;
the entry briefly closes forwarding during its check. Resume preserves the
selected acceptance or rollback direction. A reset, different deployment or
changed peer identity invalidates a stale review before any routing or file swap.

**VPN runtime updates** is a separate operation. It stages a concrete supported
candidate, shows the version and impact, then offers apply, connection checks,
rollback or acceptance. Shared runtimes list their affected consumers. Keep the
rollback window open until an existing client works; account, filter and reset
changes that would invalidate rollback are blocked while it is pending. This
does not provide arbitrary package downgrades, OS rollback or unattended updates.

Adding users can be live for IKEv2, AWG, compatible OpenVPN and new Xray/XHTTP
configurations. Other methods, older configurations and some revocations need
a reviewed listener restart. Read the action's actual capability rather than
assuming that every protocol has the same live-update behavior.

## Compatibility and evidence

Each protocol migration, recovery and runtime update needs its own qualification;
sharing a common screen does not prove every combination. Helper rollback covers
management code; runtime rollback covers the reviewed runtime and supported
dependencies, not the operating system. Ubuntu eligibility,
successful server installation, Linux traffic, exact Android APK execution and
physical-phone/carrier behavior are distinct checks. A passing server test does
not establish regional availability or universal provider support.
