# Scoped administrator access

This module adds local SSH administration; it does not run a web service. Enabling
it is an owner action and does not reinstall a VPN or restart its listeners. It
requires a compatible, already owner-installed protocol helper. A VPN profile,
VPN username/password and administrative device identity remain independent.

## Authentication and enrollment

The owner enables `server/access_install.py` through the pinned owner SSH path.
It installs a fixed root-owned dispatcher, a dedicated sudo rule with **no command
arguments**, and OpenSSH restrictions. Each invitation and device receives its own
locked Unix account. Public authorized-key files live in a separate root-owned,
traversable directory; the SQLite authority database remains root-only. The
interpreter uses isolated mode. User startup files, PTYs, agent/X11/TCP/Unix socket
forwarding and password authentication are prohibited. Arbitrary SSH command text
is ignored by ForceCommand; executable bytes, scripts, URLs and shell commands are
not accepted by the management contract.

`.rookadmin` is a bounded JSON document with purpose
`rookstride.admin.invitation`, schema 1, one pinned SSH endpoint, an expiring
bootstrap credential, invitation identifier and informational scope/role. The
server record is authoritative. The bootstrap can only request its enrollment
challenge or redeem that invitation. It cannot invoke normal management actions.
The phone creates a fresh RSA-3072 key before redemption and persists its draft in
the encrypted phone vault. A SHA-256 RSA proof binds the server, invitation,
challenge and device public key. The first claim commits durably before provisioning
the Unix account or synchronizing peers. Interrupted enrollment can resume only
that device; subsequent import by another device fails. An already provisioned
device can resume with its own key even after the original invitation expires.
No second owner approval is involved.

Invitations last 1 minute to 24 hours (UI default 1 hour). An unused valid
invitation is a credential: whoever first holds and redeems it gains its preset
role. Revoke a lost invitation before it is used. Invitation revocation does not
revoke an already enrolled device; device revocation is a separate operation.

## Authority and objects

The four role labels are Owner, Infrastructure administrator, VPN user manager
and Viewer. Root/sudo owners retain full OS privileges; invitations cannot create
another root owner. Capabilities advertised by this version are:

| Role | Implemented capabilities |
| --- | --- |
| Owner | Invitations, grants, devices, peer linking, inventory refresh, audit, protocol users/profile export, supported listener/filter maintenance and lifecycle inspection |
| Infrastructure administrator | Scoped protocol users/profile export, access inventory, audit, supported listener/filter maintenance and lifecycle inspection |
| VPN user manager | Scoped user creation, updates, revocation and profile export |
| Viewer | Scoped user names, estimated usage, audit and lifecycle inspection; no profile secrets |

Topology changes, protocol installation and OS erasure remain owner-only through
the reviewed lifecycle controller. These actions are not advertised as delegated
capabilities. Unsupported requests are rejected rather than forwarded to a shell.

Delegated listener maintenance is limited to supported isolated native listeners.
Paired listener changes and IKEv2 listener maintenance remain owner-controlled.
Shared ad-blocking changes require authority over every affected consumer, not
just one protocol using that resolver. Review tokens bind the exact target,
revision, affected consumers and requested change; a stale review is refused.
Pending runtime updates also block mutations that would invalidate rollback.

Each grant is limited to an exact protocol instance, physical server ID or logical
deployment ID. Protocol object IDs derive from server ID, protocol and installed
instance. An owner-supplied physical server ID must never be reused for a replacement
machine. Every protocol action checks the enrolled instance against current owned
server state. An owner `inventory.refresh` deliberately reconciles changed local
objects; an old exact-instance grant never expands to a newly installed instance.
Deployment scopes may follow an explicitly reviewed peer link. There is no
implicit trust in unchanged DNS or a changed host key.

User scope defaults to `own`: only accounts issued by that device may be viewed,
exported or revoked. Owners can explicitly grant `all`. Issuance attribution is
stored in the authority database and bound to a random account-generation marker,
independently of VPN passwords and native keys. The fixed adapter verifies both
the protocol instance and required account generation while holding the same
management locks used by the installed protocol helper. Reusing a deleted login
does not let its former issuing administrator control the new account.
A role change/revocation updates administrative authorization without rewriting
those VPN credentials or external-client profiles.

In the app, open **Servers → Manage → Maintenance → Administrators**. After the
owner enables sharing, choose a role and exact scope, then save or share the
invitation file. The recipient uses **Add VPN → Accept administrator invitation**.
This is separate from **VPN users → Share access**, which creates ordinary
connection details and grants no server-management authority.

## Paired nodes

The owner enables both nodes and links one reachable node as the authority. This
one-time link provisions a separate peer-service credential that is restricted to
this deployment and the same forced dispatcher. It is held only in root-owned
authority storage. The peer's exact host key, address, port and expected server ID
are checked before linking. Recipients never receive that credential or arbitrary
SSH forwarding permission.

One invitation is redeemed only at the authority. The authority binds the claimed
device key and synchronizes the same immutable key identity to eligible peers.
A partial failure returns `pending_peers`; `enrollment.resume` retries only that
identity. Management requests for a peer pass through the authority, which checks
current grants and own-issued users before sending bounded JSON over the pinned
peer connection. The peer independently checks its authenticated authority identity,
fixed deployment ceiling, current object, capability and monotonic authority
revision. A recipient cannot connect directly as a peer credential or supply its
own actor/role fields. Authority or peer outage fails closed. No parallel redemption
on separate nodes and no generic relay exist.

Local peer device records are audit/binding records, not independently usable
recipient SSH credentials. This central request path makes a grant change or
revocation effective on the next paired operation without a claim of instantaneous
replication to unreachable nodes. Losing/wiping the authority requires owner
re-enrollment/relinking; old grants are not silently restored from backups.

## Concurrency, revocation and limits

Every request reads current authority under a SQLite write lock; mutations require
an expected revision and unique operation ID. Before a protocol mutation is sent,
a durable running record commits. If the result is lost, the request is not
blindly replayed: the user must inspect actual state. Revocation waits for a
synchronous already accepted operation to finish; it cannot undo a completed OS
or VPN action. Next requests fail immediately, and revocation also terminates the
device Unix account's existing SSH sessions. An expired bootstrap session cannot
redeem: expiry is checked in each request as well as SSH key expiry.

Requests are capped at 64 KiB with a 15-second input deadline, responses at 2 MiB,
subprocesses at 120 seconds,
audit at 10,000 events, completed operation receipts at 10,000, unconfirmed mutations at 32 per device
and 2,048 total, and credential
creation at 4,096 accounts. Audit stores actor/device, operation, object, revision,
time and result; not passwords, private keys, user payloads or command output.
Protocol operations and RSA enrollment allocate work only while an SSH request is
active; no persistent management process is introduced. Actual 1 GB VPS cost and
all supported SSH configurations require deployment measurement.

## Explicit removal of administrator sharing

Ordinary one-protocol and all-VPN resets retain administrator SSH access, as their
existing review promises. Removing scoped administration is a separate owner-only
review: `module.removal-plan` returns a five-minute token and exact generated
accounts; `module.remove` requires that token, current revision and the confirmation
`REMOVE ADMINISTRATION`. The authority first commits disabled/revoked records, then
terminates and removes only matching generated Unix accounts and public key files.
It verifies each account's expected name, nonzero UID, primary group, root-owned
home and fixed shell; any ownership change stops cleanup. Only marker-owned SSH
and sudo snippets are removed. Unrelated accounts, root SSH and all VPN passwords,
keys, listeners and profiles stay. Remote peers need their own explicit removal.

The root-only helper and disabled database remain as revocation tombstones and a
recovery path. A new owner enable action can restore the management entry point,
but all previous devices, invitations and grants remain revoked. An interrupted
cleanup stays disabled and can be reviewed again; it does not silently reopen
credentials. Tests separately cover ownership refusal and delegated cleanup denial.

## Verification boundaries

`tests/test_scoped_access.py` executes the real enrollment/authorization state
machine with isolated OS effects. It covers role/payload tampering, forged actor,
wrong proof, replay, expiry, concurrent redemption, current-role enforcement,
existing-session revocation checks, own-issued accounts, unknown/cross-instance
objects, partial paired claims and fail-closed paired requests. This does not prove
OpenSSH or active VPN behavior. `tests/integration/ScopedAccessProbe.java` uses the
actual Android controllers, JSch and installed server helper on explicitly
configured disposable servers. Its result must be recorded separately from unit
checks, APK/UI execution and physical-device/network acceptance.

Account changes currently use the installed protocol adapters. IKEv2 rereads
credentials and terminates targeted sessions; AWG uses `syncconf`; password-based
OpenVPN reloads its credential file and uses its management socket to terminate
revoked sessions, with a restart fallback if targeted termination fails. Certificate OpenVPN additions no longer restart a running owned listener. New
Xray/XHTTP configurations enable the existing loopback API’s HandlerService and
hot-add one account, verifying both the exact CLI receipt and runtime user record.
Older Xray configurations require a reviewed helper upgrade before hot-add; API
failure never silently falls back to a listener restart. Pinned Xray revocation
does not terminate established user connections, so its complete revocation still
requires reviewed maintenance. Other adapters can still restart listeners.
Scoped account requests whose advertised policy requires a restart must explicitly
acknowledge that consequence; the peer enforces the same requirement. Administrative enrollment itself never
restarts them. No broad uninterrupted-session claim is made for all engines.

Primary references: [OpenSSH authorized-key restrictions](https://man.openbsd.org/sshd.8),
[OpenSSH ForceCommand and forwarding controls](https://man.openbsd.org/sshd_config.5).

Xray primary implementation references (pinned server version): [add-user CLI](https://github.com/XTLS/Xray-core/blob/v26.3.27/main/commands/all/api/inbound_user_add.go), [runtime user query](https://github.com/XTLS/Xray-core/blob/v26.3.27/main/commands/all/api/inbound_user.go), [VLESS removal behavior](https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/vless/inbound/inbound.go).
