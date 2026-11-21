# Reusable VPN sign-in

Rookstride can install a VPN that friends and family join with a server address,
VPN username and VPN password. They do not need the server administrator password.
In **Connect to a VPN → Username and password**, choose the method and enter those
three details. **Connection preferences → Edit sign-in details** lets a user
correct these details later. The address may include `:port` when the administrator shares one.

| Method | Reusable username/password | What is retained on a user's phone |
| --- | --- | --- |
| IKEv2 EAP | Yes | Address, username/password, normal trusted CA selection |
| OpenVPN TCP | Yes, in username/password mode | Reusable server template and username/password; no device certificate or private key |
| Hysteria 2 | Yes, in username/password mode | Address and user details; no separate Salamander secret in this mode |
| TrustTunnel HTTP/2 | Yes, in username/password mode | Address and user details |
| NaïveProxy HTTP/2 | Yes, in username/password mode | Address and user details |
| AmneziaWG 3.1 | No | Peer keys and connection file |
| VLESS REALITY TCP / XHTTP | No conventional username/password | UUID, REALITY public identity and transport settings |
| Outline / Shadowsocks with WSS | Password/key plus additional connection settings | Connection file including method, WebSocket path and verified TLS settings; the displayed account label is not a wire username |

Rookstride builds the OpenVPN template for manual sign-in. Other OpenVPN clients
may still need that generic `.ovpn` template once; it contains no per-user client
key and can remain unchanged across a compatible server reinstall. Worker-method
exports remain `.rookvpn` files for Rookstride. They are not falsely labelled as
another application's native import format.

## Keeping access after a reinstall

Use the same VPN address, method, sign-in mode and listening port, then recreate
the same username and password. Rookstride remembers an automatically selected
port on the managing phone, including after managed removal. It never silently
moves a reinstall to another port when that remembered port is occupied.
Changing the address, port or method changes the connection contract.

A newly issued **server** certificate is normal. Username/password mode verifies
it against trusted certificate authorities rather than pinning a changing leaf
certificate. Users do not receive a client certificate or private key. Account
creation offers readable sign-in sharing immediately. Connection-file sharing
also remains available. OpenVPN stores a password hash; it cannot recover a
forgotten password for later sharing. Set a replacement password if needed.

The immediate **Copy sign-in details** action includes the chosen VPN username
and password, server address and method. It never includes the server's SSH
password. Newly chosen user secrets are retained only briefly in app memory,
bound to the exact server instance and account; they survive screen recreation,
not process death. If a later share cannot recover a password, the app asks for
the known password or offers a connection that prompts its recipient. Sharing
does not silently reset that user's password.

AmneziaWG exports remain native `.conf` files. Each save suggests a fresh short
filename so repeated exports do not collide. Android storage providers may
rename a duplicate; the app writes the complete configuration and attempts to
keep its filename compatible with AmneziaWG. Rookstride imports the file's
contents independently of its display name.

New installations in the app prefer username/password mode where supported.
Before installation, **Sign-in** offers connection-file mode as an alternative.
Existing private-certificate installations are not silently converted. For an
existing standalone IKEv2 server, **Enable username/password sign-in** prepares
trusted identity without deleting users. An older profile that pins a private
certificate needs a one-time migration/import; it cannot automatically trust an
unrelated replacement certificate. Rookstride can migrate its own cached pin only
when an authenticated server report identifies the exact preceding private leaf.

A clean OS rebuild also changes SSH host keys. The administrator must verify that
replacement before Rookstride sends administrator credentials. That separate
SSH protection does not require VPN users to change their VPN password.

## IP addresses, domains and trusted certificates

An entered domain is retained and used for the VPN identity. It must already
resolve to the VPS; Rookstride does not have the user's domain-provider account.
For IP setups, IKEv2 can use a public IP certificate. The four other password
methods use a deterministic automatic TLS name, `<IPv4-with-dashes>.sslip.io`.
This accommodates TrustTunnel's SNI requirement and OpenVPN's certificate-name
verification. Rookstride still dials the original IP when that was entered and
verifies the expected TLS name. It does not require the phone to resolve this
name just to connect to that IP.

[sslip.io](https://nip.io/) is an independent public DNS service, not Rookstride
infrastructure. No administrator or VPN password is sent to it. Its availability,
blocklist and shared certificate issuance limits are external dependencies. A
domain the administrator owns avoids this shared naming dependency. Rookstride
never changes the TLS name to another provider behind an existing client's back.

Automatic issuance requires a public reachable server, outgoing access to the
certificate authority and incoming HTTP port 80 for validation/renewal. A busy
website is preserved; Rookstride refuses the challenge instead of stopping it.
DNS errors, blocked HTTP access and issuer limits are reported as setup failures.
A request for username/password mode does not report success with a private CA
fallback. Connection-file mode remains an explicit alternative.

The common certificate cache is shared by the four native password methods and
kept across an individual protocol removal. Renewal is checked every four hours
with jitter. All-VPN removal deletes the owned certificate/account/configuration
cache; downloaded tools and OS packages remain. This is managed VPN removal,
not a provider OS rebuild. A small, nonsecret package-ownership receipt is
retained so a later deployment can switch Rookstride’s own inactive IKE daemon
when its Ubuntu package plan requires it. Active, unowned or customized daemon
setups are preserved and require review. Public certificate names appear in certificate
transparency, as normal for public certificates.

## Accounts and Double VPN

Generated account passwords contain 15 random characters. Manual passwords may be shorter or longer; the app warns about easy-to-guess choices and lets the administrator continue. The compatibility limit is 127 UTF-8 bytes, with no control characters or empty passwords. Letters alone,
numbers alone, spaces and punctuation are allowed; no character mixture is forced.
Usernames use up to 64 letters/numbers plus `.`, `@`, `_` and `-`. Display names
remain separate. An account is scoped to its selected protocol on its server.
Creating the same user on another protocol is an explicit administrator action.

The same username/password capability applies to **the phone-facing entry** of
new Double VPN routes. Exit bridge credentials are generated separately and
remain private to the two servers. Existing immutable routes keep their saved
recipe until explicitly redeployed through the reviewed change flow. Ad blocking
and available operational statistics retain their existing shared modules.

Administrator commands use pinned SSH; server passwords needed by protocol
engines stay root-readable in owned files. OpenVPN uses salted PBKDF2-SHA256
verifiers and terminates revoked sessions. The phone stores saved credentials and
native connection wrappers in its encrypted vault/profile store. Native profiles use
a fresh random encryption key wrapped by Android Keystore; the saved profile and
its identifier are authenticated. Earlier saved profiles remain readable. Normal IKEv2
profile storage does not contain the saved VPN password. Sharing/copying is an
explicit action, and administrator access is never part of a user export.

## Implementation and verification

The backend's optional `access_mode: "password"` is capability checked.
Omitted mode preserves older CLI recipes and private connection-file behavior.
`single/access.py` owns account rules; `single/public_tls.py` owns the shared
trusted identity; server protocol adapters own wire authentication. IKEv2 keeps
its separately owned certificate activation and renewal helper. Client and server
must agree on mode: Hysteria's reusable wire token is `username:password`, while
legacy Salamander profiles retain their original password and obfuscation key.

`tests/test_reusable_sign_in.py`, `PasswordSignInTest` and
`ReusableSignInUiTest` cover validation, sharing, persistence and client creation.
The opt-in disposable `password_fixture.py` is a synthetic test authority, not
public CA evidence. `openvpn_password_probe.py` exercises a real isolated client.
Public issuance, app deployment, encrypted traffic, signed UI, physical devices,
carrier reachability and region-specific availability are separate acceptance
checks; see the dated internal release evidence for exact completed gates.
