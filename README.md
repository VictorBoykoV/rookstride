<p align="center"><img src="brand/rook.svg" width="110" alt="Rook, the Rookstride mascot"></p>

# Rookstride

**Your gateway. Keep moving.**

An Android app for deploying and managing a personal IKEv2 VPN on your own VPS. The admin can connect in Rookstride; invited users import a profile into the official strongSwan Android app. Country and hosting provider independent.

**Early alpha.** Download the signed APK and complete corresponding source from [Releases](https://github.com/VictorBoykoV/rookstride/releases). See [test status](docs/TESTING.md) before relying on a release. Requires Android 8 or later and a fresh Ubuntu 24.04 VPS for installation. A phone Internet connection and reachable SSH are required; the app bundles its installation code, while the VPS downloads Ubuntu packages and AdGuard Home.

## What it does

- Deploy StrongSwan IKEv2/EAP-MSCHAPv2, AdGuard Home and Unbound over SSH.
- Manage multiple gateways, people, shared logins and separate device credentials.
- Connect directly with the embedded strongSwan VPN engine.
- Export password-free `.sswan` profiles for other Android users.
- Inspect active sessions, public endpoints, VPN addresses and traffic counters; disconnect or revoke access.
- Optionally collect daily and monthly traffic totals with a small local SQLite service.
- Choose Standard, Strong or Strict DNS filtering.
- Review and reset a recognized gateway with an explicit deletion confirmation.
- Read the built-in guide offline. The mascot and visual identity are original.

No cloud account or public web management API is involved. Root access belongs to the administrator; it is never included in user profiles.

<p><img src="brand/screenshots/gateway.png" width="230" alt="Gateway demo"><img src="brand/screenshots/people.png" width="230" alt="People and device logins demo"><img src="brand/screenshots/sessions.png" width="230" alt="Sessions and usage demo"></p>

Screenshots show the explicitly labeled, offline demo with fictional data.

## Get started

1. Install the APK from a release whose checksum and signing certificate you have verified. Android may ask you to allow installation from your download app.
2. Choose **Add gateway**. Enter the VPS address, SSH port, administrator name and password or private key. Root or passwordless sudo is required.
3. Inspect the gateway. Compare the presented SSH fingerprint with your provider console before trusting it. A changed fingerprint stops the connection.
4. On a fresh Ubuntu 24.04 VPS, choose **Install gateway**, create the first VPN login, and decide whether to enable usage history.
5. Keep the VPS reachable while installation completes. The job continues on the VPS if the app disconnects; reconnect to check its status.
6. Choose **VPN on this phone**, or share a user's profile and provide their VPN password separately.

Use a disposable VPS to try the alpha. An interrupted installation can leave partial configuration; inspect its root-only log before deciding to rebuild. The fresh-install guard deliberately refuses to overwrite an existing VPN or DNS setup.

Existing installations of the bundled [single VPS gateway](https://github.com/VictorBoykoV/single-vps-vpn-gateway) can explicitly enroll the management helper. Arbitrary StrongSwan installations need a migration review; they are not automatically compatible.

## VPN and filtering behavior

The Android profile uses MTU 1280, full IPv4 and IPv6 traffic selectors, and blocks traffic outside the VPN while the tunnel is active. This gateway provides IPv4 Internet access and sinks IPv6; AdGuard suppresses AAAA answers. The strongSwan engine exempts Rookstride’s own administration/certificate-fetch traffic so management remains reachable; other applications use the VPN. Android's **Always-on VPN / Block connections without VPN** setting is a separate phone setting for protection while disconnected.

DNS blocking can remove ads and trackers served from separate domains. It cannot reliably remove YouTube in-stream ads, change a datacenter IP's reputation, or stop a site using account, browser or GPS signals. Applications with their own encrypted DNS may bypass DNS filtering. Stronger lists can also break websites; return to Standard or allow a required domain in the private AdGuard dashboard.

## People, devices and totals

A shared login can have several simultaneous connections. Separate device credentials give each profile its own login and make revocation and totals clearer. Device labels are administrator supplied; IPsec does not reveal a phone's physical model or router hostname.

Disconnect closes the selected session; a client may automatically reconnect. Revoke removes the login and attempts to close all its sessions, preventing new authentication with that login.

The optional collector samples every 30 seconds and consumes disconnect/rekey events. Totals are UTC calendar-month estimates, excluding IPsec transport overhead. They begin at enrollment, survive collector restarts, and expose monitoring gaps. They are not billing records. See [architecture and resource limits](docs/ARCHITECTURE.md).

## Build, test and contribute

- [Build the APK and corresponding source](docs/BUILD.md)
- [Testing and release gates](docs/TESTING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security and recovery](SECURITY.md)
- [Third-party licenses](NOTICE.md)

The original Android administration code and branding are GPL-3.0-or-later. The embedded strongSwan code retains its upstream GPL-2.0-or-later notices; the combined app is distributed under GPL version 3 or later. Gateway scripts retain their MIT license. No affiliation with strongSwan, AdGuard, OnePlus or Amnezia is implied.
