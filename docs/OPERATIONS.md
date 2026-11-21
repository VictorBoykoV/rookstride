# Rookstride app operations

## Install from your phone

Choose **Add VPN → Set up a VPN → Single-server VPN** and a connection method.
Enter the server address, administrator name (prefilled `root`) and password.
Ubuntu 22.04+ and root or passwordless administrator access are required for single-server and new native Double VPN setups. See [Ubuntu compatibility](UBUNTU-COMPATIBILITY.md) for legacy pairs and tested scope. Compare
the SSH fingerprint with an independent provider/console source before trusting
it. A changed identity stops access before credentials are sent.

Rookstride selects free VPN ports, generates device credentials and configures
the method, private DNS filtering and available monitoring. Methods that need a
private TLS name generate it automatically, with a pinned private authority and
renewing leaf certificates. No domain purchase, certificate import or companion
client is required for normal Rookstride setup. Custom SSH settings are optional.
Administrator access is saved encrypted on the phone by default; opting out
means signing in again for server commands.

For **Double VPN**, choose the phone-to-entry method and entry-to-exit method,
then provide or select the two servers. Review removal of existing owned VPNs
when preparation requires dedicated nodes. Both nodes are staged before client
forwarding opens. Ad blocking runs at the exit; management reads each node over
SSH. See [progress and recovery](INSTALLATION-PROGRESS.md).

**Manage a server** adds an existing server without forcing an installation.
Inventory recognizes Rookstride-owned setups; it does not adopt arbitrary VPN
software. Additional standalone protocols can be installed later using free
ports. Direct and Double VPN coexistence on the same nodes remains separate work.

## Connect and share

Home shows the active connection with **Disconnect**, or the most recent
connection with **Connect**. Open a server for its installed methods and direct
connection buttons. Every supported method connects inside Rookstride; Android
permits one active VPN service at a time.

Inside a protocol, **VPN users** manages credentials for that protocol on that
server. **Add new user** creates independent access; Edit changes its label;
deletion revokes it. Sharing one profile aggregates its sessions and usage. A
label or observed address does not identify physical hardware.

**Connection** offers text/file sharing and saving. AmneziaWG exports native 3.1
`.conf`, IKEv2 `.sswan`, OpenVPN self-contained `.ovpn`, and the Xray methods VLESS
links. The five worker methods use versioned `.rookvpn` profiles preserving their
TLS trust and transport settings. These are Rookstride profiles, not generic
Outline keys, AmneziaVPN `vpn://` packages or universally compatible proxy links.
Treat exports as credentials. Send an IKEv2 account password separately.

## The same tools for every method

Each installed protocol exposes **VPN users**, **View log**, **Connection
statistics** and **Ad blocking**. Administrator commands use pinned, encrypted
SSH and do not require this phone to be connected to that VPN. SSH must still be
reachable from the current network. VPN reachability and SSH reachability are
separate checks.

Statistics refresh when opened and about every five minutes while the screen is
resumed; **Refresh** requests an earlier reading. A failed read is unavailable,
not a zero-usage result. Counters have different lifetimes:

| Method | What the reading covers |
| --- | --- |
| IKEv2 | Live sessions; optional collector history with recorded gaps and resets |
| AmneziaWG | Per-peer interface counters and recent handshakes; daemon generation |
| VLESS TCP / XHTTP | Per-user traffic in the current Xray daemon generation |
| OpenVPN | Currently active sessions per login; reconnecting starts new counters |
| Hysteria 2, Outline/WSS, Shadowsocks/WSS, TrustTunnel H2, NaïveProxy H2 | Per-user current worker counters and active-session estimates; daemon generation |

These are operational estimates, not billing records. Active sessions are not a
device count. Shared logins aggregate traffic. Durable cross-restart history for
all native methods remains planned; a common interface does not imply identical
measurement sources.

## Ad blocking

Open a protocol's **Ad blocking** tool. Standard uses the AdGuard DNS filter,
Strong uses HaGeZi Pro, and Strict uses HaGeZi Pro++. The selected preset and
aggregate query/blocked counts appear in the app. No separate AdGuard dashboard
password is needed for these controls.

Standalone native methods share one private AdGuard Home instance per server;
changing it affects all users of that instance. IKEv2 retains its separate
AdGuard/Unbound integration. Double VPN controls target the exit's resolver.
The server settings screen explains shared scope. Individual protocol removal
keeps a resolver needed by another method; removing all setups removes owned
filtering data last.

Filtering applies to DNS sent through the managed resolver. Android Private DNS
Automatic or Off permits that route; a strict custom provider or an application's
own encrypted DNS can bypass filtering. Stronger lists may break a site; return
to Standard if necessary. DNS blocking cannot reliably remove ads served from
the same host as the content or change a VPS IP's reputation.

## Remove and reuse a server

**Uninstall this protocol** removes that method's owned service, credentials,
configuration and rules after review. Other protocols remain. **Server settings →
Remove all VPN setups** reviews and removes all recognized Rookstride VPNs,
accounts, keys, filtering data and owned routing/firewall state. Pair nodes use
their pair cleanup, including locally recognized nodes whose old phone record
is missing. The app clears obsolete local profiles and keeps administrator
access so the server can be used again.

Ubuntu, SSH, administrator credentials, unrelated applications and installed
package/helper caches remain. An already empty server succeeds without deleting
anything. Expired reviews, changed inventory, ownership mismatches, symlinked
managed paths or active installations require a fresh review. An unreachable
server cannot be cleaned through SSH.

This managed removal workflow keeps Ubuntu. **Wipe server & reinstall Ubuntu**
is a separate system-disk replacement on eligible full VMs, with its own erase
review, signed image checks, planned replacement SSH key and returned-OS check.
It is not a universal provider rebuild API; unsupported layouts need provider
or rescue tools. **Remove server from this phone** only changes the local list.
See [server management](SERVER-MANAGEMENT.md) for exact scope and recovery.

Private key/certificate connection files need fresh exports after removal.
Compatible username/password clients can keep their saved definition when the
same address, method, mode, port and account are recreated with normal trusted
server identity. See [reusable sign-in](REUSABLE-SIGN-IN.md).

## Check the actual connection

Test websites, exit address, DNS and IPv6 on each actual device/network. A server
health check does not prove that a carrier permits its VPN transport. Android
lockdown while disconnected, per-app routing, network handoff and OEM background
restrictions need their own checks. Logs are scoped to the selected connection;
never publish credentials or an unredacted profile with a bug report.
