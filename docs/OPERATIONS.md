# Rookstride app operations

## Add and install

Add the server address, SSH port and administrator credentials. Root or passwordless sudo is required. Independently compare the SSH fingerprint with your provider console before trusting it; changed keys stop access. Saved credentials are optionally encrypted with Android Keystore.

Use **Install gateway on fresh VPS** for Ubuntu 24.04 without existing VPN/DNS configuration. Choose a unique VPN password and optional usage history. The installation continues on the VPS if the phone disconnects; reopen the app to check the recorded job. A VPS reboot during installation may interrupt it. Inspect the root-only `/var/lib/rookstride/jobs/<job>/install.log` if it fails.

**Manage an existing gateway** is an explicit enrollment action for the compatible bundled template. First enrollment may briefly restart strongSwan to enable local management. Back up a working gateway first; arbitrary existing VPN configurations are not automatically supported.

## Connect and invite

In **People**, create a shared login or separate device login, then choose **Use on this phone** to import its pinned profile into Rookstride. Enter the VPN password and approve Android's VPN, notification and background-operation requests. Only one Android VPN can be active at a time.

To invite someone else, choose **Share StrongSwan profile** and send the password separately over a trusted channel. The recipient uses the official strongSwan Android app. The profile contains the server certificate and login, without the VPN password or administrator access.

Check website loading, exit IPv4, DNS and IPv6 on each actual device over Wi-Fi and mobile data. Profiles use MTU 1280 and active-tunnel IPv4/IPv6 blocking; IPv6 Internet egress is intentionally unavailable. Rookstride's own administration traffic is exempt. Android lockdown while disconnected is a separate OS setting.

## People and sessions

Shared accounts aggregate usage and may have several simultaneous sessions. Separate EAP device logins allow individual revocation and totals; their labels identify credentials, not physical hardware. A copied login can be used on another device.

Refresh the gateway before interpreting connection state. Observed endpoint IPs/ports may change or be shared behind NAT. **Disconnect** closes a session and permits automatic reconnection. **Revoke this login** removes its credentials and attempts to close its sessions.

Usage totals start when the optional collector is enabled. They use UTC months, omit network/encryption overhead and expose collection gaps. They are estimates rather than provider billing records. See [retention and resource limits](ARCHITECTURE.md).

## AdGuard controls

Choose **Gateways → AdGuard controls**:

| Level | Filter |
|---|---|
| Standard | AdGuard DNS filter |
| Strong | HaGeZi Pro |
| Strict | HaGeZi Pro++ |

Compare affected sites after each change. If access breaks, return to Standard or allow a required domain in AdGuard. Stronger DNS filtering cannot reliably remove YouTube in-video ads or change the reputation of a VPS IP.

For custom settings, connect to the VPN and open `http://10.254.0.1:3000` (or the configured DNS address). Retrieve the independent dashboard login from `/root/single-vps-vpn/adguard-login.txt` through trusted administrator SSH. In AdGuard, **Filters → DNS blocklists** manages lists; **Filters → Custom filtering rules** manages individual rules. Back up configuration before broad changes. The dashboard uses HTTP inside IPsec and is not publicly bound.

## Reset and reinstall

**Reset gateway data** first shows the recognized files/services and a review token valid for five minutes. Type `DELETE VPN` to apply the reviewed deletion. Accounts, certificates, AdGuard data, managed firewall rules and traffic history are permanently removed; connected users lose access. Ubuntu, SSH, unrelated files and package binaries remain.

The app refuses unknown configurations, extra VPN connections, symlinked managed paths, changed reset plans and recorded active installations. It cannot reset an unreachable server. A complete OS rebuild is a provider control-panel operation.

After resetting, install again and **export fresh client profiles**: the new installation has new certificates. Old profiles cannot authenticate the new server certificate. Keep the administrator SSH key and APK signing key backups private. See [security and recovery](../SECURITY.md).
