# Security and recovery

This alpha manages root-level changes on a VPS. Test it on a disposable Ubuntu 24.04 server first. Use official release artifacts, verify checksums and retain backups before enrolling an existing compatible gateway.

## Trust boundaries

Compare SSH fingerprints against an independent provider console before first trust. Credentials are sent only after host-key verification; changed keys stop access. Reset a saved fingerprint only after checking a legitimate server rebuild/key rotation. SSH password or private key access is for the administrator alone; root or passwordless sudo can modify the entire VPS.

User values are bounded and validated, transported as JSON on standard input, and never interpolated into remote shell commands. The helper offers a fixed action set and is root-only. The installation bundle is supplied by the trusted APK; verify APK provenance before supplying administrator access.

The server's certificate is fetched over pinned SSH and pinned in client profiles. Keep system time correct. Renew certificates and re-export profiles before expiry. A changed server certificate may require a new client profile.

Saved secrets are encrypted with Android Keystore. Secret dialogs inhibit screenshots. Do not export administrator credentials, publish logs containing identities, or commit a signing keystore. Copying a password to the clipboard is an explicit user action; clipboard handling by other software remains outside the app's control.

## VPN limits

The profile blocks outside-tunnel IPv4/IPv6 while connected. To block connectivity when disconnected, enable Android's Always-on VPN and Block connections without VPN settings yourself. Rookstride cannot silently change those settings. DNS filtering does not establish anonymity, change IP geolocation or reputation, override a site's account location, or filter every encrypted app request.

## Installation failures

The VPS installer refuses existing VPN/DNS configuration. A disconnected phone can reattach to the recorded job. If the VPS was rebooted or a package operation failed, inspect `/var/lib/rookstride/jobs/<job>/install.log` through the root console. Treat this log as sensitive. Rebuild a disposable server or repair the specific cause; do not remove the guard to overwrite production configuration.

The first helper enrollment can restart StrongSwan to load VICI, briefly disconnecting VPN clients. The app explains this before enrollment. Statistics can be disabled without deleting saved totals.

## Reset

Gateway reset permanently deletes the recognized installation’s VPN accounts, certificates, AdGuard data and usage history after a five-minute review token and typed DELETE VPN confirmation. Changed configurations, symlinked managed paths, extra VPN connections and recorded active installations are refused. Only named managed firewall chains are removed. Ubuntu, SSH, unrelated files and package binaries remain. A whole-OS wipe is a provider control-panel operation. The app cannot reset an unreachable server.

## Reporting

For vulnerabilities, use GitHub's private vulnerability reporting if enabled, or contact the repository owner privately before publishing exploit details. Do not attach passwords, private keys or live user records to a public issue. Routine bugs may be filed publicly with sanitized steps and version information.
