# Rookstride development rules

Keep all real addresses, passwords, administrator keys, deployment exports, signing keys, and logs out of Git. The app speaks directly to a user-selected VPS over SSH. Verify and pin SSH host keys before sending credentials; reject changed keys. Never concatenate user input into remote shell commands.

Preserve the gateway's fresh-install guard. Existing gateways may be inspected; helper installation and statistics enrollment must be an explicit app action. Do not rerun the installer over a running VPN. Keep monitoring local to the VPS and access it through SSH. Test deployment on a disposable Ubuntu 24.04 environment, not the user's working VPN.

Traffic totals are operational estimates, not billing records. Retain separate counters per daemon boot and CHILD_SA generation, record gaps, and test reconnects, rekeys, restarts, and shared logins. Never infer a physical device from its public IP address.

The Android app embeds strongSwan and must preserve source availability and upstream license notices. Mark release gates honestly: an APK build, emulator UI test, Linux integration test, and real-device VPN test are different checks.
