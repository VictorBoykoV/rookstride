# Ubuntu versions

Single-server setup and new Double VPN setups assess **Ubuntu 22.04 or newer** on
x86_64/aarch64 VPSs with apt, systemd and working administrator SSH. Each server is
checked separately. For example, an Ubuntu22.04 entry can use an Ubuntu26.04 exit;
the reverse arrangement is also eligible. Matching OS versions are unnecessary.

Eligibility checks are prerequisites. New releases, package availability, provider
networking and individual protocol combinations still need actual deployment tests.
Do not interpret a version-shaped string as certification of a future OS.

New Double VPN drafts use the userspace/native installer, including IKEv2 → AWG.
The original kernel-based IKEv2 → AWG recipe retains its Ubuntu24.04 requirement.
Existing saved pairs keep their original plan; Resume does not upgrade their
installer or switch their routing. Use reviewed removal and a new Double VPN setup
to move an old pair to the newer installer. The review lists owned data to remove;
Ubuntu, administrator SSH and unrelated files stay.

Installation verifies encrypted traffic and exit DNS before opening client
forwarding. The two machines' main routes and SSH access stay independent. Tests
use an exit-only destination as well as public egress, since two lab machines can
share the same public internet address.

XHTTP and the older VLESS TCP option use different transports and profiles.
Automatic XHTTP setup checks its REALITY cover target through repeated authenticated
VPN sessions. A successful generic TLS check is insufficient. An explicit target
is never silently substituted. Ordinary server refresh does not rewrite profiles,
credentials or working VPN configuration.

The **Wipe server & reinstall Ubuntu** selector is separate from VPN eligibility.
It offers only reviewed LTS image targets, currently22.04/24.04/26.04, on a compatible
full VM. A future Ubuntu version can pass non-destructive prerequisites without
automatically becoming a destructive image target. See
[Server management](SERVER-MANAGEMENT.md) for scope and recovery.

Canonical's [release cycle](https://ubuntu.com/about/release-cycle) describes
LTS/interim maintenance. Eligibility does not replace checking upstream support,
security updates and actual protocol deployment on each new release.
