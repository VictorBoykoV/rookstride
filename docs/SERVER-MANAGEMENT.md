# Server access, passwords and OS replacement

Rookstride uses encrypted SSH for administrator commands. VPN sign-in is separate:
you do not need to connect a VPN before refreshing a server or managing users.
If another VPN client is active, Android routes Rookstride according to that
client’s rules. Rookstride cannot override another client’s lockdown policy.
The owned Double VPN entry permits its configured SSH port from the VPN client
pool; other local services and the fail-closed internet policy remain guarded. Proxy-entry
clients have the same SSH-only exception for sockets addressed to the entry itself;
it does not permit internet access during an exit outage.

## Automatic two-server management

New Double VPN drafts default to **Automatic**. The app checks both SSH endpoints
independently before changing either server. If only one is reachable, it opens an
encrypted SSH forwarding session through it and verifies the destination host key
separately. Entry and exit roles do not change. Incorrect administrator credentials
or changed SSH identities stop the attempt; they do not trigger routing fallback.
The review screen also offers Direct only and either explicit relay direction.

A saved pair can change this preference under **Server connection**, without
reinstalling its VPNs. The first reachable server needs SSH forwarding enabled. The entry VPN itself
need not be installed to relay SSH. Exit VPN/DNS preparation and route verification
still precede client forwarding. A timed-out server action is inspected as its
existing durable job, never replayed as a new install or wipe.

## Chosen passwords

Generated VPN passwords contain 15 random characters. At creation/editing, the app
warns about short/easily guessed passwords and offers **Use anyway**. A manually
chosen `1` is accepted; this is an administrator choice, not a security recommendation.
Longer passphrases are accepted. Joining an existing VPN does not show strength
warnings. Supported text passwords must be nonempty, printable and at most
127 UTF-8 bytes for consistent client compatibility; no silent truncation occurs.
Username/key/certificate constraints remain specific to each protocol. SSH provider
passwords are independent of these VPN-account rules.

Existing IKEv2 management helpers need the explicit helper update before creating
accounts under the new policy. Existing accounts are retained. Saved immutable
Double VPN recipes keep their upgrade/reconfiguration boundary.

## Three different removal actions

| Action | Effect |
| --- | --- |
| Remove VPN setups | Removes the reviewed owned VPNs, accounts, keys, filtering and usage data. Keeps Ubuntu, SSH and unrelated applications. |
| Wipe server & reinstall Ubuntu | Replaces the selected system disk on a compatible full VM. All applications, files and settings on that disk are erased. Root SSH and network access are provisioned again. |
| Remove server from this phone | Removes the local app record; does not change the VPS. |

OS replacement has its own review, confirmation and durable job. It is never a
fallback for a failed VPN installation. The reviewed boot adapter is pinned in
`reinstall/upstream.json`; Ubuntu image checksums are verified using the system’s
Ubuntu cloud-image signing keyring. The future SSH identity is supplied over the
old pinned connection before the destructive action. Changed unrelated keys are
never silently accepted. The app reports completion only after pinned SSH returns
and the actual Ubuntu version matches the requested job. The separate saved SSH-identity cache then moves from the recorded old key to that verified replacement, so a new setup can use it. An unrelated changed key is still rejected.

Whole-disk replacement requires a direct phone network: disconnect the active VPN
before reviewing or starting it. The app checks the Android network again before
each not-yet-started paired erase. It can still poll an already started detached
OS job; it does not erase the next server while that direct-access check fails.
This restriction does not apply to ordinary server management or managed VPN
removal. For Double VPN, entry and exit Ubuntu targets are selected separately,
and the usable SSH relay is retained until its dependent server has returned.
See [paired maintenance and recovery](MAINTENANCE-AND-RECOVERY.md).

The first adapter is deliberately limited to a supported full x86_64/ARM64 VM,
one writable system disk, compatible GRUB/network/storage and enough RAM/free
space. Containers, Secure Boot, ambiguous/multiple writable disks and encrypted
or RAID roots need provider rebuild tools. Provider backups/snapshots are separate
from the selected system disk. Reimaging replaces the filesystem; it is not a
guarantee of forensic secure erasure of SSD blocks. A provider’s API needs hosting-account authorization;
root SSH credentials do not grant that API access.

**Release evidence:** OS boot/reconnect and provider acceptance are separate from
a passing preflight or APK build. This edition has x86_64 local-VM and disposable
KVM-provider evidence; ARM64 full-OS boot and broader provider/OEM testing remain
separate gates. Eligibility does not guarantee every provider layout.
