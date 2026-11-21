# Reviewed Ubuntu replacement adapter

This module is separate from owned VPN removal. The Android controller uploads it
only after the operator chooses **Wipe server & reinstall Ubuntu**. It is not a
failure fallback and is not a generic remote wipe command.

`run.py` accepts JSON stdin with `plan`, `start` or `status`. Review creates a
short-lived disk/machine/network scope and planned replacement host key. Start
requires that review token, explicit full-disk confirmation and unchanged scope.
A detached systemd job owns preparation/reboot. Resume polls the same job; it
never launches another erase. Root-password access is required by this adapter. Fresh target Ubuntu archive
sources use HTTPS with normal APT signature/hash checking and bounded metadata
retries. The old OS's repository settings are not rewritten.

The initial scope is Ubuntu on an x86_64/ARM64 full VM, one writable root disk,
GRUB, a clear IPv4 primary route and adequate RAM/storage. Containers, encrypted
or RAID roots, ambiguous extra writable disks and Secure Boot are refused before
reboot. Hardware/provider acceptance is recorded independently of preflight.
Provider APIs and provider backups/snapshots are outside this module.

## Trusted inputs

- `upstream.json` pins an unmodified GPL-3.0 source snapshot of
  [bin456789/reinstall](https://github.com/bin456789/reinstall).
- Integration patches are deterministic and check their exact anchors at runtime.
  Remote helper code is supplied from that snapshot, not fetched from a floating
  branch. Keep the originals unmodified when changing the adapter.
- `boot-pins.json` pins official versioned Alpine boot archives and the network
  helper for both architectures. Verify bytes/hash before use. Embed the checked
  modules; refuse the bootstrap's unverified network-module fallback.
- Ubuntu cloud-image SHA256SUMS signatures are checked with Ubuntu's installed
  cloud-image keyring. Verify the complete image before preparing reboot, and
  again before the temporary installer parses/writes it. Use immutable dated
  release URLs rather than mutable `current` images.

Administrator passwords travel over pinned SSH/JSON stdin and a root-only
short-lived file, never process arguments. The temporary and final SSH listeners
use the replacement key supplied over the original pinned session. Only that
planned identity is accepted. The boot environment provisions root sign-in before
starting services. The public upstream HTTP log viewer is disabled.

Completion requires the matching job receipt, pinned returned SSH and an actual
Ubuntu/version probe. A structured temporary-installer failure stops polling with
attention required. Raw preparation/installer logs stay private; never commit them.
The phone removes affected owned connection records only after verified return.

## Maintenance gates

Run Python guards, Linux generated-shell checks, actual full boot/reconnect with
canary erasure, signed-app background/recreation/resume checks and disposable
provider cycles. A passing preparation step or source-only update is insufficient.
Record source/APK hashes and failed attempts as well as passes. Unsupported
provider recovery still needs that provider's console or separately authorized API.
Reimaging is logical filesystem replacement, not guaranteed forensic SSD erasure.
