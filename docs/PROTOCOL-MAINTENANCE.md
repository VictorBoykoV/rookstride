# Protocol lifecycle and maintenance

## One journey, separate adapters

The phone asks for an address, administrator and password. It verifies SSH
identity, stages reviewed code and starts durable server jobs. Protocol adapters
implement install, health, profile, users, revocation and removal. Filtering,
job progress and server inventory are shared services. Private TLS names,
authorities, device keys and renewing leaf certificates are generated where
needed; the ordinary journey does not ask for them.

| Boundary | Source |
| --- | --- |
| Method identity and phone capabilities | `SingleProtocols.java`, engine adapters |
| Pinning, transfer and job coordination | `Ssh.java`, `DeploymentService.java`, pair controllers |
| Standalone native lifecycles | `single/model.py`, `runtime.py`, `routes.py` |
| Private shared filtering | `single/filtering.py` |
| IKEv2 / management / accounting | `gateway/`, `server/` |
| Double VPN staging and fail-closed forwarding | `twohop/` and pair controllers |
| Owned cleanup and reusable nodes | `single/reset_server.py`, `server/reset.py`, `twohop/reset.py` |

The five worker methods share a routing engine; XHTTP and TCP/REALITY share Xray.
An update to a shared engine can affect several protocols. The OS-provided
OpenVPN package, official server endpoint, phone library and related upstream
project may have different release numbers. Do not substitute one for another.

## Tested updates

Release pins are explicit in bootstrap/build scripts, native pin manifests and
the worker's Go modules. Update review must identify the actual installed
implementation, inspect release notes/security notices and verify source and
binary hashes. A version change may need configuration, API, profile or database
migrations; modularity reduces duplication but does not make these automatic.

Before an update ships, check source/licensing, supported architectures, minimum
Android version, signed packaging, real tunnel traffic, DNS filtering, available
statistics, user management, export/revocation, removal/reinstall and reboot
recovery. A changed Double VPN transport also needs route, outage/recovery and
exit-only egress checks. Preserve existing profile trust and provide explicit
migration/rollback guidance when it changes.

An upstream release is a review candidate, not an instruction to upgrade live
servers. Current installation uses the tested pins. Reviewed phone-managed
helper updates are available for compatible native Double VPN deployments, with
retained VPN identities and rollback; see
[maintenance and recovery](MAINTENANCE-AND-RECOVERY.md). They do not replace VPN
engine binaries. Phone-managed engine updates, staged engine rollout and upstream
watch integration remain roadmap work; this edition performs no unattended
protocol update.

## Compatibility and availability

All methods use the same app tools; measurements retain their actual session or
daemon scope. See [operations](OPERATIONS.md) for these limits. Do not replace
unavailable readings with invented zeroes or physical-device counts.

Reachability depends on endpoint reputation, carrier, transport and current
filtering behavior. Country labels cannot promise availability. Test real
networks independently, keep alternative methods available and distinguish a
blocked endpoint from protocol authentication or DNS errors.
