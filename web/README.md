# Rookstride local website and browser app

Version 0.1.0 combines the public-facing pages, Payload editor and a personal
browser client. Start it on your own computer. The guest list and VPN service
live on the rented server. Supported deployment in this browser edition is one
IKEv2 gateway with AdGuard Home on a fresh Ubuntu 22.04, 24.04 or 26.04 LTS VPS.

## Prerequisites

- **Website, editor and practice workspace.** Use a regular user account with Bash,
  Node.js 24.22.1 or newer (tested with 24.22.3), npm, and write access to the
  web checkout for the build and local SQLite data. These features run on a
  workstation without a rented server. The local check suite also uses Python 3
  and OpenSSH `ssh-keygen` for a disposable loopback SSH host key.
- **Private test host.** For a new test VPS, the recommended starting size is
  2 vCPU, 4 GB RAM and 60 GB SSD. A host with 2 GB RAM is a candidate for a
  low-traffic trial with a compatible prebuilt Linux bundle and one private
  management job at a time. Build on the same OS and architecture as the
  destination when moving a bundle with native dependencies. Both sizes still
  need capacity testing on the chosen host.
- **Real VPN installation.** The hosting machine runs the web app and makes an
  outbound SSH connection. Supply a separate, disposable Ubuntu target using
  the [target and fingerprint requirements](#manage-a-server-from-this-computer).
  Keep the adjacent gateway recipes and locked dependencies with the worker.
  Future Double VPN deployment tests require two distinct gateway targets,
  one for entry and one for exit. The current real browser installer supports
  the single-server IKEv2 workflow.

## Start locally

Start at the Rookstride application root (`projects/rookstride` in the private
checkout) on the machine that will host the local preview.

```sh
cd web
npm ci
./scripts/local.sh dev
```

Open the homepage once to initialize the local CMS. Run the remaining commands
in this guide from the same web directory.

The helper uses an optional workspace-local Node runtime if present; otherwise it
uses Node on PATH. It binds **127.0.0.1:3100**, never a public/LAN interface.

- Website: http://127.0.0.1:3100/
- Browser app and practice workspace: http://127.0.0.1:3100/manage
- Personal server setup and guest access: http://127.0.0.1:3100/manage/server
- Content editor: http://127.0.0.1:3100/admin

Create the first local editor account in the admin screen. This is operator access,
not a required account for website visitors. No default password is supplied.
Email delivery is intentionally disabled; do not expect password-reset emails.
First-editor setup is limited to an empty local user collection. Subsequent
unauthenticated enrollment and cross-origin API changes are refused.

## What works and what remains

The website, Journal/article reads, local SQLite persistence, editor authentication,
draft isolation and explicit publication are working local components. The first
launch seeds one clearly marked preview article and one private draft. Comics
have a library and an on-demand chapter page. One story can appear below the
homepage guides when the chapter is published, editorial approval is set and
every page has publicly approved art with alternative text. The reader displays
the images and captions in editorial order. The library also contains Rook's
short origin. Historical editions keep their own publication lifecycle.

The route guide connects both paths to the same internet destination. Get started
compares the browser, Android releases, assistant tools and planned Telegram
interface. The provider page offers a one-plan pilot with repeatable acceptance
criteria and links to the practice workspace. Practice uses the single-server
setup and management screens with local simulated responses. It supports four
inspection scenarios, ten methods, timed installation, sample users, filtering,
removal and labelled sample downloads. Restart starts a new exercise. Demo state
lives in the active tab.

### Manage a server from this computer

Run the app as a regular local user. The worker needs the source checkout,
locked dependencies and the adjacent reviewed `gateway` and `server` recipes.
The standalone Next bundle by itself does not contain a portable installer.
Open the server setup page and use a dedicated Ubuntu 22.04, 24.04 or 26.04 LTS x86_64 or arm64
server, its public IPv4 address, root SSH password and the **Ed25519 SSH host
fingerprint obtained independently from the provider console**. Start a second
setup for a different address with **Set up another server in a new tab**. Each
tab has its own session, with up to two active sessions per local app. Inspection
makes no changes. Review the plan, choose a VPN username and password, then
explicitly approve installation.
Allow UDP 500/4500 in the provider firewall.

Hysteria 2, Outline, Shadowsocks, TrustTunnel and NaïveProxy use the Linux
runtime packaged in the corresponding Android build. Stage the two
architecture archives from a verified APK that matches the checkout's
`single/routes-pins.json` in a private directory readable by the worker.
Extract the exact `assets/server-runtime/ARCH/runtime.bin` member for each
of `x86_64` and `aarch64`, and name it `ARCH.tar.gz`. Set the absolute
directory as `ROOKSTRIDE_ROUTE_ASSETS` before starting the web app. The
worker verifies the archive during review and sends it only after the
operator applies the matching plan. The target verifies it again before
installing the runtime and starting the recipe.

After verification, download a password-free strongSwan Android profile. Import
it on the device and supply the separate VPN password. The same page can reopen
a gateway created here, grant an invited person access, download their profile,
or revoke their login. Guest edits use a reviewed roster revision. Existing
or partly configured servers require inspection. There is no automatic reinstall.
DNS filtering is installed by this recipe. Installed gateways expose DNS
controls and the usage data available for their selected method.

The workstation's **Double VPN** workspace uses AmneziaWG on two distinct
Ubuntu servers. Verify each SSH fingerprint through its provider console or an
independent record, then inspect both servers. Review and confirm the named
entry, exit and profile before installation. The workstation verifies egress
and DNS on the exit before opening the entry. Download the owner's AmneziaWG
`.conf` from the same browser session, then connect using a compatible client.

Use **Open existing Double VPN** with both pinned records to reopen an owned
AmneziaWG pair. Refresh health and users to review the entry roster. You can
add or revoke a guest, download their profile, or review removal of the two
owned VPN roles. **Encrypted recovery archive** downloads the portable
Android-compatible owner backup. Keep its passphrase separately. **Check
recovery archive** rehearses the file against both matching roles. Select or
drop the `.rookrec` file, or paste the encrypted code shown after an export.

The local operator can rebuild both supported Ubuntu disks and restore that
same AmneziaWG pair with `scripts/pair-rebuild.mjs`. Run it as an unprivileged
user with Node 24.22.1 or newer. Use an empty owner-only journal directory and
absolute paths to an owner-only JSON target file and the current encrypted
archive. The target file has `entry` and `exit` objects with `address`,
`sshPort`, `fingerprint`, `keyType` and `password`. Use independently verified
SSH records for both roles.

1. Run `node scripts/pair-rebuild.mjs review JOURNAL TARGETS ARCHIVE ENTRY_UBUNTU EXIT_UBUNTU`.
   Supply the archive passphrase as one line on protected standard input. Check
   the returned roles, Ubuntu releases, disk sizes and replacement SSH pins.
2. Run `node scripts/pair-rebuild.mjs start JOURNAL TARGETS ARCHIVE` with the
   passphrase followed on the next line by `REBUILD BOTH SERVERS AND RESTORE DOUBLE VPN`.
   The reviewed exit erase is dispatched first.
3. Run `node scripts/pair-rebuild.mjs resume JOURNAL TARGETS ARCHIVE` with the
   same two input lines. It follows the reviewed job across reboot, verifies the
   returned exit before starting the entry and restores the archive after both
   Ubuntu installations return. Use the updated pins in `restored.json` for
   future SSH connections. Verify an original VPN profile from an independent client.

The journal contains job IDs and verified server records. Keep the journal,
target file and encrypted archive outside Git. If a reviewed job has an
uncertain outcome, resume the same operation. A confirmed mismatch or failed
installer requires inspecting the corresponding server through its provider.

The worker verifies the supplied fingerprint before SSH password authentication.
It permits one numeric public destination, bounds inputs/time and reads an
explicit source allowlist. Node's file permissions reduce incidental access;
they are not a shared-host isolation sandbox. The local service keeps only
short-lived connection state. The browser session token may survive page
reloads in the same tab. Server passwords, profiles and command transcripts are
not saved to the local CMS, browser storage or application logs. Local terminal
output on the target is discarded by the adapter. The gateway itself holds its
operational credentials and configuration. An interrupted install must be
inspected again. The personal workflow also passed on a disposable Ubuntu
24.04 guest. A Linux VPN client connected, resolved DNS, loaded an HTTPS site
through the gateway and observed an ad-domain block. The local lab used a
forwarded SSH port and a reserved certificate hostname. Public-provider and
physical-device testing are separate.

Signed catalogs, static publication bundles, announcements, app updating and
offline or panel-by-panel comic reading are separate delivery work.

### Workspace language and API responses

The personal and practice interfaces use the `manage` message catalog. In
`/api/gateway` responses, `state` identifies the outcome and `messageKey`
selects the matching explanation in the workspace language. The English
`message` field remains available to existing callers. A localized client
looks up the key for each response and uses a local fallback for an unknown
key. Installation and verification failures have distinct keys.

Only the visible wording changes with the catalog. Action names, scenario
IDs, stored practice choices, usernames and profile data keep their existing
values. The website sends no language preference to SSH workers or VPN recipes.

## Local state and safety

The launcher generates a random owner-readable secret in `.private/`; SQLite,
uploads and generated Payload types also stay there. This folder, `node_modules/`
and `.next/` are ignored. Never commit or share runtime data, real SSH credentials,
generated profiles or signing material. A local database is not an external backup.

No telemetry registration or external email service is configured. Browser images
and fonts are local/system resources. API writes require the local origin and
host; no public deployment, TLS/proxy trust or production isolation is qualified
by this development adapter. Keep it on loopback.

## Checks and build

```sh
./scripts/local.sh check
# With the local server already running:
./scripts/local.sh http-check
# Stop the dev server before building, then:
./scripts/local.sh build
./scripts/local.sh start
```

The HTTP check exercises a disposable first-editor/draft/publish round trip only
when no editor exists, then removes that test account/article. It preserves any
existing editor and reports that part not run. The HTTP smoke suite never opens
SSH. The module checks use a disposable loopback SSH peer and local Python
fixtures. Initialize the
local database with `dev` before the production-build/start check; production
migration/restore workflows are not implemented yet. The build is limited to one
Next page worker. Capacity testing on a 4 GB host is a separate check.

The site uses the existing project mark and Rook helper poses. Both route
diagrams are drawn in the page so their labels adapt to screen size. The old Python
website remains separate; its historical Android export now needs an explicit
`--export-legacy-android` flag and is not used by this app.

## Second visual iteration and agents

Iteration0.0.2 replaces the first paper/serif design with the shared graphite/red,
self-hosted Geist system in DESIGN.md. `/agents` offers client-specific stdio
setup and a prepared task for Codex, Claude Code, Cursor and Gemini CLI. The
website shows local absolute paths at runtime; these are not a public package.
Do not give customers access to the private development repository. Public
runner distribution remains a separate reviewed export/release gate.

With this checkout's dependencies installed, a local MCP client can start:

```text
/path/to/node24 /path/to/reviewed-checkout/web/scripts/mcp-preview.mjs
```

`get_capabilities` and `inspect_example` are read-only fixture tools sharing the
browser logic. Only192.0.2.10 and the four listed scenarios are accepted. No
network, credential input, SSH, arbitrary shell, file access or CMS authority is
exposed. `scripts/local.sh check` includes an actual SDK stdio client handshake,
tool discovery/calls and rejected extra-authority checks. This is not a live VPN
deployment test or qualification of all four installed agent clients.

### Operate one real VPS with a local assistant

On macOS or Linux, use `scripts/mcp-gateway.mjs` as a second, separately named
stdio server. Set its `ROOKSTRIDE_MCP_TARGET_FILE` environment variable to an
absolute path on your computer. Create that private file outside Git with
permission `0600` and these fields.

```json
{
  "address": "192.0.2.10",
  "sshPort": 22,
  "fingerprint": "SHA256:<independently verified host fingerprint>",
  "password": "<SSH password>"
}
```

For Codex, add a separate entry to its MCP configuration.

```toml
[mcp_servers.rookstride-operator]
command = "/path/to/node24"
args = ["/path/to/reviewed-checkout/web/scripts/mcp-gateway.mjs"]

[mcp_servers.rookstride-operator.env]
ROOKSTRIDE_MCP_TARGET_FILE = "/path/to/private/target.json"
```

For a JSON-configured stdio client, use the same `command`, `args` and an
`env` map under `mcpServers.rookstride-operator`.

Use the provider console or independent key record for the fingerprint. If it
is an ECDSA P-256 key, also set `"keyType": "ecdsa-sha2-nistp256"` in the private
target file. The connector lists all ten single-server methods through
`list_methods`. Configure `ROOKSTRIDE_ROUTE_ASSETS` in its environment for the
methods that use the [verified runtime archives](#manage-a-server-from-this-computer).

Use `inspect_gateway` before `review_install`. Open the returned review path
in a separate terminal using this command. It shows the server, exact
operation and confirmation phrase. If IKEv2 needs a new VPN password, enter
it at the hidden terminal prompt.

```text
/path/to/node24 /path/to/reviewed-checkout/web/scripts/mcp-gateway.mjs approve /path/from/review.json
```

The assistant can call `apply_install` and track the result with
`install_status`. Use `read_gateway` for accounts, Ubuntu eligibility, IKEv2
health, or an installed method's supported usage and DNS settings. Use `review_change` and `apply_change`
for managed removal, account creation or revocation, saving a profile, or
changing IKEv2 guest passwords and DNS presets. Native DNS filtering also
accepts separately approved protection pause and resume. Profile exports are saved in a
private local directory and the connector returns the path. Keep these files
with your other VPN credentials. Approval expires in five minutes and binds
one attempt. Finish active jobs before using `close_gateway`.

To enable standalone Ubuntu replacement, set
`ROOKSTRIDE_MCP_UBUNTU_REINSTALL=1` for the local connector. The
`review_ubuntu_reinstall` tool checks the selected Ubuntu version and reviewed
system disk. The terminal displays the existing SSH identity, the planned
replacement key, and the full erase confirmation. `apply_change` saves a
password-free recovery record in an owner-only directory next to the private
target file before dispatch. Use `reinstall_status` to check that same job.
To resume after restarting the connector, set `ROOKSTRIDE_MCP_RECOVERY_FILE`
to the absolute path of the saved record and retain the original target file
until recovery completes. Use the returned server record to update the
configured SSH key for subsequent connections. This workflow requires a
compatible existing Ubuntu host. The provider still supplies a blank server
or a rebuild when the SSH replacement adapter cannot run.

The connector shares the workstation browser's single-server replacement
adapter. The hosted browser pilot offers Ubuntu eligibility checks.
Delegated administration has its own workflow. The assistant endpoint at
rookstride.com serves read-only examples.

For local Double VPN, set `ROOKSTRIDE_MCP_PAIR_TARGET_FILE` in place of
`ROOKSTRIDE_MCP_TARGET_FILE`. The owner-only JSON file contains separate
`entry` and `exit` objects using the single-target fields. Use `inspect_pair`
to check both independently pinned servers, then `review_pair_install`.
Approve that review in a terminal with the same `approve` command and call
`apply_pair_install`. Follow `pair_status` through installation. Use
`open_pair` and `read_pair` to reconnect and get the current roster revision.
Use `review_pair_account` with that revision to review a guest grant or
revocation. Export a named account with `review_pair_export` and
`apply_pair_export`. Use the separate removal review for both owned VPN roles.

Use `review_pair_backup` and `apply_pair_backup` to save an encrypted owner
file. The terminal asks for the passphrase outside the assistant session.
Use `review_pair_rehearsal` and `apply_pair_rehearsal` to check a file, choosing
it in the approval terminal. The connector returns the readiness result
without exposing private archive contents to the assistant.

The local browser and MCP connector support an AmneziaWG entry with an
AmneziaWG, OpenVPN certificate, IKEv2 or VLESS TCP/REALITY exit. The client
profile is always AmneziaWG. Rebuild and recovery have per-route test scope.
For a reviewed Ubuntu rebuild and identity restore, set
`ROOKSTRIDE_MCP_PAIR_REBUILD=1` and set
`ROOKSTRIDE_MCP_PAIR_REBUILD_STATE_DIR` to an absolute path to a dedicated,
owner-only directory. Keep both original pinned target records available until
the job completes.

Use `review_pair_rebuild` and `apply_pair_rebuild_review` to prepare both disk
plans. Supply the current encrypted archive in the approval terminal. Use
`review_pair_rebuild_erase` and `apply_pair_rebuild_erase` for the separate erase
approval. That approval displays the reviewed disk sizes, Ubuntu releases and
replacement SSH identities. The connector verifies that the exit has returned
before starting the entry. Use `pair_rebuild_status` to follow the same
operation. After an interruption, reopen the connector with the original
target file and state directory. Use `review_pair_rebuild_resume` and
`apply_pair_rebuild_resume`.
Supply the same encrypted archive in the approval terminal. Once both roles
return, the state directory's `restored.json` records their verified
replacement pins. Update both target records with those pins before the next
connection.

On a memory-constrained development machine, keep one heavy operation active.
The wrapper defaults Node to a1536MB heap cap and Next uses one build worker.
Stop the preview before building; do browser checks after the build completes.
The cap is per process, not a system-wide memory guarantee. An explicit
NODE_OPTIONS overrides it when the operator has measured appropriate headroom.

Supplied Cursor/Gemini CLI marks retain separate trademark/provenance notices in
`public/licenses/assistant-marks.txt`; they are not original GPL Rookstride art.
