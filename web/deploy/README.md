# Private website pilot deployment

Start after verifying the SSH host key through the hosting provider console and recording the host OS, architecture, available resources and existing listeners. The website build includes the editor. The browser's personal VPN worker, gateway recipes and private source history stay on their own path.

## Build a release

On a builder matching the host architecture and Linux runtime, use Node 24.22.1 or newer with `npm` on `PATH`. Replace `REVISION` with the checked private commit. The build installs the locked dependencies in a disposable checkout and never reads its database or the operator's CMS secret.

```sh
bash projects/rookstride/web/deploy/package.sh REVISION /absolute/output/rookstride-web.tar.gz
```

Keep the archive and its SHA-256 receipt in the private deployment channel. The archive includes a release manifest, standalone dependencies and the static assets. On the destination, check the receipt against the trusted builder result, verify the manifest platform, architecture, Node version and commit, then unpack under `/opt/rookstride-web/releases/<commit>`. Do not overwrite a release directory. Run `sha256sum -c rookstride-web.tar.gz.sha256` from the receipt's directory before unpacking.

## Install privately

Use Node at `/usr/local/bin/node` or change the unit's `ExecStart` to the verified executable. Set up a non-login `rookstride-web` user and group. The release tree, `/opt/rookstride-web` and its `current` pointer must be operator-owned. Grant the service group read and directory traversal permission on the selected release, with no write permission. Keep `/var/lib/rookstride-web` mode `0700` and owned by the service user.

Set `release` to the absolute path of the freshly unpacked and permissioned release. With the service stopped, initialize or migrate the state as the service user. Bootstrap creates the versioned SQLite schema, a private Payload secret and the media directory. It does not create an editor or load sample articles.

```sh
sudo install -d -o rookstride-web -g rookstride-web -m 0700 /var/lib/rookstride-web
sudo -u rookstride-web env ROOKSTRIDE_DATA_DIR=/var/lib/rookstride-web \
  /usr/local/bin/node "$release/deploy/cms-state.mjs" migrate
sudo install -m 0644 "$release/deploy/rookstride-web.service" /etc/systemd/system/rookstride-web.service
sudo ln -sT "$release" /opt/rookstride-web/candidate
sudo mv -T /opt/rookstride-web/candidate /opt/rookstride-web/current
sudo systemctl daemon-reload
sudo systemctl enable --now rookstride-web.service
curl --fail --silent --show-error http://127.0.0.1:3100/api/local-status
```

Forward the port over the pinned operator SSH connection and open `http://127.0.0.1:3100/`. Create the first editor in `/admin` through that tunnel. Confirm that the homepage and bridge artwork load, try the practice workspace and publish a disposable article while keeping a second article in draft. Restart the service and confirm editor login and content persistence. Remove the test content when done.

Only the private listener uses port `3100`. The `serve.mjs public` role listens separately on loopback port `3101` with the reader route policy. The provided unit starts the private role. For public operation, provision a distinct unprivileged reader service with its own state and secret, populated from a reviewed approved-content export. Keep accounts, editor state, unpublished data and the editor service's secret and database outside the reader's filesystem access. The publishing export is a separate gate. Point the external reverse proxy only to the verified reader instance and verify its hostname, TLS and allowed routes before opening access.

## Back up and restore

Stop the service and confirm no other instance is writing to this dataset before taking a snapshot. SQLite's backup operation captures a consistent database, and stopping the writer keeps the corresponding media directory stable. Use a new destination inside a private staging directory writable by the service user, outside the release tree and active dataset. Run these examples as the service user with the matching release's Node and `cms-state.mjs`.

```sh
export ROOKSTRIDE_DATA_DIR=/var/lib/rookstride-web
/usr/local/bin/node "$release/deploy/cms-state.mjs" backup /absolute/staging/backup
ROOKSTRIDE_DATA_DIR=/absolute/staging/restored \
  /usr/local/bin/node "$release/deploy/cms-state.mjs" restore /absolute/staging/backup
```

The backup contains the database, uploads, editor credential hashes and the CMS secret. Encrypt it before keeping it off-host. Use the retained secret only in the restricted restore environment. Verify restoring from off-host storage into an isolated dataset. Check a published article and uploaded image, draft privacy and editor login before removing the test instance. The restore command verifies file digests and refuses an existing destination. Neither backup nor restore publishes the data.

Before switching releases, stop the service, record the previous release target and take an off-host snapshot. Run the candidate's migration and switch the symlink atomically. Start the service and check its private health endpoint and routes. On failure, stop the service and switch back to the previously verified release. If it requires an earlier schema, restore the corresponding snapshot to a new directory and point the service at it during recovery. Reconcile any writes since the snapshot before manually re-enabling publishing. Preserve the failed dataset until reconciliation. Startup rejects an incompatible schema and never runs migrations implicitly.

The first migration rolls out the Payload 3.93.0 schema generated by `payload migrate:create` as checked SQLite SQL. Append separately numbered, reviewed SQL for schema changes. Keep each change transactional and rehearse upgrades and matching-snapshot rollbacks off-host. The website module's `node --test tests/hosted-cms.test.mjs` exercises CMS bootstrap, role checks and local content/media restore using disposable directories.
