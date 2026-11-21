import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { EventEmitter } from "node:events";
import { rootCertificates } from "node:tls";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { executePairRequest, executePairRuntime, loadPairRecipe } from "../scripts/pair-ssh.mjs";
import { createPairRuntime, pairArchiveDigest, pairRestoreStages, pairStages } from "../src/lib/pair-deployment.mjs";

const entry = { address: "192.0.2.21", sshPort: 22, fingerprint: "SHA256:" + "A".repeat(43), password: "fixture-ssh-entry" };
const exit = { address: "198.51.100.22", sshPort: 22, fingerprint: "SHA256:" + "B".repeat(43), password: "fixture-ssh-exit" };
const digest = "a".repeat(64);
const bridge = "c".repeat(64);
const account = "pilot-owner";
const initialRevision = "1".padStart(64, "0");
const replacementGeneration = { entry: "3".repeat(32), exit: "4".repeat(32) };
const restoreOperation = "7".repeat(32);
const transport = { protocol: "awg", endpoint: exit.address, profile: { content: "fixture-private-bridge-key" }, dns: { address: "10.253.0.1" } };
const config = [
  "[Interface]",
  "PrivateKey = private-key",
  "DNS = 1.1.1.1, 9.9.9.9",
  "Address = 10.66.0.2/32, fd00::2/128",
  "[Peer]",
  "PublicKey = public-key",
  "PresharedKey = shared-key",
  "Endpoint = " + entry.address + ":51820",
  "AllowedIPs = 0.0.0.0/0, ::/0",
  "",
].join("\n");

function nativeProfile(protocol, login) {
  if (protocol === "awg") return { format: protocol, content: config };
  if (protocol === "ikev2") return { format: protocol, content: JSON.stringify({
    uuid: "d2e06308-2bcc-41fb-b769-265788e6dec3", name: "Fixture VPN", type: "ikev2-eap",
    remote: { addr: entry.address, id: entry.address, certreq: false, cert: new X509Certificate(rootCertificates[0]).raw.toString("base64") },
    local: { eap_id: login }, mtu: 1280,
    "split-tunneling": { "block-ipv4": true, "block-ipv6": true },
  }) };
  if (protocol === "openvpn") return { format: protocol, content: [
    "client", "dev tun", "tun-mtu 1280", "proto tcp-client", `remote ${entry.address} 1194`,
    "nobind", "persist-key", "persist-tun", "remote-cert-tls server", "verify-x509-name server name",
    "tls-version-min 1.2", "data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM",
    "redirect-gateway def1 ipv6", "block-ipv6", "verb 3",
    ...["ca", "cert", "key", "tls-crypt"].flatMap((tag) => [`<${tag}>`, "inert-fixture-data", `</${tag}>`]), "",
  ].join("\n") };
  if (protocol === "xray" || protocol === "xhttp") {
    const query = new URLSearchParams({
      encryption: "none", security: "reality", type: protocol === "xray" ? "tcp" : "xhttp",
      flow: protocol === "xray" ? "xtls-rprx-vision" : "", fp: "chrome", sni: "example.com",
      pbk: "A".repeat(43), sid: "a".repeat(16),
      ...(protocol === "xhttp" && { mode: "auto", path: "/" + "a".repeat(48) }),
    });
    return { format: protocol, content: `vless://d2e06308-2bcc-41fb-b769-265788e6dec3@${entry.address}:443?${query}#${login}` };
  }
  return { format: protocol, content: JSON.stringify({
    schema: 1, protocol, server: entry.address, port: 443, login,
    password: "fixture-only-account", certificate: rootCertificates[0],
    server_name: protocol === "trusttunnel" ? `vpn-${"c".repeat(32)}.internal` : entry.address,
    ...(protocol === "hysteria2" && { obfs: "o".repeat(30) }),
    ...(["outline", "shadowsocks"].includes(protocol) && { method: "chacha20-ietf-poly1305", path: "/" + "d".repeat(48) }),
  }) };
}

function fixture(testRequest, {
  machines = { entry: "1".repeat(64), exit: "2".repeat(64) },
  architectures = { entry: "x86_64", exit: "aarch64" },
  loadRuntime = async (architecture) => Buffer.from(architecture),
  transferReady = true,
  cachedRuntime = [],
} = {}) {
  const owners = { entry: null, exit: null };
  const calls = [];
  const closed = [];
  const stages = [];
  let counter = 0;
  const jobs = { entry: {}, exit: {} };
  const bindings = {};
  const identityWrites = new Set();
  const users = new Set([account]);
  let rosterRevision = 1;
  const roster = () => ({ owner: account, users: [...users], revision: rosterRevision.toString(16).padStart(64, "0") });
  const removalPlan = (role, pair) => ({
    pair, role, token: (role === "entry" ? "e" : "f").repeat(64),
    configuration: "c".repeat(64), expires: 1_900_000_000,
  });
  const runtime = createPairRuntime({
    connect: async (node) => {
      const role = node.address === entry.address ? "entry" : "exit";
      calls.push({ role, mode: "connect", keyType: node.keyType });
      return { role, destroy: () => closed.push(role) };
    },
    eligibleTarget: (address) => address === entry.address || address === exit.address,
    loadRecipe: async () => ({ digest, archive: Buffer.from("fixture archive"), routePins: Buffer.from("fixture pins") }),
    loadRuntime,
    async transferRuntime({ role }, { topology: req, architecture, archive, routePins }) {
      assert.equal(routePins.toString(), "fixture pins");
      if (archive === undefined) {
        calls.push({ mode: "runtime-check", role, req, architecture });
        return { ready: cachedRuntime.includes(role) };
      }
      calls.push({ mode: "runtime", role, req, architecture, archive: archive.toString() });
      return { ready: transferReady };
    },
    async request(client, { mode = "recipe", request: req, bundle, archive }) {
      const { role } = client;
      calls.push({ role, mode, req, bundle, archive: Boolean(archive) });
      const override = testRequest?.(role, mode, req);
      if (override !== undefined) return override;
      if (mode === "probe") return { owner: owners[role], os: "ubuntu", version: "24.04", machine: machines[role], standaloneDnsPresent: false, runtimeArchitecture: architectures[role] };
      if (mode === "resolver") return { local: false };
      if (mode === "restore") {
        const binding = [req.operation, req.archiveDigest, req.revision, req.pair].join("/");
        if (bindings[role] && bindings[role] !== binding)
          throw Object.assign(new Error("fixture binding"), { code: "restore-ownership-mismatch" });
        if (req.action === "inspect")
          return { recorded: Boolean(bindings[role]), jobs: { ...jobs[role] } };
        if (req.action === "validate") return {
          readiness_schema: 2, verified: true, deployment: req.pair,
          entry_users: req.archive.nodes.entry.state.users.length,
          exit_users: req.archive.nodes.exit.state.users.length, live_restore_tested: false,
        };
        if (req.action === "enroll") {
          bindings[role] = binding;
          return { recorded: true };
        }
        if (req.action === "identity") {
          identityWrites.add(role);
          return {
            restored: true,
            usage_generation: req.snapshot.state.protocol === "ikev2"
              ? req.snapshot.state.instance
              : replacementGeneration[role],
            users: req.snapshot.state.users.length,
          };
        }
        if (req.action === "revision") return { revision: req.revision };
      }
      if (mode === "management") {
        if (req.action === "node") return {
          pairId: req.pair, role, bridge, topologyRevision: 1, healthy: true,
          ...(role === "entry" ? roster() : { dnsHealthy: true }),
        };
        if (req.action === "profile") return nativeProfile(req.entry_protocol, req.login);
        if (req.action === "grant") users.add(req.login);
        if (req.action === "revoke") users.delete(req.login);
        rosterRevision++;
        return roster();
      }
      if (mode === "reset") {
        if (req.action === "plan") return removalPlan(role, req.pair);
        if (req.action === "check") return { ready: req.token === removalPlan(role, req.pair).token, role };
        if (req.action === "apply") {
          owners[role] = null;
          return { reset: true, role };
        }
      }
      if (mode === "recovery") {
        if (req.action === "export") {
          const { action, bridge: fingerprint, ...plan } = req;
          const protocol = role === "entry" ? req.entry_protocol : req.exit_protocol;
          assert.equal(fingerprint, bridge);
          return {
            schema: 2, purpose: "rookstride-owner-recovery-node", adapter: protocol + "-identity-v1",
            role, deployment: req.pair,
            plan: { ...plan, client_pool: "10.66.0.0/24", test_ip: "10.249.255.254",
              entry_address: "10.253.0.2/30", exit_address: "10.253.0.1/30", route_table: 51831 },
            state: { protocol, users: [{}], private: "private-snapshot-fixture", instance: "0".repeat(32) },
            initial_user: { login: role === "entry" ? account : "bridge",
              password: "fixture-owner-recovery-password", statistics: true },
            ...(role === "exit" && { filter_policy: { level: "strong", enabled: false } }),
          };
        }
        if (req.action === "rehearse-pair") return {
          readiness_schema: 2, verified: true, deployment: req.pair,
          entry_users: 1, exit_users: 1, live_restore_tested: false,
          archive: req.archive,
        };
      }
      if (req.command === "preflight") return { ready: true, role };
      if (req.command === "start") {
        if (req.action === "bootstrap") owners[role] = {
          pairId: req.pair, role, bundle: digest,
          ...(req.entry_protocol !== "awg" && { entryProtocol: req.entry_protocol }),
          ...(req.exit_protocol !== "awg" && { exitProtocol: req.exit_protocol }),
        };
        const job = jobs[role][req.action] ?? (++counter).toString(16).padStart(32, "0");
        jobs[role][req.action] = job;
        return { job, state: "running" };
      }
      if (req.command === "status") return { job: req.job, state: "complete" };
      if (req.command === "health") return { services: { protocol: true, adguard: role === "exit" } };
      if (req.command === "material") return { ...transport, protocol: req.exit_protocol };
      if (req.command === "overview") return { configured: true, activated: role === "entry", exit_ip: exit.address };
      throw new Error("unhandled fixture command");
    },
    wait: async (signal) => signal.throwIfAborted(),
  });
  const credentials = { entry, exit };
  const review = (overrides) => runtime.reviewPair({ ...credentials, login: account, ...overrides });
  const deploy = (receipt, overrides) =>
    runtime.deployPair({ ...credentials, review: receipt, onProgress: ({ stage }) => stages.push(stage), ...overrides });
  const profile = (receipt, login) => runtime.exportPairProfile({ ...credentials, review: receipt, login });
  const manage = (action, receipt, options) => runtime[action]({ ...credentials, review: receipt, ...options });
  const adopt = () => runtime.adoptPair(credentials);
  const restore = (archive, options) => runtime.restorePair({
    ...credentials, archive, operation: restoreOperation, archiveDigest: pairArchiveDigest(archive),
    onProgress: ({ stage }) => stages.push(stage), ...options,
  });
  return { calls, closed, stages, owners, review, deploy, profile, manage, adopt, restore, identityWrites };
}

for (const [exitProtocol, port] of [["openvpn", 1194], ["ikev2", 500], ["xray", 443]]) {
test(`mixed review, ownership, archive and restore bind the ${exitProtocol} exit`, async () => {
  const f = fixture();
  const reviewed = await f.review({ exitProtocol });
  assert.equal(reviewed.exitProtocol, exitProtocol);
  await f.deploy(reviewed);
  assert.equal((await f.adopt()).exitProtocol, exitProtocol);
  assert.equal((await f.profile(reviewed)).configuration, config);
  const archive = await f.manage("capturePairRecovery", reviewed);
  assert.equal(archive.nodes.entry.state.protocol, "awg");
  assert.equal(archive.nodes.exit.state.protocol, exitProtocol);
  assert.equal((await f.manage("rehearsePairRecovery", reviewed, { archive })).verified, true);

  delete f.owners.exit.exitProtocol;
  await assert.rejects(f.adopt(), { code: "ownership-mismatch" });
  await assert.rejects(f.review({ exitProtocol: "wireguard" }), { code: "review-mismatch" });
  const fresh = fixture();
  const restored = await fresh.restore(archive);
  assert.equal(restored.review.exitProtocol, exitProtocol);
  for (const { req } of [...f.calls, ...fresh.calls].filter(({ req }) => req?.engine === "native-v2")) {
    assert.equal(req.entry_protocol, "awg");
    assert.equal(req.vpn_port, 51820);
    assert.equal(req.exit_protocol, exitProtocol);
    assert.equal(req.tunnel_port, port);
  }
  const altered = structuredClone(archive);
  altered.nodes.exit.plan.tunnel_port = port + 1;
  await assert.rejects(fresh.restore(altered), { code: "invalid-recovery" });
});
}

const methodFixtures = [
  ["awg", 51820, 443, "conf"], ["openvpn", 1194, 1194, "ovpn"], ["ikev2", 500, 500, "sswan"],
  ["xray", 443, 443, "txt"], ["xhttp", 443, 443, "txt"], ["hysteria2", 443, 443, "rookvpn"],
  ["outline", 443, 443, "rookvpn"], ["shadowsocks", 443, 443, "rookvpn"],
  ["trusttunnel", 443, 443, "rookvpn"], ["naive", 443, 443, "rookvpn"],
];

test("reviews all 100 ordered protocol selections with their Android default ports", async () => {
  for (const [entryProtocol, vpnPort] of methodFixtures) {
    for (const [exitProtocol, , tunnelPort] of methodFixtures) {
      const f = fixture();
      const receipt = await f.review({ entryProtocol, exitProtocol });
      assert.equal(receipt.entryProtocol, entryProtocol === "awg" ? undefined : entryProtocol);
      assert.equal(receipt.exitProtocol, exitProtocol === "awg" ? undefined : exitProtocol);
      const preflights = f.calls.filter(({ req }) => req?.command === "preflight");
      assert.equal(preflights.length, 2);
      for (const { req } of preflights) {
        assert.equal(req.entry_protocol, entryProtocol);
        assert.equal(req.exit_protocol, exitProtocol);
        assert.equal(req.vpn_port, vpnPort);
        assert.equal(req.tunnel_port, tunnelPort);
      }
      assert.ok(!f.calls.some(({ mode }) => mode === "runtime"));
    }
  }
});

test("each entry method has a matching owned profile and preserves its identity adapter through restore", async () => {
  for (const [index, [entryProtocol, , , extension]] of methodFixtures.entries()) {
    const [exitProtocol] = methodFixtures[(index + 1) % methodFixtures.length];
    const f = fixture();
    const review = await f.review({ entryProtocol, exitProtocol });
    const credentials = entryProtocol === "ikev2" ? { password: "fixture owner VPN password" } : {};
    await f.deploy(review, credentials);
    assert.deepEqual(await f.adopt(), review);
    assert.deepEqual(await f.profile(review), {
      configuration: nativeProfile(entryProtocol, account).content,
      filename: `rookstride-${account}.${extension}`,
    });
    const archive = await f.manage("capturePairRecovery", review);
    assert.equal(archive.nodes.entry.adapter, entryProtocol + "-identity-v1");
    assert.equal(archive.nodes.exit.adapter, exitProtocol + "-identity-v1");
    assert.equal((await f.manage("rehearsePairRecovery", review, { archive })).verified, true);
    assert.deepEqual((await fixture().restore(archive)).review, review);
    if (entryProtocol !== "awg") {
      delete f.owners.exit.entryProtocol;
      await assert.rejects(f.adopt(), { code: "ownership-mismatch" });
    }
  }
});

test("IKEv2 entry requires a chosen owner and guest password while profiles exclude it", async () => {
  const f = fixture();
  const receipt = await f.review({ entryProtocol: "ikev2" });
  const ownerPassword = "fixture owner VPN password";
  const guestPassword = "fixture guest VPN password";
  assert.ok(!Object.hasOwn(receipt, "password"));
  await assert.rejects(f.deploy(receipt), { code: "invalid-password", uncertain: false });
  await assert.rejects(f.deploy(receipt, { password: "invalid\npassword" }), { code: "invalid-password" });
  assert.ok(!f.calls.some(({ req }) => req?.command === "start"));
  await f.deploy(receipt, { password: ownerPassword });
  const bootstrap = f.calls.find(({ role, req }) => role === "entry" && req?.action === "bootstrap");
  assert.equal(bootstrap.req.password, ownerPassword);
  const grant = { operation: "grant", login: "guest", revision: initialRevision };
  await assert.rejects(f.manage("changePairAccount", receipt, grant), { code: "invalid-password" });
  await f.manage("changePairAccount", receipt, { ...grant, password: guestPassword });
  const { configuration } = await f.profile(receipt, "guest");
  assert.deepEqual(JSON.parse(configuration).local, { eap_id: "guest" });
  assert.ok(!configuration.includes(guestPassword));
  assert.equal(f.calls.find(({ mode, req }) => mode === "management" && req.action === "grant").req.password, guestPassword);
});

test("checks architecture assets before a worker route and binds the transfer to each required pinned role", async () => {
  const missing = fixture(undefined, { loadRuntime: async () => null });
  await assert.rejects(missing.review({ entryProtocol: "trusttunnel" }), { code: "runtime-unavailable", uncertain: false });
  const unsupported = fixture(undefined, { architectures: { entry: "x86_64", exit: "i386" } });
  await assert.rejects(unsupported.review({ exitProtocol: "naive" }), { code: "runtime-unavailable", uncertain: false });
  assert.ok(unsupported.calls.every(({ mode, req }) => mode !== "runtime" && req?.command !== "start"));
  const rejected = fixture(undefined, { transferReady: false });
  const attempted = await rejected.review({ entryProtocol: "trusttunnel" });
  await assert.rejects(rejected.deploy(attempted), { code: "runtime-transfer-unconfirmed", uncertain: false });
  assert.ok(rejected.calls.every(({ req }) => req?.command !== "start"));
  for (const [selection, expected] of [
    [{ entryProtocol: "trusttunnel" }, [["entry", "x86_64"]]],
    [{ exitProtocol: "hysteria2" }, [["entry", "x86_64"], ["exit", "aarch64"]]],
    [{ entryProtocol: "xhttp", exitProtocol: "ikev2" }, []],
  ]) {
    const f = fixture();
    const receipt = await f.review(selection);
    await f.deploy(receipt);
    const transfers = f.calls.filter(({ mode }) => mode === "runtime");
    assert.deepEqual(transfers.map(({ role, architecture }) => [role, architecture]), expected);
    for (const transfer of transfers) {
      assert.equal(transfer.req.pair, receipt.pairId);
      assert.equal(transfer.req.role, transfer.role);
      assert.equal(transfer.req.entry_protocol, selection.entryProtocol ?? "awg");
      assert.equal(transfer.req.exit_protocol, selection.exitProtocol ?? "awg");
      assert.equal(transfer.archive, transfer.architecture);
      assert.ok(f.calls.indexOf(transfer) < f.calls.findIndex(({ req }) => req?.command === "start"));
    }
  }
  const cached = fixture(undefined, { cachedRuntime: ["entry"] });
  const review = await cached.review({ exitProtocol: "shadowsocks" });
  await cached.deploy(review);
  assert.deepEqual(cached.calls.filter(({ mode }) => mode === "runtime-check").map(({ role }) => role), ["entry", "exit"]);
  assert.deepEqual(cached.calls.filter(({ mode }) => mode === "runtime").map(({ role }) => role), ["exit"]);
});

test("refuses an exit transport that does not match the reviewed protocol and address", async () => {
  const f = fixture((role, mode, req) => req?.command === "material" ? transport : undefined);
  const review = await f.review({ exitProtocol: "xray" });
  await assert.rejects(f.deploy(review), { code: "exit-route-unavailable", uncertain: true });
  assert.ok(!f.calls.some(({ mode }) => mode === "resolver"));
});

test("the upload manifest is byte-identical to the reviewed Android source digest", async () => {
  const { digest: actual, archive } = await loadPairRecipe();
  const wrapper = fileURLToPath(new URL("../scripts/pair_remote.py", import.meta.url));
  const project = fileURLToPath(new URL("../../", import.meta.url));
  const result = spawnSync("python3", [
    "-B", "-c", `
import runpy, sys, tempfile
from pathlib import Path
project = Path(sys.argv[1])
sys.path.insert(0, str(project / 'server'))
import pair
wrapper = runpy.run_path(sys.argv[2])
expected = pair.source_digest(project)
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory)
    wrapper['unpack'](sys.stdin.buffer, target, expected)
    assert pair.source_digest(target) == expected
print(expected)
`, project, wrapper,
  ], { input: archive, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), actual);
});

test("fresh deployment verifies exit DNS and route before opening the entry", async () => {
  const run = fixture();
  const review = await run.review();
  assert.equal(review.entry.ubuntu, "24.04");
  assert.equal(review.exit.address, exit.address);
  assert.equal(Object.hasOwn(review.entry, "password"), false);
  assert.equal(Object.hasOwn(review.exit, "password"), false);
  assert.equal(run.calls.filter(({ req }) => req?.command === "start").length, 0);
  assert.ok(run.calls.filter(({ req }) => req?.command === "preflight").every(({ archive }) => archive));

  run.calls.length = 0;
  const result = await run.deploy(JSON.parse(JSON.stringify(review)));
  assert.deepEqual(result, { state: "installed", pairId: review.pairId, exitIp: exit.address });
  assert.deepEqual(run.stages, pairStages);
  assert.deepEqual(run.calls.filter(({ req }) => req?.command === "start")
    .map(({ role, req }) => [role, req.action]), [
    ["exit", "bootstrap"], ["entry", "bootstrap"], ["exit", "configure"],
    ["entry", "configure"], ["entry", "verify"], ["entry", "activate"],
  ]);
  const { calls } = run;
  const exitHealth = calls.findIndex(({ role, req }) => role === "exit" && req?.command === "health");
  const entryBootstrap = calls.findIndex(({ role, req }) => role === "entry" && req?.action === "bootstrap");
  assert.ok(exitHealth < entryBootstrap);
  assert.equal(calls[entryBootstrap].req.login, "pilot-owner");
  assert.notEqual(calls[entryBootstrap].req.password, entry.password);
  const starts = calls.filter(({ req }) => req?.command === "start");
  assert.deepEqual(starts.find(({ role, req }) => role === "entry" && req.action === "configure").req.transport, transport);
  assert.deepEqual(starts.filter(({ req }) => ["verify", "activate"].includes(req.action)).map(({ req }) => req.expected_exit_ip), [exit.address, exit.address]);
  assert.deepEqual(run.closed.sort(), ["entry", "entry", "exit", "exit"]);
  assert.deepEqual(await run.profile(review), { configuration: config, filename: "rookstride-pilot-owner.conf" });
});

test("refuses cloned machine IDs and changed review pins before mutation", async () => {
  const same = fixture(undefined, { machines: { entry: "1".repeat(64), exit: "1".repeat(64) } });
  await assert.rejects(same.review(), { code: "same-node", uncertain: false });
  assert.equal(same.calls.filter(({ req }) => Boolean(req)).length, 0);

  const run = fixture();
  const review = await run.review();
  await assert.rejects(
    run.deploy(review, { entry: { ...entry, fingerprint: "SHA256:" + "X".repeat(43) } }),
    { code: "review-mismatch", uncertain: false },
  );
  assert.equal(run.calls.filter(({ req }) => req?.command === "start").length, 0);
});

test("refuses entry DNS state or a local exit resolver before opening the entry", async () => {
  const occupied = fixture((role, mode) => role === "entry" && mode === "probe" ? {
    owner: null, os: "ubuntu", version: "24.04", machine: "1".repeat(64), standaloneDnsPresent: true,
  } : undefined);
  await assert.rejects(occupied.review(), { code: "entry-dns-conflict", uncertain: false });
  assert.ok(occupied.calls.every(({ req }) => !req));

  const localRoute = fixture((role, mode) => role === "entry" && mode === "resolver" ? { local: true } : undefined);
  const review = await localRoute.review();
  await assert.rejects(localRoute.deploy(review), { code: "entry-dns-conflict", uncertain: true });
  assert.ok(!localRoute.calls.some(({ req }) => ["configure", "verify", "activate"].includes(req?.action)));
});

test("fails closed when target preflight, exit DNS, or staged verification fails", async () => {
  const preflight = fixture((role, mode, req) => role === "exit" && req?.command === "preflight" ? { ready: false } : undefined);
  await assert.rejects(preflight.review(), { code: "preflight-rejected", uncertain: false });
  assert.equal(preflight.calls.filter(({ req }) => req?.command === "start").length, 0);

  const dns = fixture((role, mode, req) => role === "exit" && req?.command === "health" ? { services: {} } : undefined);
  await assert.rejects(dns.deploy(await dns.review()), { code: "exit-dns-unavailable", stage: "exit-dns", uncertain: true });
  assert.equal(dns.calls.filter(({ role, req }) => role === "entry" && req?.command === "start").length, 0);

  const verify = fixture((role, mode, req) => req?.action === "verify" ? { job: "1".repeat(32), state: "failed" } : undefined);
  await assert.rejects(verify.deploy(await verify.review()), { code: "step-failed", stage: "verify", uncertain: true });
  assert.equal(verify.calls.filter(({ req }) => req?.action === "activate").length, 0);
});

test("only an explicit original review may resume the owned exit", async () => {
  const run = fixture();
  const review = await run.review();
  run.owners.exit = { pairId: review.pairId, role: "exit", bundle: digest };
  await assert.rejects(run.review(), { code: "occupied" });
  await assert.rejects(run.deploy(review), { code: "resume-required", uncertain: false });
  await assert.rejects(run.deploy({ ...review, pairId: "0".repeat(32) }, { resume: true }), {
    code: "ownership-mismatch", uncertain: false,
  });
  await assert.rejects(run.deploy(review, { resume: true, exit: { ...exit, keyType: "ecdsa-sha2-nistp256" } }), {
    code: "review-mismatch", uncertain: false,
  });
  const result = await run.deploy(review, { resume: true });
  assert.equal(result.state, "installed");
  assert.ok(run.calls.filter(({ req }) => req?.command === "start").every(({ req }) => req.resume === true));
});

test("disconnects both sessions when interrupted and never activates after polling stops", async () => {
  const controller = new AbortController();
  const run = fixture((role, mode, req) => {
    if (role === "exit" && req?.command === "status") controller.abort();
  });
  await assert.rejects(run.deploy(await run.review(), { signal: controller.signal }), {
    code: "interrupted", stage: "exit-bootstrap", uncertain: true,
  });
  assert.equal(run.calls.filter(({ req }) => req?.action === "activate").length, 0);
  assert.equal(run.closed.length, 4);
});

test("rejects executable directives and unowned or redirected configuration downloads", async () => {
  const bad = fixture((role, mode, req) => mode === "management" && req.action === "profile" ? {
    format: "awg", content: config.replace("[Interface]", "[Interface]\nPostUp = unwanted"),
  } : undefined);
  const review = await bad.review();
  await assert.rejects(bad.profile(review), { code: "ownership-mismatch" });
  await bad.deploy(review);
  await assert.rejects(bad.profile(review), { code: "invalid-profile" });
  const redirected = fixture((role, mode, req) => mode === "management" && req.action === "profile" ? {
    format: "awg", content: config.replace(entry.address + ":51820", exit.address + ":51820"),
  } : undefined);
  const otherReview = await redirected.review();
  await redirected.deploy(otherReview);
  await assert.rejects(redirected.profile(otherReview), { code: "invalid-profile" });
});

test("rejects altered endpoints, identities and extra client directives for non-AWG entry profiles", async () => {
  const variants = {
    ikev2: (content) => content.replace('"eap_id":"pilot-owner"', '"eap_id":"wrong-owner"'),
    openvpn: (content) => content.replace("<ca>", "up /tmp/fixture-script\n<ca>"),
    xhttp: (content) => content.replace("#pilot-owner", "&security=reality#pilot-owner"),
    naive: (content) => content.replace('"port":443', '"port":444'),
  };
  for (const [method, mutate] of Object.entries(variants)) {
    const f = fixture((role, mode, req) => {
      if (mode !== "management" || req.action !== "profile") return;
      const profile = nativeProfile(method, req.login);
      return { ...profile, content: mutate(profile.content) };
    });
    const review = await f.review({ entryProtocol: method });
    await f.deploy(review, method === "ikev2" ? { password: "fixture VPN password" } : {});
    await assert.rejects(f.profile(review), { code: "invalid-profile" });
  }
});

test("reopens only matching pinned owned nodes with the original login and stays read-only during outage", async () => {
  const run = fixture((role, mode, req) => role === "exit" && mode === "management" && req.action === "node"
    ? { pairId: req.pair, role, bridge, topologyRevision: 1, healthy: false, dnsHealthy: false }
    : undefined);
  const review = await run.review();
  await assert.rejects(run.adopt(), { code: "ownership-mismatch" });
  await run.deploy(review);
  run.calls.length = 0;
  assert.deepEqual(await run.adopt(), review);
  assert.deepEqual(await run.manage("readPairManagement", review), {
    owner: account, users: [account], revision: initialRevision,
    entryHealthy: true, exitHealthy: false, dnsHealthy: false,
  });
  assert.ok(run.calls.every(({ mode, req }) => mode === "connect" || mode === "probe" || req?.action === "node"));

  run.owners.exit = { ...run.owners.exit, pairId: "d".repeat(32) };
  await assert.rejects(run.adopt(), { code: "ownership-mismatch" });

  const otherBridge = fixture((role, mode, req) => role === "exit" && mode === "management" && req.action === "node"
    ? { pairId: req.pair, role, bridge: "f".repeat(64), topologyRevision: 1, healthy: true, dnsHealthy: true }
    : undefined);
  await otherBridge.deploy(await otherBridge.review());
  await assert.rejects(otherBridge.adopt(), { code: "ownership-mismatch" });
});

test("grant and revoke use reviewed revisions and profiles are scoped to enabled entry accounts", async () => {
  const run = fixture();
  const review = await run.review();
  await run.deploy(review);
  const mutate = (operation, login, revision) => run.manage("changePairAccount", review, { operation, login, revision });
  await assert.rejects(mutate("revoke", account, initialRevision), { code: "account-unavailable", uncertain: false });
  await assert.rejects(mutate("grant", "guest", "b".repeat(64)), { code: "roster-changed", uncertain: false });
  await assert.rejects(run.profile(review, "guest"), { code: "account-unavailable" });
  let roster = await mutate("grant", "guest", initialRevision);
  assert.deepEqual(roster.users, [account, "guest"]);
  assert.notEqual(roster.revision, initialRevision);
  await assert.rejects(mutate("revoke", "guest", initialRevision), { code: "roster-changed", uncertain: false });
  assert.deepEqual(await run.profile(review, "guest"), { configuration: config, filename: "rookstride-guest.conf" });
  roster = await mutate("revoke", "guest", roster.revision);
  assert.deepEqual(roster.users, [account]);
  await assert.rejects(run.profile(review, "guest"), { code: "account-unavailable" });
  assert.deepEqual(run.calls.filter(({ mode, req }) => mode === "management" && ["grant", "revoke"].includes(req.action))
    .map(({ role, req }) => [role, req.action, req.login]), [["entry", "grant", "guest"], ["entry", "revoke", "guest"]]);
});

test("checks both native reset reviews and removes the entry before the exit", async () => {
  const run = fixture();
  const review = await run.review();
  await run.deploy(review);
  const removal = await run.manage("reviewPairRemoval", review);
  await assert.rejects(run.manage("removePair", review, {
    removal: { ...removal, exit: { ...removal.exit, token: "0".repeat(64) } },
  }), { code: "removal-review-stale", uncertain: false });
  assert.equal(run.calls.filter(({ mode, req }) => mode === "reset" && req.action === "apply").length, 0);
  run.calls.length = 0;
  assert.deepEqual(await run.manage("removePair", review, { removal }), { state: "removed" });
  assert.deepEqual(run.calls.filter(({ mode }) => mode === "reset").map(({ role, req }) => [role, req.action]), [
    ["entry", "check"], ["exit", "check"], ["entry", "apply"], ["exit", "apply"],
  ]);
  await assert.rejects(run.adopt(), { code: "ownership-mismatch" });

  const failed = fixture((role, mode, req) => role === "entry" && mode === "reset" && req.action === "apply"
    ? { reset: false, role }
    : undefined);
  const another = await failed.review();
  await failed.deploy(another);
  const failedRemoval = await failed.manage("reviewPairRemoval", another);
  await assert.rejects(failed.manage("removePair", another, { removal: failedRemoval }), {
    code: "removal-unconfirmed", stage: "entry-remove", uncertain: true,
  });
  assert.equal(failed.calls.filter(({ role, mode, req }) => role === "exit" && mode === "reset" && req.action === "apply").length, 0);
});

test("captures an Android pair archive and returns only the redacted rehearsal receipt", async () => {
  const run = fixture();
  const review = await run.review();
  await run.deploy(review);
  const archive = await run.manage("capturePairRecovery", review);
  assert.equal(archive.schema, 1);
  assert.equal(archive.deployment, review.pairId);
  assert.equal(archive.nodes.exit.schema, 2);
  assert.equal(archive.nodes.entry.state.private, "private-snapshot-fixture");
  const receipt = await run.manage("rehearsePairRecovery", review, { archive });
  assert.deepEqual(receipt, {
    readiness_schema: 2, verified: true, deployment: review.pairId, entry_users: 1, exit_users: 1, live_restore_tested: false,
  });
  assert.ok(!JSON.stringify(receipt).includes("private-snapshot-fixture"));
  const stale = { ...archive, revision: archive.revision + 1 };
  await assert.rejects(run.manage("rehearsePairRecovery", review, { archive: stale }), { code: "invalid-recovery" });
  const wrongTopology = structuredClone(archive);
  wrongTopology.nodes.exit.plan.tunnel_port = 1194;
  await assert.rejects(run.manage("rehearsePairRecovery", review, { archive: wrongTopology }), { code: "invalid-recovery" });
  assert.deepEqual(run.calls.filter(({ mode }) => mode === "recovery").map(({ role, req }) => [role, req.action]), [
    ["entry", "export"], ["exit", "export"], ["entry", "rehearse-pair"],
  ]);
});

test("larger SSH limits apply only to recovery export and rehearsal", async () => {
  function ssh(result) {
    const client = new EventEmitter();
    const calls = [];
    client.exec = (command, options, callback) => {
      const channel = new EventEmitter();
      channel.stderr = { resume() {} };
      channel.write = (message) => calls.push(message);
      channel.destroy = () => {};
      channel.end = () => {
        channel.emit("data", Buffer.from(JSON.stringify({ ok: true, result })));
        channel.emit("close", 0);
      };
      callback(null, channel);
    };
    return { client, calls };
  }
  const sample = { body: "x".repeat(70_000) };
  const ordinary = ssh(sample);
  await assert.rejects(executePairRequest(ordinary.client, { request: { command: "health" } }));
  const download = ssh(sample);
  assert.deepEqual(await executePairRequest(download.client, {
    mode: "recovery", request: { action: "export" },
  }), sample);
  const rehearsal = ssh({ verified: true });
  assert.deepEqual(await executePairRequest(rehearsal.client, {
    mode: "recovery", request: { action: "rehearse-pair", archive: sample },
  }), { verified: true });
  const oversized = ssh({ verified: true });
  await assert.rejects(executePairRequest(oversized.client, {
    mode: "recovery", request: { action: "rehearse-pair", archive: { body: "x".repeat(2 * 1024 * 1024) } },
  }));
  assert.equal(oversized.calls.length, 0);
});

test("worker transfer uses the same fixed SSH input with the exact reviewed topology and raw archive", async () => {
  const client = new EventEmitter();
  const payload = [];
  client.exec = (command, options, callback) => {
    assert.match(command, /^\/usr\/bin\/python3 -I -B -c /);
    const channel = new EventEmitter();
    channel.stderr = { resume() {} };
    channel.write = (part) => payload.push(part);
    channel.end = () => {
      channel.emit("data", Buffer.from('{"ready":true}'));
      channel.emit("close", 0);
    };
    callback(null, channel);
  };
  const topology = {
    pair: "b".repeat(32), role: "exit", engine: "native-v2", entry_protocol: "xray", exit_protocol: "trusttunnel",
    server: entry.address, exit_host: exit.address, vpn_port: 443, tunnel_port: 443,
  };
  const archive = Buffer.from([0, 255, 13, 10, 4]);
  const routePins = Buffer.from("fixture route pins");
  assert.deepEqual(await executePairRuntime(client, { topology, architecture: "aarch64", routePins, archive }), { ready: true });
  assert.equal(payload.length, 2);
  const [, header] = payload[0].split("\n");
  assert.deepEqual(JSON.parse(header), {
    action: "pairRuntime", address: exit.address, topology,
    runtimeArchitecture: "aarch64", routesPins: routePins.toString("base64"),
  });
  assert.deepEqual(payload[1], archive);
});

test("the remote account handler binds the update to the current roster under the native locks", () => {
  const wrapper = fileURLToPath(new URL("../scripts/pair_remote.py", import.meta.url));
  const project = fileURLToPath(new URL("../../", import.meta.url));
  const result = spawnSync("python3", [
    "-B", "-c", `
import json, runpy, sys, tempfile
from pathlib import Path
from unittest.mock import patch

project = Path(sys.argv[1])
sys.path[:0] = [str(project / 'server'), str(project / 'single')]
import lifecycle, native_pair, pair, run as single_api
wrapper = runpy.run_path(sys.argv[2])
manage = wrapper['manage']
scope = manage.__globals__
request = {'pair':'a'*32, 'role':'entry', 'server':'192.0.2.21', 'exit_host':'198.51.100.22',
           'engine':'native-v2', 'entry_protocol':'awg', 'exit_protocol':'awg',
           'vpn_port':51820, 'tunnel_port':443}
plan = pair.plan(request)
expected = 'c'*64
manifest = {'plan':plan, 'version':2, 'bundle':expected, 'verified':True, 'first_activated_at':1,
            'jobs':{'bootstrap':'1'*32, 'configure':'2'*32}}
transport = {'dns':{'address':'10.253.0.1', 'dns_port':53}}
state = {'protocol':'awg', 'users':[{'login':'owner'}], 'initialLogin':'owner', 'instance':'b'*32,
         'pair':request['pair'], 'server':request['server'], 'port':51820, 'pair_dns':transport['dns']}
view = {'read_only':False, 'active':True, 'bundle':expected, 'plan':plan, 'revision':1}
def apply(change):
    assert change == {'action':'add-user', 'protocol':'awg', 'login':'guest'}
    state['users'].append({'login':'guest'})
    return {'login':'guest'}

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / 'initial-user.json').write_text(json.dumps({'login':'owner'}))
    (root / 'transport.json').write_text(json.dumps(transport))
    with patch.dict(scope, {'RELEASE':project, 'MANAGEMENT_LOCKS':[root / name for name in ('shared', 'lifecycle', 'pair')],
                            'owned':lambda:manifest, 'protected':lambda path:path, 'installed_digest':lambda value:None}), \\
         patch.object(pair, 'OWN', root), patch.object(lifecycle, 'inspect', return_value=view), \\
         patch.object(lifecycle, 'route_override', return_value=None), patch.object(lifecycle, 'records', return_value=[]), \\
         patch.object(lifecycle, 'read', return_value={'state':'complete'}), \\
         patch.object(native_pair, 'validate_material'), patch.object(native_pair.filtering, 'exists', return_value=False), \\
         patch.object(native_pair.runtime, 'load', return_value=state), patch.object(single_api, 'action', side_effect=apply) as action:
        change = dict(request, action='grant', login='guest', revision='0'*64)
        try:
            manage('management', change, expected)
            raise AssertionError('accepted stale roster')
        except wrapper['PairRejected'] as error:
            assert str(error) == 'roster-changed'
        action.assert_not_called()
        change['revision'] = lifecycle.digest({'pair':request['pair'], 'instance':state['instance'], 'users':state['users']})
        response = manage('management', change, expected)
        assert response['users'] == ['guest', 'owner']
        assert response['revision'] != change['revision']
        action.assert_called_once()
`, project, wrapper,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

async function capturedArchive() {
  const original = fixture();
  const review = await original.review();
  await original.deploy(review);
  return original.manage("capturePairRecovery", review);
}

test("restore stages each original identity in the Android order before opening forwarding", async () => {
  const archive = await capturedArchive();
  const rebuilt = fixture(undefined, { machines: { entry: "7".repeat(64), exit: "8".repeat(64) } });
  const result = await rebuilt.restore(archive);
  assert.equal(result.state, "restored");
  assert.equal(result.pairId, archive.deployment);
  assert.equal(result.exitIp, exit.address);
  assert.equal(result.revision, 2);
  assert.equal(result.review.entry.machine, "7".repeat(64));
  assert.equal(result.review.login, account);
  assert.deepEqual(result.usageGenerations, replacementGeneration);
  assert.deepEqual(rebuilt.stages, pairRestoreStages);
  const writes = rebuilt.calls.filter(({ mode, req }) =>
    req?.command === "start" || mode === "restore" && ["identity", "revision"].includes(req?.action));
  assert.deepEqual(writes.map(({ role, req }) => [role, req.action]), [
    ["exit", "bootstrap"], ["exit", "identity"], ["exit", "configure"],
    ["entry", "bootstrap"], ["entry", "configure"], ["entry", "identity"],
    ["entry", "verify"], ["entry", "activate"], ["entry", "revision"], ["exit", "revision"],
  ]);
  const bootstrap = writes.find(({ role, req }) => role === "entry" && req.action === "bootstrap");
  assert.equal(bootstrap.req.password, archive.nodes.entry.initial_user.password);
  assert.equal(bootstrap.req.statistics, true);
  for (const { req } of writes.filter(({ req }) => ["verify", "activate"].includes(req.action))) {
    assert.equal(req.expected_exit_ip, exit.address);
    assert.equal(req.filtering_enabled, false);
    assert.equal(req.repeat, undefined);
  }
  const validate = rebuilt.calls.find(({ mode, req }) => mode === "restore" && req.action === "validate");
  assert.equal(validate.role, "entry");
  assert.equal(validate.archive, true);
  assert.ok(rebuilt.calls.indexOf(validate) < rebuilt.calls.indexOf(writes[0]));
  assert.ok(!JSON.stringify(result).includes("fixture-owner-recovery-password"));
});

test("restore checks the original archive digest before touching either new host", async () => {
  const archive = await capturedArchive();
  const rebuilt = fixture();
  const reordered = Object.fromEntries(Object.entries(archive).reverse());
  assert.equal(pairArchiveDigest(reordered), pairArchiveDigest(archive));
  const changed = structuredClone(archive);
  changed.nodes.entry.state.private = "changed-fixture";
  await assert.rejects(rebuilt.restore(changed, { archiveDigest: pairArchiveDigest(archive) }),
    { code: "invalid-recovery", stage: "preflight", uncertain: false });
  assert.equal(rebuilt.calls.length, 0);
  const untrusted = fixture((role, mode, req) => mode === "restore" && req.action === "validate"
    ? { verified: false } : undefined);
  await assert.rejects(untrusted.restore(archive), { code: "invalid-recovery", uncertain: false });
  assert.equal(untrusted.calls.some(({ req }) => req?.action === "enroll" || req?.command === "start"), false);
});

test("restore requires explicit same-operation resume and does not restart completed native jobs", async () => {
  const archive = await capturedArchive();
  let interrupt = true;
  const rebuilt = fixture((role, mode, req) => {
    if (interrupt && role === "entry" && mode === "restore" && req.action === "identity") {
      interrupt = false;
      return Promise.reject(new Error("interrupted fixture"));
    }
  });
  await assert.rejects(rebuilt.restore(archive), { stage: "entry-identity", uncertain: true });
  await assert.rejects(rebuilt.restore(archive), { code: "restore-resume-required", uncertain: false });
  await assert.rejects(rebuilt.restore(archive, { operation: "9".repeat(32), resume: true }),
    { code: "restore-ownership-mismatch", uncertain: false });
  rebuilt.calls.length = 0;
  const result = await rebuilt.restore(archive, { resume: true });
  assert.equal(result.state, "restored");
  assert.deepEqual(rebuilt.calls.filter(({ req }) => req?.command === "start").map(({ req }) => req.action), ["verify", "activate"]);
  rebuilt.calls.length = 0;
  assert.deepEqual(await rebuilt.restore(archive, { resume: true }), result);
  assert.equal(rebuilt.calls.some(({ req }) => req?.command === "start" || req?.action === "enroll"), false);
});

test("failed restored verification leaves entry forwarding guarded", async () => {
  const archive = await capturedArchive();
  const rebuilt = fixture((role, mode, req) => req?.command === "start" && req.action === "verify"
    ? { state: "failed", job: "1".repeat(32) } : undefined);
  await assert.rejects(rebuilt.restore(archive), { stage: "verify", code: "step-failed", uncertain: true });
  assert.equal(rebuilt.calls.some(({ req }) => ["activate", "revision"].includes(req?.action)), false);
});

const recoveryFixtureImports = `
import subprocess
sys.path[:0] = [str(project / 'server'), str(project / 'tests')]
import recovery

# macOS LibreSSL cannot read this DER key type. In that environment use Node's
# X25519 primitive while retaining the pinned Python schema and matching checks.
def fixture_public(secret):
    command = '''
        const { createPrivateKey, createPublicKey } = require('node:crypto');
        const { readFileSync } = require('node:fs');
        const key = createPrivateKey({
          key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), readFileSync(0)]),
          format: 'der', type: 'pkcs8'
        });
        process.stdout.write(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32));
    '''
    return subprocess.run([sys.argv[3], '-e', command], input=secret, capture_output=True, check=True).stdout
try:
    recovery.adapters.derived_public(bytes(range(32)))
except ValueError:
    recovery.adapters.derived_public = fixture_public

def use_browser_addresses(node):
    node['plan'].update(server='192.0.2.21', exit_host='198.51.100.22')
    node['state']['server'] = node['plan']['server' if node['role']=='entry' else 'exit_host']
    if node['transport']:
        node['transport']['endpoint'] = node['plan']['exit_host']
        profile = node['transport']['profile']
        profile['content'] = profile['content'].replace('exit.example.net', node['plan']['exit_host'])
`;

test("fresh remote archive validation uses the native cryptographic checks", async () => {
  const { digest, archive } = await loadPairRecipe();
  const wrapper = fileURLToPath(new URL("../scripts/pair_remote.py", import.meta.url));
  const project = fileURLToPath(new URL("../../", import.meta.url));
  const result = spawnSync("python3", [
    "-B", "-c", `
import io, runpy, sys
from pathlib import Path
project = Path(sys.argv[1])
${recoveryFixtureImports}
from test_owner_recovery import archive as synthetic_archive

wrapper = runpy.run_path(sys.argv[2])
archive = synthetic_archive()
archive.update(revision=1, created=1)
for node in archive['nodes'].values():
    use_browser_addresses(node)
    node.update(schema=2, identity_files={}, adapter='awg-identity-v1')
request = dict(archive['nodes']['entry']['plan'], revision=2, archive=archive)
recipe = sys.stdin.buffer.read()
outcome = wrapper['validate_restore_archive'](io.BytesIO(recipe), request, sys.argv[4])
assert outcome['verified'] is True and outcome['entry_users'] == outcome['exit_users'] == 1
archive['nodes']['exit']['state']['users'][0]['psk'] = 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='
try:
    wrapper['validate_restore_archive'](io.BytesIO(recipe), request, sys.argv[4])
    raise AssertionError('accepted an archive with a mismatched bridge secret')
except wrapper['PairRejected'] as error:
    assert str(error) == 'invalid-recovery'
`, project, wrapper, process.execPath, digest,
  ], { input: archive, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("native complete restore receipts reconcile without replaying identity writes", () => {
  const wrapper = fileURLToPath(new URL("../scripts/pair_remote.py", import.meta.url));
  const project = fileURLToPath(new URL("../../", import.meta.url));
  const result = spawnSync("python3", [
    "-B", "-c", `
import copy, io, json, runpy, sys, tempfile
from pathlib import Path
from unittest.mock import patch
project = Path(sys.argv[1])
${recoveryFixtureImports}
from test_owner_recovery import lifecycle, native_pair, pair, recovery, snapshot as synthetic_snapshot

wrapper = runpy.run_path(sys.argv[2])
operate = wrapper['restore_operation']
snapshot = synthetic_snapshot()
use_browser_addresses(snapshot)
snapshot.update(schema=2, identity_files={}, adapter='awg-identity-v1')
state = copy.deepcopy(snapshot['state'])
state['instance'] = 'e'*32
plan = snapshot['plan']
expected = 'c'*64
jobs = {'bootstrap':'1'*32, 'configure':'2'*32}
manifest = None

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    binding = dict(plan, operation='9'*32, archiveDigest='2'*64, revision=2)
    def request(action, **fields):
        return operate(io.BytesIO(), dict(binding, action=action, **fields), expected)
    with patch.dict(operate.__globals__, {
            'RELEASE': project, 'RESTORE_OPERATION': root/'lifecycle'/'operation.json',
            'MANAGEMENT_LOCKS': [root / name for name in ('shared', 'lifecycle.lock', 'pair')],
            'owned': lambda:manifest, 'protected': lambda path:path, 'installed_digest': lambda value:None,
    }), patch.object(lifecycle, 'ROOT', root/'lifecycle'), patch.object(pair, 'STATE', root/'jobs'), \\
            patch.object(pair, 'protected', side_effect=lambda p:Path(p)), \\
            patch.object(native_pair.runtime, 'load', return_value=state), \\
            patch.object(native_pair.runtime, 'health', return_value={'running':True}), \\
            patch.object(recovery, 'dispatch') as replay:
        assert request('inspect') == {'recorded':False, 'jobs':{}}
        assert request('enroll') == {'recorded':True}
        manifest = {'bundle':expected, 'version':2, 'plan':plan, 'jobs':jobs, 'configured':True, 'activated':True}
        for job in jobs.values():
            status = pair.STATE / job / 'status.json'
            status.parent.mkdir(parents=True)
            status.write_text(json.dumps({'state':'complete'}))
        receipt = lifecycle.ROOT / 'restores' / 'entry.json'
        identity = lifecycle.digest({'snapshot':snapshot,'new_endpoint':None})
        record = {'snapshot':identity,'state':'restoring','generation':state['instance']}
        lifecycle.write(receipt, record)
        try:
            request('identity', snapshot=snapshot, resume=False)
            raise AssertionError('implicitly replayed an interrupted identity')
        except wrapper['PairRejected'] as error:
            assert str(error) == 'restore-resume-required'
        record.update(state='complete', restored_identity=recovery.restored_identity(state))
        lifecycle.write(receipt, record)
        assert request('identity', snapshot=snapshot, resume=True) == {
            'restored':True,'usage_generation':state['instance'],'users':1,
        }
        state['users'][0]['enabled'] = False
        try:
            request('identity', snapshot=snapshot, resume=True)
            raise AssertionError('accepted changed identity after completed restoration')
        except wrapper['PairRejected'] as error:
            assert str(error) == 'restore-ownership-mismatch'
        replay.assert_not_called()
`, project, wrapper, process.execPath,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
