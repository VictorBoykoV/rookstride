import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createPairRebuild,
  pairRebuildConfirmation,
  readPairRebuildInput,
} from "../src/lib/pair-rebuild.mjs";
import { encryptPairRecovery } from "../src/lib/pair-recovery.mjs";

const entry = {
  address: "192.0.2.10",
  sshPort: 22,
  fingerprint: "SHA256:" + "A".repeat(43),
  keyType: "ecdsa-sha2-nistp256",
  machine: "1".repeat(64),
};
const exit = {
  address: "198.51.100.20",
  sshPort: 22,
  fingerprint: "SHA256:" + "B".repeat(43),
  machine: "2".repeat(64),
};
const review = {
  version: 1,
  pairId: "a".repeat(32),
  login: "owner",
  bundle: "f".repeat(64),
  entry,
  exit,
};
const passphrase = "fixture archive password";
const ubuntu = { entry: "24.04", exit: "26.04" };
const targets = {
  entry: { ...entry, password: "fixture entry password" },
  exit: { ...exit, password: "fixture exit password" },
};
const approval = "c".repeat(64);
const plan = {
  pair: review.pairId,
  server: entry.address,
  exit_host: exit.address,
  vpn_port: 51820,
  tunnel_port: 443,
  entry_protocol: "awg",
  exit_protocol: "awg",
  engine: "native-v2",
  client_pool: "10.66.0.0/24",
  test_ip: "10.249.255.254",
  entry_address: "10.253.0.2/30",
  exit_address: "10.253.0.1/30",
  route_table: 51831,
};
const archive = {
  schema: 1,
  purpose: "rookstride-owner-recovery",
  deployment: review.pairId,
  revision: 1,
  created: 42,
  nodes: Object.fromEntries(
    [
      ["entry", "owner"],
      ["exit", "bridge-aaaaaaaaaaaa"],
    ].map(([role, login]) => [
      role,
      {
        schema: 2,
        purpose: "rookstride-owner-recovery-node",
        deployment: review.pairId,
        role,
        adapter: "awg-identity-v1",
        state: { protocol: "awg", initialLogin: login },
        initial_user: { login, password: "fixture only" },
        plan: { ...plan, role },
      },
    ]),
  ),
};

async function fixture(t, entryProtocol) {
  const directory = await mkdtemp(
    join(tmpdir(), "rookstride-pair-rebuild-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const original = entryProtocol ? { ...review, entryProtocol, exitProtocol: "openvpn" } : review;
  const approvedArchive = structuredClone(archive);
  if (entryProtocol) {
    for (const [role, node] of Object.entries(approvedArchive.nodes)) {
      const protocol = role === "entry" ? entryProtocol : "openvpn";
      Object.assign(node.plan, { vpn_port: 443, entry_protocol: entryProtocol, tunnel_port: 1194, exit_protocol: "openvpn" });
      Object.assign(node.state, { protocol, server: original[role].address, port: role === "entry" ? 443 : 1194 });
      node.adapter = protocol + "-identity-v1";
    }
  }
  const encrypted = await encryptPairRecovery(approvedArchive, passphrase, original);
  const calls = [];
  const states = { exit: "complete", entry: "complete" };
  const machines = { exit: "e".repeat(64), entry: "d".repeat(64) };
  const restore = { failures: 0 };
  const denials = {};
  const live = structuredClone(approvedArchive);
  live.created++;
  const replacements = {
    entry: "SHA256:" + "C".repeat(43),
    exit: "SHA256:" + "D".repeat(43),
  };
  const jobs = { entry: "3".repeat(32), exit: "4".repeat(32) };
  const file = (name) => join(directory, name + ".json");
  const issued = async (role) =>
    JSON.parse(await readFile(file(role + "-issued"), "utf8"));
  const runtime = {
    async adoptPair() {
      calls.push("adopt");
      return original;
    },
    async rehearsePairRecovery() {
      calls.push("rehearse");
      return { verified: true, readiness_schema: 2 };
    },
    async reviewPairRestoreRuntime({ review }) {
      assert.deepEqual(review, original);
      calls.push("runtime-check");
      if (restore.runtimeMissing) throw new Error("runtime-unavailable");
    },
    async capturePairRecovery() {
      return live;
    },
    pairArchiveDigest(value) {
      return createHash("sha256").update(JSON.stringify(value)).digest("hex");
    },
    async restorePair(input) {
      const { entry: first, exit: second } = input;
      assert.equal(first.fingerprint, replacements.entry);
      assert.equal(second.fingerprint, replacements.exit);
      assert.equal(first.keyType, "ecdsa-sha2-nistp256");
      assert.equal(second.keyType, "ecdsa-sha2-nistp256");
      assert.deepEqual(input.archive, approvedArchive);
      assert.equal(input.expectedBundle, review.bundle);
      calls.push(input.resume ? "restore:resume" : "restore");
      if (restore.failures-- > 0)
        throw new Error("interrupted identity restore");
      const result = {
        state: "restored",
        pairId: review.pairId,
        review: {
          ...original,
          entry: {
            ...entry,
            fingerprint: replacements.entry,
            ubuntu: ubuntu.entry,
          },
          exit: {
            ...exit,
            fingerprint: replacements.exit,
            keyType: second.keyType,
            ubuntu: ubuntu.exit,
          },
        },
      };
      if (restore.wrongKind) delete result.review[restore.wrongKind];
      return result;
    },
  };

  const openWorker = () => ({
    async request(input) {
      const role =
        input.role ??
        (input.server?.address === exit.address ? "exit" : "entry");
      switch (input.action) {
        case "inspect":
          return { state: "ready" };
        case "pairUbuntuReview":
          calls.push("review:" + role);
          assert.match(input.snapshot, /^[a-f0-9]{64}$/);
          return {
            token: approval,
            job: jobs[role],
            fingerprint: replacements[role],
            ubuntu: ubuntu[role],
            diskBytes: 32 * 1024 ** 3,
            boot: "BIOS",
            machine: machines[role],
          };
        case "pairUbuntuPlan":
          calls.push("plan:" + role);
          assert.equal(input.fingerprint, replacements[role]);
          assert.equal(input.ubuntu, ubuntu[role]);
          return { token: approval };
        case "pairUbuntuApply":
          calls.push("erase:" + role);
          assert.equal(input.token, approval);
          assert.deepEqual(await issued(role), {
            operation: input.operation,
            job: input.job,
          });
          if (denials[role])
            return { state: "conflict", reason: denials[role] };
          throw new Error("installer disconnected");
        case "ubuntuResume":
          calls.push("poll:" + role);
          assert.equal(input.fingerprint, replacements[role]);
          assert.equal(input.job, jobs[role]);
          return { state: states[role] };
        default:
          assert.fail(input.action);
      }
    },
    stop() {},
  });
  const coordinator = () =>
    createPairRebuild({
      directory,
      runtime,
      eligible: () => true,
      openWorker,
      loadRecipe: async () => ({ digest: review.bundle }),
    });
  const inputs = { targets, encrypted, passphrase };
  return {
    coordinator,
    file,
    states,
    machines,
    calls,
    restore,
    denials,
    live,
    inputs,
    issued,
    stage: () => coordinator().review({ ...inputs, ubuntu }),
    run: (options = {}) =>
      coordinator().run({
        ...inputs,
        confirmation: pairRebuildConfirmation,
        ...options,
      }),
  };
}

test("review and interrupted paired reboot use the original jobs and both new SSH pins", async (t) => {
  const f = await fixture(t);
  const review = await f.stage();
  const content = await readFile(f.file("operation"), "utf8");
  assert.equal(content.includes("password"), false);
  assert.equal(content.includes(approval), false);
  assert.equal(content.includes("fixture only"), false);
  assert.deepEqual(f.calls, [
    "adopt",
    "rehearse",
    "review:exit",
    "review:entry",
  ]);
  assert.deepEqual(await f.run({ pauseAfterDispatch: true }), {
    state: "waiting",
    role: "exit",
  });
  assert.equal((await f.issued("exit")).operation, review.operation);
  await assert.rejects(f.issued("entry"), { code: "ENOENT" });
  assert.equal((await f.run()).state, "restored");
  assert.equal((await f.run()).state, "restored");
  assert.deepEqual(f.calls.slice(4), [
    "rehearse",
    "plan:exit",
    "erase:exit",
    "poll:exit",
    "plan:entry",
    "erase:entry",
    "poll:entry",
    "restore",
  ]);
});

test("unexpected exit identity prevents entry dispatch", async (t) => {
  const f = await fixture(t);
  await f.stage();
  f.states.exit = "keyMismatch";
  await assert.rejects(f.run(), { code: "ubuntu-keyMismatch", role: "exit" });
  await assert.rejects(f.run(), { code: "ubuntu-keyMismatch", role: "exit" });
  assert.equal(f.calls.filter((value) => value === "erase:exit").length, 1);
  assert.equal(f.calls.includes("plan:entry"), false);
});

test("a rejected approval, different archive, unknown original key or same machine never dispatches", async (t) => {
  const f = await fixture(t);
  f.machines.entry = f.machines.exit;
  await assert.rejects(f.stage(), { code: "invalid-journal" });
  f.machines.entry = "d".repeat(64);
  await f.stage();
  await assert.rejects(f.run({ confirmation: "yes" }), {
    code: "explicit-rebuild-approval-required",
  });
  const changed = Buffer.from(f.inputs.encrypted);
  changed[changed.length - 1] ^= 1;
  await assert.rejects(f.run({ encrypted: changed }), {
    code: "reviewed-archive-required",
  });
  await assert.rejects(
    f.run({
      targets: {
        ...targets,
        entry: {
          ...entry,
          fingerprint: exit.fingerprint,
          password: targets.entry.password,
        },
      },
    }),
    { code: "invalid-target-authority", role: "entry" },
  );
  assert.equal(
    f.calls.some((value) => value.startsWith("erase:")),
    false,
  );
});

test("explicit restore resume rechecks both returned installations without another erase", async (t) => {
  const f = await fixture(t);
  await f.stage();
  f.restore.failures = 1;
  await assert.rejects(f.run(), /interrupted identity restore/);
  await assert.rejects(f.run(), { code: "restore-review-in-progress" });
  assert.equal((await f.run({ resumeRestore: true })).state, "restored");
  assert.equal(f.calls.filter((value) => value.startsWith("erase:")).length, 2);
  assert.deepEqual(f.calls.slice(-3), [
    "poll:exit",
    "poll:entry",
    "restore:resume",
  ]);
});

test("an archive with stale account data is blocked before review and dispatch", async (t) => {
  const f = await fixture(t);
  f.live.nodes.entry.state.users = [];
  await assert.rejects(f.stage(), {
    code: "current-recovery-archive-required",
  });
  delete f.live.nodes.entry.state.users;
  await f.stage();
  f.live.nodes.entry.state.users = [];
  await assert.rejects(f.run(), { code: "current-recovery-archive-required" });
  assert.equal(
    f.calls.some((value) => value.startsWith("erase:")),
    false,
  );
});

test("a changed entry identity under the native erase lock stops immediately and remains denied", async (t) => {
  const f = await fixture(t);
  await f.stage();
  f.denials.entry = "pair-snapshot-changed";
  await assert.rejects(f.run(), {
    code: "pair-snapshot-changed",
    role: "entry",
  });
  await assert.rejects(f.run(), {
    code: "pair-snapshot-changed",
    role: "entry",
  });
  assert.equal(f.calls.filter((value) => value === "erase:entry").length, 1);
  assert.equal(f.calls.includes("poll:entry"), false);
  assert.equal(f.calls.includes("restore"), false);
});

test("archive and target credential input refuses a publicly readable file", async (t) => {
  const f = await fixture(t);
  await writeFile(f.file("public"), "test", { mode: 0o644 });
  assert.throws(() => readPairRebuildInput(f.file("public")), {
    code: "invalid-private-file",
  });
});

test("a mixed rebuild preserves both reviewed methods in the operation and restored receipt", async (t) => {
  const f = await fixture(t, "xhttp");
  const review = await f.stage();
  assert.equal(review.review.entryProtocol, "xhttp");
  assert.equal(review.review.exitProtocol, "openvpn");
  assert.equal(f.coordinator().journalStatus().record.review.exitProtocol, "openvpn");
  f.restore.wrongKind = "entryProtocol";
  await assert.rejects(f.run(), { code: "restore-identity-unverified" });
  assert.equal(f.coordinator().journalStatus().restored, null);
  f.restore.wrongKind = false;
  const receipt = await f.run({ resumeRestore: true });
  assert.equal(receipt.review.entryProtocol, "xhttp");
  assert.equal(receipt.review.exitProtocol, "openvpn");
  assert.equal(f.coordinator().journalStatus().restored.review.exitProtocol, "openvpn");
  assert.deepEqual(f.calls.filter((call) => call.startsWith("erase:")), ["erase:exit", "erase:entry"]);
});

test("a worker route requires restore assets both in review and before first erase", async (t) => {
  const f = await fixture(t, "trusttunnel");
  f.restore.runtimeMissing = true;
  await assert.rejects(f.stage(), /runtime-unavailable/);
  assert.ok(!f.calls.some((call) => call.startsWith("review:")));
  f.restore.runtimeMissing = false;
  await f.stage();
  f.restore.runtimeMissing = true;
  await assert.rejects(f.run(), /runtime-unavailable/);
  assert.ok(!f.calls.some((call) => call.startsWith("erase:")));
});
