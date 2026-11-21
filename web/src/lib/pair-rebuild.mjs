import { createHash, randomBytes } from "node:crypto";
import {
  constants,
  closeSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { loadPairRecipe } from "../../scripts/pair-ssh.mjs";
import { publicDestination, startWorker } from "./gateway-service.mjs";
import {
  isMixedPairExit,
  readServerRecord,
  readUbuntuRecovery,
  ubuntuEraseConfirmation,
  ubuntuVersions,
} from "./gateway-input.mjs";
import { replacementServer } from "./hosted-ubuntu.mjs";
import { decryptPairRecovery, maxPairRecoveryBytes } from "./pair-recovery.mjs";
import * as pairRuntime from "./pair-deployment.mjs";

export const pairRebuildConfirmation =
  "REBUILD BOTH SERVERS AND RESTORE DOUBLE VPN";
const order = ["exit", "entry"];
const operationId = /^[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const loginPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/;
const receiptLimit = 16 * 1024;
const timeoutMs = 30 * 60_000;

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// The native export timestamps are the only fields that change just by
// reading the backup. All revoked or changed account keys stay covered.
function nodeIdentity({ created: _exported, ...node }) {
  return node;
}

export class PairRebuildError extends Error {
  constructor(code, role) {
    super(code);
    this.code = code;
    this.role = role;
  }
}

function privateDirectory(directory) {
  if (!isAbsolute(directory))
    throw new PairRebuildError("invalid-journal-directory");
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.uid !== process.getuid() || info.mode & 0o077)
    throw new PairRebuildError("invalid-journal-directory");
}

function privateBytes(path, limit, linkedJournal = false) {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o077 ||
      stat.nlink > (linkedJournal ? 2 : 1) ||
      stat.size > limit
    )
      throw new PairRebuildError("invalid-private-file");
    const buffer = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, used);
      if (!count) break;
      used += count;
    }
    if (!used || used !== stat.size)
      throw new PairRebuildError("invalid-private-file");
    return buffer.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

function journal(directory) {
  privateDirectory(directory);
  function read(name) {
    try {
      return JSON.parse(
        privateBytes(
          join(directory, name + ".json"),
          receiptLimit,
          true,
        ).toString("utf8"),
      );
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  }
  function write(name, value) {
    const scratch = join(
      directory,
      "." + randomBytes(16).toString("hex") + ".tmp",
    );
    const file = openSync(scratch, "wx", 0o600);
    try {
      try {
        writeFileSync(file, JSON.stringify(value) + "\n");
        fsyncSync(file);
      } finally {
        closeSync(file);
      }
      try {
        linkSync(scratch, join(directory, name + ".json"));
      } catch (error) {
        if (error.code === "EEXIST") return false;
        throw error;
      }
    } finally {
      unlinkSync(scratch);
      const parent = openSync(
        directory,
        constants.O_RDONLY | constants.O_DIRECTORY,
      );
      try {
        fsyncSync(parent);
      } finally {
        closeSync(parent);
      }
    }
    return true;
  }
  return { read, write };
}

function serverFrom(node) {
  const { address, sshPort, fingerprint, keyType } = node ?? {};
  if (
    keyType !== undefined &&
    !["ssh-ed25519", "ecdsa-sha2-nistp256"].includes(keyType)
  )
    return null;
  return readServerRecord(
    keyType === "ecdsa-sha2-nistp256"
      ? { version: 2, address, sshPort, fingerprint, keyType }
      : { version: 1, address, sshPort, fingerprint },
  );
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function matchingTargets(targets, review, eligible) {
  for (const role of order) {
    const input = targets?.[role];
    const server = serverFrom(input);
    if (
      !server ||
      !eligible(server.address) ||
      !same(server, serverFrom(review[role])) ||
      typeof input.password !== "string" ||
      !input.password ||
      Buffer.byteLength(input.password) > 512 ||
      /[\0\r\n]/.test(input.password)
    )
      throw new PairRebuildError("invalid-target-authority", role);
  }
}

function checkedMember(server, reply) {
  const recovery = readUbuntuRecovery({
    job: reply?.job,
    ubuntu: reply?.ubuntu,
    fingerprint: reply?.fingerprint,
    server,
  });
  if (
    !recovery ||
    !Number.isSafeInteger(reply.diskBytes) ||
    reply.diskBytes < 6 * 1024 ** 3 ||
    !["BIOS", "EFI"].includes(reply.boot) ||
    !digestPattern.test(reply.machine ?? "")
  )
    throw new PairRebuildError("invalid-ubuntu-review");
  return {
    ...recovery,
    diskBytes: reply.diskBytes,
    boot: reply.boot,
    machine: reply.machine,
  };
}

function checkedOperation(record, eligible) {
  const {
    version,
    operation,
    review,
    members,
    archiveDigest,
    encryptedDigest,
  } = record ?? {};
  if (
    version !== 1 ||
    !operationId.test(operation ?? "") ||
    review?.version !== 1 ||
    !operationId.test(review.pairId ?? "") ||
    (review.exitProtocol !== undefined && !isMixedPairExit(review.exitProtocol)) ||
    !digestPattern.test(review.bundle ?? "") ||
    !loginPattern.test(review.login ?? "") ||
    !digestPattern.test(archiveDigest ?? "") ||
    !digestPattern.test(encryptedDigest ?? "") ||
    review.entry?.machine === review.exit?.machine
  )
    throw new PairRebuildError("invalid-journal");
  for (const role of order) {
    const server = serverFrom(review[role]);
    if (
      !server ||
      !eligible(server.address) ||
      !digestPattern.test(review[role].machine ?? "") ||
      !same(checkedMember(server, members?.[role]), members[role])
    )
      throw new PairRebuildError("invalid-journal", role);
  }
  if (
    review.entry.address === review.exit.address ||
    members.entry.machine === members.exit.machine ||
    members.entry.fingerprint === members.exit.fingerprint ||
    members.entry.job === members.exit.job ||
    [review.entry.fingerprint, review.exit.fingerprint].some(
      (pin) =>
        pin === members.entry.fingerprint || pin === members.exit.fingerprint,
    )
  )
    throw new PairRebuildError("invalid-journal");
  return record;
}

function recoveryOf(member) {
  const { job, ubuntu, fingerprint, server } = member;
  return { job, ubuntu, fingerprint, server };
}

function matchesRestoredReview(record, review) {
  return (
    review?.version === 1 &&
    review.pairId === record.review.pairId &&
    review.bundle === record.review.bundle &&
    review.exitProtocol === record.review.exitProtocol &&
    review.login === record.review.login &&
    review.entry?.machine !== review.exit?.machine &&
    order.every(
      (role) =>
        digestPattern.test(review[role]?.machine ?? "") &&
        same(
          serverFrom(review[role]),
          replacementServer(record.members[role]),
        ) &&
        review[role].ubuntu === record.members[role].ubuntu,
    )
  );
}

function matchesOriginalReview(original, expected) {
  return ["version", "pairId", "bundle", "login", "exitProtocol"].every((field) => original[field] === expected[field]) &&
    order.every((role) =>
      same(serverFrom(original[role]), serverFrom(expected[role])) &&
      original[role]?.machine === expected[role]?.machine &&
      original[role]?.ubuntu === expected[role]?.ubuntu);
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

export function readPairRebuildInput(path, limit = receiptLimit) {
  if (!isAbsolute(path)) throw new PairRebuildError("invalid-private-file");
  return privateBytes(path, limit);
}

export function createPairRebuild({
  directory,
  openWorker = () => startWorker({ reinstall: true }),
  runtime = pairRuntime,
  loadRecipe = loadPairRecipe,
  eligible = publicDestination,
  wait = () => sleep(6000),
  clock = Date.now,
  isAlive = alive,
}) {
  const store = journal(directory);

  function loaded() {
    return checkedOperation(store.read("operation"), eligible);
  }

  function proof(name, record, role) {
    const value = store.read(name);
    if (!value) return false;
    if (
      value.operation !== record.operation ||
      value.job !== record.members[role].job
    )
      throw new PairRebuildError("journal-receipt-mismatch", role);
    return value;
  }

  function journalStatus() {
    const saved = store.read("operation");
    if (!saved) return null;
    const record = checkedOperation(saved, eligible);
    const restored = store.read("restored");
    if (restored && (
      restored.operation !== record.operation || restored.state !== "restored" ||
      restored.pairId !== record.review.pairId || !matchesRestoredReview(record, restored.review)
    )) throw new PairRebuildError("journal-receipt-mismatch");
    const started = order.some((role) => Boolean(proof(role + "-issued", record, role)));
    return { record, started, restored };
  }

  function rejectDenied(record, role) {
    const denial = proof(role + "-denied", record, role);
    if (!denial) return;
    const { reason } = denial;
    throw new PairRebuildError(
      reason === "pair-snapshot-changed" ? reason : "ubuntu-apply-rejected",
      role,
    );
  }

  async function withOriginal(node, scope, work) {
    const worker = openWorker({ ...scope, server: serverFrom(node) });
    try {
      // Inspect binds the credential to this pinned connection. The paired
      // actions verify their own role marker rather than using single-VPN status.
      await worker.request({ ...node, action: "inspect" });
      return await work(worker);
    } finally {
      worker.stop();
    }
  }

  function requestFor(record, role) {
    return { pair: record.review.pairId, role, operation: record.operation };
  }

  async function rehearseCurrent(targets, review, archive) {
    const receipt = await runtime.rehearsePairRecovery({
      ...targets,
      review,
      archive,
    });
    if (receipt?.verified !== true || receipt.readiness_schema !== 2)
      throw new PairRebuildError("rehearsal-required");
    // Captures differ by time. A changed account, key or filter setting means
    // this backup would revert current VPN access after the disks were erased.
    const comparable = ({ created: _captured, nodes, ...rest }) => ({
      ...rest,
      nodes: Object.fromEntries(
        order.map((role) => [role, nodeIdentity(nodes[role])]),
      ),
    });
    const live = await runtime.capturePairRecovery({ ...targets, review });
    if (
      runtime.pairArchiveDigest(comparable(live)) !==
      runtime.pairArchiveDigest(comparable(archive))
    )
      throw new PairRebuildError("current-recovery-archive-required");
  }

  async function review({ targets, ubuntu, encrypted, passphrase, expectedReview }) {
    if (store.read("operation"))
      throw new PairRebuildError("operation-already-reviewed");
    if (
      !(encrypted instanceof Uint8Array) ||
      encrypted.byteLength > maxPairRecoveryBytes ||
      !order.every((role) => ubuntuVersions.includes(ubuntu?.[role]))
    )
      throw new PairRebuildError("invalid-rebuild-input");
    // Reject invalid destinations before authenticating, even if a test transport is injected.
    matchingTargets(targets, targets, eligible);
    const original = await runtime.adoptPair(targets);
    matchingTargets(targets, original, eligible);
    if (expectedReview && !matchesOriginalReview(original, expectedReview))
      throw new PairRebuildError("reviewed-pair-changed");
    const archive = await decryptPairRecovery(encrypted, passphrase, original);
    await rehearseCurrent(targets, original, archive);
    const record = {
      version: 1,
      operation: randomBytes(16).toString("hex"),
      review: original,
      archiveDigest: runtime.pairArchiveDigest(archive),
      encryptedDigest: digest(encrypted),
      members: {},
    };
    for (const role of order) {
      const result = await withOriginal(targets[role], {
        ...requestFor(record, role), purpose: "review", ubuntu: ubuntu[role],
      }, (worker) =>
        worker.request({
          action: "pairUbuntuReview",
          ...requestFor(record, role),
          ubuntu: ubuntu[role],
          snapshot: runtime.pairArchiveDigest(
            nodeIdentity(archive.nodes[role]),
          ),
        }),
      );
      if (result.reason === "pair-snapshot-changed")
        throw new PairRebuildError(result.reason, role);
      record.members[role] = checkedMember(serverFrom(original[role]), result);
      if (record.members[role].ubuntu !== ubuntu[role])
        throw new PairRebuildError("ubuntu-review-changed", role);
    }
    checkedOperation(record, eligible);
    if (!store.write("operation", record))
      throw new PairRebuildError("operation-already-reviewed");
    return record;
  }

  async function statusFor(record, role, password) {
    const recovery = recoveryOf(record.members[role]);
    const worker = openWorker({
      ...requestFor(record, role), purpose: "resume", server: recovery.server, recovery,
    });
    try {
      return await worker.request({
        action: "ubuntuResume",
        ...recovery,
        password,
      });
    } catch {
      return { state: "waiting" };
    } finally {
      worker.stop();
    }
  }

  async function poll(record, role, password, onProgress) {
    const deadline = clock() + timeoutMs;
    while (clock() < deadline) {
      rejectDenied(record, role);
      const { state } = await statusFor(record, role, password);
      onProgress?.({ role, state });
      if (state === "complete") return;
      if (
        [
          "failed",
          "cancelled",
          "expired",
          "keyMismatch",
          "unverified",
        ].includes(state)
      )
        throw new PairRebuildError("ubuntu-" + state, role);
      await wait();
    }
    throw new PairRebuildError("ubuntu-return-pending", role);
  }

  async function dispatch(record, role, target) {
    return withOriginal(target, {
      ...requestFor(record, role), purpose: "dispatch", recovery: recoveryOf(record.members[role]),
    }, async (worker) => {
      const { job, fingerprint, ubuntu } = record.members[role];
      const scope = { ...requestFor(record, role), job, fingerprint, ubuntu };
      const reply = await worker.request({
        action: "pairUbuntuPlan",
        ...scope,
      });
      if (reply.reason === "pair-snapshot-changed")
        throw new PairRebuildError(reply.reason, role);
      if (!digestPattern.test(reply.token ?? ""))
        throw new PairRebuildError("ubuntu-review-changed", role);
      // Publish a durable, one-writer dispatch marker before sending the first byte.
      if (!store.write(role + "-issued", { operation: record.operation, job }))
        return false;
      const result = await worker
        .request({
          action: "pairUbuntuApply",
          ...scope,
          token: reply.token,
          confirmation: ubuntuEraseConfirmation,
        })
        .catch(() => undefined);
      if (result?.state === "conflict") {
        store.write(role + "-denied", {
          operation: record.operation,
          job,
          reason:
            result.reason === "pair-snapshot-changed"
              ? result.reason
              : "ubuntu-apply-rejected",
        });
        rejectDenied(record, role);
      }
      return true;
    });
  }

  function reserveRestore(record, resume) {
    for (let attempt = 0; attempt < 16; attempt++) {
      const name = "restore-" + attempt;
      const previous = store.read(name);
      if (previous) {
        if (
          previous.operation !== record.operation ||
          !Number.isSafeInteger(previous.pid) ||
          previous.pid <= 0
        )
          throw new PairRebuildError("journal-receipt-mismatch");
        if (
          !resume ||
          (isAlive(previous.pid) && !store.read(name + "-finished"))
        )
          throw new PairRebuildError("restore-review-in-progress");
        continue;
      }
      if (!store.write(name, { operation: record.operation, pid: process.pid }))
        throw new PairRebuildError("restore-review-in-progress");
      return { name, resume: attempt > 0 };
    }
    throw new PairRebuildError("restore-review-limit");
  }

  async function run({
    targets,
    encrypted,
    passphrase,
    confirmation,
    pauseAfterDispatch = false,
    resumeRestore = false,
    onProgress,
  }) {
    if (confirmation !== pairRebuildConfirmation)
      throw new PairRebuildError("explicit-rebuild-approval-required");
    const record = loaded();
    matchingTargets(targets, record.review, eligible);
    if (
      !(encrypted instanceof Uint8Array) ||
      encrypted.byteLength > maxPairRecoveryBytes ||
      digest(encrypted) !== record.encryptedDigest
    )
      throw new PairRebuildError("reviewed-archive-required");
    const archive = await decryptPairRecovery(
      encrypted,
      passphrase,
      record.review,
    );
    if (runtime.pairArchiveDigest(archive) !== record.archiveDigest)
      throw new PairRebuildError("reviewed-archive-required");
    const done = store.read("restored");
    if (done) {
      if (
        done.operation !== record.operation ||
        done.state !== "restored" ||
        done.pairId !== record.review.pairId ||
        !matchesRestoredReview(record, done.review)
      )
        throw new PairRebuildError("journal-receipt-mismatch");
      return done;
    }
    if (!proof("exit-issued", record, "exit"))
      await rehearseCurrent(targets, record.review, archive);
    for (const role of order) {
      rejectDenied(record, role);
      const { password } = targets[role];
      if (proof(role + "-returned", record, role)) {
        if (
          !proof(role + "-issued", record, role) ||
          (await statusFor(record, role, password)).state !== "complete"
        )
          throw new PairRebuildError("returned-ubuntu-unverified", role);
        continue;
      }
      if (!proof(role + "-issued", record, role)) {
        if ((await loadRecipe()).digest !== record.review.bundle)
          throw new PairRebuildError("reviewed-recipe-unavailable", role);
        onProgress?.({ role, state: "issuing" });
        const issued = await dispatch(record, role, targets[role]);
        if (issued && pauseAfterDispatch) return { state: "waiting", role };
      }
      await poll(record, role, password, onProgress);
      store.write(role + "-returned", {
        operation: record.operation,
        job: record.members[role].job,
      });
    }
    const replacement = Object.fromEntries(
      order.map((role) => [
        role,
        {
          ...replacementServer(record.members[role]),
          password: targets[role].password,
        },
      ]),
    );
    const attempt = reserveRestore(record, resumeRestore);
    try {
      const restored = await runtime.restorePair({
        ...replacement,
        archive,
        operation: record.operation,
        archiveDigest: record.archiveDigest,
        expectedBundle: record.review.bundle,
        resume: attempt.resume,
        onProgress,
      });
      if (
        restored?.state !== "restored" ||
        restored.pairId !== record.review.pairId ||
        !matchesRestoredReview(record, restored.review)
      )
        throw new PairRebuildError("restore-identity-unverified");
      const result = {
        operation: record.operation,
        state: "restored",
        pairId: restored.pairId,
        review: restored.review,
      };
      store.write("restored", result);
      return result;
    } finally {
      store.write(attempt.name + "-finished", { operation: record.operation });
    }
  }

  return { review, run, loaded, journalStatus };
}
