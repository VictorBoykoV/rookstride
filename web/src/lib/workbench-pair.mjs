import { randomBytes } from "node:crypto";
import * as runtime from "./pair-deployment.mjs";
import { pairRebuildConfirmation } from "./pair-rebuild.mjs";
import { hostedPairExits, isMixedPairEntry, isMixedPairExit, ubuntuVersions, validVpnPassword } from "./gateway-input.mjs";
import {
  decryptPairRecovery,
  encryptPairRecovery,
  maxPairRecoveryBytes,
} from "./pair-recovery.mjs";

const actions = new Set([
  "pairReview", "pairAdopt", "pairApply", "pairStatus", "pairProfile", "pairClose",
  "pairManage", "pairAccount", "pairRemoveReview", "pairRemoveApply",
  "pairBackup", "pairRehearse",
]);
const rebuildPayloads = {
  pairRebuildReview: ["archive", "password", "confirmed", "entryUbuntu", "exitUbuntu"],
  pairRebuildStart: ["operation", "confirmation"],
  pairRebuildStatus: [],
  pairRebuildReconnect: ["entry", "exit", "operation"],
  pairRebuildResume: ["operation", "archive", "password", "confirmation"],
};
const roles = ["entry", "exit"];
const nodeFields = ["address", "sshPort", "fingerprint", "password"];
const loginPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/;
const revisionPattern = /^[a-f0-9]{64}$/;
const reviewLifetime = 5 * 60_000;
const operationPattern = /^[a-f0-9]{32}$/;
const maxEncodedArchive = 4 * Math.ceil(maxPairRecoveryBytes / 3);
const recoveryRequestLimit = maxEncodedArchive + 2048;
const rebuildFailures = new Set([
  "pair-snapshot-changed", "current-recovery-archive-required", "reviewed-archive-required",
  "reviewed-recipe-unavailable", "ubuntu-review-changed", "ubuntu-apply-rejected",
  "ubuntu-return-pending", "ubuntu-keyMismatch", "ubuntu-unverified", "ubuntu-failed",
  "ubuntu-cancelled", "ubuntu-expired", "returned-ubuntu-unverified", "restore-review-in-progress",
  "restore-ownership-mismatch", "restore-resume-required", "restore-incomplete", "awaiting-reboot",
]);

export function recoveryPassword(value) {
  return typeof value === "string" && value.length >= 12 && value.length <= 256;
}

function exact(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field));
}

function recoveryBytes(value) {
  if (typeof value !== "string" || value.length > maxEncodedArchive) return null;
  const bytes = Buffer.from(value, "base64");
  return bytes.length && bytes.length <= maxPairRecoveryBytes && bytes.toString("base64") === value
    ? bytes
    : null;
}

function pairDisplay(review) {
  return {
    entry: { address: review.entry.address, os: "Ubuntu " + review.entry.ubuntu },
    exit: { address: review.exit.address, os: "Ubuntu " + review.exit.ubuntu },
    login: review.login,
    ...(review.entryProtocol && { entryProtocol: review.entryProtocol }),
    ...(review.exitProtocol && { exitProtocol: review.exitProtocol }),
  };
}

function rebuildDisplay(record) {
  const members = Object.fromEntries(roles.map((role) => {
    const { ubuntu, boot, diskBytes, fingerprint } = record.members[role];
    return [role, { ubuntu, boot, diskBytes, fingerprint }];
  }));
  const { entryProtocol, exitProtocol } = record.review;
  return { ...members, ...(entryProtocol && { entryProtocol }), ...(exitProtocol && { exitProtocol }) };
}

export function createWorkbenchPair({
  canReserve,
  validateNode,
  validateOriginalNode = validateNode,
  deny,
  reserveAttempts = () => {},
  review = runtime.reviewPair,
  adopt = runtime.adoptPair,
  deploy = runtime.deployPair,
  profile = runtime.exportPairProfile,
  manage = runtime.readPairManagement,
  account = runtime.changePairAccount,
  removalReview = runtime.reviewPairRemoval,
  remove = runtime.removePair,
  capture = runtime.capturePairRecovery,
  rehearse = runtime.rehearsePairRecovery,
  rebuild,
  allowMixedExits = Boolean(rebuild),
  allowAllPairMethods = false,
  idleMs = 10 * 60_000,
  now = Date.now,
}) {
  let record;

  function discardRebuildInput(current, keepEncrypted = false) {
    clearTimeout(current.rebuildTimer);
    if (!keepEncrypted) current.rebuildInput?.encrypted.fill(0);
    current.rebuildInput = undefined;
  }

  function release(current) {
    if (record !== current) return;
    clearTimeout(current.timer);
    discardRebuildInput(current);
    current.nodes = undefined;
    record = undefined;
  }

  function expire(current) {
    if (record !== current || current.expiresAt > now() || current.reading || current.rebuildRunning) return;
    if (
      ["reviewed", "installed", "removed", "reconnected", "restored"].includes(current.state) ||
      current.state === "needsAttention" && !current.uncertain
    ) release(current);
  }

  function refresh(current) {
    clearTimeout(current.timer);
    current.expiresAt = now() + idleMs;
    current.timer = setTimeout(() => expire(current), idleMs);
    current.timer.unref();
  }

  function active() {
    if (record) expire(record);
    return Boolean(record);
  }

  function result(current) {
    return {
      state: current.state,
      ...(current.stage && { stage: current.stage }),
      ...(current.uncertain && { uncertain: true }),
    };
  }

  function validPairNodes(input, validate) {
    return roles.every((role) => {
      const node = input[role];
      const fields = node?.keyType === "ecdsa-sha2-nistp256" ? [...nodeFields, "keyType"] : nodeFields;
      return exact(node, fields) && validate(node, role);
    });
  }

  async function inspect(input, token) {
    const adopting = input.action === "pairAdopt";
    const entryProtocol = !adopting && allowAllPairMethods && isMixedPairEntry(input.entryProtocol)
      ? input.entryProtocol
      : undefined;
    const exitProtocol = !adopting && allowMixedExits && isMixedPairExit(input.exitProtocol) &&
      (allowAllPairMethods || hostedPairExits.includes(input.exitProtocol))
      ? input.exitProtocol
      : undefined;
    if (
      !exact(input, adopting ? ["action", "entry", "exit"] :
        ["action", "entry", "exit", "login", ...(entryProtocol ? ["entryProtocol"] : []), ...(exitProtocol ? ["exitProtocol"] : [])]) ||
      !validPairNodes(input, validateNode)
    ) deny(400, "invalidServerDetails");
    if (!adopting && (typeof input.login !== "string" || !loginPattern.test(input.login)))
      deny(400, "invalidInstallDetails");
    if (input.entry.address === input.exit.address || input.entry.fingerprint === input.exit.fingerprint)
      deny(400, "pairRequiresTwoServers");
    if (token) deny(409, "sessionAlreadyOpen");
    if (active() || !canReserve()) deny(409, "pairInspectionBusy");
    const recovery = rebuild?.journalStatus();
    if (recovery && !recovery.restored) deny(409, "operationBusy");
    reserveAttempts(2);
    const current = {
      token: randomBytes(32).toString("base64url"),
      state: "inspecting",
      nodes: { entry: { ...input.entry }, exit: { ...input.exit } },
    };
    record = current;
    try {
      const plan = adopting ? await adopt(current.nodes) : await review({
        ...current.nodes, login: input.login, ...(entryProtocol && { entryProtocol }), ...(exitProtocol && { exitProtocol }),
      });
      if ((!adopting && (plan.entryProtocol !== entryProtocol || plan.exitProtocol !== exitProtocol)) ||
          (!allowAllPairMethods && (plan.entryProtocol || plan.exitProtocol && !hostedPairExits.includes(plan.exitProtocol))))
        throw new Error("review-mismatch");
      current.review = plan;
      current.state = adopting ? "installed" : "reviewed";
      refresh(current);
      return {
        session: current.token,
        pair: pairDisplay(plan),
        state: current.state,
      };
    } catch (error) {
      release(current);
      if (error?.code === "same-node") deny(409, "pairRequiresTwoServers");
      if (error?.code === "ssh-pin-mismatch") deny(409, "identityMismatch");
      if (error?.code === "entry-dns-conflict") deny(409, "pairEntryDnsConflict");
      deny(409, "inspectionUnavailable");
    }
  }

  async function install(current, password) {
    try {
      const receipt = await deploy({
        ...current.nodes,
        review: current.review,
        ...(password && { password }),
        onProgress: ({ stage }) => {
          if (runtime.pairStages.includes(stage)) current.stage = stage;
        },
      });
      if (receipt?.state !== "installed" || receipt.pairId !== current.review.pairId)
        throw new Error("Invalid Double VPN result");
      current.state = "installed";
      current.stage = "health";
      refresh(current);
    } catch (error) {
      current.state = "needsAttention";
      current.uncertain = !(error instanceof runtime.PairDeploymentError) || error.uncertain;
      current.nodes = undefined;
      if (!current.uncertain) refresh(current);
    }
  }

  async function removeOwned(current, plan) {
    try {
      const result = await remove({ ...current.nodes, review: current.review, removal: plan });
      if (result?.state !== "removed") throw new Error("Invalid removal receipt");
      current.state = "removed";
      current.nodes = undefined;
      refresh(current);
    } catch {
      current.state = "needsAttention";
      current.uncertain = true;
      current.nodes = undefined;
    }
  }

  function rebuildStatus(current, status, details) {
    if (!status) return { state: "idle" };
    const { operation } = status.record;
    const state = status.restored ? "restored" : current?.rebuildRunning ? "rebuilding"
      : current?.rebuildInput && now() < current.rebuildInput.expires ? "reviewed" : "needsAttention";
    return {
      operation, state,
      ...(details && rebuildDisplay(status.record)),
      ...(details && current?.rebuildProgress && { progress: current.rebuildProgress }),
      ...(details && current?.rebuildFailure && { reason: current.rebuildFailure }),
    };
  }

  function onRebuildProgress(current, update) {
    const { role, state, stage } = update;
    const nodeStates = ["issuing", "waiting", "preparing", "rebooting", "complete", "failed",
      "cancelled", "expired", "keyMismatch", "unverified"];
    if (roles.includes(role) && nodeStates.includes(state))
      current.rebuildProgress = { role, state };
    else if (runtime.pairRestoreStages.includes(stage))
      current.rebuildProgress = { stage };
  }

  async function runRebuild(current, input, resumeRestore) {
    try {
      const result = await rebuild.run({
        ...input,
        targets: current.nodes,
        resumeRestore,
        confirmation: pairRebuildConfirmation,
        onProgress: (update) => onRebuildProgress(current, update),
      });
      const status = rebuild.journalStatus();
      if (result?.state !== "restored" || result.operation !== status?.restored?.operation)
        throw new Error("Invalid paired rebuild result");
      current.state = "restored";
      current.nodes = undefined;
    } catch (error) {
      current.state = "reconnected";
      if (rebuildFailures.has(error?.code)) current.rebuildFailure = error.code;
    } finally {
      input.encrypted.fill(0);
      current.rebuildRunning = false;
      refresh(current);
    }
  }

  async function rebuildPost(input, token) {
    const { action, operation } = input;
    if (!exact(input, ["action", ...rebuildPayloads[action]])) deny(400, "invalidRequest");
    const current = active() ? record : undefined;
    if (token && (!current || token !== current.token)) deny(401, "sessionEnded");
    const status = rebuild.journalStatus();
    if (action === "pairRebuildStatus")
      return rebuildStatus(current, status, Boolean(token));

    if (action === "pairRebuildReconnect") {
      if (!validPairNodes(input, validateOriginalNode)) deny(400, "invalidServerDetails");
      if (!status || status.restored || operation !== status.record.operation)
        deny(409, "pairRecoveryUnavailable");
      if (token || current || !canReserve()) deny(409, "pairInspectionBusy");
      reserveAttempts(2);
      record = {
        token: randomBytes(32).toString("base64url"),
        state: "reconnected",
        nodes: { entry: { ...input.entry }, exit: { ...input.exit } },
      };
      refresh(record);
      return {
        session: record.token,
        pair: pairDisplay(status.record.review),
        ...rebuildStatus(record, status, true),
      };
    }

    if (!token || !current) deny(401, "sessionEnded");
    if (current.reading || current.rebuildRunning) deny(409, "operationBusy");
    if (action === "pairRebuildReview") {
      if (current.state !== "installed" || status) deny(409, "verifiedSessionRequired");
      const { password, confirmed, entryUbuntu, exitUbuntu } = input;
      const encrypted = recoveryBytes(input.archive);
      if (!encrypted || !recoveryPassword(password) || confirmed !== true ||
          ![entryUbuntu, exitUbuntu].every((version) => ubuntuVersions.includes(version)))
        deny(400, "invalidRequest");
      current.reading = true;
      delete current.removal;
      refresh(current);
      try {
        const plan = await rebuild.review({
          targets: current.nodes, ubuntu: { entry: entryUbuntu, exit: exitUbuntu },
          encrypted, passphrase: password,
        });
        current.rebuildInput = { encrypted, passphrase: password, expires: now() + idleMs };
        current.rebuildTimer = setTimeout(() => discardRebuildInput(current), idleMs);
        current.rebuildTimer.unref();
        return { operation: plan.operation, ...rebuildDisplay(plan) };
      } catch {
        encrypted.fill(0);
        deny(409, "pairRecoveryUnavailable");
      } finally {
        current.reading = false;
        expire(current);
      }
    }

    if (
      !status || status.restored || !operationPattern.test(operation ?? "") ||
      operation !== status.record.operation || input.confirmation !== pairRebuildConfirmation ||
      !["installed", "reconnected"].includes(current.state)
    ) deny(409, "pairRecoveryUnavailable");
    let approved;
    if (action === "pairRebuildStart") {
      approved = current.rebuildInput;
      if (!approved || now() >= approved.expires || status.started) deny(409, "pairRecoveryUnavailable");
    } else {
      const encrypted = recoveryBytes(input.archive);
      if (!encrypted || !recoveryPassword(input.password)) deny(400, "invalidRequest");
      approved = { encrypted, passphrase: input.password };
    }
    discardRebuildInput(current, action === "pairRebuildStart");
    clearTimeout(current.timer);
    current.rebuildRunning = true;
    delete current.rebuildFailure;
    current.rebuildProgress = { stage: "preflight" };
    void runRebuild(current, approved, action === "pairRebuildResume");
    return rebuildStatus(current, status, true);
  }

  const payloads = {
    pairApply: ["confirmed"],
    pairAccount: ["operation", "login", "revision", "confirmed"],
    pairRemoveApply: ["review", "confirmation"],
    pairBackup: ["password", "confirmed"],
    pairRehearse: ["password", "archive", "confirmed"],
  };

  async function post(input, token) {
    const action = input?.action;
    if (rebuild && Object.hasOwn(rebuildPayloads, action)) return rebuildPost(input, token);
    if (!actions.has(action)) deny(400, "unknownAction");
    if (action === "pairReview" || action === "pairAdopt") return inspect(input, token);
    const fields = action === "pairProfile" && Object.hasOwn(input, "login") ? ["login"] : payloads[action] ?? [];
    const suppliedPassword = ["pairApply", "pairAccount"].includes(action) && Object.hasOwn(input, "vpnPassword");
    if (!exact(input, ["action", ...fields, ...(suppliedPassword ? ["vpnPassword"] : [])]))
      deny(400, "invalidRequest");
    if (!active() || record.state === "inspecting" || record.token !== token)
      deny(401, "sessionEnded");

    const current = record;
    const needsPassword = current.review?.entryProtocol === "ikev2" &&
      (action === "pairApply" || action === "pairAccount" && input.operation === "grant");
    if (suppliedPassword !== needsPassword || (needsPassword && !validVpnPassword(input.vpnPassword)))
      deny(400, "invalidInstallDetails");
    if (action === "pairStatus") {
      if (["reviewed", "installed", "removed"].includes(current.state)) refresh(current);
      return result(current);
    }

    if (action === "pairApply") {
      if (input.confirmed !== true) deny(400, "invalidInstallDetails");
      if (current.state !== "reviewed") deny(409, "operationBusy");
      clearTimeout(current.timer);
      current.state = "installing";
      current.stage = "preflight";
      void install(current, input.vpnPassword);
      return result(current);
    }

    if (action === "pairClose") {
      if (["installing", "removing"].includes(current.state) || current.reading || current.rebuildRunning)
        deny(409, "operationBusy");
      release(current);
      return { state: "closed" };
    }

    if (rebuild) {
      const recovery = rebuild.journalStatus();
      if (current.rebuildRunning || (recovery && !recovery.restored)) deny(409, "operationBusy");
    }

    if (action === "pairRemoveApply" && typeof input.review === "string" &&
        input.confirmation === "DELETE PAIR" && current.removalReceipt === input.review) return result(current);
    if (current.state !== "installed") deny(409, "verifiedSessionRequired");
    if (current.reading) deny(409, "operationBusy");
    const options = { ...current.nodes, review: current.review };
    if (action === "pairRemoveApply") {
      const plan = current.removal;
      if (input.confirmation !== "DELETE PAIR" || !plan || plan.id !== input.review || now() >= plan.expires)
        deny(409, "removalReviewRequired");
      delete current.removal;
      current.removalReceipt = plan.id;
      current.state = "removing";
      delete current.stage;
      clearTimeout(current.timer);
      void removeOwned(current, plan.review);
      return result(current);
    }
    current.reading = true;
    refresh(current);
    try {
      switch (action) {
        case "pairManage":
          return await manage(options);
        case "pairAccount":
          if (!["grant", "revoke"].includes(input.operation) ||
              typeof input.login !== "string" || !loginPattern.test(input.login) ||
              typeof input.revision !== "string" || !revisionPattern.test(input.revision) || input.confirmed !== true)
            deny(400, "invalidMaintenanceDetails");
          delete current.removal;
          return await account({ ...options, operation: input.operation, login: input.login, revision: input.revision,
            ...(needsPassword && { password: input.vpnPassword }) });
        case "pairProfile":
          if (fields.length && (typeof input.login !== "string" || !loginPattern.test(input.login)))
            deny(400, "invalidMaintenanceDetails");
          return await profile({ ...options, ...(fields.length && { login: input.login }) });
        case "pairRemoveReview": {
          delete current.removal;
          const expires = now() + reviewLifetime;
          const removal = await removalReview(options);
          const id = randomBytes(24).toString("base64url");
          current.removal = { id, expires, review: removal };
          return { review: id };
        }
        case "pairBackup":
        case "pairRehearse": {
          if (!recoveryPassword(input.password) || input.confirmed !== true) deny(400, "invalidRequest");
          if (action === "pairBackup") {
            const archive = await capture(options);
            return { recovery: await encryptPairRecovery(archive, input.password, current.review) };
          }
          const bytes = recoveryBytes(input.archive);
          if (!bytes) deny(400, "invalidRequest");
          const archive = await decryptPairRecovery(bytes, input.password, current.review);
          await rehearse({ ...options, archive });
          return { ready: true };
        }
      }
    } catch (error) {
      if (typeof error?.messageKey === "string") throw error;
      if (error?.code === "roster-changed") deny(409, "rosterChanged");
      if (action === "pairProfile") deny(409, "invalidProfile");
      if (action === "pairBackup" || action === "pairRehearse") deny(409, "pairRecoveryUnavailable");
      deny(409, "maintenanceResultUnknown");
    } finally {
      current.reading = false;
      expire(current);
    }
  }

  return {
    active, post,
    handles: (action) => actions.has(action) || Boolean(rebuild && Object.hasOwn(rebuildPayloads, action)),
    requestLimit(token, action) {
      if (!active() || record.token !== token) return 2048;
      const installed = record.state === "installed";
      const recovery = rebuild && (installed || record.state === "reconnected");
      const allowed = action === undefined ? installed || recovery
        : action === "pairRehearse" ? installed
        : action === "pairRebuildReview" ? rebuild && installed
        : action === "pairRebuildResume" && recovery;
      return allowed ? recoveryRequestLimit : 2048;
    },
  };
}
