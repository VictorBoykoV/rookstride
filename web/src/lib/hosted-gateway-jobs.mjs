import { randomBytes, randomUUID } from "node:crypto";

const version = 1;
const inspectionStates = new Set([
  "ready",
  "installed",
  "occupied",
  "unsupported",
]);
const settledStates = new Set(["succeeded", "unchanged", "stale"]);
const unresolvedStates = new Set(["running", "uncertain", "reconciling"]);

class HostedGatewayError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function reject(code) {
  throw new HostedGatewayError(code);
}

// Single-process pilot contract exercised with fixture workers. Target IDs are
// operator-assigned aliases; no addresses, credentials or transport belong here.
// The worker must enforce the inspected revisions under its own target-side
// lock. A settled result asserts that the original mutation is no longer active.
export function createHostedGatewayJobs({
  targetIds,
  worker,
  maxActive = 1,
  maxQueued = 1,
  maxSessions = 16,
  maxOperationsPerSession = 8,
  sessionLifetimeMs = 30 * 60_000,
  now = Date.now,
}) {
  if (
    !Array.isArray(targetIds) ||
    !targetIds.length ||
    new Set(targetIds).size !== targetIds.length ||
    ![...targetIds].every(
      (id) => typeof id === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(id),
    ) ||
    ![maxActive, maxSessions, maxOperationsPerSession, sessionLifetimeMs].every(
      (limit) => Number.isSafeInteger(limit) && limit > 0,
    ) ||
    !Number.isSafeInteger(maxQueued) ||
    maxQueued < 0 ||
    !["inspect", "apply", "reconcile"].every(
      (action) => typeof worker?.[action] === "function",
    )
  )
    reject("invalid-configuration");

  const eligibleTargets = new Set(targetIds);
  const sessions = new Map();
  const operations = new Map();
  const locks = new Map();
  const queue = [];
  let active = 0;

  function release(record) {
    for (const id of record.targets) {
      if (locks.get(id) === record) locks.delete(id);
    }
  }

  function reserve(record) {
    if (record.targets.some((id) => locks.has(id))) reject("target-busy");
    for (const id of record.targets.toSorted()) locks.set(id, record);
  }

  function unqueue(record) {
    queue.splice(queue.indexOf(record), 1);
    release(record);
  }

  function expire() {
    const time = now();
    for (const [token, session] of sessions) {
      if (session.expiresAt <= time) sessions.delete(token);
    }
    for (const record of operations.values()) {
      if (record.owner.expiresAt > time || unresolvedStates.has(record.state))
        continue;
      if (record.state === "queued") unqueue(record);
      operations.delete(record.operationId);
    }
  }

  function authorize(token) {
    expire();
    const session = sessions.get(token);
    if (!session) reject("session-ended");
    return session;
  }

  function owned(token, operationId) {
    const session = authorize(token);
    const record = operations.get(operationId);
    if (record?.owner !== session) reject("operation-not-found");
    return record;
  }

  function receipt(record) {
    return {
      version,
      operationId: record.operationId,
      planId: record.planId,
      jobId: record.jobId,
      route: record.route,
      state: record.state,
      inspection: record.inspection.map(({ id, state }) => ({ id, state })),
    };
  }

  async function run(record, action) {
    active++;
    record.state = action === "apply" ? "running" : "reconciling";
    try {
      const result = await worker[action]({
        version,
        operationId: record.operationId,
        planId: record.planId,
        jobId: record.jobId,
        route: record.route,
        targets: record.inspection.map(({ id, revision }) => ({
          id,
          revision,
        })),
      });
      record.state = settledStates.has(result) ? result : "uncertain";
    } catch {
      record.state = "uncertain";
    } finally {
      active--;
      if (record.state !== "uncertain") release(record);
      drain();
    }
  }

  function drain() {
    expire();
    while (active < maxActive && queue.length) void run(queue.shift(), "apply");
  }

  function reconcile(record) {
    if (record.state === "uncertain") {
      if (active >= maxActive) reject("busy");
      record.reconciliation = run(record, "reconcile");
    } else if (
      record.state !== "reconciling" &&
      !settledStates.has(record.state)
    ) {
      reject("reconciliation-unavailable");
    }
    return receipt(record);
  }

  return {
    // Trusted admission and recovery belong to the operator, outside any client API.
    operator: {
      admit(allowed) {
        expire();
        if (
          !Array.isArray(allowed) ||
          !allowed.length ||
          new Set(allowed).size !== allowed.length ||
          ![...allowed].every((id) => eligibleTargets.has(id))
        )
          reject("target-denied");
        if (sessions.size >= maxSessions) reject("busy");
        const token = randomBytes(32).toString("base64url");
        const expiresAt = now() + sessionLifetimeMs;
        sessions.set(token, { targets: new Set(allowed), expiresAt });
        return { version, token, expiresAt };
      },
      async recoverExpired(operationId) {
        expire();
        const record = operations.get(operationId);
        if (!record || record.owner.expiresAt > now())
          reject("operation-not-found");
        reconcile(record);
        await record.reconciliation;
        return receipt(record);
      },
    },
    jobs: {
      async inspect(token, targets) {
        const owner = authorize(token);
        if (
          !Array.isArray(targets) ||
          targets.length < 1 ||
          targets.length > 2 ||
          new Set(targets).size !== targets.length ||
          ![...targets].every((id) => owner.targets.has(id))
        )
          reject("target-denied");
        const ownerOperations = [...operations.values()].filter(
          (record) => record.owner === owner,
        );
        if (
          ownerOperations.length >= maxOperationsPerSession ||
          active >= maxActive
        )
          reject("busy");

        const record = {
          operationId: randomUUID(),
          planId: null,
          jobId: null,
          owner,
          route: targets.length === 1 ? "ikev2" : "two-hop-fixture",
          targets: [...targets],
          state: "inspecting",
          inspection: [],
        };
        reserve(record);
        operations.set(record.operationId, record);
        active++;
        try {
          const inspected = await worker.inspect({
            version,
            operationId: record.operationId,
            route: record.route,
            targetIds: [...record.targets],
          });
          if (
            !Array.isArray(inspected) ||
            inspected.length !== record.targets.length
          )
            throw new Error();
          record.inspection = record.targets.map((id, index) => {
            const { id: inspectedId, state, revision } = inspected[index];
            if (
              inspectedId !== id ||
              !inspectionStates.has(state) ||
              typeof revision !== "string" ||
              !/^[a-f0-9]{64}$/.test(revision)
            )
              throw new Error();
            return { id, state, revision };
          });
        } catch {
          operations.delete(record.operationId);
          reject("inspection-failed");
        } finally {
          active--;
          release(record);
          drain();
        }

        authorize(token);
        const ready = record.inspection.every(({ state }) => state === "ready");
        record.state = ready ? "planned" : "blocked";
        if (ready) record.planId = randomUUID();
        return receipt(record);
      },
      approve(token, operationId, planId) {
        const record = owned(token, operationId);
        if (!record.planId || record.planId !== planId) reject("plan-mismatch");
        if (record.jobId) return receipt(record);
        if (record.state !== "planned") reject("approval-unavailable");
        if (active >= maxActive && queue.length >= maxQueued) reject("busy");
        reserve(record);
        record.jobId = randomUUID();
        record.state = "queued";
        queue.push(record);
        drain();
        return receipt(record);
      },
      status(token, operationId) {
        return receipt(owned(token, operationId));
      },
      cancel(token, operationId) {
        const record = owned(token, operationId);
        if (record.state === "queued") unqueue(record);
        else if (record.state !== "planned" && record.state !== "cancelled")
          reject("cancellation-unavailable");
        record.state = "cancelled";
        return receipt(record);
      },
      reconcile(token, operationId) {
        return reconcile(owned(token, operationId));
      },
    },
  };
}
