import assert from "node:assert/strict";
import test from "node:test";
import { createHostedGatewayJobs } from "../src/lib/hosted-gateway-jobs.mjs";

const targets = ["gateway-a", "gateway-b", "gateway-c", "gateway-d"];
const [a, b, c, d] = targets;
const revision = "1".repeat(64);
const marker = "synthetic-sensitive-marker";
const wait = () => new Promise((resolve) => setImmediate(resolve));
const error = (code) => ({ code, message: code });

function fixture(options = {}) {
  const calls = { inspect: [], apply: [], reconcile: [] };
  const worker = {
    inspect(input) {
      calls.inspect.push(input);
      return input.targetIds.map((id) => ({
        id,
        state: "ready",
        revision,
        password: marker,
      }));
    },
    apply(input) {
      const result = Promise.withResolvers();
      calls.apply.push({ input, ...result });
      return result.promise;
    },
    reconcile(input) {
      const result = Promise.withResolvers();
      calls.reconcile.push({ input, ...result });
      return result.promise;
    },
  };
  const { jobs, operator } = createHostedGatewayJobs({
    targetIds: targets,
    worker,
    ...options,
  });
  const admit = (...ids) => operator.admit(ids).token;
  const approve = (token, plan) =>
    jobs.approve(token, plan.operationId, plan.planId);
  return { admit, approve, calls, jobs, operator };
}

test("each session can inspect only its designated targets and can access only its own operations", async () => {
  const { admit, approve, calls, jobs, operator } = fixture();
  const first = admit(a);
  const second = admit(b);
  assert.throws(
    () => operator.admit([a, "undeclared"]),
    error("target-denied"),
  );
  await assert.rejects(jobs.inspect(first, [a, b]), error("target-denied"));
  await assert.rejects(jobs.inspect(first, [a, a]), error("target-denied"));
  await assert.rejects(jobs.inspect(null, [a]), error("session-ended"));
  assert.equal(calls.inspect.length, 0);

  const plan = await jobs.inspect(first, [a]);
  assert.equal(plan.state, "planned");
  assert.equal(plan.version, 1);
  assert.equal(plan.route, "ikev2");
  assert.equal(plan.jobId, null);
  assert.deepEqual(plan.inspection, [{ id: a, state: "ready" }]);
  assert.deepEqual(calls.inspect[0], {
    version: 1,
    operationId: plan.operationId,
    route: "ikev2",
    targetIds: [a],
  });
  assert.throws(
    () => jobs.status(second, plan.operationId),
    error("operation-not-found"),
  );
  assert.throws(
    () => jobs.cancel(second, plan.operationId),
    error("operation-not-found"),
  );
  assert.throws(
    () => jobs.reconcile(second, plan.operationId),
    error("operation-not-found"),
  );
  assert.throws(() => approve(second, plan), error("operation-not-found"));
  assert.throws(
    () => jobs.approve(first, plan.operationId, plan.operationId),
    error("plan-mismatch"),
  );
  assert.equal(calls.apply.length, 0);
  assert.equal(jobs.cancel(first, plan.operationId).state, "cancelled");
  assert.throws(() => approve(first, plan), error("approval-unavailable"));
});

test("separate sessions overlap within the worker limit and share a bounded queue", async () => {
  const { admit, approve, calls, jobs } = fixture({ maxActive: 2 });
  const sessions = targets.map((id) => admit(id));
  const plans = await Promise.all([
    jobs.inspect(sessions[0], [a]),
    jobs.inspect(sessions[1], [b]),
  ]);
  plans.push(
    await jobs.inspect(sessions[2], [c]),
    await jobs.inspect(sessions[3], [d]),
  );

  const first = approve(sessions[0], plans[0]);
  const second = approve(sessions[1], plans[1]);
  const third = approve(sessions[2], plans[2]);
  assert.equal(first.state, "running");
  assert.equal(second.state, "running");
  assert.equal(third.state, "queued");
  assert.notEqual(first.jobId, second.jobId);
  assert.deepEqual(approve(sessions[0], plans[0]), first);
  assert.deepEqual(approve(sessions[2], plans[2]), third);
  assert.throws(() => approve(sessions[3], plans[3]), error("busy"));
  assert.equal(jobs.status(sessions[3], plans[3].operationId).jobId, null);
  assert.equal(calls.apply.length, 2);

  calls.apply[1].resolve("succeeded");
  await wait();
  assert.equal(calls.apply[2].input.jobId, third.jobId);
  assert.equal(jobs.status(sessions[0], first.operationId).state, "running");
  assert.equal(jobs.status(sessions[1], second.operationId).state, "succeeded");
  assert.equal(approve(sessions[1], plans[1]).jobId, second.jobId);
  assert.equal(calls.apply.length, 3);
  calls.apply[0].resolve("succeeded");
  calls.apply[2].resolve("succeeded");
  await wait();
});

test("a two-hop fixture reserves both nodes atomically and a cancelled queued job releases its reservation", async () => {
  const { admit, approve, calls, jobs } = fixture({ maxActive: 2 });
  const pairOwner = admit(a, b);
  const otherPairOwner = admit(a, c);
  const otherNodeOwner = admit(b);
  const separateOwner = admit(c);
  const fourthOwner = admit(d);
  const pair = await jobs.inspect(pairOwner, [b, a]);
  const sharesSecond = await jobs.inspect(otherPairOwner, [a, c]);
  const sharesFirst = await jobs.inspect(otherNodeOwner, [b]);
  const separate = await jobs.inspect(separateOwner, [c]);
  const fourth = await jobs.inspect(fourthOwner, [d]);

  const runningPair = approve(pairOwner, pair);
  assert.equal(runningPair.route, "two-hop-fixture");
  assert.deepEqual(calls.apply[0].input.targets, [
    { id: b, revision },
    { id: a, revision },
  ]);
  assert.throws(
    () => approve(otherPairOwner, sharesSecond),
    error("target-busy"),
  );
  assert.throws(
    () => approve(otherNodeOwner, sharesFirst),
    error("target-busy"),
  );
  assert.equal(approve(separateOwner, separate).state, "running");
  const queued = approve(fourthOwner, fourth);
  assert.equal(jobs.cancel(fourthOwner, queued.operationId).state, "cancelled");
  assert.equal(approve(fourthOwner, fourth).jobId, queued.jobId);
  calls.apply[0].resolve("succeeded");
  calls.apply[1].resolve("succeeded");
  await wait();
  assert.equal(calls.apply.length, 2);
  assert.equal((await jobs.inspect(fourthOwner, [d])).state, "planned");
});

test("an uncertain worker result keeps the original lock and is reconciled without reapplying", async () => {
  const { admit, approve, calls, jobs } = fixture();
  const first = admit(a);
  const second = admit(a);
  const plan = await jobs.inspect(first, [a]);
  const running = approve(first, plan);
  calls.apply[0].reject(new Error(marker));
  await wait();
  const uncertain = jobs.status(first, plan.operationId);
  assert.equal(uncertain.state, "uncertain");
  assert.equal(uncertain.jobId, running.jobId);
  await assert.rejects(jobs.inspect(second, [a]), error("target-busy"));
  assert.throws(
    () => jobs.reconcile(second, plan.operationId),
    error("operation-not-found"),
  );
  assert.throws(
    () => jobs.cancel(first, plan.operationId),
    error("cancellation-unavailable"),
  );
  assert.deepEqual(approve(first, plan), uncertain);
  assert.equal(jobs.reconcile(first, plan.operationId).state, "reconciling");
  assert.equal(jobs.reconcile(first, plan.operationId).state, "reconciling");
  assert.equal(calls.reconcile.length, 1);
  assert.deepEqual(calls.reconcile[0].input, calls.apply[0].input);

  calls.reconcile[0].resolve("succeeded");
  await wait();
  assert.equal(jobs.reconcile(first, plan.operationId).state, "succeeded");
  assert.equal(calls.apply.length, 1);
  assert.equal(calls.reconcile.length, 1);
  assert.equal((await jobs.inspect(second, [a])).state, "planned");
  assert.equal(JSON.stringify({ calls, uncertain }).includes(marker), false);
  assert.equal(JSON.stringify({ calls, uncertain }).includes(first), false);
});

test("expired queued work never starts and only operator recovery retains access to unresolved work", async () => {
  let time = 10;
  const { admit, approve, calls, jobs, operator } = fixture({
    sessionLifetimeMs: 30,
    now: () => time,
  });
  const first = admit(a);
  const second = admit(b);
  const firstPlan = await jobs.inspect(first, [a]);
  const secondPlan = await jobs.inspect(second, [b]);
  const running = approve(first, firstPlan);
  assert.equal(approve(second, secondPlan).state, "queued");
  await assert.rejects(
    operator.recoverExpired(running.operationId),
    error("operation-not-found"),
  );

  time = 40;
  assert.throws(
    () => jobs.status(first, running.operationId),
    error("session-ended"),
  );
  calls.apply[0].resolve("uncertain");
  await wait();
  assert.equal(calls.apply.length, 1);
  const fresh = admit(a, b);
  await assert.rejects(jobs.inspect(fresh, [a]), error("target-busy"));
  assert.equal((await jobs.inspect(fresh, [b])).state, "planned");
  const recovery = operator.recoverExpired(running.operationId);
  const retry = operator.recoverExpired(running.operationId);
  assert.equal(calls.reconcile.length, 1);
  calls.reconcile[0].resolve("unchanged");
  assert.deepEqual(await recovery, await retry);
  assert.equal((await recovery).state, "unchanged");
  assert.equal((await jobs.inspect(fresh, [a])).state, "planned");
  await assert.rejects(
    operator.recoverExpired(running.operationId),
    error("operation-not-found"),
  );
});

test("worker revisions reach apply unchanged and a stale inspection cannot be replayed", async () => {
  const { admit, approve, calls, jobs } = fixture();
  const token = admit(a);
  const plan = await jobs.inspect(token, [a]);
  const running = approve(token, plan);
  assert.equal(calls.apply[0].input.targets[0].revision, revision);
  calls.apply[0].resolve("stale");
  await wait();
  assert.deepEqual(approve(token, plan), { ...running, state: "stale" });
  assert.notEqual((await jobs.inspect(token, [a])).planId, plan.planId);
  assert.equal(calls.apply.length, 1);
});

test("invalid inspection results fail closed and occupied nodes never produce an approval plan", async () => {
  let malformed = true;
  const worker = {
    inspect({ targetIds }) {
      return targetIds.map((id) => ({
        id: malformed ? b : id,
        state: "occupied",
        revision,
      }));
    },
    apply() {
      throw new Error("unexpected apply");
    },
    reconcile() {
      throw new Error("unexpected reconciliation");
    },
  };
  const { admit, approve, jobs } = fixture({
    worker,
    maxOperationsPerSession: 1,
  });
  const token = admit(a);
  await assert.rejects(jobs.inspect(token, [a]), error("inspection-failed"));
  malformed = false;
  const blocked = await jobs.inspect(token, [a]);
  assert.equal(blocked.state, "blocked");
  assert.equal(blocked.planId, null);
  assert.throws(() => approve(token, blocked), error("plan-mismatch"));
  await assert.rejects(jobs.inspect(token, [a]), error("busy"));
});
