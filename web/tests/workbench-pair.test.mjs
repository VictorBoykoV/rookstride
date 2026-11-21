import assert from "node:assert/strict";
import { setImmediate as flush } from "node:timers/promises";
import test from "node:test";
import { PairDeploymentError } from "../src/lib/pair-deployment.mjs";
import { handleGateway } from "../src/lib/gateway-http.mjs";
import { GatewayError } from "../src/lib/gateway-service.mjs";
import { createWorkbenchPair } from "../src/lib/workbench-pair.mjs";

const entry = { address: "192.0.2.1", sshPort: 22, fingerprint: "fixture-entry", password: "entry-ssh-fixture" };
const exit = { address: "198.51.100.1", sshPort: 22, fingerprint: "fixture-exit", password: "exit-ssh-fixture" };
const request = { action: "pairReview", entry, exit, login: "owner" };
const pairId = "a".repeat(32);
const plan = {
  pairId, login: "owner",
  entry: { address: entry.address, ubuntu: "24.04" },
  exit: { address: exit.address, ubuntu: "22.04" },
};
const deny = (status, messageKey) => { throw Object.assign(new Error(messageKey), { status, messageKey }); };

function fixture(options = {}) {
  let time = 0;
  const events = [];
  const api = createWorkbenchPair({
    canReserve: () => true,
    validateNode: () => true,
    reserveAttempts: (count) => events.push(count),
    deny,
    review: async () => plan,
    deploy: async () => ({ state: "installed", pairId }),
    profile: async () => ({ configuration: "profile fixture", filename: "fixture.conf" }),
    idleMs: 1000,
    now: () => time,
    ...options,
  });
  return { ...api, events, advance: (value = 1000) => { time += value; } };
}

test("review takes the shared reservation before contacting either server", async () => {
  const inspecting = Promise.withResolvers();
  const api = fixture({ review: () => inspecting.promise });
  const inspection = api.post(request);
  assert.equal(api.active(), true);
  await assert.rejects(api.post(request), { status: 409, message: "pairInspectionBusy" });
  await assert.rejects(api.post({ action: "pairStatus" }, "other-token"), { status: 401 });
  inspecting.resolve(plan);
  const result = await inspection;
  assert.match(result.session, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(result.pair, {
    entry: { address: entry.address, os: "Ubuntu 24.04" },
    exit: { address: exit.address, os: "Ubuntu 22.04" },
    login: "owner",
  });
  assert.deepEqual(api.events, [2]);
  await assert.rejects(api.post({ action: "pairStatus" }, "other-token"), { status: 401 });
  assert.deepEqual(await api.post({ action: "pairStatus" }, result.session), { state: "reviewed" });
  assert.deepEqual(await api.post({ action: "pairClose" }, result.session), { state: "closed" });
  assert.equal(api.active(), false);
});

test("invalid or unsupported requests and unavailable workers never reserve", async () => {
  const api = fixture({ canReserve: () => false });
  await assert.rejects(api.post({ ...request, token: "inject" }), { status: 400 });
  await assert.rejects(api.post({ ...request, exit: { ...exit, address: entry.address } }), { status: 400 });
  await assert.rejects(api.post({ ...request, login: "" }), { status: 400 });
  await assert.rejects(api.post({ action: "pairDelete" }), { status: 400 });
  await assert.rejects(api.post(request, "already-open"), { status: 409, message: "sessionAlreadyOpen" });
  await assert.rejects(api.post(request), { status: 409, message: "pairInspectionBusy" });
  assert.equal(api.active(), false);

  const failed = fixture({ review: async () => { throw new PairDeploymentError("ssh-pin-mismatch", "preflight"); } });
  await assert.rejects(failed.post(request), { status: 409, message: "identityMismatch" });
  assert.equal(failed.active(), false);
});

test("mixed exits require an explicitly enabled browser workspace", async () => {
  for (const exitProtocol of ["openvpn", "ikev2", "xray"]) {
    const mixed = { ...request, exitProtocol };
    await assert.rejects(fixture().post(mixed), { status: 400 });
    const isolated = fixture({
      ...(exitProtocol === "openvpn"
        ? { rebuild: { journalStatus: () => null } }
        : { allowMixedExits: true }),
      review: async (input) => {
        assert.equal(input.exitProtocol, exitProtocol);
        return { ...plan, exitProtocol };
      },
    });
    await assert.rejects(isolated.post({ ...mixed, exitProtocol: "wireguard" }), { status: 400 });
    const verified = await isolated.post(mixed);
    assert.equal(verified.pair.exitProtocol, exitProtocol);
    await isolated.post({ action: "pairClose" }, verified.session);
  }
});

test("the expanded workspace binds both methods and scopes IKEv2 passwords to mutations", async () => {
  const route = { entryProtocol: "ikev2", exitProtocol: "xhttp" };
  const password = "owner-password-fixture";
  const guestPassword = "guest-password-fixture";
  const revision = "e".repeat(64);
  const api = fixture({
    allowAllPairMethods: true,
    allowMixedExits: true,
    review: async (input) => {
      assert.equal(input.entryProtocol, route.entryProtocol);
      assert.equal(input.exitProtocol, route.exitProtocol);
      return { ...plan, ...route };
    },
    deploy: async ({ password: supplied }) => {
      assert.equal(supplied, password);
      return { state: "installed", pairId };
    },
    account: async ({ operation, login, password: supplied }) => {
      assert.equal(operation, "grant");
      assert.equal(login, "guest");
      assert.equal(supplied, guestPassword);
      return { users: ["owner", "guest"] };
    },
  });
  await assert.rejects(fixture({ allowMixedExits: true }).post({ ...request, ...route }), { status: 400 });
  const reviewed = await api.post({ ...request, ...route });
  const { session } = reviewed;
  assert.equal(reviewed.pair.entryProtocol, route.entryProtocol);
  assert.equal(reviewed.pair.exitProtocol, route.exitProtocol);
  const install = { action: "pairApply", confirmed: true };
  await assert.rejects(api.post(install, session), { status: 400, message: "invalidInstallDetails" });
  await assert.rejects(api.post({ ...install, vpnPassword: password }, "foreign"), { status: 401 });
  await api.post({ ...install, vpnPassword: password }, session);
  await flush();
  assert.deepEqual(await api.post({ action: "pairStatus" }, session), { state: "installed", stage: "health" });
  const guest = { action: "pairAccount", operation: "grant", login: "guest", revision, confirmed: true };
  await assert.rejects(api.post(guest, session), { status: 400, message: "invalidInstallDetails" });
  await assert.rejects(api.post({ ...guest, operation: "revoke", vpnPassword: guestPassword }, session), { status: 400 });
  assert.deepEqual(await api.post({ ...guest, vpnPassword: guestPassword }, session), { users: ["owner", "guest"] });
  await api.post({ action: "pairClose" }, session);
});

test("approval is one-time and a job stays reserved past idle expiration", async () => {
  const running = Promise.withResolvers();
  let update;
  let count = 0;
  const api = fixture({ deploy: (input) => {
    assert.equal(input.review, plan);
    update = input.onProgress;
    count++;
    return running.promise;
  } });
  const { session } = await api.post(request);
  await assert.rejects(api.post({ action: "pairProfile" }, session), { status: 409 });
  await assert.rejects(api.post({ action: "pairApply", confirmed: false }, session), { status: 400 });
  await assert.rejects(api.post({ action: "pairApply", confirmed: true }, "other-token"), { status: 401 });
  assert.deepEqual(await api.post({ action: "pairApply", confirmed: true }, session), { state: "installing", stage: "preflight" });
  update({ stage: "exit-bootstrap" });
  update({ stage: "private-fixture-secret" });
  api.advance();
  assert.equal(api.active(), true);
  assert.deepEqual(await api.post({ action: "pairStatus" }, session), { state: "installing", stage: "exit-bootstrap" });
  await assert.rejects(api.post({ action: "pairClose" }, session), { status: 409, message: "operationBusy" });
  await assert.rejects(api.post({ action: "pairApply", confirmed: true }, session), { status: 409 });
  assert.equal(count, 1);
  running.resolve({ state: "installed", pairId });
  await flush();
  assert.deepEqual(await api.post({ action: "pairStatus" }, session), { state: "installed", stage: "health" });
  assert.deepEqual(await api.post({ action: "pairProfile" }, session), { configuration: "profile fixture", filename: "fixture.conf" });
  api.advance();
  assert.equal(api.active(), false);
  await assert.rejects(api.post({ action: "pairProfile" }, session), { status: 401 });
});

test("an uncertain deployment drops credentials and keeps the reservation until explicit close", async () => {
  const failed = fixture({
    deploy: async () => { throw new PairDeploymentError("interrupted", "exit-bootstrap", true); },
  });
  const { session } = await failed.post(request);
  await failed.post({ action: "pairApply", confirmed: true }, session);
  await flush();
  failed.advance();
  assert.deepEqual(await failed.post({ action: "pairStatus" }, session), { state: "needsAttention", stage: "preflight", uncertain: true });
  assert.equal(failed.active(), true);
  await assert.rejects(failed.post(request), { status: 409 });
  await assert.rejects(failed.post({ action: "pairProfile" }, session), { status: 409 });
  await failed.post({ action: "pairClose" }, session);
  assert.equal(failed.active(), false);

  const certain = fixture({
    deploy: async () => { throw new PairDeploymentError("review-mismatch", "preflight"); },
  });
  const { session: other } = await certain.post(request);
  await certain.post({ action: "pairApply", confirmed: true }, other);
  await flush();
  assert.deepEqual(await certain.post({ action: "pairStatus" }, other), { state: "needsAttention", stage: "preflight" });
  certain.advance();
  assert.equal(certain.active(), false);
});

test("adoption reconnects ownership and binds management, exports and removal to its session", async () => {
  const revision = "b".repeat(64);
  const events = [];
  const view = { owner: "owner", users: ["owner", "guest"], revision, entryHealthy: true, exitHealthy: true, dnsHealthy: true };
  const removal = { entry: "private entry receipt", exit: "private exit receipt" };
  const running = Promise.withResolvers();
  const api = fixture({
    async adopt() { return plan; },
    async manage() { return view; },
    async account({ operation, login, revision: current }) {
      if (current !== revision) throw new PairDeploymentError("roster-changed", "health");
      events.push([operation, login]);
      return view;
    },
    async removalReview() { return removal; },
    async remove({ removal: approved }) {
      assert.equal(approved, removal);
      events.push("remove");
      return running.promise;
    },
  });
  const opened = await api.post({ action: "pairAdopt", entry, exit });
  assert.equal(opened.state, "installed");
  assert.doesNotMatch(JSON.stringify(opened), /ssh-fixture/);
  const { session } = opened;
  await assert.rejects(api.post({ action: "pairManage" }, "foreign"), { status: 401 });
  assert.deepEqual(await api.post({ action: "pairManage" }, session), view);
  const account = { action: "pairAccount", operation: "revoke", login: "guest", revision, confirmed: true };
  await assert.rejects(api.post({ ...account, revision: "d".repeat(64) }, session), { status: 409, message: "rosterChanged" });
  const oldReview = await api.post({ action: "pairRemoveReview" }, session);
  await api.post(account, session);
  await assert.rejects(api.post({ action: "pairRemoveApply", ...oldReview, confirmation: "DELETE PAIR" }, session), { status: 409 });
  const review = await api.post({ action: "pairRemoveReview" }, session);
  assert.match(review.review, /^[A-Za-z0-9_-]{32}$/);
  const apply = { action: "pairRemoveApply", ...review, confirmation: "DELETE PAIR" };
  await assert.rejects(api.post(apply, "foreign"), { status: 401 });
  assert.deepEqual(await api.post(apply, session), { state: "removing" });
  await assert.rejects(api.post({ action: "pairClose" }, session), { status: 409 });
  running.resolve({ state: "removed" });
  await flush();
  assert.deepEqual(await api.post(apply, session), { state: "removed" });
  assert.deepEqual(events, [["revoke", "guest"], "remove"]);
  await api.post({ action: "pairClose" }, session);
});

test("only an authenticated pair rehearsal may use the larger HTTP request limit", async () => {
  const api = fixture({
    adopt: async () => plan,
    deny(status, key) { throw new GatewayError(status, key); },
  });
  const { session } = await api.post({ action: "pairAdopt", entry, exit });
  const rehearse = { action: "pairRehearse", archive: "a".repeat(3000), password: "fixture-passphrase", confirmed: true };
  const post = (token, body, recovery = true) => handleGateway(new Request("https://test.example/vpn/api", {
    method: "POST",
    headers: {
      "Content-Type": "application/json", Authorization: `Bearer ${token}`,
      ...(recovery && { "X-Rookstride-Recovery": "1" }),
    },
    body: JSON.stringify(body),
  }), api);
  assert.equal((await post("x".repeat(43), rehearse)).status, 413);
  assert.equal((await post(session, rehearse, false)).status, 413);
  assert.equal((await post(session, { ...rehearse, action: "pairManage" })).status, 413);
  const malformed = await post(session, rehearse);
  assert.equal(malformed.status, 409);
  assert.equal(malformed.headers.get("Cache-Control"), "no-store");
  assert.equal((await malformed.json()).messageKey, "pairRecoveryUnavailable");
  await api.post({ action: "pairClose" }, session);
});
