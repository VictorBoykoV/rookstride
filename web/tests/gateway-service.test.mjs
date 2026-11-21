import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gatewayMessage } from "../src/lib/gateway-messages.ts";
import {
  readServerRecord,
  readUbuntuRecovery,
  singleProtocolCatalog,
  ubuntuEraseConfirmation,
} from "../src/lib/gateway-input.mjs";
import { handleGateway } from "../src/lib/gateway-http.mjs";
import {
  createGatewayService,
  publicDestination,
} from "../src/lib/gateway-service.mjs";
import { createHostedUbuntu, hostedServerMatches } from "../src/lib/hosted-ubuntu.mjs";

const target = "192.0.2.10"; // Transport replaced; this address is refused by the real API.
const pin = "SHA256:" + Buffer.alloc(32).toString("base64").replace(/=+$/, "");
const inspect = {
  action: "inspect",
  address: target,
  sshPort: 22,
  password: "test-only",
  fingerprint: pin,
};
const install = {
  action: "install",
  login: "owner",
  vpnPassword: "sample.only.for.tests",
  confirmed: true,
};
const wait = () => new Promise((resolve) => setImmediate(resolve));

test("route preserves a safe gateway error from a long-lived service after code reload", async () => {
  const { GatewayError } =
    await import("../src/lib/gateway-service.mjs?new-module");
  const response = await handleGateway(
    new Request("http://localhost:3100/api/gateway"),
    {
      get() {
        throw new GatewayError(409, "rosterChanged");
      },
    },
  );
  assert.equal(response.status, 409);
  assert.equal((await response.json()).messageKey, "rosterChanged");
});
function harness(answer, options) {
  const calls = [];
  let stopped = 0;
  const app = createGatewayService(
    () => ({
      async request(input) {
        calls.push(input.action);
        return await answer(input);
      },
      stop() {
        stopped++;
      },
    }),
    (ip) => ip === target,
    options,
  );
  return { app, calls, stopped: () => stopped };
}
test("VPN removal binds the current review to its session and applies it at most once", async () => {
  const remoteToken = "a".repeat(64);
  let finish;
  const { app, calls } = harness((input) => {
    if (input.action === "inspect")
      return { state: "installed", os: "Ubuntu 24.04" };
    if (input.action === "removeReview") return { token: remoteToken };
    assert.deepEqual(input, {
      action: "removeApply",
      token: remoteToken,
      confirmation: "DELETE VPN",
    });
    return new Promise((resolve) => {
      finish = resolve;
    });
  });
  const { session } = await app.post(inspect);
  const first = await app.post({ action: "removeReview" }, session);
  const plan = await app.post({ action: "removeReview" }, session);
  assert.deepEqual(Object.keys(plan), ["review"]);
  assert.notEqual(plan.review, remoteToken);
  const apply = {
    action: "removeApply",
    review: plan.review,
    confirmation: "DELETE VPN",
  };
  await assert.rejects(app.post({ ...apply, review: first.review }, session), {
    messageKey: "removalReviewRequired",
  });
  await assert.rejects(
    app.post({ ...apply, confirmation: "DELETE" }, session),
    { messageKey: "invalidMaintenanceDetails" },
  );
  await assert.rejects(app.post(apply, "another-session"), {
    messageKey: "sessionEnded",
  });
  assert.equal((await app.post(apply, session)).state, "removing");
  assert.equal((await app.post(apply, session)).state, "removing");
  await assert.rejects(app.post({ action: "close" }, session), {
    messageKey: "operationBusy",
  });
  finish({ state: "removed" });
  await wait();
  assert.equal(app.get(session).state, "removed");
  assert.equal((await app.post(apply, session)).state, "removed");
  assert.equal(calls.filter((action) => action === "removeApply").length, 1);
  await app.post({ action: "close" }, session);
});

test("Ubuntu compatibility returns only a bounded safety result", async () => {
  const { app, calls } = harness(({ action }) =>
    action === "inspect"
      ? { state: "removed", os: "Ubuntu 26.04" }
      : {
          eligible: true,
          diskBytes: 16 * 1024 ** 3,
          boot: "EFI",
          diskId: "private",
        },
  );
  const { session } = await app.post(inspect);
  const check = await app.post({ action: "ubuntuCheck" }, session);
  assert.deepEqual(check, {
    eligible: true,
    diskBytes: 16 * 1024 ** 3,
    boot: "EFI",
  });
  assert.deepEqual(calls, ["inspect", "ubuntuCheck"]);
  await app.post({ action: "close" }, session);
});

test("Ubuntu erase preserves the reviewed replacement key and never repeats a lost apply", async () => {
  const future = "SHA256:" + Buffer.alloc(32, 2).toString("base64").replace(/=+$/, "");
  const job = "f".repeat(32);
  const planToken = "c".repeat(64);
  const { app, calls } = harness(async (input) => {
    if (input.action === "inspect") return { state: "occupied", os: "Ubuntu 24.04" };
    if (input.action === "ubuntuReview") {
      assert.equal(input.ubuntu, "26.04");
      return { ubuntu: input.ubuntu, token: planToken, job, fingerprint: future, boot: "EFI", diskBytes: 8 * 1024 ** 3, privateDiskId: "fixture" };
    }
    if (input.action === "ubuntuApply") {
      assert.deepEqual(input, {
        action: "ubuntuApply",
        job,
        fingerprint: future,
        token: planToken,
        confirmation: ubuntuEraseConfirmation,
      });
      throw new Error("SSH disconnected before the apply reply");
    }
    throw new Error("unexpected");
  }, { ubuntuReinstall: true });
  const { session } = await app.post(inspect);
  const review = await app.post({ action: "ubuntuReview", ubuntu: "26.04" }, session);
  assert.deepEqual(Object.keys(review), ["review", "recovery", "diskBytes", "boot"]);
  assert.deepEqual(readUbuntuRecovery(review.recovery), review.recovery);
  assert.equal(review.recovery.server.fingerprint, pin);
  assert.equal(review.recovery.fingerprint, future);
  assert.ok(!JSON.stringify(review).includes(planToken));
  const apply = { action: "ubuntuApply", review: review.review, confirmation: ubuntuEraseConfirmation };
  await assert.rejects(app.post({ ...apply, confirmation: "DELETE VPN" }, session), { messageKey: "invalidUbuntuReinstall" });
  await assert.rejects(app.post({ ...apply, review: "stale" }, session), { messageKey: "ubuntuReviewExpired" });
  await assert.rejects(app.post(apply, "another-session"), { messageKey: "sessionEnded" });
  assert.equal((await app.post(apply, session)).state, "ubuntuReinstalling");
  await wait();
  assert.equal((await app.post(apply, session)).state, "ubuntuReinstalling");
  await assert.rejects(app.post({ action: "close" }, session), { messageKey: "ubuntuReinstalling" });
  assert.equal(calls.filter((action) => action === "ubuntuApply").length, 1);

  let state = "keyMismatch";
  const recoveredApp = harness(async (input) => {
    if (input.action === "ubuntuResume") {
      const { action, password, ...recovery } = input;
      assert.equal(password, inspect.password);
      assert.deepEqual(recovery, review.recovery);
      return { state };
    }
    assert.equal(input.keyType, "ecdsa-sha2-nistp256");
    return { state: "ready", os: "Ubuntu 26.04" };
  }, { ubuntuReinstall: true });
  const resume = { action: "ubuntuResume", recovery: review.recovery, password: inspect.password };
  assert.deepEqual(await recoveredApp.app.post(resume), { state });
  state = "unverified";
  assert.deepEqual(await recoveredApp.app.post(resume), { state });
  state = "complete";
  const verified = await recoveredApp.app.post(resume);
  assert.deepEqual(verified, {
    state: "complete",
    ubuntu: "26.04",
    server: { version: 2, address: target, sshPort: 22, fingerprint: future, keyType: "ecdsa-sha2-nistp256" },
  });
  assert.deepEqual(readServerRecord(verified.server), verified.server);
  const { session: replacement, connection } = await recoveredApp.app.post({
    ...inspect,
    fingerprint: verified.server.fingerprint,
    keyType: verified.server.keyType,
  });
  assert.deepEqual(connection, verified.server);
  await recoveredApp.app.post({ action: "close" }, replacement);
});

test("hosted configuration cannot review an erase or select the recovery key algorithm", async () => {
  const { app, calls } = harness(() => ({ state: "installed", os: "Ubuntu 24.04" }));
  const { session } = await app.post(inspect);
  await assert.rejects(app.post({ action: "ubuntuReview", ubuntu: "26.04" }, session), { messageKey: "unknownAction" });
  await assert.rejects(app.post({ ...inspect, keyType: "ecdsa-sha2-nistp256" }), { messageKey: "invalidServerDetails" });
  assert.deepEqual(calls, ["inspect"]);
  await app.post({ action: "close" }, session);
});

test("a configured ECDSA pin works without enabling Ubuntu replacement", async () => {
  const keyType = "ecdsa-sha2-nistp256";
  const { app } = harness((request) => {
    assert.equal(request.keyType, keyType);
    assert.equal(request.fingerprint, pin);
    return { state: "installed", os: "Ubuntu 24.04" };
  }, { allowEcdsa: true });
  const { session } = await app.post({ ...inspect, keyType });
  await assert.rejects(app.post({ action: "ubuntuReview", ubuntu: "26.04" }, session), { messageKey: "unknownAction" });
  await app.post({ action: "close" }, session);
});

test("hosted recovery survives restart, refuses forged jobs, and promotes only the verified replacement", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "rookstride-hosted-recovery-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const initial = { version: 1, address: target, sshPort: 22, fingerprint: pin };
  const fingerprint = "SHA256:" + "B".repeat(43);
  const token = "f".repeat(64);
  const job = "e".repeat(32);
  const reviewRequest = { action: "ubuntuReview", ubuntu: "24.04" };
  let applies = 0;
  let resumes = 0;
  let report = { state: "keyMismatch" };
  function launch() {
    const hostedUbuntu = createHostedUbuntu(directory, initial);
    return createGatewayService(() => ({
      async request(input) {
        if (input.action === "inspect") return { state: "ready", os: "Ubuntu 24.04" };
        if (input.action === "ubuntuReview")
          return { job, fingerprint, ubuntu: input.ubuntu, token, boot: "EFI", diskBytes: 8 * 1024 ** 3 };
        if (input.action === "ubuntuApply") {
          applies++;
          assert.equal(hostedUbuntu.load().pending.job, job);
          throw new Error("Lost SSH acknowledgement");
        }
        assert.equal(input.action, "ubuntuResume");
        resumes++;
        return report;
      },
      stop() {},
    }), (_ip, input) => hostedServerMatches(hostedUbuntu.load().current, input), { hostedUbuntu });
  }
  let app = launch();
  const enter = { action: "ubuntuRecovery" };
  assert.deepEqual(await app.post(enter), { recovery: null, server: null });
  const { session } = await app.post(inspect);
  const { review, recovery } = await app.post(reviewRequest, session);
  const apply = { action: "ubuntuApply", review, confirmation: ubuntuEraseConfirmation };
  await assert.rejects(app.post({ ...apply, confirmation: "DELETE VPN" }, session), { messageKey: "invalidUbuntuReinstall" });
  assert.deepEqual(await app.post(enter), { recovery: null, server: null });
  await app.post(apply, session);
  await app.post(apply, session);
  assert.equal(applies, 1);
  const path = join(directory, "ubuntu-recovery.json");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  const saved = readFileSync(path, "utf8");
  assert.ok(!saved.includes(token) && !saved.includes(inspect.password));

  app = launch();
  assert.deepEqual(await app.post(enter), { recovery, server: null });
  await assert.rejects(app.post(inspect), { messageKey: "ubuntuReinstalling" });
  const resume = { action: "ubuntuResume", recovery, password: inspect.password };
  for (const forged of [
    { ...recovery, fingerprint: "SHA256:" + "C".repeat(43) },
    { ...recovery, job: "0".repeat(32) },
    { ...recovery, server: { ...initial, address: "192.0.2.20" } },
  ]) {
    await assert.rejects(app.post({ ...resume, recovery: forged }), { messageKey: "ubuntuRecoveryChanged" });
  }
  assert.equal(resumes, 0);
  assert.deepEqual(await app.post(resume), { state: "keyMismatch" });
  report = { state: "failed" };
  assert.deepEqual(await app.post(resume), { state: "providerRecovery" });
  assert.deepEqual(await app.post(enter), { recovery, server: null });
  report = { state: "unverified" };
  assert.deepEqual(await app.post(resume), report);
  report = { state: "complete" };
  const verified = await app.post(resume);
  assert.equal(verified.server.fingerprint, fingerprint);
  assert.equal(verified.server.keyType, "ecdsa-sha2-nistp256");
  app = launch();
  assert.deepEqual(await app.post(enter), { recovery: null, server: verified.server });
  assert.deepEqual(await app.post(resume), verified);
  assert.equal(resumes, 4);
  assert.equal(applies, 1);
  await assert.rejects(app.post(inspect), { messageKey: "invalidServerDetails" });
  const fresh = await app.post({ ...inspect, fingerprint, keyType: verified.server.keyType });
  assert.deepEqual(fresh.connection, verified.server);
  await app.post({ action: "close" }, fresh.session);
});

test("hosted recovery releases the original pin after an original-system terminal receipt", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "rookstride-hosted-expired-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const initial = { version: 1, address: target, sshPort: 22, fingerprint: pin };
  const store = createHostedUbuntu(directory, initial);
  const recovery = { job: "d".repeat(32), server: initial, fingerprint: "SHA256:" + "B".repeat(43), ubuntu: "24.04" };
  store.begin(recovery);
  assert.equal(store.finish(recovery, { state: "expired", original: true }), true);
  assert.deepEqual(createHostedUbuntu(directory, initial).load(), {
    current: initial,
    pending: null,
    last: { job: recovery, state: "expired" },
  });
});

test("native gateway DNS, usage and administration use the verified protocol session", async () => {
  const dns = { presets: ["standard"], queries: 12, blocked: 3, protectionEnabled: true };
  const usage = { available: true, kind: "sessions", scope: "daemon", profiles: 2, upload: 100, download: 200 };
  let privateUsage = false;
  const { app, calls } = harness(({ action, enabled, method }) => {
    if (action === "inspect")
      return { state: "protocolInstalled", method: "hysteria2", port: 443, os: "Ubuntu 24.04" };
    if (action === "protocolFilter") return { ...dns, protectionEnabled: enabled ?? true };
    if (action === "protocolUsage")
      return privateUsage ? { ...usage, ip: "fixture" } : usage;
    assert.equal(action, "administrationStatus");
    assert.equal(method, "hysteria2");
    return { state: "notRegistered" };
  }, { scopedAdministration: true });
  const { session } = await app.post(inspect);
  await assert.rejects(app.post({ action: "protocolFilter", enabled: false }, session), { messageKey: "invalidMaintenanceDetails" });
  await assert.rejects(app.post({ action: "administrationStatus", method: "xray" }, session), { messageKey: "invalidMaintenanceDetails" });
  assert.deepEqual(calls, ["inspect"]);
  assert.deepEqual(await app.post({ action: "protocolFilter" }, session), { filtering: dns });
  assert.deepEqual(await app.post({ action: "protocolFilter", enabled: false, confirmed: true }, session), {
    filtering: { ...dns, protectionEnabled: false },
  });
  assert.deepEqual(await app.post({ action: "protocolUsage" }, session), { usage });
  privateUsage = true;
  await assert.rejects(app.post({ action: "protocolUsage" }, session), { messageKey: "maintenanceResultUnknown" });
  assert.deepEqual(await app.post({ action: "administrationStatus" }, session), { state: "notRegistered" });
  await app.post({ action: "close" }, session);

  const hosted = harness(() => ({ state: "protocolInstalled", method: "xray", port: 443, os: "Ubuntu 24.04" }));
  const opened = await hosted.app.post(inspect);
  await assert.rejects(hosted.app.post({ action: "administrationStatus" }, opened.session), { messageKey: "unknownAction" });
  assert.deepEqual(hosted.calls, ["inspect"]);
  await hosted.app.post({ action: "close" }, opened.session);
});

test("VLESS setup keeps its reviewed port and owner and protects profile exports", async () => {
  let pending;
  const login = "vless-owner";
  const configuration =
    "vless://c8ecf4bc-2b0d-48b8-9c56-952cc1630fe0@" +
    target +
    ":443?security=reality&type=tcp#" +
    login;
  const { app, calls } = harness((input) => {
    if (input.action === "inspect")
      return { state: "removed", os: "Ubuntu 24.04" };
    if (input.action === "protocolReview") return { port: 443 };
    if (input.action === "protocolApply") {
      assert.deepEqual(input, {
        action: "protocolApply",
        port: 443,
        login,
        method: "xray",
      });
      return new Promise((resolve) => {
        pending = resolve;
      });
    }
    if (input.action === "protocolStatus")
      return { state: "protocolInstalled", method: "xray", port: 443 };
    return { configuration, method: "xray", port: 443 };
  });
  const { session } = await app.post(inspect);
  const { review } = await app.post(
    { action: "protocolReview", login },
    session,
  );
  const apply = { action: "protocolApply", review, confirmed: true };
  await assert.rejects(app.post({ ...apply, port: 80 }, session), {
    messageKey: "invalidMaintenanceDetails",
  });
  const installJob = app.post(apply, session);
  await assert.rejects(
    app.post({ action: "protocolProfile", login }, session),
    { messageKey: "verifiedSessionRequired" },
  );
  pending({ state: "protocolRunning", method: "xray" });
  assert.equal((await installJob).state, "protocolRunning");
  assert.equal((await app.post(apply, session)).state, "protocolRunning");
  assert.equal(
    (await app.post({ action: "protocolStatus" }, session)).state,
    "protocolInstalled",
  );
  assert.deepEqual(
    await app.post({ action: "protocolProfile", login }, session),
    { configuration, filename: "rookstride-vless-owner.txt" },
  );
  await assert.rejects(
    app.post({ action: "protocolProfile", login: "another" }, session),
    { messageKey: "maintenanceResultUnknown" },
  );
  assert.equal(calls.filter((action) => action === "protocolApply").length, 1);
  await app.post({ action: "close" }, session);
});

test("every native single-server method binds review to the right method and enforces hosted availability", async () => {
  for (const method of Object.keys(singleProtocolCatalog)) {
    const { app } = harness((input) => {
      if (input.action === "inspect")
        return { state: "ready", os: "Ubuntu 24.04" };
      assert.equal(input.method, method);
      if (input.action === "protocolReview") return { port: 8443 };
      assert.deepEqual(input, {
        action: "protocolApply",
        port: 8443,
        login: "owner",
        method,
      });
      return { state: "protocolRunning", method };
    });
    const { session, availableMethods } = await app.post(inspect);
    assert.deepEqual(availableMethods, Object.keys(singleProtocolCatalog));
    const { review } = await app.post(
      { action: "protocolReview", method, login: "owner" },
      session,
    );
    const result = await app.post(
      { action: "protocolApply", review, confirmed: true },
      session,
    );
    assert.equal(result.method, method);
    await app.post({ action: "close" }, session);
  }
  const { app } = harness(() => ({ state: "ready" }), {
    availableMethods: ["xray"],
  });
  const { session, availableMethods } = await app.post(inspect);
  assert.deepEqual(availableMethods, ["xray"]);
  await assert.rejects(
    app.post(
      { action: "protocolReview", method: "xhttp", login: "owner" },
      session,
    ),
    { messageKey: "invalidMaintenanceDetails" },
  );
  await app.post({ action: "close" }, session);
});

test("a missing runtime before apply permits a fresh installation review", async () => {
  const { app } = harness((input) => {
    if (input.action === "inspect") return { state: "ready", os: "Ubuntu 24.04" };
    if (input.action === "protocolReview") return { port: 8443 };
    return { state: "runtimeUnavailable" };
  });
  const { session } = await app.post(inspect);
  const request = { action: "protocolReview", method: "hysteria2", login: "owner" };
  const { review } = await app.post(request, session);
  await assert.rejects(app.post({ action: "protocolApply", review, confirmed: true }, session), {
    messageKey: "protocolRuntimeUnavailable",
  });
  const second = await app.post(request, session);
  assert.notEqual(second.review, review);
  await app.post({ action: "close" }, session);
});

test("personal gateway refuses internal, metadata, documentation, encoded and nonliteral destinations", () => {
  for (const ip of [
    "127.0.0.1",
    "localhost",
    "::ffff:127.0.0.1",
    "0x7f000001",
    "100.64.0.1",
    "169.254.169.254",
    "168.63.129.16",
    "10.0.0.1",
    "172.31.1.2",
    "192.168.1.1",
    target,
    "198.18.1.2",
    "203.0.113.20",
    "224.0.0.1",
  ])
    assert.equal(publicDestination(ip), false, ip);
});
test("sessions bind one inspected target and start a confirmed install exactly once", async () => {
  let finish;
  const { app, calls, stopped } = harness((req) =>
    req.action === "install"
      ? new Promise((res) => {
          finish = res;
        })
      : { state: "ready", os: "Ubuntu 26.04" },
  );
  const checked = await app.post(inspect);
  const token = checked.session;
  assert.equal(checked.os, "Ubuntu 26.04");
  assert.equal(token.length, 43);
  assert.throws(
    () => app.get("different"),
    (e) => e.status === 401,
  );
  await assert.rejects(app.post(inspect), (e) => e.status === 409);
  await assert.rejects(
    app.post({ ...install, confirmed: false }, token),
    (e) => e.status === 400,
  );
  await assert.rejects(
    app.post({ ...install, address: target }, token),
    (e) => e.status === 400,
  );
  await assert.rejects(
    app.post({ action: "profile" }, token),
    (e) => e.status === 409,
  );
  assert.equal((await app.post(install, token)).state, "running");
  assert.equal((await app.post(install, token)).state, "running");
  await assert.rejects(
    app.post({ action: "close" }, token),
    (e) => e.status === 409,
  );
  finish({ state: "installed", password: "never-echo-this" });
  await wait();
  assert.equal(app.get(token).state, "installed");
  assert.equal(JSON.stringify(app.get(token)).includes("never-echo"), false);
  await assert.rejects(
    app.post({ action: "profile" }, token),
    (e) => e.status === 502,
  );
  await app.post({ action: "close" }, token);
  assert.equal(stopped(), 1);
  assert.throws(
    () => app.get(token),
    (e) => e.status === 401,
  );
  assert.deepEqual(calls, ["inspect", "install", "profile"]);
});
test("two personal installs overlap with isolated workers and address reservations", async () => {
  const other = "198.51.100.20";
  const third = "203.0.113.30";
  const workers = [];
  const app = createGatewayService(
    () => {
      const worker = {
        install: Promise.withResolvers(),
        calls: [],
        stopped: false,
        request(input) {
          this.calls.push(input);
          if (input.action === "inspect") return { state: "ready" };
          return this.install.promise;
        },
        stop() {
          this.stopped = true;
        },
      };
      workers.push(worker);
      return worker;
    },
    (address) => [target, other, third].includes(address),
  );

  const firstCheck = app.post(inspect);
  await assert.rejects(app.post({ ...inspect, sshPort: 2222 }), {
    messageKey: "targetInUse",
  });
  const secondCheck = app.post({ ...inspect, address: other });
  const [first, second] = await Promise.all([firstCheck, secondCheck]);
  assert.notEqual(first.session, second.session);
  await assert.rejects(app.post({ ...inspect, address: third }), {
    messageKey: "sessionLimitReached",
  });
  assert.equal(workers.length, 2);
  assert.throws(() => app.get(undefined), { messageKey: "sessionEnded" });
  assert.equal(app.get(first.session).address, target);
  assert.equal(app.get(second.session).address, other);

  await Promise.all([
    app.post({ ...install, login: "first" }, first.session),
    app.post({ ...install, login: "second" }, second.session),
  ]);
  assert.equal(app.get(first.session).state, "running");
  assert.equal(app.get(second.session).state, "running");
  assert.deepEqual(
    workers.map(({ calls }) => calls[1].login),
    ["first", "second"],
  );

  workers[0].install.reject(new Error("test-only interrupted transport"));
  await wait();
  assert.equal(app.get(first.session).state, "indeterminate");
  assert.equal(app.get(second.session).state, "running");
  await app.post({ action: "close" }, first.session);
  assert.throws(() => app.get(first.session), { messageKey: "sessionEnded" });
  assert.equal(workers[0].stopped, true);
  assert.equal(workers[1].stopped, false);

  const thirdCheck = await app.post({ ...inspect, address: third });
  assert.equal(thirdCheck.state, "ready");
  workers[1].install.resolve({ state: "installed" });
  await wait();
  assert.equal(app.get(second.session).state, "installed");
  await app.post({ action: "close" }, second.session);
  await app.post({ action: "close" }, thirdCheck.session);
});
test("occupied and unsupported inspections release the worker without granting a session", async () => {
  for (const state of ["occupied", "unsupported"]) {
    const { app, stopped } = harness(() => ({ state }));
    assert.equal((await app.post(inspect)).session, undefined);
    assert.equal(stopped(), 1);
    await assert.rejects(
      app.post(install, "someone-else"),
      (e) => e.status === 401,
    );
  }
});
test("unknown install outcome never silently applies a second time", async () => {
  const { app, calls } = harness((req) => {
    if (req.action === "inspect") return { state: "ready" };
    throw new Error("remote-diagnostic");
  });
  const { session } = await app.post(inspect);
  await app.post(install, session);
  await wait();
  const result = await app.post(install, session);
  assert.equal(result.state, "indeterminate");
  assert.ok(!JSON.stringify(result).includes("remote-diagnostic"));
  assert.deepEqual(calls, ["inspect", "install"]);
  await app.post({ action: "close" }, session);
});
test("failed setups return stable presentation keys and discard all remote diagnostics", async () => {
  for (const [stage, messageKey, expected] of [
    ["installation", "installationFailed", /Ubuntu package sources/],
    [
      "verification",
      "verificationFailed",
      /did not pass the VPN, DNS and ad-filter checks/,
    ],
    ["untrusted message", "failed", /did not finish successfully/],
  ]) {
    const { app } = harness((req) =>
      req.action === "inspect"
        ? { state: "ready" }
        : { state: "failed", stage, message: "untrusted message" },
    );
    const { session } = await app.post(inspect);
    await app.post(install, session);
    await wait();
    const outcome = app.get(session);
    assert.equal(outcome.messageKey, messageKey);
    assert.match(outcome.message, expected);
    assert.equal(
      gatewayMessage({ [messageKey]: "alternate wording" }, outcome.messageKey),
      "alternate wording",
    );
    assert.ok(!JSON.stringify(outcome).includes("untrusted message"));
    await app.post({ action: "close" }, session);
  }
  assert.equal(gatewayMessage({}, "constructor", "fallback"), "fallback");
});
test("failed sign-ins are bounded and errors do not echo input or remote output", async () => {
  const { app, calls } = harness(() => {
    throw new Error("untrusted");
  });
  for (let i = 0; i < 5; i++)
    await assert.rejects(
      app.post(inspect),
      (e) =>
        e.status === 422 &&
        e.messageKey === "inspectionUnavailable" &&
        !e.message.includes(inspect.password),
    );
  await assert.rejects(app.post(inspect), (e) => e.status === 429);
  assert.equal(calls.length, 5);
});
test("account edits bind to a verified gateway and reviewed revision", async () => {
  const revision = "c".repeat(64);
  const inventory = { owner: "owner", guests: ["friend"], revision };
  const { app, calls } = harness((req) => {
    if (req.action === "inspect") return { state: "installed" };
    if (req.action === "revoke")
      return { state: "conflict", private: "server-output" };
    return { ...inventory, private: "never-return" };
  });
  const { session } = await app.post(inspect);
  assert.deepEqual(await app.post({ action: "guests" }, session), inventory);
  await assert.rejects(
    app.post(
      { action: "revoke", login: "friend", confirmed: false, revision },
      session,
    ),
    (e) => e.status === 400,
  );
  await assert.rejects(
    app.post(
      { action: "grant", login: "friend", vpnPassword: "one\ntwo", revision },
      session,
    ),
    (e) => e.status === 400,
  );
  const result = await app.post(
    {
      action: "grant",
      login: "friend",
      vpnPassword: "A long passphrase with spaces 🔑",
      revision,
    },
    session,
  );
  assert.deepEqual(result, inventory);
  await assert.rejects(
    app.post(
      { action: "revoke", login: "friend", confirmed: true, revision },
      session,
    ),
    (e) => e.status === 409 && !e.message.includes("server-output"),
  );
  assert.deepEqual(calls, ["inspect", "guests", "grant", "revoke"]);
  await app.post({ action: "close" }, session);
});

test("only a verified server can produce a portable connection record, without credentials", async () => {
  const { app } = harness(() => ({ state: "installed" }));
  const { session, connection } = await app.post(inspect);
  assert.deepEqual(readServerRecord(connection), {
    version: 1,
    address: target,
    sshPort: 22,
    fingerprint: pin,
  });
  assert.deepEqual(app.get(session).connection, connection);
  for (const invalid of [
    { ...connection, password: "unexpected" },
    { ...connection, address: "127.001.0.1" },
    { ...connection, address: "256.0.0.1" },
    { ...connection, sshPort: "22" },
    { ...connection, version: 2 },
  ])
    assert.equal(readServerRecord(invalid), null);
  await app.post({ action: "close" }, session);
});

test("live IKEv2 usage accepts only aggregate counters from the pinned session", async () => {
  let usage = { available: true, sessions: 2, upload: 1024, download: 4096 };
  const { app } = harness((request) =>
    request.action === "inspect" ? { state: "installed" } : usage,
  );
  const { session } = await app.post(inspect);
  await assert.rejects(app.post({ action: "usage" }, "other"), {
    messageKey: "sessionEnded",
  });
  assert.deepEqual(await app.post({ action: "usage" }, session), { usage });
  usage = { available: false };
  assert.deepEqual(await app.post({ action: "usage" }, session), { usage });
  usage = { available: true, sessions: 1, upload: 2, download: 3, endpoint: target };
  await assert.rejects(app.post({ action: "usage" }, session), {
    messageKey: "maintenanceResultUnknown",
  });
});

test("health snapshots, DNS presets and password changes are scoped to verified sessions", async () => {
  const health = { vpn: true, filter: true, resolver: false, firewall: true };
  const filtering = { presets: ["strict"], queries: 25, blocked: 8 };
  const revision = "d".repeat(64);
  const roster = {
    owner: "owner",
    guests: ["guest"],
    revision: "e".repeat(64),
  };
  const { app, calls } = harness((req) => {
    if (req.action === "inspect") return { state: "installed" };
    if (req.action === "health") return health;
    if (req.action === "filter") return filtering;
    if (req.action === "rotate")
      return req.revision === revision ? roster : { state: "conflict" };
    assert.fail(req.action);
  });
  const { session } = await app.post(inspect);
  await assert.rejects(app.post({ action: "health" }, "other"), {
    messageKey: "sessionEnded",
  });
  assert.deepEqual(await app.post({ action: "health" }, session), {
    services: health,
  });
  assert.deepEqual(await app.post({ action: "filter" }, session), {
    filtering,
  });
  for (const fields of [
    { level: "strict" },
    { level: "custom", confirmed: true },
  ]) {
    await assert.rejects(app.post({ action: "filter", ...fields }, session), {
      messageKey: "invalidMaintenanceDetails",
    });
  }
  assert.deepEqual(
    await app.post(
      { action: "filter", level: "strict", confirmed: true },
      session,
    ),
    { filtering },
  );
  await assert.rejects(
    app.post({ action: "filter", level: "strong", confirmed: true }, session),
    { messageKey: "maintenanceResultUnknown" },
  );
  const rotate = {
    action: "rotate",
    login: "guest",
    vpnPassword: "a new sample password",
    revision,
  };
  await assert.rejects(app.post(rotate, session), {
    messageKey: "invalidGuestDetails",
  });
  await assert.rejects(
    app.post(
      { ...rotate, confirmed: true, revision: roster.revision },
      session,
    ),
    { messageKey: "rosterChanged" },
  );
  assert.deepEqual(
    await app.post({ ...rotate, confirmed: true }, session),
    roster,
  );
  assert.deepEqual(calls, [
    "inspect",
    "health",
    "filter",
    "filter",
    "filter",
    "rotate",
    "rotate",
  ]);
  await app.post({ action: "close" }, session);
});

test("pair inspection uses two pinned workers, rejects aliases, and returns no identifiers or passwords", async () => {
  const exit = "198.51.100.15";
  const calls = [];
  const pending = Promise.withResolvers();
  let stopped = 0;
  let alias = false;
  const app = createGatewayService(
    () => ({
      async request(input) {
        calls.push(input.action);
        assert.equal(input.keyType, input.address === exit ? "ecdsa-sha2-nistp256" : undefined);
        await pending.promise;
        return {
          state: "ready",
          os: "Ubuntu 24.04",
          machine: (alias || input.address === target ? "a" : "b").repeat(64),
          private: input.password,
        };
      },
      stop() {
        stopped++;
      },
    }),
    (address) => [target, exit].includes(address),
    { pairPreflight: true },
  );
  const { action: _unused, ...entry } = inspect;
  const check = {
    action: "inspectPair",
    entry,
    exit: { ...entry, address: exit, keyType: "ecdsa-sha2-nistp256" },
  };
  await assert.rejects(app.post({ ...check, exit: entry }), {
    messageKey: "pairRequiresTwoServers",
  });
  assert.equal(calls.length, 0);
  const inProgress = app.post(check);
  await assert.rejects(app.post(check), { messageKey: "pairInspectionBusy" });
  await assert.rejects(app.post(inspect), {
    messageKey: "sessionLimitReached",
  });
  pending.resolve();
  const ready = { state: "ready", os: "Ubuntu 24.04" };
  assert.deepEqual(await inProgress, { entry: ready, exit: ready });
  assert.equal(stopped, 2);
  alias = true;
  await assert.rejects(app.post(check), {
    messageKey: "pairRequiresTwoServers",
  });
  assert.equal(stopped, 4);
  assert.deepEqual(calls, Array(4).fill("inspectPairNode"));
});
