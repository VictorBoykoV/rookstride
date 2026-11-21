import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { setImmediate as flush } from "node:timers/promises";
import test from "node:test";
import { androidRelease } from "../src/lib/android-release.mjs";
import {
  configuredPilotMethods,
  createEnrolledPairService,
  handleHostedGateway,
  isolatedPairRebuild,
  parsePilotEnrollments,
  pilotRequestStatus,
} from "../src/lib/pilot-access.mjs";
import { createGatewayService } from "../src/lib/gateway-service.mjs";
import { createWorkbenchPair } from "../src/lib/workbench-pair.mjs";
import { pairRebuildConfirmation } from "../src/lib/pair-rebuild.mjs";
import {
  indexableSitePaths,
  isLoopbackRequest,
  mcpBrowserRequest,
  personalGatewayEnabled,
  publicReaderRoute,
  webRuntimeRole,
} from "../src/lib/web-runtime.mjs";

test("only an HTML navigation gets the browser representation of MCP", () => {
  const request = (accept, method = "GET", headers = {}) =>
    new Request("https://example.org/mcp", {
      method,
      headers: { Accept: accept, ...headers },
    });
  for (const accept of [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Text/HTML;q=0.8,text/event-stream;q=0",
  ])
    assert.equal(mcpBrowserRequest(request(accept)), true, accept);
  for (const accept of [
    "",
    "*/*",
    "application/json",
    "text/event-stream",
    "text/html,text/event-stream",
    "text/html;q=0,*/*",
  ])
    assert.equal(mcpBrowserRequest(request(accept)), false, accept);
  for (const method of ["POST", "DELETE"])
    assert.equal(mcpBrowserRequest(request("text/html", method)), false);
  for (const header of [
    "MCP-Protocol-Version",
    "MCP-Session-Id",
    "Last-Event-ID",
  ])
    assert.equal(
      mcpBrowserRequest(request("text/html", "GET", { [header]: "fixture" })),
      false,
      header,
    );
});

test("hosting roles cannot enable personal execution through the workstation flag", (context) => {
  const original = process.env.ROOKSTRIDE_HOSTED_SITE;
  const originalPersonal = process.env.ROOKSTRIDE_PERSONAL_WEB;
  context.after(() => {
    if (original === undefined) delete process.env.ROOKSTRIDE_HOSTED_SITE;
    else process.env.ROOKSTRIDE_HOSTED_SITE = original;
    if (originalPersonal === undefined)
      delete process.env.ROOKSTRIDE_PERSONAL_WEB;
    else process.env.ROOKSTRIDE_PERSONAL_WEB = originalPersonal;
  });
  process.env.ROOKSTRIDE_PERSONAL_WEB = "1";
  for (const [setting, role] of [
    ["1", "private"],
    ["public", "reader"],
    ["invalid", "disabled"],
  ]) {
    process.env.ROOKSTRIDE_HOSTED_SITE = setting;
    assert.equal(webRuntimeRole(), role);
    assert.equal(personalGatewayEnabled(), false);
  }
  delete process.env.ROOKSTRIDE_HOSTED_SITE;
  assert.equal(webRuntimeRole(), "workstation");
  assert.equal(personalGatewayEnabled(), process.getuid?.() !== 0);
});

test("public reading only permits named pages and single-file asset routes", () => {
  for (const path of [
    "/",
    "/agents",
    "/comics/story-1",
    "/connect",
    "/journal/caf%C3%A9",
    "/manage",
    "/self-hosted-vpn",
    androidRelease.arm64.sitePath,
    "/brand/rook-bridge-team.webp",
    "/brand/assistants/cursor-cube.svg",
    "/_next/static/chunks/app/(site)/journal/%5Bslug%5D/page-123.js",
    "/_next/static/media/font.woff2",
    "/api/media/file/chapter%20one.webp",
  ]) {
    assert.equal(publicReaderRoute(path, "GET"), true, path);
    assert.equal(publicReaderRoute(path, "HEAD"), true, path);
    assert.equal(publicReaderRoute(path, "POST"), false, path);
  }
  for (const path of [
    "/admin",
    "/admin/create-first-user",
    "/api/users/first-register",
    "/api/articles",
    "/api/chapters",
    "/api/media",
    "/api/gateway",
    "/api/local-status",
    "/api/preview/inspect",
    "/manage/server",
    androidRelease.arm64.sitePath.replace("-arm64.apk", "-universal.apk"),
    "/downloads/other.apk",
    "/.private/cms.sqlite",
    "/_next/static/chunks/page.js.map",
    "/_next/image",
    "/api/media/file/a%2Fb.png",
    "/api/media/file/a%252Fb.png",
    "/api/media/file/a%5Cb.png",
    "/journal/%2E%2E",
    "/journal/%ZZ",
    "/api/media/file/another/path.png",
  ])
    assert.equal(publicReaderRoute(path, "GET"), false, path);
});

test("discovery files require the canonical reader role and its configured HTTPS origin", (context) => {
  for (const key of ["ROOKSTRIDE_HOSTED_SITE", "ROOKSTRIDE_PUBLIC_ORIGIN"]) {
    const previous = process.env[key];
    context.after(() => {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    });
  }
  for (const path of ["/robots.txt", "/sitemap.xml", "/llms.txt"]) {
    process.env.ROOKSTRIDE_HOSTED_SITE = "1";
    process.env.ROOKSTRIDE_PUBLIC_ORIGIN = "https://example.org";
    assert.equal(publicReaderRoute(path, "GET"), false);
    process.env.ROOKSTRIDE_HOSTED_SITE = "public";
    process.env.ROOKSTRIDE_PUBLIC_ORIGIN = "http://example.org";
    assert.equal(publicReaderRoute(path, "GET"), false);
    process.env.ROOKSTRIDE_PUBLIC_ORIGIN = "https://example.org";
    assert.equal(publicReaderRoute(path, "GET"), true);
    assert.equal(publicReaderRoute(path, "HEAD"), true);
    assert.equal(publicReaderRoute(path, "POST"), false);
  }
  for (const path of ["/admin", "/vpn", "/vpn/api", "/manage", "/mcp"])
    assert.equal(indexableSitePaths.includes(path), false);
});

test("loopback checks use the actual Host and require its matching origin for changes", () => {
  assert.equal(
    isLoopbackRequest(new Headers({ host: "localhost:3100" }), "GET"),
    true,
  );
  assert.equal(
    isLoopbackRequest(
      new Headers({
        host: "127.0.0.1:3100",
        origin: "http://127.0.0.1:3100",
      }),
      "POST",
    ),
    true,
  );
  for (const headers of [
    {
      host: "other.example",
      "x-forwarded-host": "127.0.0.1:3100",
      origin: "http://127.0.0.1:3100",
    },
    { host: "127.0.0.1:3100", origin: "http://localhost:3100" },
    { host: "127.0.0.1:3100", origin: "https://other.example" },
    { host: "127.0.0.1:3100" },
  ])
    assert.equal(isLoopbackRequest(new Headers(headers), "POST"), false);
});

test("hosted protocol admission is additive, explicit, and requires a runtime directory", () => {
  assert.deepEqual(configuredPilotMethods(), ["xray", "xhttp"]);
  assert.deepEqual(configuredPilotMethods("awg,openvpn"), [
    "xray",
    "xhttp",
    "awg",
    "openvpn",
  ]);
  for (const [methods, directory] of [
    ["xray"],
    ["unknown"],
    ["awg,awg"],
    ["awg,"],
    ["hysteria2"],
    ["hysteria2", "relative"],
  ])
    assert.equal(configuredPilotMethods(methods, directory), undefined);
  assert.deepEqual(
    configuredPilotMethods("hysteria2,outline", "/private/route-assets"),
    ["xray", "xhttp", "hysteria2", "outline"],
  );
});

test("hosted VPN requests require an invitation and the real HTTPS origin", () => {
  const origin = new URL("https://pilot.example");
  const invite = randomBytes(32).toString("base64url");
  const digest = createHash("sha256").update(invite).digest();
  const authorized = { host: origin.host, "x-rookstride-invite": invite };
  const status = (method, headers) =>
    pilotRequestStatus(new Headers(headers), method, origin, digest);
  assert.equal(status("GET", { host: origin.host }), 401);
  assert.equal(
    status("GET", { ...authorized, "x-rookstride-invite": "A".repeat(43) }),
    401,
  );
  assert.equal(
    status("GET", {
      ...authorized,
      host: "other.example",
      "x-forwarded-host": origin.host,
    }),
    403,
  );
  assert.equal(status("GET", authorized), 204);
  assert.equal(status("POST", authorized), 403);
  assert.equal(
    status("POST", { ...authorized, origin: "https://other.example" }),
    403,
  );
  assert.equal(status("POST", { ...authorized, origin: origin.origin }), 0);
});

test("hosted invitations isolate real gateway session capabilities and target selection", async () => {
  const origin = new URL("https://pilot.example");
  const invitations = Array.from({ length: 4 }, () => randomBytes(32).toString("base64url"));
  const records = invitations.map((invite, index) => ({
    inviteHash: createHash("sha256").update(invite).digest("hex"),
    server: {
      version: index === 0 ? 2 : 1,
      address: `192.0.2.${index + 10}`,
      sshPort: 22,
      fingerprint: "SHA256:" + "ABCD"[index].repeat(43),
      ...(index === 0 && { keyType: "ecdsa-sha2-nistp256" }),
    },
  }));
  const accepted = parsePilotEnrollments(records, () => true);
  assert.equal(accepted.length, 4);
  assert.throws(() => parsePilotEnrollments([...records, records[0]], () => true));
  assert.throws(() => parsePilotEnrollments([records[0], records[0]], () => true));
  assert.throws(() => parsePilotEnrollments([{ ...records[0], invite: invitations[0] }], () => true));
  const requests = [];
  const services = accepted.map((entry, index) => ({
    ...entry,
    service: createGatewayService(() => ({
      async request(input) {
        requests.push([index, input.action]);
        return { state: "ready", os: "Ubuntu 24.04" };
      },
      stop() {},
    }), (target) => target === entry.server.address, { allowEcdsa: Boolean(entry.server.keyType) }),
  }));
  async function call(invitation, payload, token, requestOrigin = origin.origin) {
    return handleHostedGateway(new Request(new URL("/vpn/api", origin), {
      method: payload ? "POST" : "GET",
      headers: {
        host: origin.host, origin: requestOrigin,
        "x-rookstride-invite": invitation,
        ...(payload && { "Content-Type": "application/json" }),
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      ...(payload && { body: JSON.stringify(payload) }),
    }), origin, services);
  }
  const inspect = (index) => {
    const { version, ...ssh } = records[index].server;
    return { ...ssh, action: "inspect", password: "test-fixture-only" };
  };
  assert.equal((await call(invitations[0])).headers.get("X-Rookstride-ECDSA"), "1");
  assert.equal((await call(invitations[1])).headers.get("X-Rookstride-ECDSA"), null);
  assert.equal((await call(invitations[0], inspect(1))).status, 400);
  assert.equal((await call(invitations[0], inspect(0), undefined, "https://foreign.example")).status, 403);
  assert.deepEqual(requests, []);
  const opened = await Promise.all(invitations.map(async (invite, i) => (await call(invite, inspect(i))).json()));
  assert.equal(new Set(opened.map(({ session }) => session)).size, 4);
  for (let i = 0; i < opened.length; i++) {
    const other = (i + 1) % opened.length;
    assert.equal((await call(invitations[i], undefined, opened[i].session)).status, 200);
    for (const payload of [undefined, { action: "profile" }, { action: "close" }]) {
      const forbidden = await call(invitations[i], payload, opened[other].session);
      assert.equal(forbidden.status, 401);
      assert.equal(forbidden.headers.get("Cache-Control"), "no-store");
    }
  }
  assert.equal((await call(invitations[0], inspect(0))).status, 409);
  assert.equal(requests.length, 4);
  await Promise.all(opened.map(({ session }, i) => call(invitations[i], { action: "close" }, session)));
});

test("hosted pair invitations reserve both roles exclusively and refuse standalone actions", async () => {
  const origin = new URL("https://pilot.example");
  const invite = randomBytes(32).toString("base64url");
  const inviteHash = createHash("sha256").update(invite).digest("hex");
  const entry = { version: 2, address: "192.0.2.20", sshPort: 22,
    fingerprint: "SHA256:" + "A".repeat(43), keyType: "ecdsa-sha2-nistp256" };
  const exit = { version: 1, address: "192.0.2.21", sshPort: 22,
    fingerprint: "SHA256:" + "B".repeat(43) };
  const row = { entry, exit, inviteHash };
  const [enrollment] = parsePilotEnrollments([row], () => true);
  assert.throws(() => parsePilotEnrollments([{ ...row, exit: entry }], () => true));
  assert.throws(() => parsePilotEnrollments([row, { server: exit, inviteHash: "c".repeat(64) }], () => true));
  assert.throws(() => parsePilotEnrollments([{ ...row, server: entry }], () => true));
  let reviews = 0;
  const service = createEnrolledPairService(enrollment.pair, (options) => createWorkbenchPair({
    ...options,
    async review(input) {
      reviews++;
      return { login: input.login, exitProtocol: input.exitProtocol, entry: { address: entry.address, ubuntu: "24.04" },
        exit: { address: exit.address, ubuntu: "26.04" } };
    },
  }), { allowMixedExits: true });
  const nodes = [entry, exit].map(({ version, ...node }) => ({ ...node, password: "test-fixture-only" }));
  const request = (body, token, invitation = invite) => handleHostedGateway(new Request(new URL("/vpn/api", origin), {
    method: body ? "POST" : "GET",
    headers: { host: origin.host, origin: origin.origin, "X-Rookstride-Invite": invitation,
      ...(body && { "Content-Type": "application/json" }),
      ...(token && { Authorization: `Bearer ${token}` }) },
    ...(body && { body: JSON.stringify(body) }),
  }), origin, [{ ...enrollment, service, pairExitChoices: true }]);
  const admission = await request();
  assert.equal(admission.status, 204);
  assert.equal(admission.headers.get("X-Rookstride-Pair"), "1");
  assert.equal(admission.headers.get("X-Rookstride-Pair-Exit-Choices"), "1");
  assert.equal(admission.headers.get("X-Rookstride-Pair-Rebuild"), null);
  const refused = await request(undefined, undefined, "x".repeat(43));
  assert.equal(refused.status, 401);
  assert.equal(refused.headers.get("X-Rookstride-Pair-Exit-Choices"), null);
  const review = { action: "pairReview", login: "fixture-entry", entry: nodes[0], exit: nodes[1], exitProtocol: "xray" };
  assert.equal((await request({ action: "inspect", ...nodes[0] })).status, 400);
  assert.equal((await request({ ...review, entry: nodes[1], exit: nodes[0] })).status, 400);
  assert.equal((await request({ ...review, exit: { ...nodes[1], fingerprint: entry.fingerprint } })).status, 400);
  assert.equal((await request({ action: "pairRebuildStatus" })).status, 400);
  assert.equal(reviews, 0);
  const opened = await request(review);
  assert.equal(opened.status, 200);
  const { session, pair } = await opened.json();
  assert.equal(pair.exitProtocol, "xray");
  assert.equal((await request({ action: "pairStatus" }, session)).status, 200);
  assert.equal((await request({ action: "pairStatus" }, session, "x".repeat(43))).status, 401);
  assert.equal((await request({ action: "pairProfile" }, "x".repeat(43))).status, 401);
  assert.equal((await request({ action: "pairClose" }, session)).status, 200);
});

test("hosted rebuild reattaches the same operation after restart and admits only verified replacement pins", async () => {
  const origin = new URL("https://pilot.example");
  const invite = randomBytes(32).toString("base64url");
  const inviteHash = createHash("sha256").update(invite).digest("hex");
  const entry = { version: 1, address: "192.0.2.24", sshPort: 22, fingerprint: "SHA256:" + "A".repeat(43) };
  const exit = { version: 2, address: "192.0.2.26", sshPort: 22, fingerprint: "SHA256:" + "B".repeat(43),
    keyType: "ecdsa-sha2-nistp256" };
  const [admission] = parsePilotEnrollments([{ entry, exit, inviteHash }], () => true);
  const original = {
    entry: { ...entry, keyType: "ssh-ed25519", ubuntu: "24.04" }, exit: { ...exit, ubuntu: "26.04" }, login: "owner",
  };
  const directory = "/owner-only-journal";
  assert.equal(isolatedPairRebuild([admission], directory), true);
  assert.equal(isolatedPairRebuild([admission, { server: entry }], directory), false);
  assert.equal(isolatedPairRebuild([{ server: entry }], directory), false);
  assert.equal(isolatedPairRebuild([admission], "./relative"), false);
  const operation = "a".repeat(32);
  const prepared = {
    operation, review: original,
    members: {
      entry: { ubuntu: "24.04", boot: "BIOS", diskBytes: 32 * 1024 ** 3, fingerprint: "SHA256:" + "C".repeat(43), job: "1".repeat(32) },
      exit: { ubuntu: "26.04", boot: "EFI", diskBytes: 32 * 1024 ** 3, fingerprint: "SHA256:" + "D".repeat(43), job: "2".repeat(32) },
    },
  };
  const returned = {
    entry: { ...entry, version: 2, keyType: "ecdsa-sha2-nistp256", fingerprint: prepared.members.entry.fingerprint, ubuntu: "24.04" },
    exit: { ...exit, fingerprint: prepared.members.exit.fingerprint, ubuntu: "26.04" }, login: "owner",
  };
  const credentials = (pair) => Object.fromEntries(["entry", "exit"].map((role) => {
    const { version, ubuntu, ...node } = pair[role];
    return [role, { ...node, password: "ssh-fixture" }];
  }));
  const originalNodes = credentials(admission.pair);
  const returnedNodes = credentials(returned);
  const archive = Buffer.alloc(2400, 17).toString("base64");
  const password = "archive-passphrase-fixture";
  let saved = null;
  let runs = 0;
  let running = Promise.withResolvers();
  let validatedWorkers = 0;
  const configuration = {
    rebuildDirectory: directory,
    openPairWorker(scope) { validatedWorkers++; return { scope }; },
    createRebuild({ directory: actual, openWorker }) {
      assert.equal(actual, directory);
      assert.throws(() => openWorker({ role: "entry", server: exit }), /enrollment mismatch/);
      openWorker({ role: "entry", server: entry });
      return {
        journalStatus: () => saved,
        async review({ targets, ubuntu, encrypted, passphrase }) {
          assert.deepEqual(targets, originalNodes);
          assert.deepEqual(ubuntu, { entry: "24.04", exit: "26.04" });
          assert.equal(encrypted.toString("base64"), archive);
          assert.equal(passphrase, password);
          saved = { record: prepared, started: false };
          return prepared;
        },
        async run({ targets, encrypted, passphrase, resumeRestore, onProgress }) {
          assert.deepEqual(targets, originalNodes);
          assert.equal(encrypted.toString("base64"), archive);
          assert.equal(passphrase, password);
          assert.equal(resumeRestore, runs > 0);
          runs++;
          saved.started = true;
          onProgress({ role: "exit", state: "rebooting", privateMaterial: password });
          return running.promise;
        },
      };
    },
  };
  const service = () => createEnrolledPairService(admission.pair, (options) => createWorkbenchPair({
    ...options,
    adopt: async (nodes) => nodes.entry.fingerprint === entry.fingerprint ? original : returned,
  }), configuration);
  let current = service();
  const send = (body, session, { invitation = invite, recovery = true } = {}) => handleHostedGateway(
    new Request(new URL("/vpn/api", origin), {
      method: body ? "POST" : "GET",
      headers: {
        host: origin.host, origin: origin.origin, "X-Rookstride-Invite": invitation,
        ...(body && { "Content-Type": "application/json" }),
        ...(session && { Authorization: "Bearer " + session }),
        ...(recovery && { "X-Rookstride-Recovery": "1" }),
      },
      ...(body && { body: JSON.stringify(body) }),
    }), origin, [{ ...admission, pairRebuild: true, service: current }],
  );
  assert.equal((await send()).headers.get("X-Rookstride-Pair-Rebuild"), "1");
  const { session } = await (await send({ action: "pairAdopt", ...originalNodes })).json();
  const review = { action: "pairRebuildReview", entryUbuntu: "24.04", exitUbuntu: "26.04", archive, password, confirmed: true };
  assert.equal((await send(review, session, { recovery: false })).status, 413);
  assert.equal((await send(review, "x".repeat(43))).status, 413);
  assert.equal((await send({ ...review, action: "pairRebuildStatus" }, session)).status, 413);
  const approved = await (await send(review, session)).json();
  assert.equal(approved.operation, operation);
  assert.deepEqual(Object.keys(approved.exit), ["ubuntu", "boot", "diskBytes", "fingerprint"]);
  assert.doesNotMatch(JSON.stringify(approved), /ssh-fixture|archive-passphrase|job/);
  const start = { action: "pairRebuildStart", operation, confirmation: pairRebuildConfirmation };
  assert.equal((await send({ ...start, confirmation: "yes" }, session)).status, 409);
  assert.equal((await send({ ...start, operation: "b".repeat(32) }, session)).status, 409);
  const begun = await (await send(start, session)).json();
  assert.equal(begun.state, "rebuilding");
  assert.deepEqual(begun.progress, { role: "exit", state: "rebooting" });
  assert.equal((await send(start, session)).status, 409);
  assert.equal((await send({ action: "pairClose" }, session)).status, 409);
  assert.equal((await send({ action: "pairManage" }, session)).status, 409);
  assert.equal(runs, 1);

  running.reject(Object.assign(new Error(password), { code: "ubuntu-return-pending" }));
  await flush();
  current = service();
  assert.equal(validatedWorkers, 2);
  const status = { action: "pairRebuildStatus" };
  assert.equal((await send(status, session)).status, 401);
  assert.equal((await send(status, undefined, { invitation: "x".repeat(43) })).status, 401);
  assert.deepEqual(await (await send(status)).json(), { operation, state: "needsAttention" });
  const reconnect = { action: "pairRebuildReconnect", operation, ...originalNodes };
  assert.equal((await send({ ...reconnect, entry: originalNodes.exit, exit: originalNodes.entry })).status, 400);
  assert.equal((await send({ ...reconnect, ...returnedNodes })).status, 400);
  assert.equal((await send({ action: "pairAdopt", ...originalNodes })).status, 409);
  const recovered = await (await send(reconnect)).json();
  assert.equal(recovered.state, "needsAttention");
  assert.equal(recovered.entry.fingerprint, approved.entry.fingerprint);
  const fresh = recovered.session;
  assert.notEqual(fresh, session);
  assert.equal((await send(start, fresh)).status, 409);
  running = Promise.withResolvers();
  const resume = { ...start, action: "pairRebuildResume", archive, password };
  assert.equal((await send(resume, session)).status, 413);
  assert.equal((await send(resume, fresh, { recovery: false })).status, 413);
  assert.equal((await (await send(resume, fresh)).json()).state, "rebuilding");
  saved.restored = { operation, state: "restored", review: returned };
  running.resolve(saved.restored);
  await flush();
  assert.equal((await (await send(status, fresh)).json()).state, "restored");
  assert.equal((await send({ action: "pairClose" }, fresh)).status, 200);
  assert.equal((await send({ action: "pairAdopt", ...originalNodes })).status, 400);
  assert.equal((await send({ action: "pairAdopt", ...returnedNodes })).status, 200);
  assert.equal(runs, 2);
});
