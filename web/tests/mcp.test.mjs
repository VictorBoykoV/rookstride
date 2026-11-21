import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createGatewayService } from "../src/lib/gateway-service.mjs";
import {
  createOperatorMcp,
  describeOperation,
  operatorPlanSchema,
} from "../src/lib/operator-mcp.mjs";
import { singleProtocolCatalog } from "../src/lib/gateway-input.mjs";
import { PairDeploymentError } from "../src/lib/pair-deployment.mjs";
import {
  createPairOperatorMcp,
  openPairRebuildApproval,
  operatorPairPlanSchema,
  operatorPairTargets,
  sealPairRebuildApproval,
} from "../src/lib/pair-operator-mcp.mjs";
import { decryptPairRecovery } from "../src/lib/pair-recovery.mjs";
import { pairRebuildConfirmation } from "../src/lib/pair-rebuild.mjs";

const pairAuthorities = operatorPairTargets.parse({
  entry: {
    address: "192.0.2.10",
    sshPort: 22,
    fingerprint: `SHA256:${"A".repeat(43)}`,
    password: "entry-fixture-ssh-secret",
    keyType: "ecdsa-sha2-nistp256",
  },
  exit: {
    address: "198.51.100.30",
    sshPort: 22,
    fingerprint: `SHA256:${"B".repeat(43)}`,
    password: "exit-fixture-ssh-secret",
  },
});

function pairReview(login) {
  const node = ({ password, ...authority }, identity, ubuntu) => ({
    ...authority,
    machine: identity.repeat(64),
    ubuntu,
  });
  return {
    version: 1,
    pairId: "1".repeat(32),
    bundle: "f".repeat(64),
    login,
    entry: node(pairAuthorities.entry, "a", "24.04.5"),
    exit: node(pairAuthorities.exit, "b", "26.04.1"),
  };
}

test("local MCP reviews the exact two pinned roles and requires separate approvals to deploy and export", async () => {
  const inspected = pairReview("pair-owner");
  const finished = Promise.withResolvers();
  let approval;
  let staged;
  let installs = 0;
  let exports = 0;
  let saves = 0;
  const server = createPairOperatorMcp(
    pairAuthorities,
    {
      async stage(plan) {
        staged = operatorPairPlanSchema.parse(plan);
        return { id: plan.id, path: "/private/pair-review.json" };
      },
      async consume(receipt) {
        if (receipt.id !== approval) return;
        approval = undefined;
        return {};
      },
      async saveProfile(name, contents) {
        saves++;
        assert.equal(name, "rookstride-pair-owner.conf");
        assert.equal(contents, "fixture-private-profile\n");
        return `/private/${name}`;
      },
    },
    {
      async reviewPair(input) {
        assert.deepEqual(input, { ...pairAuthorities, login: "pair-owner" });
        return inspected;
      },
      async deployPair({ onProgress, ...input }) {
        installs++;
        assert.deepEqual(input, { ...pairAuthorities, review: inspected });
        onProgress({ stage: "exit-bootstrap" });
        await finished.promise;
        onProgress({ stage: "health" });
        return { state: "installed", pairId: inspected.pairId };
      },
      async exportPairProfile(input) {
        exports++;
        assert.deepEqual(input, { ...pairAuthorities, review: inspected });
        return {
          filename: "rookstride-pair-owner.conf",
          configuration: "fixture-private-profile",
        };
      },
    },
  );
  const client = new Client({ name: "pair-operator-fixture", version: "1" });
  const [caller, service] = InMemoryTransport.createLinkedPair();
  await server.connect(service);
  await client.connect(caller);
  async function call(name, input = {}) {
    const result = await client.callTool({ name, arguments: input });
    assert.doesNotMatch(
      JSON.stringify(result),
      /fixture-ssh-secret|fixture-private-profile/,
    );
    return result;
  }
  async function accepted(name, input) {
    const result = await call(name, input);
    assert.equal(result.isError, undefined, JSON.stringify(result));
    return result.structuredContent;
  }
  try {
    assert.equal((await call("review_pair_export")).isError, true);
    assert.equal((await call("review_pair_install")).isError, true);
    assert.deepEqual(await accepted("inspect_pair", { login: "pair-owner" }), {
      state: "ready",
      entry: { ubuntu: "24.04.5" },
      exit: { ubuntu: "26.04.1" },
      method: "awg",
    });
    const install = await accepted("review_pair_install");
    assert.equal(staged.kind, "pair-install");
    assert.deepEqual(staged.review, inspected);
    assert.equal(
      (await call("apply_pair_install", { id: install.id })).isError,
      true,
    );
    assert.equal(installs, 0);
    approval = install.id;
    assert.equal(
      (await call("apply_pair_export", { id: install.id })).isError,
      true,
    );
    const running = await accepted("apply_pair_install", { id: install.id });
    assert.deepEqual(running, { state: "running", stage: "exit-bootstrap" });
    assert.deepEqual(await accepted("pair_status"), running);
    assert.deepEqual(
      await accepted("apply_pair_install", { id: install.id }),
      running,
    );
    assert.equal(
      (await call("inspect_pair", { login: "pair-owner" })).isError,
      true,
    );
    assert.equal((await call("review_pair_export")).isError, true);
    assert.equal(installs, 1);
    finished.resolve();
    const installed = { state: "installed", stage: "health" };
    assert.deepEqual(await accepted("pair_status"), installed);
    assert.deepEqual(
      await accepted("apply_pair_install", { id: install.id }),
      installed,
    );
    const exportPlan = await accepted("review_pair_export");
    assert.equal(staged.kind, "pair-export");
    assert.deepEqual(staged.review, inspected);
    assert.equal(
      (await call("apply_pair_export", { id: exportPlan.id })).isError,
      true,
    );
    assert.equal(exports, 0);
    approval = exportPlan.id;
    const exported = await accepted("apply_pair_export", { id: exportPlan.id });
    assert.deepEqual(exported, {
      filename: "rookstride-pair-owner.conf",
      file: "/private/rookstride-pair-owner.conf",
    });
    assert.deepEqual(
      await accepted("apply_pair_export", { id: exportPlan.id }),
      exported,
    );
    assert.equal(exports, 1);
    assert.equal(saves, 1);
  } finally {
    finished.resolve();
    await client.close();
    await server.close();
  }
});

test("local MCP rejects exchanged roles, expired approval and repeat installation after an uncertain pair step", async (t) => {
  let time = Date.now();
  t.mock.method(Date, "now", () => time);
  let exchangeRoles = true;
  let installs = 0;
  const server = createPairOperatorMcp(
    pairAuthorities,
    {
      async stage() {
        return { path: "/private/pair-review.json" };
      },
      async consume() {
        return {};
      },
    },
    {
      async reviewPair({ login }) {
        const review = pairReview(login);
        return exchangeRoles
          ? { ...review, entry: review.exit, exit: review.entry }
          : review;
      },
      async deployPair({ onProgress }) {
        installs++;
        onProgress({ stage: "exit-bootstrap" });
        throw new PairDeploymentError("interrupted", "exit-bootstrap", true);
      },
    },
  );
  const client = new Client({
    name: "pair-operator-guard-fixture",
    version: "1",
  });
  const [caller, service] = InMemoryTransport.createLinkedPair();
  await server.connect(service);
  await client.connect(caller);
  const call = (name, input = {}) =>
    client.callTool({ name, arguments: input });
  const inspect = () => call("inspect_pair", { login: "owner" });
  try {
    assert.equal((await inspect()).isError, true);
    assert.equal((await call("review_pair_install")).isError, true);
    exchangeRoles = false;
    assert.equal((await inspect()).structuredContent.state, "ready");
    const expired = (await call("review_pair_install")).structuredContent;
    time = expired.expiresAt;
    assert.equal(
      (await call("apply_pair_install", { id: expired.id })).isError,
      true,
    );
    assert.equal(installs, 0);
    assert.equal((await inspect()).structuredContent.state, "ready");
    const current = (await call("review_pair_install")).structuredContent;
    await call("apply_pair_install", { id: current.id });
    const failed = {
      state: "failed",
      stage: "exit-bootstrap",
      reason: "interrupted",
      uncertain: true,
    };
    assert.deepEqual((await call("pair_status")).structuredContent, failed);
    assert.deepEqual(
      (await call("apply_pair_install", { id: current.id })).structuredContent,
      failed,
    );
    assert.equal((await inspect()).isError, true);
    assert.equal((await call("review_pair_install")).isError, true);
    assert.equal(installs, 1);
  } finally {
    await client.close();
    await server.close();
  }
});

test(
  "local MCP Double VPN discovery over stdio accepts only a private pair target file",
  { skip: !process.getuid || process.getuid() === 0, timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rookstride-pair-stdio-"));
    const pairFile = join(directory, "pair.json");
    await writeFile(pairFile, JSON.stringify(pairAuthorities), { mode: 0o600 });
    const transport = (env = {}) =>
      new StdioClientTransport({
        command: process.execPath,
        args: [resolve("scripts/mcp-gateway.mjs")],
        env: { ROOKSTRIDE_MCP_PAIR_TARGET_FILE: pairFile, ...env },
        stderr: "pipe",
      });
    const client = new Client({
      name: "pair-operator-stdio-fixture",
      version: "1",
    });
    async function refused(env) {
      const rejected = new Client({
        name: "pair-operator-denied-fixture",
        version: "1",
      });
      try {
        await assert.rejects(() => rejected.connect(transport(env)));
      } finally {
        await rejected.close();
      }
    }
    try {
      await client.connect(transport());
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map(({ name }) => name).sort(), [
        "apply_pair_account",
        "apply_pair_backup",
        "apply_pair_export",
        "apply_pair_install",
        "apply_pair_rehearsal",
        "apply_pair_remove",
        "cancel_review",
        "inspect_pair",
        "open_pair",
        "pair_status",
        "read_pair",
        "review_pair_account",
        "review_pair_backup",
        "review_pair_export",
        "review_pair_install",
        "review_pair_rehearsal",
        "review_pair_remove",
      ]);
      for (const tool of tools)
        assert.equal(tool.inputSchema.additionalProperties, false);
      const result = await client.callTool({
        name: "pair_status",
        arguments: {},
      });
      assert.deepEqual(result.structuredContent, { state: "uninspected" });
      await refused({ ROOKSTRIDE_MCP_TARGET_FILE: pairFile });
      await refused({ ROOKSTRIDE_MCP_PAIR_REBUILD: "1" });
      const rebuildClient = new Client({ name: "pair-rebuild-stdio-fixture", version: "1" });
      try {
        await rebuildClient.connect(transport({
          ROOKSTRIDE_MCP_PAIR_REBUILD: "1",
          ROOKSTRIDE_MCP_PAIR_REBUILD_STATE_DIR: directory,
        }));
        const list = (await rebuildClient.listTools()).tools.map(({ name }) => name);
        for (const name of [
          "pair_rebuild_status", "review_pair_rebuild", "apply_pair_rebuild_review",
          "review_pair_rebuild_erase", "apply_pair_rebuild_erase",
          "review_pair_rebuild_resume", "apply_pair_rebuild_resume",
        ]) assert.ok(list.includes(name), name);
        const state = await rebuildClient.callTool({ name: "pair_rebuild_status", arguments: {} });
        assert.deepEqual(state.structuredContent, { state: "unreviewed" });
      } finally {
        await rebuildClient.close();
      }
      await chmod(pairFile, 0o644);
      await refused();
    } finally {
      await client.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test("operator MCP uses its pinned target and requires an exact external approval once", async (t) => {
  let now = Date.now();
  t.mock.method(Date, "now", () => now);
  const target = {
    address: "192.0.2.10",
    sshPort: 22,
    fingerprint: `SHA256:${"A".repeat(43)}`,
    password: "fixture-password-must-stay-private",
  };
  let applyCount = 0;
  let protectionChanges = 0;
  let protectionEnabled = true;
  const service = createGatewayService(
    () => ({
      async request(input) {
        if (input.action === "inspect") {
          assert.deepEqual(input, { ...target, action: "inspect" });
          return { state: "ready", os: "Ubuntu 24.04" };
        }
        if (input.action === "protocolReview") return { port: 20443 };
        if (input.action === "protocolStatus")
          return { state: "protocolInstalled", port: 20443, method: "xhttp" };
        if (input.action === "protocolFilter") {
          if (Object.hasOwn(input, "enabled")) {
            assert.deepEqual(input, {
              action: "protocolFilter",
              enabled: false,
            });
            protectionEnabled = false;
            protectionChanges++;
          }
          return {
            presets: ["standard"],
            queries: 12,
            blocked: 3,
            protectionEnabled,
          };
        }
        if (input.action === "protocolUsage")
          return {
            available: true,
            kind: "traffic",
            scope: "daemon",
            profiles: null,
            upload: 5,
            download: 9,
          };
        assert.deepEqual(input, {
          action: "protocolApply",
          port: 20443,
          login: "owner",
          method: "xhttp",
        });
        applyCount++;
        return { state: "protocolRunning", port: 20443, method: "xhttp" };
      },
      stop() {},
    }),
    (address) => address === target.address,
  );
  let staged;
  let approved;
  const server = createOperatorMcp(service, target, {
    async stage(plan) {
      staged = plan;
      return { path: "/private/review", id: plan.id };
    },
    async consume(receipt) {
      return approved === receipt.id ? {} : undefined;
    },
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({
    name: "rookstride-operator-check",
    version: "1",
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const call = async (name, args = {}) => {
    const result = await client.callTool({ name, arguments: args });
    const output = JSON.stringify(result);
    for (const value of [target.address, target.password, target.fingerprint])
      assert.equal(output.includes(value), false);
    return result;
  };
  try {
    assert.equal(
      (await call("inspect_gateway", { password: "unauthorized" })).isError,
      true,
    );
    assert.equal(
      (await call("inspect_gateway")).structuredContent.state,
      "ready",
    );
    const { id: stale } = (
      await call("review_install", { method: "xhttp", login: "owner" })
    ).structuredContent;
    assert.equal(staged.fingerprint, target.fingerprint);
    assert.equal(staged.operation.method, "xhttp");
    assert.equal(operatorPlanSchema.safeParse(staged).success, true);
    approved = stale;
    now += 6 * 60_000;
    assert.equal((await call("apply_install", { id: stale })).isError, true);
    const { id } = (
      await call("review_install", { method: "xhttp", login: "owner" })
    ).structuredContent;
    assert.equal((await call("apply_install", { id })).isError, true);
    assert.equal(applyCount, 0);
    approved = id;
    assert.equal(
      (await call("apply_install", { id })).structuredContent.state,
      "protocolRunning",
    );
    assert.equal(
      (await call("apply_install", { id })).structuredContent.state,
      "protocolInstalled",
    );
    assert.equal(
      (await call("install_status")).structuredContent.state,
      "protocolInstalled",
    );
    assert.equal(applyCount, 1);
    const { usage } = (await call("read_gateway", { section: "usage" }))
      .structuredContent;
    assert.equal(usage.scope, "daemon");
    assert.equal(usage.profiles, null);
    const first = await call("read_gateway", { section: "dns" });
    assert.equal(first.structuredContent.filtering.protectionEnabled, true);
    const operation = { kind: "filter-protection", enabled: false };
    const review = (await call("review_change", { operation }))
      .structuredContent;
    assert.deepEqual(staged.operation, operation);
    assert.equal(staged.fingerprint, target.fingerprint);
    assert.equal((await call("apply_change", { id: review.id })).isError, true);
    assert.equal(protectionChanges, 0);
    approved = review.id;
    const changed = await call("apply_change", { id: review.id });
    assert.equal(changed.structuredContent.filtering.protectionEnabled, false);
    assert.deepEqual(await call("apply_change", { id: review.id }), changed);
    assert.equal(protectionChanges, 1);
  } finally {
    await client.close();
    await server.close();
  }
});

test(
  "real MCP stdio handshake, discovery, shared scenarios and rejected authority",
  { timeout: 15000 },
  async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("scripts/mcp-preview.mjs")],
      stderr: "pipe",
    });
    let diagnostic = "";
    transport.stderr?.on("data", (chunk) => {
      diagnostic += chunk.toString();
    });
    const client = new Client({ name: "rookstride-local-check", version: "1" });
    try {
      await client.connect(transport);
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name).sort(), [
        "get_capabilities",
        "inspect_example",
      ]);
      for (const tool of tools) {
        assert.equal(tool.annotations.readOnlyHint, true);
        assert.equal(tool.inputSchema.additionalProperties, false);
      }
      const capabilities = await client.callTool({
        name: "get_capabilities",
        arguments: {},
      });
      assert.equal(capabilities.structuredContent.executionAvailable, false);
      assert.equal(capabilities.structuredContent.credentialInput, false);
      for (const scenario of [
        "fresh",
        "existing",
        "unreachable",
        "changed-key",
      ]) {
        const reply = await client.callTool({
          name: "inspect_example",
          arguments: { address: "192.0.2.10", scenario },
        });
        assert.equal(reply.isError, undefined);
        const body = reply.structuredContent;
        assert.equal(body.mode, "fixture");
        assert.equal(body.serverContacted, false);
        assert.equal(body.executionAvailable, false);
        if (scenario !== "fresh") assert.deepEqual(body.steps, []);
        if (scenario === "changed-key") assert.equal(body.state, "blocked");
      }
      for (const args of [
        { address: "127.0.0.1", scenario: "fresh" },
        {
          address: "192.0.2.10",
          scenario: "fresh",
          password: "secret-marker-never-echo",
        },
        { address: "192.0.2.10", scenario: "arbitrary-command" },
      ]) {
        let rejected = false;
        try {
          const reply = await client.callTool({
            name: "inspect_example",
            arguments: args,
          });
          rejected = reply.isError === true;
          assert.equal(
            JSON.stringify(reply).includes("secret-marker-never-echo"),
            false,
          );
        } catch (error) {
          rejected = true;
          assert.equal(
            error.message.includes("secret-marker-never-echo"),
            false,
          );
        }
        assert.ok(rejected);
      }
      assert.equal(diagnostic.includes("secret-marker-never-echo"), false);
    } finally {
      await client.close();
    }
  },
);

test("operator MCP exposes the ten methods and keeps approvals, passwords and exports local", async () => {
  const target = {
    address: "192.0.2.10",
    sshPort: 22,
    fingerprint: `SHA256:${"A".repeat(43)}`,
    password: "fixture-ssh-secret",
  };
  const nativeMethods = Object.keys(singleProtocolCatalog);
  let state = "ready";
  let pendingMethod;
  let approval;
  let profile;
  let preset;
  let protectionEnabled;
  let guests;
  let revision;
  const requests = [];
  const owner = "owner";
  const addedGuest = "new-user";
  const service = {
    get() {
      return { state, method: pendingMethod };
    },
    async post(input, session) {
      requests.push(input);
      if (input.action !== "inspect") assert.equal(session, "fixture-session");
      switch (input.action) {
        case "inspect":
          assert.deepEqual(input, { ...target, action: "inspect" });
          state = "ready";
          pendingMethod = undefined;
          preset = "standard";
          protectionEnabled = true;
          guests = ["guest"];
          revision = "a".repeat(64);
          return { state, session: "fixture-session" };
        case "protocolReview":
          pendingMethod = input.method;
          return { port: 443, review: "fixture-review" };
        case "protocolApply":
          state = "protocolInstalled";
          return { state, method: pendingMethod };
        case "install":
          assert.equal(input.vpnPassword, "terminal-only-fixture");
          state = "installed";
          return { state };
        case "guests":
          return { owner, guests, revision };
        case "protocolUsers":
          return { owner, users: [owner, ...guests], revision };
        case "grant":
          assert.equal(input.vpnPassword, "terminal-only-fixture");
          assert.equal(input.revision, revision);
          guests = [...guests, input.login];
          revision = "b".repeat(64);
          return { owner, guests, revision };
        case "protocolGrant":
          assert.deepEqual(input, {
            action: "protocolGrant",
            login: addedGuest,
            revision,
          });
          guests = [...guests, input.login];
          revision = "b".repeat(64);
          return { owner, users: [owner, ...guests], revision };
        case "revoke":
        case "protocolRevoke":
          assert.deepEqual(input, {
            action: input.action,
            login: addedGuest,
            revision,
            confirmed: true,
          });
          guests = guests.filter((login) => login !== input.login);
          revision = "c".repeat(64);
          return {
            owner,
            ...(pendingMethod ? { users: [owner, ...guests] } : { guests }),
            revision,
          };
        case "profile":
          return { profile: { marker: "private-profile-bytes" } };
        case "protocolProfile":
          return {
            configuration: "private-profile-bytes",
            filename: `${input.login}.${singleProtocolCatalog[pendingMethod].extension}`,
          };
        case "health":
          return { services: { vpn: true } };
        case "usage":
          assert.deepEqual(input, { action: "usage" });
          return {
            usage: { available: true, sessions: 2, upload: 5, download: 9 },
          };
        case "protocolUsage":
          assert.deepEqual(input, { action: "protocolUsage" });
          return {
            usage: {
              available: true,
              kind: "traffic",
              scope: "daemon",
              profiles: null,
              upload: 5,
              download: 9,
            },
          };
        case "filter":
        case "protocolFilter": {
          const { action, level, enabled } = input;
          if (level !== undefined) {
            assert.deepEqual(input, { action, level, confirmed: true });
            preset = level;
          } else if (enabled !== undefined) {
            assert.equal(action, "protocolFilter");
            assert.deepEqual(input, { action, enabled, confirmed: true });
            protectionEnabled = enabled;
          } else {
            assert.deepEqual(input, { action });
          }
          return {
            filtering: {
              presets: [preset],
              queries: 12,
              blocked: 3,
              ...(action === "protocolFilter" && { protectionEnabled }),
            },
          };
        }
        case "removeReview":
          return { review: "fixture-remove" };
        case "removeApply":
          assert.equal(input.confirmation, "DELETE VPN");
          state = "removed";
          return { state };
        case "close":
          return { state: "closed" };
        default:
          assert.fail(input.action);
      }
    },
  };
  const server = createOperatorMcp(service, target, {
    async stage(plan) {
      assert.ok(operatorPlanSchema.parse(plan));
      return { path: "/private/review", id: plan.id };
    },
    async consume(receipt) {
      if (approval !== receipt.id) return;
      approval = undefined;
      return { vpnPassword: "terminal-only-fixture" };
    },
    async saveProfile(filename, contents) {
      profile = { filename, contents };
      return "/private/export/" + filename;
    },
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "operator-parity-check", version: "1" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  async function call(name, args = {}) {
    const result = await client.callTool({ name, arguments: args });
    for (const secret of [
      target.password,
      target.fingerprint,
      target.address,
      "terminal-only-fixture",
      "private-profile-bytes",
    ])
      assert.equal(JSON.stringify(result).includes(secret), false);
    return result;
  }
  async function accepted(name, args) {
    const result = await call(name, args);
    assert.equal(result.isError, undefined, JSON.stringify(result));
    return result.structuredContent;
  }
  async function apply(operation) {
    const plan = await accepted("review_change", { operation });
    const before = requests.length;
    assert.ok((await call("apply_change", { id: plan.id })).isError);
    assert.equal(requests.length, before);
    approval = plan.id;
    const applied = await accepted("apply_change", { id: plan.id });
    assert.deepEqual(await accepted("apply_change", { id: plan.id }), applied);
    assert.equal(requests.length, before + 1);
    return applied;
  }
  try {
    const tools = (await client.listTools()).tools;
    assert.ok(
      tools.find((tool) => tool.name === "review_change").inputSchema.properties
        .operation,
    );
    const supported = (await accepted("list_methods")).methods.map(
      (method) => method.id,
    );
    assert.deepEqual(supported, ["ikev2", ...nativeMethods]);
    for (const method of supported) {
      await accepted("inspect_gateway");
      const plan = await accepted("review_install", { method, login: owner });
      assert.equal(plan.needsPassword, method === "ikev2");
      const before = requests.length;
      assert.ok((await call("apply_install", { id: plan.id })).isError);
      assert.equal(requests.length, before);
      approval = plan.id;
      const installed = await accepted("apply_install", { id: plan.id });
      assert.equal(installed.method, method);
      assert.ok((await call("apply_change", { id: plan.id })).isError);
      assert.deepEqual(
        await accepted("apply_install", { id: plan.id }),
        installed,
      );
      const users = await accepted("read_gateway", { section: "accounts" });
      assert.deepEqual(users.users, [owner, "guest"]);

      if (method === "ikev2") {
        assert.equal(
          (await accepted("read_gateway", { section: "health" })).services.vpn,
          true,
        );
        assert.deepEqual(
          (await apply({ kind: "filter", level: "strict" })).filtering.presets,
          ["strict"],
        );
        assert.deepEqual(
          (await apply({ kind: "grant", login: addedGuest })).guests,
          ["guest", addedGuest],
        );
      } else {
        assert.deepEqual(
          (await apply({ kind: "grant", login: addedGuest })).users,
          [owner, "guest", addedGuest],
        );
        assert.ok(
          (
            await call("review_change", {
              operation: { kind: "rotate", login: "guest" },
            })
          ).isError,
        );
      }
      const filter = await accepted("read_gateway", { section: "dns" });
      assert.deepEqual(filter.filtering.presets, [
        method === "ikev2" ? "strict" : "standard",
      ]);
      assert.equal(filter.filtering.queries, 12);
      const { usage } = await accepted("read_gateway", { section: "usage" });
      assert.equal(usage.upload, 5);
      assert.equal(usage.download, 9);
      assert.deepEqual(
        (await apply({ kind: "filter", level: "strong" })).filtering.presets,
        ["strong"],
      );
      const pause = { kind: "filter-protection", enabled: false };
      if (method === "ikev2") {
        assert.equal(usage.sessions, 2);
        assert.ok((await call("review_change", { operation: pause })).isError);
      } else {
        assert.equal(usage.scope, "daemon");
        assert.equal(filter.filtering.protectionEnabled, true);
        assert.ok(
          (
            await call("review_change", {
              operation: { ...pause, enabled: "false" },
            })
          ).isError,
        );
        assert.equal((await apply(pause)).filtering.protectionEnabled, false);
        assert.equal(
          (await apply({ ...pause, enabled: true })).filtering
            .protectionEnabled,
          true,
        );
      }
      const saved = await apply({ kind: "export", login: addedGuest });
      assert.equal(saved.file, "/private/export/" + profile.filename);
      assert.ok(
        profile.filename.endsWith(
          `.${method === "ikev2" ? "sswan" : singleProtocolCatalog[method].extension}`,
        ),
      );
      assert.ok(profile.contents.includes("private-profile-bytes"));
      const revoked = await apply({ kind: "revoke", login: addedGuest });
      assert.deepEqual(
        revoked.users ?? revoked.guests,
        method === "ikev2" ? ["guest"] : [owner, "guest"],
      );
      assert.ok(
        (
          await call("review_change", {
            operation: { kind: "export", login: addedGuest },
          })
        ).isError,
      );
      assert.equal((await apply({ kind: "remove" })).state, "removed");
      await accepted("close_gateway");
    }
    assert.equal(
      requests.filter(
        ({ action }) => action === "install" || action === "protocolApply",
      ).length,
      10,
    );
    assert.match(
      describeOperation({ kind: "filter-protection", enabled: false }),
      /^Pause ad blocking/,
    );
    assert.match(
      describeOperation({ kind: "filter-protection", enabled: true }),
      /^Resume ad blocking/,
    );
  } finally {
    await client.close();
    await server.close();
  }
});

test(
  "local operator starts over stdio and advertises the real operation schemas",
  {
    skip: !process.getuid || process.getuid() === 0,
    timeout: 15000,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rookstride-stdio-test-"));
    const target = join(directory, "target.json");
    await writeFile(
      target,
      JSON.stringify({
        address: "192.0.2.10",
        sshPort: 22,
        fingerprint: `SHA256:${"A".repeat(43)}`,
        password: "stdio-private-fixture",
      }),
      { mode: 0o600 },
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("scripts/mcp-gateway.mjs")],
      env: { ROOKSTRIDE_MCP_TARGET_FILE: target },
      stderr: "pipe",
    });
    const client = new Client({
      name: "rookstride-operator-stdio-test",
      version: "1",
    });
    try {
      await client.connect(transport);
      const tools = (await client.listTools()).tools;
      assert.equal(
        tools.find((tool) => tool.name === "review_install").inputSchema
          .properties.method.enum.length,
        10,
      );
      const result = await client.callTool({
        name: "list_methods",
        arguments: {},
      });
      assert.equal(result.structuredContent.methods.length, 10);
      assert.ok(!JSON.stringify(result).includes("stdio-private-fixture"));
    } finally {
      await client.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test("opt-in Ubuntu MCP saves before erase and resumes without replaying", async () => {
  const target = {
    address: "192.0.2.10",
    sshPort: 22,
    fingerprint: `SHA256:${"A".repeat(43)}`,
    password: "fixture-root-private",
  };
  const { address, sshPort, fingerprint } = target;
  const recovery = {
    job: "1".repeat(32),
    ubuntu: "24.04",
    fingerprint: `SHA256:${"B".repeat(43)}`,
    server: { version: 1, address, sshPort, fingerprint },
  };
  const returned = {
    version: 2,
    address,
    sshPort,
    fingerprint: recovery.fingerprint,
    keyType: "ecdsa-sha2-nistp256",
  };
  const recoveryPath = "/private/ubuntu-recovery.json";
  const finalPath = "/private/returned-server.json";
  let state = "ready";
  let approved;
  let saved;
  let dispatched = 0;
  let complete = false;
  let openedWith = target.fingerprint;
  const service = {
    get() {
      return { state };
    },
    async post(input, session) {
      if (input.action === "inspect") {
        openedWith = input.fingerprint;
        return { state: "ready", session: "fixture-session" };
      }
      if (input.action === "ubuntuReview") {
        assert.equal(session, "fixture-session");
        return {
          recovery,
          review: "ubuntu-token",
          diskBytes: 12 * 1024 ** 3,
          boot: "EFI",
        };
      }
      if (input.action === "ubuntuApply") {
        assert.equal(session, "fixture-session");
        assert.deepEqual(saved, recovery);
        assert.equal(input.review, "ubuntu-token");
        assert.equal(input.confirmation, "WIPE SERVER AND REINSTALL UBUNTU");
        assert.equal(Object.hasOwn(input, "password"), false);
        dispatched++;
        state = "ubuntuReinstalling";
        return { state };
      }
      if (input.action === "ubuntuResume") {
        assert.equal(session, undefined);
        assert.deepEqual(input.recovery, recovery);
        assert.equal(input.password, target.password);
        return complete
          ? { state: "complete", ubuntu: "24.04", server: returned }
          : { state: "rebooting" };
      }
      assert.fail(input.action);
    },
  };
  const approval = {
    async stage(plan) {
      assert.ok(operatorPlanSchema.parse(plan));
      assert.equal(plan.operation.replacementFingerprint, recovery.fingerprint);
      assert.equal(plan.operation.diskBytes, 12 * 1024 ** 3);
      return { id: plan.id, path: "/private/review.json" };
    },
    async consume(receipt) {
      return approved === receipt.id ? {} : undefined;
    },
    async saveProfile(filename, content) {
      assert.equal(filename, "rookstride-server.json");
      assert.deepEqual(JSON.parse(content), returned);
      return finalPath;
    },
  };
  const ubuntu = {
    async saveRecovery(record) {
      saved = record;
      return recoveryPath;
    },
  };
  async function useConnector(options, run) {
    const server = createOperatorMcp(service, target, approval, options);
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "operator-ubuntu-check", version: "1" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const call = async (name, arguments_ = {}) => {
      const reply = await client.callTool({ name, arguments: arguments_ });
      for (const secret of [
        address,
        fingerprint,
        recovery.fingerprint,
        target.password,
      ])
        assert.ok(!JSON.stringify(reply).includes(secret));
      return reply;
    };
    try {
      await run(call, client);
    } finally {
      await client.close();
      await server.close();
    }
  }
  await useConnector(undefined, async (_, client) => {
    const { tools } = await client.listTools();
    assert.ok(!tools.some(({ name }) => name === "review_ubuntu_reinstall"));
  });
  await useConnector(ubuntu, async (call) => {
    await call("inspect_gateway");
    const plan = (await call("review_ubuntu_reinstall", { ubuntu: "24.04" }))
      .structuredContent;
    assert.ok((await call("apply_change", { id: plan.id })).isError);
    assert.equal(saved, undefined);
    approved = plan.id;
    const applied = (await call("apply_change", { id: plan.id }))
      .structuredContent;
    assert.deepEqual(applied, {
      state: "ubuntuReinstalling",
      recoveryFile: recoveryPath,
    });
    await call("apply_change", { id: plan.id });
    assert.equal(dispatched, 1);
    assert.equal(
      (await call("reinstall_status")).structuredContent.state,
      "rebooting",
    );
  });
  complete = true;
  await useConnector(
    { ...ubuntu, initial: { recovery: saved, file: recoveryPath } },
    async (call) => {
      assert.ok((await call("inspect_gateway")).isError);
      assert.deepEqual((await call("reinstall_status")).structuredContent, {
        state: "complete",
        recoveryFile: recoveryPath,
        ubuntu: "24.04",
        serverFile: finalPath,
      });
      assert.equal(
        (await call("inspect_gateway")).structuredContent.state,
        "ready",
      );
      assert.equal(openedWith, returned.fingerprint);
      assert.equal(dispatched, 1);
    },
  );
});

test("local MCP binds the mixed method to inspection, terminal approval, adoption and encrypted backup", async (t) => {
  const owner = "mixed-owner";
  const mixed = { ...pairReview(owner), exitProtocol: "openvpn" };
  const archive = {
    schema: 1, purpose: "rookstride-owner-recovery", deployment: mixed.pairId,
    revision: 2, created: 42, nodes: {},
  };
  for (const role of ["entry", "exit"]) {
    const protocol = role === "entry" ? "awg" : "openvpn";
    const login = role === "entry" ? owner : "bridge";
    archive.nodes[role] = {
      schema: 2, purpose: "rookstride-owner-recovery-node", deployment: mixed.pairId,
      role, adapter: protocol + "-identity-v1",
      state: { protocol, initialLogin: login, server: mixed[role].address, port: role === "entry" ? 51820 : 1194 },
      initial_user: { login, password: "fixture bootstrap secret" },
      plan: {
        pair: mixed.pairId, role, server: mixed.entry.address, exit_host: mixed.exit.address,
        vpn_port: 51820, tunnel_port: 1194, entry_protocol: "awg", exit_protocol: "openvpn",
        engine: "native-v2", client_pool: "10.66.0.0/24", test_ip: "10.249.255.254",
        entry_address: "10.253.0.2/30", exit_address: "10.253.0.1/30", route_table: 51831,
      },
    };
  }
  const recoveryPassword = "fixture archive passphrase";
  let approved;
  let staged;
  let installations = 0;
  let encrypted;
  const server = createPairOperatorMcp(pairAuthorities, {
    async stage(plan) {
      staged = operatorPairPlanSchema.parse(plan);
      return { id: plan.id, path: "/private/mixed-review.json" };
    },
    async consume(receipt) {
      if (receipt.id !== approved) return;
      approved = undefined;
      return { recoveryPassword };
    },
    async saveProfile(filename, bytes) {
      assert.equal(filename, "rookstride-owner-recovery.rookrec");
      encrypted = bytes;
      return "/private/" + filename;
    },
  }, {
    async reviewPair(input) {
      assert.deepEqual(input, { ...pairAuthorities, login: owner, exitProtocol: "openvpn" });
      return mixed;
    },
    async deployPair({ onProgress, ...input }) {
      assert.deepEqual(input, { ...pairAuthorities, review: mixed });
      installations++;
      onProgress({ stage: "exit-bootstrap" });
      return { state: "installed", pairId: mixed.pairId };
    },
    async adoptPair() { return mixed; },
    async capturePairRecovery(input) {
      assert.deepEqual(input, { ...pairAuthorities, review: mixed });
      return archive;
    },
  });
  const [caller, service] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "mixed-operator-fixture", version: "1" });
  await server.connect(service);
  await client.connect(caller);
  t.after(() => Promise.all([client.close(), server.close()]));
  const call = (name, args = {}) => client.callTool({ name, arguments: args });
  assert.equal((await call("inspect_pair", { login: owner, exitProtocol: "xray" })).isError, true);
  assert.equal((await call("inspect_pair", { login: owner, exitProtocol: "openvpn" })).structuredContent.exitProtocol, "openvpn");
  const install = (await call("review_pair_install")).structuredContent;
  assert.equal(staged.review.exitProtocol, "openvpn");
  assert.equal((await call("apply_pair_install", { id: install.id })).isError, true);
  approved = install.id;
  assert.equal((await call("apply_pair_install", { id: install.id })).structuredContent.exitProtocol, "openvpn");
  assert.equal((await call("open_pair")).structuredContent.exitProtocol, "openvpn");
  assert.equal(installations, 1);
  const backup = (await call("review_pair_backup")).structuredContent;
  approved = backup.id;
  const saved = await call("apply_pair_backup", { id: backup.id });
  assert.doesNotMatch(JSON.stringify(saved), /fixture.*secret|fixture archive/);
  assert.deepEqual(await decryptPairRecovery(encrypted, recoveryPassword, mixed), archive);
});

test("optional MCP rebuild status refuses a foreign journal and exposes only local scoped progress", async (t) => {
  const operation = "a".repeat(32);
  let current = {
    record: {
      operation,
      review: { ...pairReview("owner"), exitProtocol: "openvpn" },
      members: {
        entry: { ubuntu: "24.04", fingerprint: "entry-pin-fixture" },
        exit: { ubuntu: "26.04", fingerprint: "exit-pin-fixture" },
      },
    },
    started: true,
  };
  const server = createPairOperatorMcp(pairAuthorities, {}, {}, { rebuildStatus: () => current });
  const [caller, service] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "rebuild-journal-fixture", version: "1" });
  await server.connect(service);
  await client.connect(caller);
  t.after(() => Promise.all([client.close(), server.close()]));
  const call = (name) => client.callTool({ name, arguments: {} });
  assert.deepEqual((await call("pair_rebuild_status")).structuredContent, {
    operation, state: "waiting", entryUbuntu: "24.04", exitUbuntu: "26.04", exitProtocol: "openvpn",
  });
  assert.equal((await call("open_pair")).isError, true);
  current.record.review.entry = { ...current.record.review.entry, fingerprint: "SHA256:" + "F".repeat(43) };
  assert.equal((await call("pair_rebuild_status")).isError, true);
  current = null;
  assert.deepEqual((await call("pair_rebuild_status")).structuredContent, { state: "unreviewed" });
});

test("the terminal seals rebuild inputs for one exact review and connector key", () => {
  const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const unrelated = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const approvalKey = key.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const receipt = "a".repeat(64);
  const input = {
    archivePath: "/private/recovery-fixture.rookrec",
    archiveDigest: "b".repeat(64),
    recoveryPassword: "terminal-only passphrase",
  };
  const envelope = sealPairRebuildApproval(approvalKey, receipt, input);
  assert.doesNotMatch(JSON.stringify(envelope), /terminal-only|recovery-fixture|archiveDigest/);
  assert.deepEqual(openPairRebuildApproval(key.privateKey, receipt, envelope), input);
  assert.throws(() => openPairRebuildApproval(key.privateKey, "c".repeat(64), envelope));
  assert.throws(() => openPairRebuildApproval(unrelated.privateKey, receipt, envelope));
});

test("opt-in paired MCP rebuild separates terminal review from erase and resumes the same durable journal", async (t) => {
  const archive = Buffer.from("encrypted owner fixture");
  const archiveDigest = createHash("sha256").update(archive).digest("hex");
  const original = { ...pairReview("owner"), exitProtocol: "openvpn" };
  const operation = "1".repeat(32);
  const passphrase = "terminal-only fixture passphrase";
  const record = {
    operation, review: original, encryptedDigest: archiveDigest,
    members: {
      entry: { job: "3".repeat(32), ubuntu: "24.04", boot: "BIOS", diskBytes: 40 * 1024 ** 3, fingerprint: "SHA256:" + "C".repeat(43) },
      exit: { job: "4".repeat(32), ubuntu: "26.04", boot: "EFI", diskBytes: 40 * 1024 ** 3, fingerprint: "SHA256:" + "D".repeat(43) },
    },
  };
  let journal;
  let reviews = 0;
  let erases = 0;
  let running = Promise.withResolvers();
  const coordinator = {
    journalStatus: () => journal,
    async review(input) {
      assert.deepEqual(input.expectedReview, original);
      assert.deepEqual(input.targets, pairAuthorities);
      assert.deepEqual(input.ubuntu, { entry: "24.04", exit: "26.04" });
      assert.equal(input.passphrase, passphrase);
      assert.deepEqual(input.encrypted, archive);
      reviews++;
      journal = { record, started: false };
      return record;
    },
    async run(input) {
      assert.deepEqual(input.targets, pairAuthorities);
      assert.equal(input.confirmation, pairRebuildConfirmation);
      assert.equal(input.resumeRestore, erases > 0);
      assert.equal(input.passphrase, passphrase);
      assert.deepEqual(input.encrypted, archive);
      erases++;
      journal.started = true;
      input.onProgress({ role: "exit", state: "rebooting", secret: passphrase });
      return running.promise;
    },
  };
  async function connector() {
    const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const approvalKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
    const plans = new Map();
    const approvals = new Map();
    const pair = createPairOperatorMcp(pairAuthorities, {
      async stage(value) {
        const plan = operatorPairPlanSchema.parse(value);
        plans.set(plan.id, plan);
        const digest = createHash("sha256").update(JSON.stringify(plan)).digest("hex");
        return { id: plan.id, digest, path: "/private/rebuild-review.json" };
      },
      async consume(receipt) {
        const envelope = approvals.get(receipt.id);
        approvals.delete(receipt.id);
        return envelope && openPairRebuildApproval(keys.privateKey, receipt.digest, envelope);
      },
      async readRecovery(path, digest) {
        assert.equal(path, "/private/owner.rookrec");
        assert.equal(digest, archiveDigest);
        return Buffer.from(archive);
      },
    }, { adoptPair: async () => original }, { rebuild: coordinator, approvalKey });
    const [caller, service] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "mcp-durable-rebuild-fixture", version: "1" });
    await pair.connect(service);
    await client.connect(caller);
    t.after(() => Promise.all([client.close(), pair.close()]));
    return {
      async call(name, args = {}) {
        const result = await client.callTool({ name, arguments: args });
        assert.doesNotMatch(JSON.stringify(result), /terminal-only fixture|encrypted owner fixture|fixture-ssh-secret/);
        return result;
      },
      approve(id) {
        const plan = plans.get(id);
        const digest = createHash("sha256").update(JSON.stringify(plan)).digest("hex");
        approvals.set(id, sealPairRebuildApproval(plan.approvalKey, digest, {
          archivePath: "/private/owner.rookrec", archiveDigest, recoveryPassword: passphrase,
        }));
        return plan;
      },
    };
  }
  let client = await connector();
  assert.equal((await client.call("open_pair")).isError, undefined);
  const staged = (await client.call("review_pair_rebuild", { entry: "24.04", exit: "26.04" })).structuredContent;
  assert.equal(staged.kind, "pair-rebuild-review");
  assert.equal((await client.call("apply_pair_rebuild_review", { id: staged.id })).isError, true);
  assert.equal(reviews, 0);
  client.approve(staged.id);
  const disks = (await client.call("apply_pair_rebuild_review", { id: staged.id })).structuredContent;
  assert.equal(disks.state, "reviewed");
  assert.equal(disks.operation, operation);
  assert.equal(disks.exit.fingerprint, record.members.exit.fingerprint);
  assert.equal(reviews, 1);
  assert.equal(erases, 0);

  const stale = (await client.call("review_pair_rebuild_erase", { operation })).structuredContent;
  const old = record.members.entry.fingerprint;
  record.members.entry.fingerprint = "SHA256:" + "E".repeat(43);
  client.approve(stale.id);
  assert.equal((await client.call("apply_pair_rebuild_erase", { id: stale.id })).isError, true);
  record.members.entry.fingerprint = old;
  assert.equal(erases, 0);
  const erase = (await client.call("review_pair_rebuild_erase", { operation })).structuredContent;
  assert.equal(erase.kind, "pair-rebuild-start");
  assert.equal((await client.call("apply_pair_rebuild_erase", { id: erase.id })).isError, true);
  const diskPlan = client.approve(erase.id);
  assert.equal(diskPlan.rebuild.exit.job, record.members.exit.job);
  assert.equal(diskPlan.rebuild.entry.fingerprint, record.members.entry.fingerprint);
  const begun = (await client.call("apply_pair_rebuild_erase", { id: erase.id })).structuredContent;
  assert.deepEqual(begun, { state: "running", operation, progress: { role: "exit", state: "rebooting" } });
  assert.deepEqual((await client.call("apply_pair_rebuild_erase", { id: erase.id })).structuredContent, begun);
  assert.equal(erases, 1);
  running.reject(new Error("interrupted fixture"));
  await Promise.resolve();

  client = await connector();
  assert.equal((await client.call("pair_rebuild_status")).structuredContent.state, "waiting");
  assert.equal((await client.call("review_pair_rebuild_erase", { operation })).isError, true);
  const resume = (await client.call("review_pair_rebuild_resume", { operation })).structuredContent;
  assert.equal(resume.kind, "pair-rebuild-resume");
  assert.equal((await client.call("apply_pair_rebuild_resume", { id: resume.id })).isError, true);
  client.approve(resume.id);
  running = Promise.withResolvers();
  assert.equal((await client.call("apply_pair_rebuild_resume", { id: resume.id })).structuredContent.state, "running");
  journal.restored = { operation, review: original, state: "restored" };
  running.resolve(journal.restored);
  await Promise.resolve();
  assert.equal((await client.call("pair_rebuild_status")).structuredContent.state, "restored");
  assert.equal(erases, 2);
});
