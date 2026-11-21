import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { readScopedAdministration } from "../scripts/gateway-access.mjs";
import { cleanScopedAdministration } from "../src/lib/scoped-administration.mjs";

const inventory = {
  state: "enabled",
  roles: [
    { role: "infrastructure", devices: 0, invitations: 2 },
    { role: "user_manager", devices: 3, invitations: 0 },
    { role: "viewer", devices: 1, invitations: 1 },
  ],
};

test("accepts only bounded role counts and exact administration states", () => {
  assert.deepEqual(cleanScopedAdministration(inventory), inventory);
  for (const state of [
    "notEnabled",
    "disabled",
    "notRegistered",
    "unavailable",
  ]) {
    assert.deepEqual(cleanScopedAdministration({ state }), { state });
  }
  for (const candidate of [
    null,
    [inventory],
    { state: "connected" },
    { ...inventory, credentials: "fictional secret" },
    { state: "disabled", server: "fictional endpoint" },
    { ...inventory, roles: inventory.roles.slice(1) },
    { ...inventory, roles: [...inventory.roles].reverse() },
  ]) {
    assert.deepEqual(cleanScopedAdministration(candidate), {
      state: "unavailable",
    });
  }
  for (const changed of [
    { devices: 4097 },
    { invitations: -1 },
    { devices: 0.5 },
    { devices: "3" },
    { role: "owner" },
    { private_key: "fictional key" },
  ]) {
    const first = { ...inventory.roles[0], ...changed };
    assert.deepEqual(
      cleanScopedAdministration({
        ...inventory,
        roles: [first, ...inventory.roles.slice(1)],
      }),
      {
        state: "unavailable",
      },
    );
  }
});

test("sends the owned inspector via constant SSH command and validates the reply", async () => {
  const client = new EventEmitter();
  const capture = {};
  client.exec = (command, options, callback) => {
    capture.command = command;
    capture.options = options;
    const channel = new EventEmitter();
    channel.stderr = { resume() {} };
    channel.write = (data) => {
      capture.stdin = data;
    };
    channel.end = () => {
      channel.emit("data", Buffer.from(JSON.stringify(inventory)));
      channel.emit("close", 0);
    };
    callback(null, channel);
  };
  assert.deepEqual(
    await readScopedAdministration(client, "203.0.113.40", "openvpn"),
    inventory,
  );
  assert.match(capture.command, /^\/usr\/bin\/python3 -I -B -c /);
  assert.doesNotMatch(capture.command, /203\.0\.113\.40|openvpn/);
  assert.deepEqual(capture.options, { pty: false });
  const [source, request, end] = capture.stdin.split("\n");
  assert.deepEqual(
    Buffer.from(source, "base64"),
    await readFile(new URL("../scripts/gateway_access.py", import.meta.url)),
  );
  assert.deepEqual(JSON.parse(request), {
    address: "203.0.113.40",
    method: "openvpn",
  });
  assert.equal(end, "");
});
