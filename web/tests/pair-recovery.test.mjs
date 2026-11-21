import assert from "node:assert/strict";
import test from "node:test";
import {
  decryptPairRecovery,
  encryptPairRecovery,
  maxPairRecoveryBytes,
} from "../src/lib/pair-recovery.mjs";

const review = {
  pairId: "a".repeat(32),
  entry: { address: "192.0.2.10" },
  exit: { address: "198.51.100.20" },
};
const password = "fixture recovery café 🌐";

function archiveFixture() {
  const plan = {
    pair: review.pairId,
    server: review.entry.address,
    exit_host: review.exit.address,
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
  function node(role, login) {
    return {
      schema: 2,
      purpose: "rookstride-owner-recovery-node",
      deployment: review.pairId,
      role,
      adapter: "awg-identity-v1",
      state: { protocol: "awg", initialLogin: login },
      initial_user: { login, password: "fixture-only-bootstrap" },
      plan: { ...plan, role },
    };
  }
  return {
    schema: 1,
    purpose: "rookstride-owner-recovery",
    deployment: review.pairId,
    revision: 3,
    created: 42,
    nodes: {
      entry: node("entry", "first.user"),
      exit: node("exit", "bridge-aaaaaaaaaaaa"),
    },
  };
}

// Independent deterministic vector for OwnerRecovery.java's envelope. macOS
// CommonCrypto generated it with PBKDF2-SHA256, a 256-bit key, a salt of bytes
// 0–15, a nonce of bytes 16–27, a 40-byte authenticated header and a 16-byte tag.
// It contains documentation-only endpoints and inert bootstrap metadata.
const reference = Buffer.from(
  `
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
`,
  "base64",
);

test("decrypts the independently generated Android-format vector with a Unicode password", async () => {
  const input = Uint8Array.from(reference);
  assert.deepEqual(
    await decryptPairRecovery(input, password, review),
    archiveFixture(),
  );
  assert.deepEqual(input, Uint8Array.from(reference));
});

test("encrypts with fresh salt and nonce and restores legacy AWG node snapshots", async () => {
  const archive = archiveFixture();
  archive.nodes.exit.schema = 1;
  delete archive.nodes.exit.adapter;
  const [first, second] = await Promise.all([
    encryptPairRecovery(archive, password, review),
    encryptPairRecovery(archive, password, review),
  ]);
  assert.equal(first.subarray(0, 8).toString(), "ROOKREC1");
  assert.equal(first.readUInt32BE(8), 250_000);
  assert.notDeepEqual(first.subarray(12, 28), second.subarray(12, 28));
  assert.notDeepEqual(first.subarray(28, 40), second.subarray(28, 40));
  assert.equal(first.includes("fixture-only-bootstrap"), false);
  assert.deepEqual(await decryptPairRecovery(first, password, review), archive);
});

test("rejects unsupported headers and authenticates every remaining envelope region", async () => {
  for (const offset of [0, 8]) {
    const changed = Buffer.from(reference);
    changed[offset] ^= 1;
    await assert.rejects(
      decryptPairRecovery(changed, password, review),
      /Unsupported owner recovery file/,
    );
  }
  for (const offset of [12, 28, 40, reference.length - 1]) {
    const changed = Buffer.from(reference);
    changed[offset] ^= 1;
    await assert.rejects(
      decryptPairRecovery(changed, password, review),
      /Could not authenticate/,
    );
  }
  await assert.rejects(
    decryptPairRecovery(reference, "incorrect fixture password", review),
    /Could not authenticate/,
  );
  await assert.rejects(
    decryptPairRecovery(Buffer.alloc(55), password, review),
    /Unsupported owner recovery file/,
  );
  await assert.rejects(
    decryptPairRecovery(
      Buffer.alloc(maxPairRecoveryBytes + 1),
      password,
      review,
    ),
    /Unsupported owner recovery file/,
  );
});

test("rejects authenticated malformed UTF-8 and missing or malformed passwords", async () => {
  // CommonCrypto encrypted bytes 7b ff 7d, using salt 28–43 and nonce 44–55.
  const invalidUtf8 = Buffer.from(
    "Uk9PS1JFQzEAA9CQHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2NyoSTZ6A6jDSEyd+JOVRFXDuqwY=",
    "base64",
  );
  await assert.rejects(
    decryptPairRecovery(invalidUtf8, password, review),
    /Could not authenticate or decode/,
  );
  for (const invalidPassword of [
    undefined,
    "short",
    "malformed \ud800 password",
  ]) {
    await assert.rejects(
      decryptPairRecovery(reference, invalidPassword, review),
      /at least 12 characters/,
    );
  }
});

test("requires the exact reviewed pair and matching Android node identities before export or rehearsal", async () => {
  for (const mutate of [
    (archive) => {
      archive.purpose = "rookstride.admin.invitation";
    },
    (archive) => {
      delete archive.nodes.exit;
    },
    (archive) => {
      archive.nodes.entry.role = "exit";
    },
    (archive) => {
      archive.nodes.entry.state.protocol = "openvpn";
    },
    (archive) => {
      archive.nodes.entry.adapter = "awg-identity-v2";
    },
    (archive) => {
      archive.nodes.entry.initial_user.login = "wrong-owner";
    },
    (archive) => {
      delete archive.nodes.entry.initial_user.password;
    },
    (archive) => {
      archive.nodes.exit.plan.exit_host = "198.51.100.21";
    },
    (archive) => {
      archive.nodes.exit.plan.tunnel_port = 8443;
    },
    (archive) => {
      archive.nodes.exit.plan.access_mode = "password";
    },
    (archive) => {
      archive.nodes.exit.plan.route_table = 51832;
    },
  ]) {
    const archive = archiveFixture();
    mutate(archive);
    await assert.rejects(
      encryptPairRecovery(archive, password, review),
      /does not match/,
    );
  }
  await assert.rejects(
    decryptPairRecovery(reference, password, {
      ...review,
      pairId: "b".repeat(32),
    }),
    /does not match/,
  );
  await assert.rejects(
    decryptPairRecovery(reference, password, {
      ...review,
      exit: { address: "198.51.100.21" },
    }),
    /does not match/,
  );
});

test("allows exactly 2 MiB of encrypted data and counts multibyte plaintext before encrypting", async () => {
  const archive = { ...archiveFixture(), padding: "" };
  const paddingBytes =
    maxPairRecoveryBytes - 40 - 16 - Buffer.byteLength(JSON.stringify(archive));
  archive.padding = "a".repeat(paddingBytes);
  const file = await encryptPairRecovery(archive, password, review);
  assert.equal(file.byteLength, maxPairRecoveryBytes);
  assert.deepEqual(await decryptPairRecovery(file, password, review), archive);
  archive.padding = "é" + archive.padding.slice(1);
  await assert.rejects(
    encryptPairRecovery(archive, password, review),
    /too large/,
  );
});

for (const [exitProtocol, port] of [["openvpn", 1194], ["ikev2", 500], ["xray", 443]]) {
test(`binds a mixed archive to the reviewed ${exitProtocol} identity and both ports`, async () => {
  const mixed = { ...review, exitProtocol, login: "first.user" };
  const archive = archiveFixture();
  for (const [role, node] of Object.entries(archive.nodes)) {
    Object.assign(node.plan, { exit_protocol: exitProtocol, tunnel_port: port });
    Object.assign(node.state, {
      server: mixed[role].address,
      port: role === "entry" ? 51820 : port,
      protocol: role === "entry" ? "awg" : exitProtocol,
    });
    if (role === "exit") node.adapter = exitProtocol + "-identity-v1";
  }
  const encrypted = await encryptPairRecovery(archive, password, mixed);
  assert.deepEqual(await decryptPairRecovery(encrypted, password, mixed), archive);
  await assert.rejects(decryptPairRecovery(encrypted, password, review), /does not match/);
  await assert.rejects(decryptPairRecovery(reference, password, mixed), /does not match/);
  for (const mutate of [
    (value) => { value.nodes.entry.plan.exit_protocol = "awg"; },
    (value) => { value.nodes.exit.plan.tunnel_port = port + 1; },
    (value) => { value.nodes.exit.state.port = port + 1; },
    (value) => { value.nodes.exit.state.protocol = "awg"; },
    (value) => { value.nodes.exit.state.access_mode = "password"; },
    (value) => { value.nodes.exit.schema = 1; },
    (value) => { value.nodes.exit.adapter = "awg-identity-v1"; },
  ]) {
    const changed = structuredClone(archive);
    mutate(changed);
    await assert.rejects(encryptPairRecovery(changed, password, mixed), /does not match/);
  }
  const otherExit = exitProtocol === "xray" ? "openvpn" : "xray";
  await assert.rejects(encryptPairRecovery(archive, password, { ...mixed, exitProtocol: otherExit }), /does not match/);
  await assert.rejects(encryptPairRecovery(archive, password, { ...mixed, login: "different-owner" }), /does not match/);
});
}
