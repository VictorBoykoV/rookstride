import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { executeGateway, openSsh } from "../scripts/gateway-ssh.mjs";

async function fixtureHostKey(keyType = "ed25519") {
  // ssh2 1.17.0 drops leading zero bytes from generated Ed25519 public keys.
  const directory = await mkdtemp(join(tmpdir(), "rookstride-ssh-test-"));
  try {
    const keyPath = join(directory, "host");
    const generated = spawnSync(
      "ssh-keygen",
      [
        "-q",
        "-t",
        keyType,
        ...(keyType === "ecdsa" ? ["-b", "256"] : []),
        "-N",
        "",
        "-C",
        "rookstride-loopback-test",
        "-f",
        keyPath,
      ],
      { stdio: "ignore", timeout: 5000 },
    );
    if (generated.error) throw generated.error;
    assert.equal(
      generated.status,
      0,
      "Could not generate the loopback host key",
    );
    const [privateKey, publicKey] = await Promise.all([
      readFile(keyPath),
      readFile(`${keyPath}.pub`, "utf8"),
    ]);
    const fingerprint =
      "SHA256:" +
      createHash("sha256")
        .update(Buffer.from(publicKey.split(" ")[1], "base64"))
        .digest("base64")
        .replace(/=+$/, "");
    return { privateKey, fingerprint };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function sshFixture(t, reply, keyType) {
  const { privateKey, fingerprint } = await fixtureHostKey(keyType);
  const password = randomBytes(24).toString("hex");
  const clients = new Set();
  const stats = { passwordAttempts: 0, accepted: 0, execs: [] };
  const server = new ssh2.Server({ hostKeys: [privateKey] }, (peer) => {
    clients.add(peer);
    peer.on("error", () => {});
    peer.once("close", () => clients.delete(peer));
    peer.on("authentication", (auth) => {
      if (auth.method !== "password") return auth.reject(["password"]);
      stats.passwordAttempts++;
      if (auth.username !== "root" || auth.password !== password)
        return auth.reject();
      stats.accepted++;
      auth.accept();
    });
    peer.on("ready", () => {
      peer.on("session", (accept) => {
        accept().on("exec", (acceptExec, _rejectExec, info) => {
          const channel = acceptExec();
          const chunks = [];
          channel.on("error", () => {});
          channel.on("data", (chunk) => chunks.push(chunk));
          channel.once("end", () => {
            const rawInput = Buffer.concat(chunks);
            const call = {
              command: info.command,
              input: rawInput.toString("utf8"),
              rawInput,
            };
            stats.execs.push(call);
            reply?.(call, channel, peer);
          });
        });
      });
    });
  });
  const ready = once(server, "listening");
  server.listen(0, "127.0.0.1");
  await ready;
  t.after(async () => {
    for (const peer of clients) peer.end();
    await new Promise((resolve) => server.close(resolve));
  });
  return {
    stats,
    options: {
      address: "127.0.0.1",
      sshPort: server.address().port,
      password,
      fingerprint,
    },
  };
}

function complete(channel, data, code = 0) {
  channel.write(data);
  channel.exit(code);
  channel.end();
}

test(
  "an unrecognized Ed25519 host key stops SSH before the password",
  { timeout: 10000 },
  async (t) => {
    const { stats, options } = await sshFixture(t);
    const other =
      "SHA256:" + randomBytes(32).toString("base64").replace(/=+$/, "");
    await assert.rejects(openSsh({ ...options, fingerprint: other }), {
      message: "pin",
    });
    assert.equal(stats.passwordAttempts, 0);
    assert.equal(stats.accepted, 0);
  },
);

test("Ubuntu recovery pins the replacement ECDSA key before authentication", { timeout: 15000 }, async (t) => {
  const { options, stats } = await sshFixture(t, (_call, channel) => {
    complete(channel, JSON.stringify({ job: "1".repeat(32), state: "complete", version: "24.04" }));
  }, "ecdsa");
  await assert.rejects(openSsh({
    ...options,
    keyType: "ecdsa-sha2-nistp256",
    fingerprint: "SHA256:" + randomBytes(32).toString("base64").replace(/=+$/, ""),
  }), { message: "pin" });
  assert.equal(stats.passwordAttempts, 0);
  const client = await openSsh({ ...options, keyType: "ecdsa-sha2-nistp256" });
  assert.equal(stats.passwordAttempts, 1);
  client.destroy();
});

test(
  "pinned SSH authenticates once and carries the runner and user input on stdin",
  { timeout: 10000 },
  async (t) => {
    const runner = await readFile(
      new URL("../scripts/gateway_remote.py", import.meta.url),
    );
    const { stats, options } = await sshFixture(t, (_call, channel) => {
      complete(channel, JSON.stringify({ state: "ready" }));
    });
    const client = await openSsh(options);
    try {
      const requests = [
        { action: "inspect" },
        {
          action: "grant",
          login: "sample-guest",
          vpnPassword: randomBytes(18).toString("hex"),
        },
      ];
      for (const request of requests)
        assert.deepEqual(await executeGateway(client, request), {
          state: "ready",
        });
      assert.equal(stats.passwordAttempts, 1);
      assert.equal(stats.accepted, 1);
      assert.equal(stats.execs.length, 2);
      assert.equal(stats.execs[0].command, stats.execs[1].command);
      assert.match(
        stats.execs[0].command,
        /^\/usr\/bin\/python3 -I -B -c "[^"\n]+"$/,
      );
      for (const [i, call] of stats.execs.entries()) {
        const lines = call.input.trimEnd().split("\n");
        assert.equal(lines.length, 2);
        assert.equal(Buffer.from(lines[0], "base64").equals(runner), true);
        assert.deepEqual(JSON.parse(lines[1]), requests[i]);
        assert.equal(call.command.includes(options.password), false);
        assert.equal(call.command.includes(requests[1].login), false);
        assert.equal(call.command.includes(requests[1].vpnPassword), false);
      }
    } finally {
      client.end();
    }
  },
);

test("runtime bytes travel separately from the bounded JSON request", { timeout: 10000 }, async (t) => {
  const { stats, options } = await sshFixture(t, (_call, channel) => {
    complete(channel, JSON.stringify({ state: "protocolRunning" }));
  });
  const client = await openSsh(options);
  try {
    const archive = Buffer.from([0, 13, 10, 255, 7, 2, 0, 10, 229]);
    const request = {
      action: "protocolApply",
      method: "hysteria2",
      runtimeArchitecture: "x86_64",
    };
    await executeGateway(client, request, archive);
    const { rawInput } = stats.execs[0];
    const start = rawInput.indexOf(10) + 1;
    const end = rawInput.indexOf(10, start);
    assert.deepEqual(JSON.parse(rawInput.subarray(start, end)), request);
    assert.deepEqual(rawInput.subarray(end + 1), archive);
    await assert.rejects(executeGateway(client, request, "not a buffer"), {
      message: "transport",
    });
    assert.equal(stats.execs.length, 1);
  } finally {
    client.end();
  }
});

test(
  "SSH command failures and interrupted channels return only a safe failure",
  { timeout: 15000 },
  async (t) => {
    const canary = randomBytes(16).toString("hex");
    const outcomes = [
      (channel) => complete(channel, JSON.stringify({ state: "installed" }), 1),
      (channel) => complete(channel, canary),
      (channel) => complete(channel, "x".repeat(32769)),
      (channel) => {
        channel.write('{"state":"installed"}');
        channel.end();
      },
      (_channel, peer) => peer.end(),
    ];
    const { options } = await sshFixture(t, (_call, channel, peer) => {
      channel.stderr.write(canary);
      outcomes.shift()(channel, peer);
    });
    const client = await openSsh(options);
    try {
      while (outcomes.length) {
        await assert.rejects(executeGateway(client, { action: "inspect" }), {
          message: "transport",
        });
      }
    } finally {
      client.end();
    }
  },
);

test(
  "the actual Python runner over SSH declines inspection on an unsupported local host",
  {
    skip:
      process.platform !== "darwin" &&
      (typeof process.getuid !== "function" || process.getuid() === 0),
    timeout: 15000,
  },
  async (t) => {
    let child;
    const { options } = await sshFixture(t, ({ command, input }, channel) => {
      // Execute only the Python bootstrap sent by the genuine client, with a read-only inspect action.
      const match = /^\/usr\/bin\/python3 -I -B -c "([^"\n]+)"$/.exec(command);
      if (!match || JSON.parse(input.split("\n")[1]).action !== "inspect")
        return complete(channel, "", 1);
      child = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", match[1]], {
        input,
        encoding: "utf8",
        timeout: 5000,
      });
      complete(channel, child.stdout || "", child.status ?? 1);
    });
    const client = await openSsh(options);
    try {
      const result = await executeGateway(client, { action: "inspect" });
      assert.equal(child.status, 0);
      assert.equal(result.state, "unsupported");
      assert.match(result.message, /Ubuntu 22\.04, 24\.04 or 26\.04 LTS/);
    } finally {
      client.end();
    }
  },
);

test(
  "personal worker process carries approved install and guest operations over the pinned session",
  { timeout: 15000 },
  async (t) => {
    const { createGatewayService, startWorker } =
      await import("../src/lib/gateway-service.mjs");
    const { recipePaths, accountPaths } =
      await import("../src/lib/gateway-files.mjs");
    const { fileURLToPath } = await import("node:url");
    const { X509Certificate } = await import("node:crypto");
    const { rootCertificates } = await import("node:tls");
    const { setTimeout: delay } = await import("node:timers/promises");
    const revision = "1".repeat(64);
    const { options, stats } = await sshFixture(t, (call, channel) => {
      const request = JSON.parse(
        call.input.slice(call.input.indexOf("\n") + 1),
      );
      let result;
      if (request.action === "inspect")
        result = { state: "ready", os: "Ubuntu 24.04" };
      else if (request.action === "install") {
        assert.deepEqual(
          Object.keys(request.files).sort(),
          [...recipePaths].sort(),
        );
        result = { state: "installed" };
      } else {
        assert.deepEqual(
          Object.keys(request.files).sort(),
          [...accountPaths].sort(),
        );
        result =
          request.action === "profile"
            ? {
                profile: {
                  uuid: "4a9a5938-abca-4d49-a24d-098fcf7ef807",
                  type: "ikev2-eap",
                  local: { eap_id: request.login },
                  remote: {
                    addr: request.address,
                    id: request.address,
                    cert: new X509Certificate(rootCertificates[0]).raw.toString(
                      "base64",
                    ),
                  },
                },
              }
            : { owner: "owner", guests: ["friend"], revision };
      }
      complete(channel, JSON.stringify(result));
    });
    const previous = [
      process.env.ROOKSTRIDE_WEB_ROOT,
      process.env.ROOKSTRIDE_PERSONAL_WEB,
    ];
    process.env.ROOKSTRIDE_WEB_ROOT = fileURLToPath(
      new URL("../", import.meta.url),
    );
    process.env.ROOKSTRIDE_PERSONAL_WEB = "1";
    const app = createGatewayService(
      startWorker,
      (address) => address === "127.0.0.1",
    );
    let session;
    try {
      session = (await app.post({ action: "inspect", ...options })).session;
      await app.post(
        {
          action: "install",
          login: "owner",
          vpnPassword: "Test passphrase",
          confirmed: true,
        },
        session,
      );
      while (app.get(session).state === "running") await delay(10);
      assert.equal(app.get(session).state, "installed");
      assert.equal(
        (
          await app.post(
            {
              action: "grant",
              login: "friend",
              revision,
              vpnPassword: "Guest test.",
            },
            session,
          )
        ).owner,
        "owner",
      );
      const { profile } = await app.post(
        { action: "profile", login: "friend" },
        session,
      );
      assert.equal(profile.local.eap_id, "friend");
      assert.equal(stats.passwordAttempts, 1);
    } finally {
      if (session) await app.post({ action: "close" }, session);
      for (const [index, key] of [
        "ROOKSTRIDE_WEB_ROOT",
        "ROOKSTRIDE_PERSONAL_WEB",
      ].entries()) {
        if (previous[index] === undefined) delete process.env[key];
        else process.env[key] = previous[index];
      }
    }
  },
);
