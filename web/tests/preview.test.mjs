import test from "node:test";
import assert from "node:assert/strict";
import { inspectExample, previewAddress } from "../src/lib/preview.mjs";
import {
  createPracticeGateway,
  practiceProfile,
  practiceProgressStages,
} from "../src/lib/practice-gateway.ts";
import {
  singleProtocolCatalog,
  ubuntuEraseConfirmation,
  readUbuntuRecovery,
} from "../src/lib/gateway-input.mjs";

test("the complete sample is explicitly non-executing", () => {
  const result = inspectExample({ address: previewAddress, scenario: "fresh" });
  assert.equal(result.mode, "fixture");
  assert.equal(result.serverContacted, false);
  assert.equal(result.executionAvailable, false);
  assert.equal(result.steps.length, 5);
  assert.notEqual(result.state, "verified");
});

for (const scenario of ["existing", "unreachable", "changed-key"]) {
  test(`${scenario} never offers an installation plan`, () => {
    const result = inspectExample({ address: previewAddress, scenario });
    assert.deepEqual(result.steps, []);
    assert.equal(result.executionAvailable, false);
  });
}

test("real targets, credentials and unexpected shapes are refused", () => {
  for (const input of [
    null,
    [],
    {},
    { address: "127.0.0.1", scenario: "fresh" },
    { address: "203.0.113.1", scenario: "fresh" },
    {
      address: previewAddress,
      scenario: "fresh",
      password: "example-only-marker",
    },
    { address: previewAddress, scenario: "unknown" },
  ]) {
    assert.throws(() => inspectExample(input), /preview accepts only/);
  }
});

function fixture() {
  let clock = 0;
  const { request } = createPracticeGateway(() => clock);
  return {
    request,
    advance(ms) {
      clock += ms;
    },
    async send(action, payload = {}) {
      const response = request({ action, ...payload });
      assert.ok(response.ok, action);
      return response.json();
    },
  };
}

test("practice blocks install on occupied or unverifiable fixtures", async () => {
  for (const scenario of ["existing", "unreachable", "changed-key"]) {
    const { request } = fixture();
    const response = request({ action: "inspect", scenario });
    if (scenario === "existing")
      assert.equal((await response.json()).state, "occupied");
    else assert.equal(response.status, 409);
    assert.equal(
      request({ action: "install", login: "owner", confirmed: true }).status,
      409,
    );
  }
});

test("all ten sample methods can complete after a staged and cancellable review", async () => {
  const { request, advance, send } = fixture();
  const { availableMethods } = await send("inspect", { scenario: "fresh" });
  assert.deepEqual(availableMethods, Object.keys(singleProtocolCatalog));
  for (const method of ["ikev2", ...availableMethods]) {
    const first =
      method === "ikev2"
        ? await send("install", { login: "owner", confirmed: true })
        : await (async () => {
            const { review } = await send("protocolReview", {
              method,
              login: "owner",
            });
            assert.equal(
              request({ action: "protocolApply", review, confirmed: false })
                .status,
              409,
            );
            return send("protocolApply", { review, confirmed: true });
          })();
    assert.equal(first.progress, 0);
    if (method === "ikev2") {
      advance(1800);
      assert.equal((await send("status")).progress, 1);
      assert.equal((await send("cancel")).state, "ready");
      assert.equal(request({ action: "profile" }).status, 409);
      await send("install", { login: "owner", confirmed: true });
    }
    for (let step = 1; step < practiceProgressStages; step++) {
      advance(1800);
      assert.equal((await send("status")).progress, step);
    }
    advance(1800);
    const done = await send("status");
    assert.equal(
      done.state,
      method === "ikev2" ? "installed" : "protocolInstalled",
    );
    assert.equal(done.method, method);
    if (method !== "ikev2") {
      assert.equal((await send("protocolFilter")).filtering.protectionEnabled, true);
      assert.equal(request({ action: "protocolFilter", enabled: false }).status, 409);
      assert.equal((await send("protocolFilter", {
        enabled: false, confirmed: true,
      })).filtering.protectionEnabled, false);
      assert.equal((await send("protocolUsage")).usage.available, true);
    }
    const { review } = await send("removeReview");
    assert.equal(
      (await send("removeApply", { review, confirmation: "DELETE VPN" })).state,
      "removing",
    );
    advance(1800);
    assert.equal((await send("status")).state, "removed");
  }
});

test("practice accounts, exports and filters stay in the originating tab", async () => {
  const { request, advance, send } = fixture();
  const other = fixture();
  await send("inspect", { scenario: "fresh" });
  await send("install", { login: "owner", confirmed: true });
  advance(9000);
  await send("status");
  const initial = await send("guests");
  let roster = await send("grant", {
    login: "friend",
    revision: initial.revision,
  });
  assert.deepEqual(roster.guests, ["friend"]);
  assert.deepEqual(await send("profile", { login: "friend" }), {
    method: "ikev2",
    login: "friend",
  });
  assert.equal(other.request({ action: "profile" }).status, 409);
  assert.equal(
    request({
      action: "revoke",
      login: "friend",
      confirmed: true,
      revision: initial.revision,
    }).status,
    409,
  );
  roster = await send("rotate", {
    login: "friend",
    confirmed: true,
    revision: roster.revision,
  });
  assert.deepEqual(
    (
      await send("revoke", {
        login: "friend",
        confirmed: true,
        revision: roster.revision,
      })
    ).guests,
    [],
  );
  assert.equal(request({ action: "profile", login: "friend" }).status, 409);
  assert.equal((await send("health")).services.filter, true);
  assert.equal((await send("usage")).usage.available, true);
  assert.deepEqual(
    (await send("filter", { level: "strict", confirmed: true })).filtering
      .presets,
    ["strict"],
  );
  assert.equal((await send("ubuntuCheck")).eligible, true);
  assert.equal(request({ action: "close" }).status, 204);
  assert.equal((await send("status")).state, null);
});

test("practice downloads follow the native configuration shapes without keys", () => {
  assert.equal(JSON.parse(practiceProfile("ikev2", "owner")).type, "ikev2-eap");
  assert.match(
    practiceProfile("awg", "owner"),
    /\[Peer\]\nEndpoint = 192\.0\.2\.10:51820/,
  );
  assert.match(
    practiceProfile("openvpn", "owner"),
    /client\ndev tun\nproto tcp-client/,
  );
  assert.match(practiceProfile("xhttp", "owner"), /# vless:\/\/<client-id>/);
  for (const method of [
    "hysteria2",
    "outline",
    "shadowsocks",
    "trusttunnel",
    "naive",
  ]) {
    const profile = JSON.parse(practiceProfile(method, "owner"));
    assert.equal(profile.protocol, method);
    assert.equal(profile.password, undefined);
    assert.equal(profile.certificate, undefined);
  }
});

test("practice reinstall confirms the simulated key before clearing the VPN", async () => {
  const { send, advance, request } = fixture();
  await send("inspect", { scenario: "fresh" });
  await send("install", { login: "owner", confirmed: true });
  advance(9000);
  assert.equal((await send("status")).state, "installed");
  const plan = await send("ubuntuReview", { ubuntu: "26.04" });
  assert.ok(readUbuntuRecovery(plan.recovery));
  assert.equal(
    request({ action: "ubuntuApply", review: plan.review, confirmation: "" })
      .status,
    409,
  );
  assert.equal(
    (
      await send("ubuntuApply", {
        review: plan.review,
        confirmation: ubuntuEraseConfirmation,
      })
    ).state,
    "ubuntuReinstalling",
  );
  assert.equal(
    (await send("ubuntuResume", { recovery: plan.recovery })).state,
    "rebooting",
  );
  advance(2500);
  const completed = await send("ubuntuResume", { recovery: plan.recovery });
  assert.equal(completed.state, "complete");
  assert.equal(completed.server.fingerprint, plan.recovery.fingerprint);
  assert.equal(request({ action: "profile" }).status, 409);
  assert.equal(
    (await send("inspect", { scenario: "fresh" })).os,
    "Ubuntu 26.04 LTS",
  );
});
