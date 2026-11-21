import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { rootCertificates } from "node:tls";
import test from "node:test";
import { handleGateway } from "../src/lib/gateway-http.mjs";
import { singleProtocolCatalog } from "../src/lib/gateway-input.mjs";
import { createGatewayService } from "../src/lib/gateway-service.mjs";

const formats = {
  ikev2: "sswan",
  awg: "conf",
  xray: "txt",
  openvpn: "ovpn",
  xhttp: "txt",
  hysteria2: "rookvpn",
  outline: "rookvpn",
  shadowsocks: "rookvpn",
  trusttunnel: "rookvpn",
  naive: "rookvpn",
};
const address = "192.0.2.27";
const port = 8443;
const owner = "fixture-owner";
const guest = "fixture-guest";
const vpnPassword = "fixture-vpn-password";
const sshPassword = "fixture-ssh-password";
const ca = rootCertificates[0];
const identity = "00000000-0000-0000-0000-000000000001";

function nativeConfiguration(method, login) {
  const format = formats[method];
  if (format === "txt") {
    const type = method === "xray" ? "tcp" : "xhttp";
    return `vless://${identity}@${address}:${port}?security=reality&type=${type}#${login}`;
  }
  if (format === "conf") {
    return `[Interface]\n[Peer]\nEndpoint = ${address}:${port}`;
  }
  if (format === "ovpn") {
    const blocks = ["ca", "cert", "key", "tls-crypt"].map(
      (name) => `<${name}>\nnonfunctional-fixture\n</${name}>`,
    );
    return [
      `remote ${address} ${port}`,
      "verify-x509-name server name",
      ...blocks,
    ].join("\n");
  }
  return JSON.stringify({
    schema: 1,
    protocol: method,
    server: address,
    port,
    login,
    password: vpnPassword,
    certificate: ca,
    server_name: address,
    ...(method === "hysteria2" && { obfs: "fixture" }),
    ...(["outline", "shadowsocks"].includes(method) && {
      method: "fixture",
      path: "/fixture",
    }),
  });
}

test("each standalone method completes its browser HTTP lifecycle with an isolated worker fixture", async (context) => {
  assert.deepEqual(Object.keys(formats), [
    "ikev2",
    ...Object.keys(singleProtocolCatalog),
  ]);
  for (const [method, format] of Object.entries(formats)) {
    await context.test(method, async () => {
      const native = method !== "ikev2";
      const actions = [];
      let revision = "a".repeat(64);
      let guests = [];
      let level = "standard";
      let protectionEnabled = true;
      let stopped = 0;
      const roster = () => ({
        owner,
        revision,
        ...(native ? { users: [owner, ...guests] } : { guests }),
      });
      const service = createGatewayService(
        () => ({
          async request(input) {
            actions.push(input);
            switch (input.action) {
              case "inspect":
                return { state: "ready", os: "Ubuntu 24.04" };
              case "install":
                assert.deepEqual(input, {
                  action: "install",
                  login: owner,
                  vpnPassword,
                });
                return { state: "installed" };
              case "protocolReview":
                assert.deepEqual(input, {
                  action: "protocolReview",
                  login: owner,
                  method,
                });
                return { port };
              case "protocolApply":
                assert.deepEqual(input, {
                  action: "protocolApply",
                  login: owner,
                  port,
                  method,
                });
                return { state: "protocolRunning", method };
              case "protocolStatus":
                return { state: "protocolInstalled", method, port };
              case "guests":
              case "protocolUsers":
                return roster();
              case "grant":
              case "protocolGrant":
                if (input.revision !== revision) return { state: "conflict" };
                assert.equal(input.login, guest);
                if (!native) assert.equal(input.vpnPassword, vpnPassword);
                guests = [guest];
                revision = "b".repeat(64);
                return roster();
              case "revoke":
              case "protocolRevoke":
                if (input.revision !== revision) return { state: "conflict" };
                assert.equal(input.login, guest);
                guests = [];
                revision = "c".repeat(64);
                return roster();
              case "profile":
                return {
                  profile: {
                    type: "ikev2-eap",
                    uuid: identity,
                    remote: {
                      addr: address,
                      id: address,
                      cert: new X509Certificate(ca).raw.toString("base64"),
                    },
                    local: { eap_id: input.login },
                  },
                };
              case "protocolProfile":
                assert.equal(input.login, guest);
                return {
                  method,
                  port,
                  configuration: nativeConfiguration(method, guest),
                };
              case "filter":
              case "protocolFilter":
                level = input.level ?? level;
                protectionEnabled = input.enabled ?? protectionEnabled;
                return {
                  presets: [level],
                  queries: 12,
                  blocked: 3,
                  ...(native && { protectionEnabled }),
                };
              case "usage":
                return { available: true, sessions: 1, upload: 4, download: 8 };
              case "protocolUsage":
                return {
                  available: true,
                  kind: "traffic",
                  scope: "daemon",
                  profiles: null,
                  upload: 4,
                  download: 8,
                };
              case "removeReview":
              case "protocolRemoveReview":
                return { token: "d".repeat(64) };
              case "removeApply":
              case "protocolRemoveApply":
                assert.equal(input.token, "d".repeat(64));
                assert.equal(input.confirmation, "DELETE VPN");
                return { state: "removed" };
              default:
                assert.fail(input.action);
            }
          },
          stop() {
            stopped++;
          },
        }),
        (target) => target === address,
      );

      let session;
      async function request(body, expectedStatus = 200, token = session) {
        const headers = {
          ...(token && { Authorization: `Bearer ${token}` }),
          ...(body && { "Content-Type": "application/json" }),
        };
        const response = await handleGateway(
          new Request("http://localhost:3100/api/gateway", {
            method: body ? "POST" : "GET",
            headers,
            ...(body && { body: JSON.stringify(body) }),
          }),
          service,
        );
        assert.equal(response.headers.get("Cache-Control"), "no-store");
        assert.equal(
          response.status,
          expectedStatus,
          await response.clone().text(),
        );
        return response;
      }
      const post = async (body, status) => (await request(body, status)).json();

      ({ session } = await post({
        action: "inspect",
        address,
        sshPort: 22,
        password: sshPassword,
        fingerprint: `SHA256:${"A".repeat(43)}`,
      }));
      try {
        const profile = {
          action: native ? "protocolProfile" : "profile",
          login: guest,
        };
        const denied = await request(profile, 401, "z".repeat(43));
        assert.equal((await denied.json()).messageKey, "sessionEnded");
        assert.equal(
          (await post(profile, 409)).messageKey,
          "verifiedSessionRequired",
        );
        const installAction = native ? "protocolApply" : "install";
        const install = native
          ? {
              action: installAction,
              confirmed: true,
              review: (
                await post({ action: "protocolReview", method, login: owner })
              ).review,
            }
          : {
              action: installAction,
              confirmed: true,
              login: owner,
              vpnPassword,
            };
        await post(install);
        await post(install);
        await setImmediate();
        const ready = native
          ? await post({ action: "protocolStatus" })
          : await (await request()).json();
        assert.equal(ready.state, native ? "protocolInstalled" : "installed");
        if (native) assert.equal(ready.method, method);
        assert.equal(
          actions.filter(({ action }) => action === installAction).length,
          1,
        );

        const list = { action: native ? "protocolUsers" : "guests" };
        const first = await post(list);
        const grant = {
          action: native ? "protocolGrant" : "grant",
          login: guest,
          revision: first.revision,
          ...(!native && { vpnPassword }),
        };
        const added = await post(grant);
        assert.ok((added.users ?? added.guests).includes(guest));
        assert.equal((await post(grant, 409)).messageKey, "rosterChanged");
        const download = await request(profile);
        assert.equal(
          download.headers.get("Content-Type"),
          "application/octet-stream",
        );
        assert.equal(
          download.headers.get("Content-Disposition"),
          `attachment; filename="${native ? `rookstride-${guest}` : "rookstride"}.${format}"`,
        );
        if (native)
          assert.equal(
            await download.text(),
            nativeConfiguration(method, guest) + "\n",
          );
        else assert.equal((await download.json()).local.eap_id, guest);
        const revoked = await post({
          action: native ? "protocolRevoke" : "revoke",
          login: guest,
          revision: added.revision,
          confirmed: true,
        });
        assert.equal((revoked.users ?? revoked.guests).includes(guest), false);

        const filterAction = native ? "protocolFilter" : "filter";
        assert.deepEqual(
          (await post({ action: filterAction })).filtering.presets,
          ["standard"],
        );
        assert.deepEqual(
          (
            await post({
              action: filterAction,
              level: "strong",
              confirmed: true,
            })
          ).filtering.presets,
          ["strong"],
        );
        if (native) {
          for (const enabled of [false, true]) {
            assert.equal(
              (await post({ action: filterAction, enabled, confirmed: true }))
                .filtering.protectionEnabled,
              enabled,
            );
          }
        }
        assert.equal(
          (await post({ action: native ? "protocolUsage" : "usage" })).usage
            .download,
          8,
        );

        const { review } = await post({ action: "removeReview" });
        const remove = {
          action: "removeApply",
          review,
          confirmation: "DELETE VPN",
        };
        await post(remove);
        await post(remove);
        await setImmediate();
        assert.equal((await (await request()).json()).state, "removed");
        assert.equal(
          actions.filter(
            ({ action }) =>
              action === (native ? "protocolRemoveApply" : "removeApply"),
          ).length,
          1,
        );
      } finally {
        await post({ action: "close" });
      }
      await request(undefined, 401);
      assert.equal(stopped, 1);
    });
  }
});
