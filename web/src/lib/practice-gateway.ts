import {
  filterPresets,
  readUbuntuRecovery,
  singleProtocolCatalog,
  ubuntuEraseConfirmation,
  ubuntuVersions,
  validLogin,
} from "./gateway-input.mjs";
import { inspectExample, previewAddress } from "./preview.mjs";

export const practiceProgressStages = 5;
const stageMs = 1800;
const connection = {
  version: 1,
  address: previewAddress,
  sshPort: 22,
  fingerprint: "SHA256:" + "A".repeat(43),
};
type Method = "ikev2" | keyof typeof singleProtocolCatalog;
type Recovery = NonNullable<ReturnType<typeof readUbuntuRecovery>>;
type InstallReview = { code: string; method: Method; owner: string };
type Job = { start: number; install?: InstallReview };
type Gateway = { method: Method; owner: string; guests: string[] };
type State = "ready" | "occupied" | "unsupported" | "failed" | "removed";

function samplePort(method: Method) {
  if (method === "awg") return 51820;
  if (method === "openvpn") return 1194;
  return 443;
}

export function practiceProfile(method: Method, login: string) {
  const note = "Rookstride demo – no connection credentials";
  if (method === "ikev2")
    return JSON.stringify(
      {
        name: note,
        type: "ikev2-eap",
        remote: { addr: previewAddress },
        local: { eap_id: login },
      },
      null,
      2,
    );
  const extension = singleProtocolCatalog[method].extension;
  const port = samplePort(method);
  if (extension === "conf")
    return `# ${note}\n[Interface]\n# PrivateKey is issued by your own VPN.\n\n[Peer]\nEndpoint = ${previewAddress}:${port}\n# PublicKey is issued by your own VPN.\n`;
  if (extension === "ovpn")
    return `# ${note}\nclient\ndev tun\nproto tcp-client\nremote ${previewAddress} ${port}\n# Certificates and keys are issued by your own VPN.\n`;
  if (extension === "txt")
    return `# ${note}\n# vless://<client-id>@${previewAddress}:${port}?security=reality&type=${method === "xray" ? "tcp" : "xhttp"}#${login}\n`;
  return JSON.stringify(
    {
      sample: note,
      schema: 1,
      protocol: method,
      server: previewAddress,
      server_name: previewAddress,
      port,
      login,
    },
    null,
    2,
  );
}

// A tab owns its sample state. This adapter has no access to a network
// transport, gateway credentials, real destinations, or browser storage.
export function createPracticeGateway(now = Date.now) {
  let inspection: State | null = null;
  let gateway: Gateway | null = null;
  let job: Job | null = null;
  let review: InstallReview | null = null;
  let removalReview = "";
  let revision = "";
  let preset = "standard";
  let protectionEnabled = true;
  let ubuntu = "24.04";
  let server: Recovery["server"] = connection;
  let reinstall:
    | { code: string; recovery: Recovery; started?: number; finished?: boolean }
    | undefined;

  function reset() {
    inspection = null;
    gateway = null;
    job = null;
    review = null;
    removalReview = "";
    revision = "";
    preset = "standard";
    protectionEnabled = true;
    ubuntu = "24.04";
    server = connection;
    reinstall = undefined;
  }

  function status() {
    let progress: number | undefined;
    if (job) {
      const elapsed = Math.max(0, now() - job.start);
      const duration = job.install ? stageMs * practiceProgressStages : stageMs;
      if (elapsed >= duration) {
        const install = job.install;
        gateway = install
          ? { method: install.method, owner: install.owner, guests: [] }
          : null;
        inspection = install ? "ready" : "removed";
        revision = crypto.randomUUID();
        preset = "standard";
        protectionEnabled = true;
        job = null;
      } else if (job.install) progress = Math.floor(elapsed / stageMs);
    }
    const method = job?.install?.method ?? gateway?.method;
    const state = job
      ? job.install
        ? method === "ikev2"
          ? "running"
          : "protocolRunning"
        : "removing"
      : gateway
        ? method === "ikev2"
          ? "installed"
          : "protocolInstalled"
        : inspection;
    return Response.json({
      state,
      session: state ? "practice" : "",
      address: previewAddress,
      os: `Ubuntu ${ubuntu} LTS`,
      connection: server,
      method,
      availableMethods: Object.keys(singleProtocolCatalog),
      progress,
    });
  }

  function accounts() {
    if (!gateway) return fail("verifiedSessionRequired");
    const { owner, guests } = gateway;
    return Response.json({
      owner,
      guests,
      users: [owner, ...guests],
      revision,
    });
  }

  function request(payload: Record<string, unknown>) {
    const { action, login, method, confirmed } = payload;
    if (action === "close") {
      reset();
      return new Response(null, { status: 204 });
    }
    if (action === "inspect") {
      const example = inspectExample({
        address: previewAddress,
        scenario: payload.scenario,
      });
      const returned = reinstall?.finished ? { server, ubuntu } : undefined;
      reset();
      if (returned) ({ server, ubuntu } = returned);
      if (example.state === "unreachable") return fail("inspectionUnavailable");
      if (example.state === "blocked") return fail("identityMismatch");
      inspection = example.state === "example-ready" ? "ready" : "occupied";
      return status();
    }
    if (action === "status" || action === "protocolStatus") return status();
    if (action === "cancel" && job?.install) {
      job = null;
      return status();
    }
    if (job) return fail("operationBusy");
    if (action === "ubuntuCheck" && inspection)
      return Response.json({ eligible: true });
    if (
      action === "ubuntuReview" &&
      inspection &&
      typeof payload.ubuntu === "string" &&
      ubuntuVersions.includes(payload.ubuntu)
    ) {
      if (reinstall?.started !== undefined && !reinstall.finished)
        return fail("operationBusy");
      const recovery = {
        job: crypto.randomUUID().replaceAll("-", ""),
        ubuntu: payload.ubuntu,
        fingerprint:
          "SHA256:" +
          (server.fingerprint === connection.fingerprint ? "B" : "A").repeat(
            43,
          ),
        server,
      };
      reinstall = { code: crypto.randomUUID(), recovery };
      return Response.json({
        review: reinstall.code,
        recovery,
        diskBytes: 24 * 1024 ** 3,
        boot: "EFI",
      });
    }
    if (action === "ubuntuApply") {
      if (
        !reinstall ||
        reinstall.started !== undefined ||
        payload.review !== reinstall.code ||
        payload.confirmation !== ubuntuEraseConfirmation
      )
        return fail("invalidUbuntuReinstall");
      reinstall.started = now();
      return Response.json({ state: "ubuntuReinstalling" });
    }
    if (action === "ubuntuResume") {
      const recovery = readUbuntuRecovery(payload.recovery);
      if (
        reinstall?.started === undefined ||
        !recovery ||
        recovery.job !== reinstall.recovery.job ||
        recovery.fingerprint !== reinstall.recovery.fingerprint ||
        recovery.ubuntu !== reinstall.recovery.ubuntu
      )
        return fail("invalidUbuntuReinstall");
      if (now() - reinstall.started < 2500)
        return Response.json({ state: "rebooting" });
      gateway = null;
      review = null;
      removalReview = "";
      inspection = "ready";
      ubuntu = recovery.ubuntu;
      server = {
        ...server,
        version: 2,
        fingerprint: recovery.fingerprint,
        keyType: "ecdsa-sha2-nistp256",
      };
      reinstall.finished = true;
      return Response.json({ state: "complete", ubuntu, server });
    }

    const ready =
      !gateway && (inspection === "ready" || inspection === "removed");
    if (
      action === "install" &&
      ready &&
      confirmed === true &&
      validLogin(login)
    ) {
      job = {
        start: now(),
        install: { code: "", method: "ikev2", owner: login as string },
      };
      return status();
    }
    if (
      action === "protocolReview" &&
      ready &&
      validLogin(login) &&
      typeof method === "string" &&
      Object.hasOwn(singleProtocolCatalog, method)
    ) {
      review = {
        code: crypto.randomUUID(),
        method: method as Method,
        owner: login as string,
      };
      const port = samplePort(review.method);
      return Response.json({ review: review.code, port });
    }
    if (
      action === "protocolApply" &&
      ready &&
      review &&
      payload.review === review.code &&
      confirmed === true
    ) {
      job = { start: now(), install: review };
      review = null;
      return status();
    }
    if (["install", "protocolReview", "protocolApply"].includes(String(action)))
      return fail("protocolReviewRequired");
    if (!gateway) return fail("verifiedSessionRequired");

    if (action === "removeReview") {
      removalReview = crypto.randomUUID();
      return Response.json({ review: removalReview });
    }
    if (action === "removeApply") {
      if (
        !removalReview ||
        payload.review !== removalReview ||
        payload.confirmation !== "DELETE VPN"
      )
        return fail("removalReviewRequired");
      removalReview = "";
      job = { start: now() };
      return status();
    }
    if (action === "guests" || action === "protocolUsers") return accounts();

    const { guests, owner } = gateway;
    const isGuest = typeof login === "string" && guests.includes(login);
    if (action === "profile" || action === "protocolProfile") {
      if (login !== undefined && login !== owner && !isGuest)
        return fail("invalidProfile");
      return new Response(
        JSON.stringify({ method: gateway.method, login: login ?? owner }),
        {
          headers: { "Content-Type": "application/octet-stream" },
        },
      );
    }
    if (
      action === "grant" ||
      action === "protocolGrant" ||
      action === "revoke" ||
      action === "protocolRevoke" ||
      action === "rotate"
    ) {
      if (payload.revision !== revision) return fail("rosterChanged");
      if (typeof login !== "string" || !validLogin(login) || login === owner)
        return fail("invalidGuestDetails");
      if (action === "grant" || action === "protocolGrant") {
        if (isGuest) return fail("invalidGuestDetails");
        guests.push(login);
      } else {
        if (!isGuest || confirmed !== true) return fail("invalidGuestDetails");
        if (action !== "rotate") guests.splice(guests.indexOf(login), 1);
      }
      revision = crypto.randomUUID();
      return accounts();
    }
    if (action === "health")
      return Response.json({
        services: { vpn: true, filter: true, resolver: true, firewall: true },
      });
    if (action === "usage" || action === "protocolUsage") {
      const method = gateway.method;
      const traffic = method === "xray" || method === "xhttp";
      return Response.json({
        usage: {
          available: true,
          upload: 125390,
          download: 2063110,
          ...(action === "usage" ? { sessions: 2 } : {
            kind: traffic ? "traffic" : method === "awg" ? "handshake" : "sessions",
            scope: method === "awg" ? "interface" : method === "openvpn" ? "active-sessions" : "daemon",
            profiles: traffic ? null : 2,
          }),
        },
      });
    }
    if (action === "filter" || action === "protocolFilter") {
      const native = action === "protocolFilter";
      if (payload.enabled !== undefined) {
        if (!native || typeof payload.enabled !== "boolean" ||
            payload.level !== undefined || confirmed !== true)
          return fail("invalidMaintenanceDetails");
        protectionEnabled = payload.enabled;
      }
      if (payload.level !== undefined) {
        if (
          typeof payload.level !== "string" ||
          !filterPresets.includes(payload.level) ||
          confirmed !== true
        )
          return fail("invalidMaintenanceDetails");
        preset = payload.level;
      }
      return Response.json({
        filtering: {
          presets: [preset], queries: 146, blocked: 32,
          ...(native && { protectionEnabled }),
        },
      });
    }
    return fail("unknownAction");
  }

  return { request, reset };
}

function fail(messageKey: string) {
  return Response.json({ messageKey }, { status: 409 });
}
