import { gatewayMessages } from "../i18n/en/management-status.mjs";
import {
  recipePaths,
  accountPaths,
  lifecyclePaths,
  reinstallPaths,
  routeArchitectures,
  singlePaths,
} from "./gateway-files.mjs";
import {
  filterPresets,
  singleProtocolCatalog,
  readUbuntuRecovery,
  ubuntuEraseConfirmation,
  ubuntuVersions,
  validLogin,
  validVpnPassword,
} from "./gateway-input.mjs";
import { personalGatewayEnabled } from "./web-runtime.mjs";
import {
  matchesUbuntuJob,
  replacementServer,
} from "./hosted-ubuntu.mjs";
import { cleanScopedAdministration } from "./scoped-administration.mjs";
import { fork } from "node:child_process";
import { randomBytes, X509Certificate } from "node:crypto";
import { isIPv4 } from "node:net";
import { networkInterfaces } from "node:os";
import { isAbsolute, resolve } from "node:path";

const gatewayFailure = Symbol.for("rookstride.gateway.failure");
export class GatewayError extends Error {
  constructor(status, messageKey) {
    super(gatewayMessages[messageKey]);
    this.messageKey = messageKey;
    this.status = status;
    this[gatewayFailure] = true;
  }
}
export function isGatewayError(error) {
  return error?.[gatewayFailure] === true;
}
function deny(status, messageKey) {
  throw new GatewayError(status, messageKey);
}

// Allow the target's 50-minute installation and 10-minute verification budgets plus preflight.
const maxInstallTime = 65 * 60_000;
const maxRemoveTime = 10 * 60_000;
const maxReinstallTime = 2 * 60 * 60_000;
const idleTime = 10 * 60_000;
const serviceHealthKeys = ["vpn", "filter", "resolver", "firewall"];
const supportedReleases = ["Ubuntu 22.04", "Ubuntu 24.04", "Ubuntu 26.04"];
const protocolStates = [
  "protocolRunning",
  "protocolInstalled",
  "protocolFailed",
];
const validProtocolLogin = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/.test(value);
const singleMethods = Object.keys(singleProtocolCatalog);
const failedStages = new Map([
  ["installation", "installationFailed"],
  ["verification", "verificationFailed"],
]);

export function publicDestination(address) {
  if (typeof address !== "string" || !isIPv4(address)) return false;
  const [a, b, c] = address.split(".").map(Number);
  if (
    [0, 10, 127].includes(a) ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 &&
      (b === 168 ||
        (b === 0 && [0, 2].includes(c)) ||
        (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    address === "168.63.129.16"
  )
    return false;
  return !Object.values(networkInterfaces())
    .flat()
    .some((iface) => iface?.address === address);
}

function exact(input, fields) {
  return (
    input &&
    typeof input === "object" &&
    !Array.isArray(input) &&
    Object.keys(input).length === fields.length &&
    fields.every((field) => Object.hasOwn(input, field))
  );
}

function singleProfile(report, record, login) {
  const { configuration, method, port } = report;
  if (
    method !== record.method ||
    port !== record.protocolPort ||
    typeof configuration !== "string" ||
    configuration.length > 24_000 ||
    /[\u0000\r]/.test(configuration)
  )
    throw new Error("profile");
  const { extension } = singleProtocolCatalog[method];
  const endpoint = `${record.address}:${port}`;
  if (extension === "txt") {
    const uri = new URL(configuration);
    if (
      !/^vless:\/\/[^\s]+$/.test(configuration) ||
      uri.host !== endpoint ||
      uri.password ||
      !/^[\da-f-]{36}$/i.test(uri.username) ||
      uri.searchParams.get("security") !== "reality" ||
      uri.searchParams.get("type") !== (method === "xray" ? "tcp" : "xhttp") ||
      decodeURIComponent(uri.hash.slice(1)) !== login
    )
      throw new Error("profile");
  } else if (extension === "conf") {
    const lines = configuration.trim().split("\n").filter(Boolean);
    if (
      lines.filter((line) => line.startsWith("Endpoint = ")).join() !==
        `Endpoint = ${endpoint}` ||
      !lines.includes("[Interface]") ||
      !lines.includes("[Peer]") ||
      lines.some(
        (line) =>
          !/^\[(?:Interface|Peer)\]$|^(?:PrivateKey|Address|MTU|DNS|Jc|Jmin|Jmax|S[1-4]|H[1-4]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies|PublicKey|PresharedKey|Endpoint|AllowedIPs|PersistentKeepalive) = [ -~]+$/.test(
            line,
          ),
      )
    )
      throw new Error("profile");
  } else if (extension === "ovpn") {
    const blocks = /<(ca|cert|key|tls-crypt)>\n[\s\S]*?\n<\/\1>/g;
    const tags = [...configuration.matchAll(blocks)].map((match) => match[1]);
    const lines = configuration.replace(blocks, "").split("\n").filter(Boolean);
    if (
      new Set(tags).size !== 4 ||
      tags.length !== 4 ||
      lines.filter((line) => line.startsWith("remote ")).join() !==
        `remote ${record.address} ${port}` ||
      !lines.includes("verify-x509-name server name") ||
      lines.some(
        (line) =>
          !/^(?:client|dev tun|tun-mtu 1280|proto tcp-client|remote [\d.]+ \d+|nobind|persist-key|persist-tun|remote-cert-tls server|verify-x509-name server name|tls-version-min 1\.2|data-ciphers [A-Z0-9:-]+|redirect-gateway def1 ipv6|block-ipv6|verb 3)$/.test(
            line,
          ),
      )
    )
      throw new Error("profile");
  } else {
    const profile = JSON.parse(configuration);
    const extra = ["outline", "shadowsocks"].includes(method)
      ? ["method", "path"]
      : method === "hysteria2"
        ? ["obfs"]
        : [];
    if (
      !exact(profile, [
        "schema",
        "protocol",
        "server",
        "port",
        "login",
        "password",
        "certificate",
        "server_name",
        ...extra,
      ]) ||
      profile.schema !== 1 ||
      profile.protocol !== method ||
      profile.server !== record.address ||
      profile.port !== port ||
      profile.login !== login ||
      !validVpnPassword(profile.password) ||
      (profile.server_name !== record.address &&
        !(
          method === "trusttunnel" &&
          /^vpn-[a-f0-9]{32}\.internal$/.test(profile.server_name)
        )) ||
      !new X509Certificate(profile.certificate).ca ||
      extra.some(
        (key) => typeof profile[key] !== "string" || profile[key].length > 180,
      )
    )
      throw new Error("profile");
  }
  return { configuration, filename: `rookstride-${login}.${extension}` };
}

function validSshInput(input, eligibleTarget) {
  return (
    eligibleTarget(input.address, input) &&
    Number.isInteger(input.sshPort) &&
    input.sshPort >= 1 &&
    input.sshPort <= 65535 &&
    typeof input.fingerprint === "string" &&
    /^SHA256:[A-Za-z0-9+/]{43}$/.test(input.fingerprint) &&
    typeof input.password === "string" &&
    input.password.length > 0 &&
    Buffer.byteLength(input.password) <= 512
  );
}

export function startWorker({
  dir = process.env.ROOKSTRIDE_WEB_ROOT,
  pilot,
  reinstall = false,
  pairRebuild,
} = {}) {
  if (!dir || (!pilot && !pairRebuild && !personalGatewayEnabled()) || (pairRebuild && (pilot || !reinstall)))
    deny(503, "localUserRequired");
  const runtime = process.env.ROOKSTRIDE_ROUTE_ASSETS;
  const routeAssets = runtime && isAbsolute(runtime) ? runtime : undefined;
  const readable = [
    "package.json",
    "node_modules",
    "scripts/gateway-worker.mjs",
    "scripts/gateway-ssh.mjs",
    "scripts/gateway_remote.py",
    "scripts/gateway-access.mjs",
    "scripts/gateway_access.py",
    "src/lib/gateway-files.mjs",
    "src/lib/gateway-input.mjs",
    "src/lib/hosted-ubuntu.mjs",
    "src/lib/scoped-administration.mjs",
    ...new Set(
      [...recipePaths, ...accountPaths, ...lifecyclePaths, ...singlePaths].map(
        (name) => "../" + name,
      ),
    ),
    ...(reinstall
      ? [...reinstallPaths, "reinstall/vendor"].map((name) => "../" + name)
      : []),
  ];
  const child = fork(resolve(dir, "scripts", "gateway-worker.mjs"), [], {
    cwd: dir,
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    execArgv: [
      "--max-old-space-size=80",
      "--permission",
      ...readable.map((file) => "--allow-fs-read=" + resolve(dir, file)),
      ...(routeAssets
        ? routeArchitectures.map(
            (arch) => "--allow-fs-read=" + resolve(routeAssets, arch + ".tar.gz"),
          )
        : []),
    ],
    env: {
      NODE_ENV: "production",
      ...(reinstall && { ROOKSTRIDE_GATEWAY_OS_REINSTALL: "1" }),
      ...(routeAssets && { ROOKSTRIDE_ROUTE_ASSETS: routeAssets }),
      ...(pilot && { ROOKSTRIDE_WORKER_ENROLLMENT: JSON.stringify(pilot) }),
      ...(pairRebuild && { ROOKSTRIDE_WORKER_PAIR_REBUILD: JSON.stringify(pairRebuild) }),
    },
  });
  let pending;
  function abort() {
    if (!pending) return;
    const { reject, timer } = pending;
    pending = null;
    clearTimeout(timer);
    reject(new Error("connection"));
  }
  child.on("error", abort);
  child.on("exit", abort);
  child.on("disconnect", abort);
  child.on("message", (msg) => {
    if (!pending) return;
    const { resolve: finish, reject, timer } = pending;
    pending = null;
    clearTimeout(timer);
    if (msg?.ok) finish(msg.result);
    else reject(new Error(msg?.error === "pin" ? "pin" : "connection"));
  });
  return {
    request(input) {
      if (!child.connected || pending)
        return Promise.reject(new Error("connection"));
      return new Promise((finish, reject) => {
        const timer = setTimeout(
          () => {
            abort();
            child.kill();
          },
          input.action === "install"
            ? maxInstallTime
            : ["removeApply", "protocolRemoveApply"].includes(input.action)
              ? maxRemoveTime
              : input.action === "protocolApply" ||
                  (["filter", "protocolFilter"].includes(input.action) &&
                    (input.level !== undefined || input.enabled !== undefined))
                ? 5 * 60_000
                : 45000,
        );
        timer.unref();
        pending = { resolve: finish, reject, timer };
        child.send(input, (err) => {
          if (err) abort();
        });
      });
    },
    stop() {
      abort();
      child.kill();
    },
  };
}

function cleanProfile(profile, address, expectedLogin) {
  const cert = profile?.remote?.cert;
  if (
    profile?.type !== "ikev2-eap" ||
    profile.remote.addr !== address ||
    profile.remote.id !== address ||
    typeof cert !== "string" ||
    cert.length > 16000 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(cert) ||
    !validLogin(profile.local?.eap_id) ||
    (expectedLogin && profile.local.eap_id !== expectedLogin) ||
    typeof profile.uuid !== "string" ||
    !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(profile.uuid)
  )
    deny(502, "invalidProfile");
  try {
    if (!new X509Certificate(Buffer.from(cert, "base64")).ca) throw new Error();
  } catch {
    deny(502, "invalidCertificate");
  }
  return {
    uuid: profile.uuid,
    name: "Rookstride VPN · " + profile.local.eap_id,
    type: "ikev2-eap",
    remote: { addr: address, id: address, cert },
    local: { eap_id: profile.local.eap_id },
    mtu: 1280,
    "split-tunneling": { "block-ipv4": true, "block-ipv6": true },
  };
}

/**
 * Each single-server session owns one worker and one target.
 * @param {Function} [open]
 * @param {typeof publicDestination} [eligibleTarget]
 * @param {{
 *   pairPreflight?: boolean,
 *   pairFactory?: typeof import("./workbench-pair.mjs").createWorkbenchPair,
 *   pairOnly?: boolean,
 *   hostedUbuntu?: ReturnType<typeof import("./hosted-ubuntu.mjs").createHostedUbuntu>,
 *   ubuntuReinstall?: boolean,
 *   allowEcdsa?: boolean,
 *   scopedAdministration?: boolean,
 *   availableMethods?: readonly string[],
 * }} [options]
 */
export function createGatewayService(
  open,
  eligibleTarget = publicDestination,
  {
    pairPreflight = false,
    pairFactory,
    pairOnly = false,
    hostedUbuntu,
    ubuntuReinstall = Boolean(hostedUbuntu),
    allowEcdsa = pairPreflight || ubuntuReinstall,
    scopedAdministration = false,
    availableMethods = singleMethods,
  } = {},
) {
  open ??= () => startWorker({ reinstall: ubuntuReinstall });
  const sessions = new Map();
  let checkingPair = false;
  let checkingHostedUbuntu = false;
  let attempts = [];
  function reserveAttempts(count) {
    const now = Date.now();
    attempts = attempts.filter((time) => now - time < 60000);
    if (attempts.length + count > 5) deny(429, "tooManyAttempts");
    for (let i = 0; i < count; i++) attempts.push(now);
  }
  const pair = pairFactory?.({
    canReserve: () => !checkingPair && sessions.size === 0,
    validateNode: (node) => (!node.keyType || allowEcdsa) && validSshInput(node, eligibleTarget),
    deny,
    reserveAttempts,
  });
  function release(record) {
    if (!sessions.delete(record.token)) return;
    clearTimeout(record.timer);
    record.worker.stop();
  }
  function expire(record, duration) {
    clearTimeout(record.timer);
    record.timer = setTimeout(() => release(record), duration);
    record.timer.unref();
  }
  function status(record) {
    const messageKey = record.failureKey ?? record.state;
    return {
      state: record.state,
      address: record.address,
      os: record.os,
      ...(record.connection && { connection: record.connection }),
      ...(record.method && { method: record.method }),
      ...(record.connection && { availableMethods }),
      messageKey,
      message: gatewayMessages[messageKey],
    };
  }
  function noteProtocol(record, report, expected) {
    if (
      !availableMethods.includes(report.method) ||
      (expected && report.method !== expected)
    )
      throw new Error("protocol");
    if (
      report.state === "protocolInstalled" &&
      (!Number.isInteger(report.port) ||
        report.port < 1 ||
        report.port > 65535 ||
        report.port === 22 ||
        report.port === record.connection?.sshPort ||
        (record.protocolPort && record.protocolPort !== report.port))
    )
      throw new Error("port");
    record.method = report.method;
    if (report.state === "protocolInstalled") record.protocolPort = report.port;
  }
  function session(token) {
    const record = sessions.get(token);
    if (!record || record.state === "connecting") deny(401, "sessionEnded");
    return record;
  }

  async function checkUbuntuRecovery(input) {
    const recovery = readUbuntuRecovery(input.recovery);
    if (
      !exact(input, ["action", "recovery", "password"]) ||
      !recovery ||
      !validSshInput(
        { ...recovery.server, password: input.password },
        // Hosted requests must match the stored admission below.
        hostedUbuntu ? () => true : eligibleTarget,
      )
    )
      deny(400, "invalidUbuntuReinstall");
    if (hostedUbuntu) {
      const { pending, last } = hostedUbuntu.load();
      if (!matchesUbuntuJob(pending, recovery)) {
        if (!pending && matchesUbuntuJob(last?.job, recovery))
          return ubuntuResult(recovery, last.state);
        deny(409, "ubuntuRecoveryChanged");
      }
      if (checkingHostedUbuntu) deny(409, "operationBusy");
    }
    reserveAttempts(1);
    if (hostedUbuntu) checkingHostedUbuntu = true;
    let worker;
    try {
      worker = open();
      const report = await worker.request({
        ...recovery,
        action: "ubuntuResume",
        password: input.password,
      });
      if (!["complete", "preparing", "rebooting", "waiting", "failed", "cancelled", "expired", "unverified", "keyMismatch"].includes(report?.state))
        throw new Error("reinstall");
      const closed = hostedUbuntu
        ? hostedUbuntu.finish(recovery, report)
        : ["complete", "failed", "cancelled", "expired"].includes(report.state);
      if (closed) {
        for (const active of sessions.values()) {
          if (active.address === recovery.server.address && active.ubuntuJob === recovery.job)
            release(active);
        }
      }
      const state = hostedUbuntu && !closed && report.state === "failed"
        ? "providerRecovery"
        : report.state;
      return ubuntuResult(recovery, state);
    } catch {
      deny(502, "ubuntuStatusUnavailable");
    } finally {
      worker?.stop();
      checkingHostedUbuntu = false;
    }
  }

  function ubuntuResult(recovery, state) {
    return {
      state,
      ...(state === "complete" && {
        server: replacementServer(recovery),
        ubuntu: recovery.ubuntu,
      }),
    };
  }

  async function inspectPairNode(node) {
    let worker;
    try {
      worker = open();
      const details = await worker.request({
        action: "inspectPairNode",
        ...node,
      });
      if (details?.state === "unsupported") return { state: "unsupported" };
      if (
        !["ready", "occupied"].includes(details?.state) ||
        !supportedReleases.includes(details.os) ||
        !/^[0-9a-f]{64}$/.test(details.machine)
      )
        return { state: "unavailable" };
      return { state: details.state, os: details.os, machine: details.machine };
    } catch (err) {
      return {
        state: err.message === "pin" ? "identityMismatch" : "unavailable",
      };
    } finally {
      worker?.stop();
    }
  }
  return {
    requestLimit(token, action) {
      return pair?.requestLimit(token, action) ?? 2048;
    },
    get(token) {
      return status(session(token));
    },
    async post(input, token) {
      if (pair?.handles(input?.action))
        return pair.post(input, token);
      if (pairOnly) deny(400, "unknownAction");
      if (input?.action === "ubuntuRecovery" && hostedUbuntu) {
        if (!exact(input, ["action"])) deny(400, "invalidUbuntuReinstall");
        const { current, pending } = hostedUbuntu.load();
        return { recovery: pending, server: current.version === 2 ? current : null };
      }
      if (input?.action === "ubuntuResume" && ubuntuReinstall)
        return checkUbuntuRecovery(input);
      if (input?.action === "inspectPair" && pairPreflight) {
        const fields = ["address", "sshPort", "fingerprint", "password"];
        if (
          !exact(input, ["action", "entry", "exit"]) ||
          ![input.entry, input.exit].every(
            (node) => {
              const ecdsa = allowEcdsa && node?.keyType === "ecdsa-sha2-nistp256";
              return (
                exact(node, ecdsa ? [...fields, "keyType"] : fields) &&
                validSshInput(node, eligibleTarget)
              );
            },
          )
        )
          deny(400, "invalidServerDetails");
        if (input.entry.address === input.exit.address)
          deny(400, "pairRequiresTwoServers");
        if (checkingPair || pair?.active() || sessions.size !== 0)
          deny(409, "pairInspectionBusy");
        reserveAttempts(2);
        checkingPair = true;
        try {
          const [entry, exit] = await Promise.all([
            inspectPairNode(input.entry),
            inspectPairNode(input.exit),
          ]);
          if (entry.machine && entry.machine === exit.machine)
            deny(409, "pairRequiresTwoServers");
          return {
            entry: { state: entry.state, os: entry.os },
            exit: { state: exit.state, os: exit.os },
          };
        } finally {
          checkingPair = false;
        }
      }
      if (input?.action === "inspect") {
        if (hostedUbuntu?.load().pending) deny(409, "ubuntuReinstalling");
        const fields = ["action", "address", "sshPort", "fingerprint", "password"];
        const ecdsa = allowEcdsa && input.keyType === "ecdsa-sha2-nistp256";
        if (
          !exact(input, ecdsa ? [...fields, "keyType"] : fields) ||
          !validSshInput(input, eligibleTarget)
        )
          deny(400, "invalidServerDetails");
        if (sessions.has(token)) deny(409, "sessionAlreadyOpen");
        if (
          [...sessions.values()].some(
            (record) => record.address === input.address,
          )
        )
          deny(409, "targetInUse");
        if (checkingPair || pair?.active() || sessions.size >= 2)
          deny(409, "sessionLimitReached");
        reserveAttempts(1);
        const record = {
          token: randomBytes(32).toString("base64url"),
          address: input.address,
          state: "connecting",
          os: undefined,
          worker: open(),
          busy: false,
        };
        sessions.set(record.token, record);
        expire(record, 50000);
        try {
          const result = await record.worker.request(input);
          if (
            ![
              "ready",
              "installed",
              "removed",
              "occupied",
              "unsupported",
              ...protocolStates,
            ].includes(result.state)
          )
            throw new Error("inspect");
          record.state = result.state;
          if (protocolStates.includes(result.state))
            noteProtocol(record, result);
          if (supportedReleases.includes(result.os)) record.os = result.os;
          if (
            ["ready", "installed", "removed", ...protocolStates].includes(
              result.state,
            ) || (ubuntuReinstall && result.state === "occupied")
          ) {
            record.connection = {
              version: ecdsa ? 2 : 1,
              address: input.address,
              sshPort: input.sshPort,
              fingerprint: input.fingerprint,
              ...(ecdsa && { keyType: input.keyType }),
            };
            expire(record, idleTime);
            return { ...status(record), session: record.token };
          }
          release(record);
          return status(record);
        } catch (error) {
          release(record);
          deny(
            422,
            error.message === "pin"
              ? "identityMismatch"
              : "inspectionUnavailable",
          );
        }
      }
      const record = session(token);
      if (ubuntuReinstall && input?.action === "ubuntuReview") {
        if (!exact(input, ["action", "ubuntu"]) || !ubuntuVersions.includes(input.ubuntu))
          deny(400, "invalidUbuntuReinstall");
        if (record.busy || !["ready", "installed", "removed", "protocolInstalled", "occupied"].includes(record.state))
          deny(409, "verifiedSessionRequired");
        delete record.ubuntuPlan;
        record.busy = true;
        expire(record, idleTime);
        try {
          const result = await record.worker.request(input);
          const recovery = readUbuntuRecovery({
            job: result.job,
            ubuntu: result.ubuntu,
            fingerprint: result.fingerprint,
            server: record.connection,
          });
          if (
            !recovery || recovery.ubuntu !== input.ubuntu ||
            !/^[a-f0-9]{64}$/.test(result.token ?? "") ||
            !Number.isSafeInteger(result.diskBytes) || result.diskBytes < 6 * 1024 ** 3 ||
            !["EFI", "BIOS"].includes(result.boot)
          )
            throw new Error("reinstall");
          const review = randomBytes(24).toString("base64url");
          record.ubuntuPlan = {
            review,
            token: result.token,
            recovery,
            state: record.state,
            expires: Date.now() + 5 * 60_000,
          };
          return { review, recovery, diskBytes: result.diskBytes, boot: result.boot };
        } catch {
          deny(422, "ubuntuReviewUnavailable");
        } finally {
          record.busy = false;
        }
      }
      if (ubuntuReinstall && input?.action === "ubuntuApply") {
        if (
          !exact(input, ["action", "review", "confirmation"]) ||
          typeof input.review !== "string" || input.confirmation !== ubuntuEraseConfirmation
        )
          deny(400, "invalidUbuntuReinstall");
        if (record.ubuntuJob) return status(record);
        const plan = record.ubuntuPlan;
        if (!plan || plan.review !== input.review || plan.state !== record.state || plan.expires < Date.now())
          deny(409, "ubuntuReviewExpired");
        if (record.busy) deny(409, "operationBusy");
        hostedUbuntu?.begin(plan.recovery);
        delete record.ubuntuPlan;
        record.ubuntuJob = plan.recovery.job;
        record.state = "ubuntuReinstalling";
        expire(record, maxReinstallTime);
        // Lost replies only trigger read-only recovery from the recorded job.
        void record.worker.request({
          action: "ubuntuApply",
          job: plan.recovery.job,
          fingerprint: plan.recovery.fingerprint,
          token: plan.token,
          confirmation: input.confirmation,
        }).catch(() => {});
        return status(record);
      }
      if (record.state === "ubuntuReinstalling") deny(409, "ubuntuReinstalling");
      if (input?.action === "administrationStatus" && scopedAdministration) {
        if (!exact(input, ["action"])) deny(400, "invalidMaintenanceDetails");
        if (record.busy || record.state !== "protocolInstalled")
          deny(409, "verifiedSessionRequired");
        record.busy = true;
        expire(record, idleTime);
        try {
          return cleanScopedAdministration(await record.worker.request({
            action: input.action,
            method: record.method,
          }));
        } catch {
          return { state: "unavailable" };
        } finally {
          record.busy = false;
        }
      }
      if (input?.action === "install") {
        if (
          !exact(input, ["action", "confirmed", "login", "vpnPassword"]) ||
          input.confirmed !== true ||
          !validLogin(input.login) ||
          !validVpnPassword(input.vpnPassword)
        )
          deny(400, "invalidInstallDetails");
        // A retried approval can only observe this session's original attempt.
        if (record.state !== "ready") return status(record);
        if (record.busy) deny(409, "operationBusy");
        record.state = "running";
        expire(record, maxInstallTime + 60000);
        record.worker
          .request({
            action: "install",
            login: input.login,
            vpnPassword: input.vpnPassword,
          })
          .then(
            (result) => {
              record.state = [
                "installed",
                "occupied",
                "unsupported",
                "failed",
              ].includes(result.state)
                ? result.state
                : "indeterminate";
              if (record.state === "failed")
                record.failureKey = failedStages.get(result.stage);
            },
            () => {
              record.state = "indeterminate";
            },
          )
          .finally(() => {
            if (sessions.has(record.token)) expire(record, idleTime);
          });
        return status(record);
      }
      if (exact(input, ["action"]) && input.action === "close") {
        if (record.busy || ["running", "removing"].includes(record.state))
          deny(409, "operationBusy");
        release(record);
        return { state: "closed" };
      }
      if (
        typeof input?.action === "string" &&
        input.action.startsWith("protocol") &&
        !["protocolFilter", "protocolUsage"].includes(input.action)
      ) {
        const action = input.action;
        const review = action === "protocolReview";
        const apply = action === "protocolApply";
        const poll = action === "protocolStatus";
        const inputFields = {
          protocolReview: ["action", "login", "method"],
          protocolApply: ["action", "review", "confirmed"],
          protocolStatus: ["action"],
          protocolUsers: ["action"],
          protocolProfile: ["action", "login"],
          protocolGrant: ["action", "login", "revision"],
          protocolRevoke: ["action", "login", "revision", "confirmed"],
        };
        if (
          !Object.hasOwn(inputFields, action) ||
          (!exact(input, inputFields[action]) &&
            !(review && exact(input, ["action", "login"]))) ||
          (review && !availableMethods.includes(input.method ?? "xray")) ||
          (Object.hasOwn(input, "login") && !validProtocolLogin(input.login)) ||
          (Object.hasOwn(input, "confirmed") && input.confirmed !== true) ||
          (Object.hasOwn(input, "revision") &&
            (typeof input.revision !== "string" ||
              !/^[a-f0-9]{64}$/.test(input.revision))) ||
          (apply && typeof input.review !== "string")
        )
          deny(400, "invalidMaintenanceDetails");
        if (apply && record.appliedProtocol === input.review)
          return status(record);
        const states =
          review || apply
            ? ["ready", "removed"]
            : poll
              ? protocolStates
              : ["protocolInstalled"];
        if (record.busy || !states.includes(record.state))
          deny(409, "verifiedSessionRequired");
        const planned = record.protocolPlan;
        if (
          apply &&
          (planned?.review !== input.review || Date.now() >= planned.expires)
        )
          deny(409, "protocolReviewRequired");
        if (review || apply) delete record.protocolPlan;
        if (apply) record.appliedProtocol = input.review;
        record.busy = true;
        expire(record, idleTime);
        try {
          const report = await record.worker.request(
            apply
              ? {
                  action,
                  port: planned.port,
                  login: planned.login,
                  method: planned.method,
                }
              : {
                  action,
                  ...(input.login && { login: input.login }),
                  ...(input.revision && { revision: input.revision }),
                  ...(review && { method: input.method ?? "xray" }),
                },
          );
          if (report.state === "conflict") deny(409, "rosterChanged");
          if ((review || apply) && report.state === "runtimeUnavailable") {
            if (apply) delete record.appliedProtocol;
            deny(409, "protocolRuntimeUnavailable");
          }
          if (
            review &&
            Number.isInteger(report.port) &&
            report.port >= 1 &&
            report.port <= 65535 &&
            report.port !== record.connection.sshPort
          ) {
            const code = randomBytes(24).toString("base64url");
            record.protocolPlan = {
              review: code,
              port: report.port,
              login: input.login,
              method: input.method ?? "xray",
              expires: Date.now() + 5 * 60_000,
            };
            return { review: code, port: report.port };
          }
          if ((apply || poll) && protocolStates.includes(report.state)) {
            noteProtocol(
              record,
              report,
              apply ? planned.method : record.method,
            );
            if (apply) record.protocolPort = planned.port;
            record.state = report.state;
            return status(record);
          }
          if (action === "protocolProfile")
            return singleProfile(report, record, input.login);
          if (
            ["protocolUsers", "protocolGrant", "protocolRevoke"].includes(
              action,
            ) &&
            validProtocolLogin(report.owner) &&
            Array.isArray(report.users) &&
            report.users.length <= 256 &&
            report.users.every(validProtocolLogin) &&
            new Set(report.users).size === report.users.length &&
            report.users.includes(report.owner) &&
            typeof report.revision === "string" &&
            /^[a-f0-9]{64}$/.test(report.revision)
          )
            return {
              owner: report.owner,
              users: report.users,
              revision: report.revision,
            };
        } catch (error) {
          if (
            isGatewayError(error) &&
            (!apply || error.messageKey === "protocolRuntimeUnavailable")
          )
            throw error;
          // Private login and configuration data must never appear in failures.
        } finally {
          record.busy = false;
        }
        if (apply) {
          record.state = "indeterminate";
          return status(record);
        }
        deny(502, "maintenanceResultUnknown");
      }
      if (input?.action === "removeApply") {
        if (
          !exact(input, ["action", "review", "confirmation"]) ||
          typeof input.review !== "string" ||
          input.confirmation !== "DELETE VPN"
        )
          deny(400, "invalidMaintenanceDetails");
        if (record.appliedRemoval === input.review) return status(record);
        const plan = record.removalPlan;
        if (
          record.state !== plan?.state ||
          record.busy ||
          plan?.review !== input.review ||
          Date.now() >= plan.expires
        )
          deny(409, "removalReviewRequired");
        delete record.removalPlan;
        record.appliedRemoval = input.review;
        record.state = "removing";
        expire(record, maxRemoveTime + 60_000);
        record.worker
          .request({
            action:
              plan.state === "protocolInstalled"
                ? "protocolRemoveApply"
                : "removeApply",
            token: plan.token,
            confirmation: input.confirmation,
          })
          .then(
            (result) => {
              record.state =
                result.state === "removed" ? "removed" : "indeterminate";
              if (record.state === "removed") {
                delete record.method;
                delete record.protocolPort;
              }
            },
            () => {
              record.state = "indeterminate";
            },
          )
          .finally(() => {
            if (sessions.has(record.token)) expire(record, idleTime);
          });
        return status(record);
      }
      if (input?.action === "removeReview" || input?.action === "ubuntuCheck") {
        const { action } = input;
        if (!exact(input, ["action"])) deny(400, "invalidMaintenanceDetails");
        const states =
          action === "removeReview"
            ? ["installed", "protocolInstalled"]
            : ["ready", "installed", "removed", "protocolInstalled"];
        if (record.busy || !states.includes(record.state))
          deny(409, "verifiedSessionRequired");
        record.busy = true;
        expire(record, idleTime);
        if (action === "removeReview") delete record.removalPlan;
        const expires = Date.now() + 5 * 60_000;
        try {
          const result = await record.worker.request(
            action === "removeReview" && record.state === "protocolInstalled"
              ? { action: "protocolRemoveReview" }
              : input,
          );
          if (
            action === "removeReview" &&
            /^[a-f0-9]{64}$/.test(result.token ?? "")
          ) {
            const review = randomBytes(24).toString("base64url");
            record.removalPlan = {
              review,
              token: result.token,
              expires,
              state: record.state,
            };
            return { review };
          }
          if (action === "ubuntuCheck" && result.eligible === false)
            return { eligible: false };
          if (
            action === "ubuntuCheck" &&
            result.eligible === true &&
            Number.isSafeInteger(result.diskBytes) &&
            result.diskBytes >= 6 * 1024 ** 3 &&
            ["EFI", "BIOS"].includes(result.boot)
          )
            return {
              eligible: true,
              diskBytes: result.diskBytes,
              boot: result.boot,
            };
        } catch {
          // Keep remote file paths, disk identifiers and diagnostics out of the response.
        } finally {
          record.busy = false;
        }
        deny(502, "maintenanceResultUnknown");
      }
      if (["health", "filter", "usage", "protocolFilter", "protocolUsage"].includes(input?.action)) {
        const { action, level, enabled } = input;
        const native = action.startsWith("protocol");
        const filtering = action === "filter" || action === "protocolFilter";
        if (record.state !== (native ? "protocolInstalled" : "installed") || record.busy)
          deny(409, "verifiedSessionRequired");
        const setLevel = filtering && exact(input, ["action", "level", "confirmed"]) &&
          filterPresets.includes(level) && input.confirmed === true;
        const setProtection = action === "protocolFilter" &&
          exact(input, ["action", "enabled", "confirmed"]) &&
          typeof enabled === "boolean" && input.confirmed === true;
        if (!exact(input, ["action"]) && !setLevel && !setProtection)
          deny(400, "invalidMaintenanceDetails");
        record.busy = true;
        expire(record, idleTime);
        try {
          const report = await record.worker.request({
            action,
            ...(setLevel && { level }),
            ...(setProtection && { enabled }),
          });
          if (
            action === "health" &&
            exact(report, serviceHealthKeys) &&
            serviceHealthKeys.every((key) => typeof report[key] === "boolean")
          )
            return { services: report };
          if (action === "usage" || action === "protocolUsage") {
            if (exact(report, ["available"]) && report.available === false)
              return { usage: report };
            if (
              !native && exact(report, ["available", "sessions", "upload", "download"]) &&
              report.available === true &&
              [report.sessions, report.upload, report.download].every(
                (count) => Number.isSafeInteger(count) && count >= 0,
              )
            )
              return { usage: report };
            if (
              native && exact(report, ["available", "kind", "scope", "profiles", "upload", "download"]) &&
              report.available === true &&
              ((report.kind === "sessions" && ["active-sessions", "daemon"].includes(report.scope)) ||
                (report.kind === "handshake" && report.scope === "interface") ||
                (report.kind === "traffic" && report.scope === "daemon")) &&
              (report.kind === "traffic"
                ? report.profiles === null
                : Number.isSafeInteger(report.profiles) && report.profiles >= 0) &&
              [report.upload, report.download].every((count) => Number.isSafeInteger(count) && count >= 0)
            )
              return { usage: report };
          }
          if (
            filtering &&
            exact(report, native ? ["presets", "queries", "blocked", "protectionEnabled"] : ["presets", "queries", "blocked"]) &&
            (!native || typeof report.protectionEnabled === "boolean") &&
            Array.isArray(report.presets) &&
            report.presets.length <= filterPresets.length &&
            new Set(report.presets).size === report.presets.length &&
            report.presets.every((preset) => filterPresets.includes(preset)) &&
            (!setLevel || report.presets.includes(level)) &&
            (!setProtection || report.protectionEnabled === enabled) &&
            [report.queries, report.blocked].every(
              (count) => Number.isSafeInteger(count) && count >= 0,
            )
          )
            return { filtering: report };
        } catch {
          // Never disclose remote configuration, names or diagnostics in errors.
        } finally {
          record.busy = false;
        }
        deny(502, "maintenanceResultUnknown");
      }
      if (
        ["profile", "guests", "grant", "rotate", "revoke"].includes(
          input?.action,
        )
      ) {
        if (record.state !== "installed" || record.busy)
          deny(409, "verifiedSessionRequired");
        const { action } = input;
        const hasLogin = Object.hasOwn(input, "login");
        const fields = {
          guests: ["action"],
          profile: hasLogin ? ["action", "login"] : ["action"],
          grant: ["action", "login", "vpnPassword", "revision"],
          rotate: ["action", "login", "vpnPassword", "confirmed", "revision"],
          revoke: ["action", "login", "confirmed", "revision"],
        };
        if (
          !exact(input, fields[action]) ||
          (hasLogin && !validLogin(input.login)) ||
          (["grant", "rotate"].includes(action) &&
            !validVpnPassword(input.vpnPassword)) ||
          (["rotate", "revoke"].includes(action) && input.confirmed !== true) ||
          (["grant", "rotate", "revoke"].includes(action) &&
            (typeof input.revision !== "string" ||
              !/^[0-9a-f]{64}$/.test(input.revision)))
        )
          deny(400, "invalidGuestDetails");
        record.busy = true;
        expire(record, idleTime);
        try {
          const result = await record.worker.request(input);
          if (result.state === "conflict") deny(409, "rosterChanged");
          if (action === "profile")
            return {
              profile: cleanProfile(
                result.profile,
                record.address,
                input.login,
              ),
            };
          if (
            !validLogin(result.owner) ||
            !Array.isArray(result.guests) ||
            result.guests.length > 256 ||
            !result.guests.every(validLogin) ||
            result.guests.includes(result.owner) ||
            new Set(result.guests).size !== result.guests.length ||
            typeof result.revision !== "string" ||
            !/^[0-9a-f]{64}$/.test(result.revision)
          )
            deny(502, "invalidRoster");
          return {
            owner: result.owner,
            guests: result.guests,
            revision: result.revision,
            ...(result.activeSessionsUncertain === true
              ? { activeSessionsUncertain: true }
              : {}),
          };
        } catch (error) {
          if (isGatewayError(error)) throw error;
          deny(502, "guestResultUnknown");
        } finally {
          record.busy = false;
        }
      }
      deny(400, "unknownAction");
    },
  };
}
