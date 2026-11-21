import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { executePairRequest, executePairRuntime, loadPairRecipe, pairRemoteRejections } from "../../scripts/pair-ssh.mjs";
import { openSsh, verifiedRouteArchive } from "../../scripts/gateway-ssh.mjs";
import { isMixedPairEntry, isMixedPairExit, pairEntryPorts, pairExitPorts, pairProfileExtension, readServerRecord, validVpnPassword } from "./gateway-input.mjs";
import { publicDestination } from "./gateway-service.mjs";

const version = 1;
const requestTimeoutMs = 42_000;
const runtimeTimeoutMs = 120_000;
const deploymentTimeoutMs = 65 * 60_000;
const restoreTimeoutMs = 105 * 60_000;
const readTimeoutMs = 100_000;
const managementTimeoutMs = 3 * 60_000;
const removeTimeoutMs = 5 * 60_000;
const maxRecoveryBytes = 2 * 1024 * 1024 - 56;
const hex32 = /^[a-f0-9]{32}$/;
const hex64 = /^[a-f0-9]{64}$/;
const loginPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/;
const authFields = ["address", "sshPort", "fingerprint", "keyType"];
const roles = ["entry", "exit"];
const workerMethods = new Set(["hysteria2", "outline", "shadowsocks", "trusttunnel", "naive"]);
const workerArchitectures = ["x86_64", "aarch64"];
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
export const pairStages = Object.freeze([
  "preflight",
  "exit-bootstrap",
  "exit-dns",
  "entry-bootstrap",
  "exit-configure",
  "entry-configure",
  "verify",
  "activate",
  "health",
]);
export const pairRestoreStages = Object.freeze([
  "preflight", "exit-bootstrap", "exit-identity", "exit-configure",
  "entry-bootstrap", "entry-configure", "entry-identity", "verify", "activate", "health", "revision",
]);

export class PairDeploymentError extends Error {
  constructor(code, stage, uncertain = false) {
    super(code);
    this.name = "PairDeploymentError";
    this.code = code;
    this.stage = stage;
    this.uncertain = uncertain;
  }
}

function target(value, eligibleTarget) {
  const { address, sshPort, fingerprint, password } = value ?? {};
  const keyType = value?.keyType ?? "ssh-ed25519";
  const record = keyType === "ecdsa-sha2-nistp256"
    ? { version: 2, address, sshPort, fingerprint, keyType }
    : { version: 1, address, sshPort, fingerprint };
  if (
    !readServerRecord(record) ||
    !eligibleTarget(address) ||
    !["ssh-ed25519", "ecdsa-sha2-nistp256"].includes(keyType) ||
    typeof password !== "string" || !password || Buffer.byteLength(password) > 1024 ||
    /[\x00\r\n]/.test(password)
  ) throw new PairDeploymentError("invalid-node", "preflight");
  return { address, sshPort, fingerprint, keyType, password };
}

function envelope(review, role) {
  const entryProtocol = review.entryProtocol ?? "awg";
  const exitProtocol = review.exitProtocol ?? "awg";
  return {
    pair: review.pairId,
    role,
    engine: "native-v2",
    entry_protocol: entryProtocol,
    exit_protocol: exitProtocol,
    server: review.entry.address,
    exit_host: review.exit.address,
    vpn_port: pairEntryPorts[entryProtocol],
    tunnel_port: pairExitPorts[exitProtocol],
  };
}

export function pairRequiresRuntime(review, role = "entry") {
  return workerMethods.has(review.exitProtocol) || (role === "entry" && workerMethods.has(review.entryProtocol));
}

function validLogin(value) {
  return typeof value === "string" && loginPattern.test(value);
}

function validRoster(report) {
  const users = report?.users;
  return validLogin(report?.owner) && hex64.test(report?.revision ?? "") &&
    Array.isArray(users) && users.length <= 252 && users.every(validLogin) &&
    users.includes(report.owner) && new Set(users).size === users.length;
}

function validRemoval(report, role, pairId) {
  return Boolean(report) && report.pair === pairId && report.role === role &&
    hex64.test(report.token ?? "") && hex64.test(report.configuration ?? "") &&
    typeof report.expires === "number" && Number.isFinite(report.expires);
}

function archiveMatches(archive, review) {
  if (
    archive?.schema !== 1 || archive.purpose !== "rookstride-owner-recovery" ||
    archive.deployment !== review.pairId || !Number.isSafeInteger(archive.revision) ||
    archive.revision < 1 || !Number.isSafeInteger(archive.created) || archive.created < 1 ||
    !archive.nodes || Object.keys(archive.nodes).length !== 2
  ) return false;
  for (const role of roles) {
    const node = archive.nodes[role];
    const protocol = review[role + "Protocol"] ?? "awg";
    const expected = {
      ...envelope(review, role),
      client_pool: "10.66.0.0/24",
      test_ip: "10.249.255.254",
      entry_address: "10.253.0.2/30",
      exit_address: "10.253.0.1/30",
      route_table: 51831,
    };
    if (
      node?.schema !== 2 || node.adapter !== protocol + "-identity-v1" ||
      node.purpose !== "rookstride-owner-recovery-node" || node.role !== role ||
      node.deployment !== review.pairId || node.state?.protocol !== protocol ||
      !Array.isArray(node.state.users) || node.state.users.length > 252 ||
      !node.plan || Object.keys(node.plan).length !== Object.keys(expected).length ||
      Object.entries(expected).some(([key, value]) => node.plan[key] !== value)
    ) return false;
  }
  try {
    return Buffer.byteLength(JSON.stringify(archive)) <= maxRecoveryBytes;
  } catch {
    return false;
  }
}

export function pairArchiveDigest(archive) {
  function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object")
      return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    return value;
  }
  return createHash("sha256").update(JSON.stringify(canonical(archive))).digest("hex");
}

function bounded(task, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const stop = () => reject(signal.reason);
    signal.addEventListener("abort", stop, { once: true });
    task.then(resolve, reject).finally(() => signal.removeEventListener("abort", stop));
  });
}

function validAwgProfile(text, endpoint) {
  if (Buffer.byteLength(text) > 16_384 || /[^\x20-\x7e\n]/.test(text)) return false;
  const sections = new Map([
    ["[Interface]", new Set([
      "PrivateKey", "Address", "MTU", "DNS", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
      "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey",
      "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
      "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    ])],
    ["[Peer]", new Set(["PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"])],
  ]);
  const required = new Set(["PrivateKey", "Address", "DNS", "PublicKey", "PresharedKey", "Endpoint", "AllowedIPs"]);
  let fields;
  let index = 0;
  for (const line of text.split("\n").map((item) => item.trim()).filter(Boolean)) {
    if (line.startsWith("[")) {
      if (line !== [...sections.keys()][index++]) return false;
      fields = sections.get(line);
      continue;
    }
    const match = /^([A-Za-z][A-Za-z0-9]*) = (.+)$/.exec(line);
    if (!match || !fields?.delete(match[1])) return false;
    if (match[1] === "Endpoint" && match[2] !== endpoint) return false;
    if (match[1] === "AllowedIPs" && match[2] !== "0.0.0.0/0, ::/0") return false;
    required.delete(match[1]);
  }
  return index === 2 && !required.size;
}

function exactFields(value, fields) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function validOpenVpnProfile(content, address, port) {
  const blocks = /^<(ca|cert|key|tls-crypt)>\n[A-Za-z0-9+/=\s:.,()#_-]+\n<\/\1>\n/gm;
  const directives = [
    "client", "dev tun", "tun-mtu 1280", "proto tcp-client", `remote ${address} ${port}`,
    "nobind", "persist-key", "persist-tun", "remote-cert-tls server", "verify-x509-name server name",
    "tls-version-min 1.2", "data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM",
    "redirect-gateway def1 ipv6", "block-ipv6", "verb 3",
  ];
  const header = directives.join("\n") + "\n";
  if (!content.startsWith(header)) return false;
  const body = content.slice(header.length);
  const tags = [...body.matchAll(blocks)].map((match) => match[1]);
  return tags.join(",") === "ca,cert,key,tls-crypt" && body.replace(blocks, "") === "";
}

function validVlessProfile(content, endpoint, method, login) {
  if (!/^vless:\/\/[^\s]+$/.test(content)) return false;
  const uri = new URL(content);
  const common = {
    encryption: "none", security: "reality", fp: "chrome",
    type: method === "xray" ? "tcp" : "xhttp",
    flow: method === "xray" ? "xtls-rprx-vision" : "",
  };
  if (method === "xhttp") common.mode = "auto";
  const keys = [...Object.keys(common), "pbk", "sid", "sni", ...(method === "xhttp" ? ["path"] : [])];
  const query = Object.fromEntries(uri.searchParams);
  return uri.host === endpoint && !uri.password && !uri.pathname && uuid.test(uri.username) &&
    decodeURIComponent(uri.hash.slice(1)) === login && uri.searchParams.size === keys.length &&
    exactFields(query, keys) && Object.entries(common).every(([key, value]) => query[key] === value) &&
    /^[A-Za-z0-9_-]{43}$/.test(query.pbk) && /^[a-f0-9]{16}$/.test(query.sid) &&
    /^[A-Za-z0-9.-]{1,253}$/.test(query.sni) &&
    (method !== "xhttp" || /^\/[a-f0-9]{48}$/.test(query.path));
}

function validIkeProfile(content, address, login) {
  const profile = JSON.parse(content);
  const { remote, local, mtu } = profile ?? {};
  const split = profile?.["split-tunneling"];
  return exactFields(profile, ["uuid", "name", "type", "remote", "local", "mtu", "split-tunneling"]) &&
    profile.type === "ikev2-eap" && uuid.test(profile.uuid) &&
    typeof profile.name === "string" && profile.name.length <= 160 &&
    exactFields(remote, ["addr", "id", "certreq", "cert"]) && remote.addr === address &&
    remote.id === address && remote.certreq === false &&
    typeof remote.cert === "string" && remote.cert.length <= 16_000 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(remote.cert) &&
    Boolean(new X509Certificate(Buffer.from(remote.cert, "base64"))) &&
    exactFields(local, ["eap_id"]) && local.eap_id === login &&
    Number.isInteger(mtu) && mtu >= 1280 && mtu <= 1500 &&
    exactFields(split, ["block-ipv4", "block-ipv6"]) && split["block-ipv4"] === true && split["block-ipv6"] === true;
}

function validWorkerProfile(content, address, port, method, login) {
  const profile = JSON.parse(content);
  const keys = ["schema", "protocol", "server", "port", "login", "password", "certificate", "server_name"];
  if (method === "outline" || method === "shadowsocks") keys.push("method", "path");
  if (method === "hysteria2") keys.push("obfs");
  return exactFields(profile, keys) && profile.schema === 1 && profile.protocol === method &&
    profile.server === address && profile.port === port && profile.login === login &&
    validVpnPassword(profile.password) &&
    (profile.server_name === address || (method === "trusttunnel" && /^vpn-[a-f0-9]{32}\.internal$/.test(profile.server_name))) &&
    typeof profile.certificate === "string" && new X509Certificate(profile.certificate).ca &&
    (!keys.includes("path") || (profile.method === "chacha20-ietf-poly1305" && /^\/[a-f0-9]{48}$/.test(profile.path))) &&
    (!keys.includes("obfs") || (typeof profile.obfs === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(profile.obfs)));
}

function validProfile(profile, review, login) {
  const method = review.entryProtocol ?? "awg";
  const address = review.entry.address;
  const port = pairEntryPorts[method];
  const endpoint = `${address}:${port}`;
  const content = profile?.content;
  if (profile?.format !== method || typeof content !== "string" || !content ||
      Buffer.byteLength(content) > 24_000 || /[\x00\r]/.test(content)) return false;
  try {
    if (method === "awg") return validAwgProfile(content, endpoint);
    if (method === "openvpn") return validOpenVpnProfile(content, address, port);
    if (method === "xray" || method === "xhttp") return validVlessProfile(content, endpoint, method, login);
    if (method === "ikev2") return validIkeProfile(content, address, login);
    return workerMethods.has(method) && validWorkerProfile(content, address, port, method, login);
  } catch {
    return false;
  }
}

export function createPairRuntime({
  connect = openSsh,
  request = executePairRequest,
  loadRecipe = loadPairRecipe,
  loadRuntime = verifiedRouteArchive,
  transferRuntime = executePairRuntime,
  eligibleTarget = publicDestination,
  wait = (signal) => sleep(2000, undefined, { signal }),
} = {}) {
  async function withNodes(options, timeout, operation) {
    const entry = target(options.entry, eligibleTarget);
    const exit = target(options.exit, eligibleTarget);
    if (entry.address === exit.address || entry.fingerprint === exit.fingerprint)
      throw new PairDeploymentError("same-node", "preflight");
    if (Object.hasOwn(options, "review")) {
      const { review } = options;
      if (
        review?.version !== version ||
        !hex32.test(review.pairId ?? "") ||
        !hex64.test(review.bundle ?? "") ||
        (review.entryProtocol !== undefined && !isMixedPairEntry(review.entryProtocol)) ||
        (review.exitProtocol !== undefined && !isMixedPairExit(review.exitProtocol)) ||
        typeof review.login !== "string" ||
        !loginPattern.test(review.login) ||
        authFields.some((key) =>
          entry[key] !== review.entry?.[key] || exit[key] !== review.exit?.[key])
      ) throw new PairDeploymentError("review-mismatch", "preflight");
    }
    const lifetime = AbortSignal.timeout(timeout);
    const signal = options.signal ? AbortSignal.any([options.signal, lifetime]) : lifetime;
    const clients = {};
    let stage = "preflight";
    let uncertain = false;
    const fail = (code) => { throw new PairDeploymentError(code, stage, uncertain); };
    const setStage = (next) => {
      stage = next;
      signal.throwIfAborted();
      options.onProgress?.({ stage });
    };
    try {
      signal.throwIfAborted();
      const recipe = await loadRecipe().catch(() => fail("recipe-unavailable"));
      if (!hex64.test(recipe?.digest ?? "") || !Buffer.isBuffer(recipe.archive))
        fail("recipe-unavailable");
      const open = async (role, node) => {
        let client;
        try {
          client = await connect(node);
        } catch (error) {
          fail(error?.message === "pin" ? "ssh-pin-mismatch" : "ssh-unavailable");
        }
        if (signal.aborted) client.destroy();
        else clients[role] = client;
        return client;
      };
      // Open both pinned sessions before issuing a command to either node.
      await bounded(Promise.allSettled([open("entry", entry), open("exit", exit)]), signal)
        .then((results) => {
          for (const result of results) if (result.status === "rejected") throw result.reason;
        });
      const send = async (role, args) => {
        const restoreIdentity = args.mode === "restore" && args.request?.action === "identity";
        const applyRemoval = args.mode === "reset" && args.request?.action === "apply";
        const budget = restoreIdentity ? managementTimeoutMs : applyRemoval ? 105_000 : requestTimeoutMs;
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(budget)]);
        deadline.throwIfAborted();
        try {
          return await bounded(request(clients[role], { bundle: recipe.digest, ...args }), deadline);
        } catch (error) {
          if (signal.aborted) fail("interrupted");
          if (deadline.aborted) fail("ssh-command-timeout");
          if (pairRemoteRejections.has(error?.code)) fail(error.code);
          fail(args.request?.command === "preflight" ? "preflight-rejected" : "step-rejected");
        }
      };
      const uploadRuntime = async (role, topology, architecture, archive) => {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(runtimeTimeoutMs)]);
        deadline.throwIfAborted();
        try {
          const request = { topology, architecture, routePins: recipe.routePins };
          const cached = await bounded(transferRuntime(clients[role], request), deadline);
          if (cached?.ready === true) return;
          if (cached?.ready === false) {
            const installed = await bounded(transferRuntime(clients[role], { ...request, archive }), deadline);
            if (installed?.ready === true) return;
          }
        } catch {
          if (signal.aborted) fail("interrupted");
        }
        fail("runtime-transfer-unconfirmed");
      };
      const [a, b] = await Promise.all([
        send("entry", { mode: "probe" }),
        send("exit", { mode: "probe" }),
      ]);
      const probes = { entry: a, exit: b };
      for (const probe of [a, b]) {
        if (!hex64.test(probe.machine ?? "")) fail("invalid-machine");
        if (probe.os !== "ubuntu" || !/^\d{2}\.\d{2}(?:\.\d+)?$/.test(probe.version ?? ""))
          fail("unsupported-ubuntu");
      }
      if (a.machine === b.machine) fail("same-node");
      return await operation({
        probes, recipe, send, uploadRuntime, fail, setStage, signal,
        nodes: { entry, exit },
        beginMutation: () => { uncertain = true; },
      });
    } catch (error) {
      if (error instanceof PairDeploymentError) throw error;
      fail(signal.aborted ? "interrupted" : "step-rejected");
    } finally {
      for (const client of Object.values(clients)) client.destroy();
    }
  }

  function reviewNode(probe, node) {
    return {
      address: node.address, sshPort: node.sshPort, fingerprint: node.fingerprint,
      keyType: node.keyType, machine: probe.machine, ubuntu: probe.version,
    };
  }

  function expectedReview(review, context) {
    const { recipe, probes, fail } = context;
    if (review.bundle !== recipe.digest) fail("review-mismatch");
    for (const role of ["entry", "exit"]) {
      if (
        probes[role].machine !== review[role]?.machine ||
        probes[role].version !== review[role]?.ubuntu
      ) fail("review-mismatch");
      const owner = probes[role].owner;
      if (owner !== null && (
        owner?.pairId !== review.pairId || owner.bundle !== review.bundle ||
        owner.role !== role || owner.resetting || owner.entryProtocol !== review.entryProtocol ||
        owner.exitProtocol !== review.exitProtocol
      )) fail("ownership-mismatch");
    }
  }

  async function query(context, review, role, command, data = {}) {
    const archive = !context.probes[role].owner &&
      (command === "preflight" || command === "start" && data.action === "bootstrap")
      ? context.recipe.archive
      : undefined;
    return context.send(role, { request: { ...envelope(review, role), command, ...data }, archive });
  }

  async function preflight(context, review) {
    context.setStage("preflight");
    if (context.probes.entry.standaloneDnsPresent !== false)
      context.fail("entry-dns-conflict");
    const reports = await Promise.all(
      ["entry", "exit"].map((role) => query(context, review, role, "preflight")),
    );
    if (reports.some((report, index) => report.ready !== true ||
      report.role !== ["entry", "exit"][index])) context.fail("preflight-rejected");
  }

  async function checkedRuntimeArchives(context, review) {
    const assets = new Map();
    return Promise.all(roles.filter((role) => pairRequiresRuntime(review, role)).map(async (role) => {
      const architecture = context.probes[role].runtimeArchitecture;
      if (!workerArchitectures.includes(architecture) || !Buffer.isBuffer(context.recipe.routePins))
        context.fail("runtime-unavailable");
      if (!assets.has(architecture)) assets.set(architecture, Promise.resolve().then(() => loadRuntime(architecture)));
      const archive = await assets.get(architecture).catch(() => context.fail("runtime-unavailable"));
      if (!Buffer.isBuffer(archive) || !archive.length) context.fail("runtime-unavailable");
      return { role, architecture, archive };
    }));
  }

  async function prepareRuntime(context, review, transfers) {
    await Promise.all(transfers.map(({ role, architecture, archive }) =>
      context.uploadRuntime(role, envelope(review, role), architecture, archive)));
  }

  async function reviewPairRestoreRuntime(options) {
    const { review } = options;
    return withNodes(options, readTimeoutMs, async (context) => {
      expectedReview(review, context);
      await checkedRuntimeArchives(context, review);
    });
  }

  async function finishRecipeStep(context, review, role, action, { resume, knownJob, data = {} }) {
    const { fail, signal } = context;
    let report;
    if (knownJob) {
      if (!hex32.test(knownJob)) fail("invalid-job");
      report = await query(context, review, role, "status", { job: knownJob });
      if (report.job !== knownJob) fail("invalid-job");
    }
    if (!report || resume && ["failed", "paused"].includes(report.state)) {
      context.beginMutation();
      report = await query(context, review, role, "start", { action, resume, ...data });
    }
    const job = report.job;
    if (!hex32.test(job ?? "") || (knownJob && knownJob !== job)) fail("invalid-job");
    while (report.state === "starting" || report.state === "running") {
      await wait(signal);
      report = await query(context, review, role, "status", { job });
      if (report.job !== job) fail("invalid-job");
    }
    if (report.state === "awaiting-reboot") fail("awaiting-reboot");
    if (report.state !== "complete") fail("step-failed");
  }

  async function confirmEntryResolver(context, review, transport) {
    if (transport?.protocol !== (review.exitProtocol ?? "awg") || transport?.endpoint !== review.exit.address)
      context.fail("exit-route-unavailable");
    const targetResolver = await context.send("entry", {
      mode: "resolver",
      request: { address: transport.dns?.address },
    });
    if (targetResolver.local !== false) context.fail("entry-dns-conflict");
  }

  async function verifiedExitAddress(context, review) {
    const report = await query(context, review, "exit", "overview");
    const exitIp = report.exit_ip;
    if (report.configured !== true || !eligibleTarget(exitIp) || exitIp === review.entry.address)
      context.fail("exit-route-unavailable");
    return exitIp;
  }

  async function verifyPairHealth(context, review) {
    const [entry, ingress, egress] = await Promise.all([
      query(context, review, "entry", "overview"),
      query(context, review, "entry", "health"),
      query(context, review, "exit", "health"),
    ]);
    if (
      entry.configured !== true || entry.activated !== true ||
      ingress.services?.protocol !== true || egress.services?.protocol !== true ||
      egress.services?.adguard !== true
    ) context.fail("health-unavailable");
  }

  async function reviewPair(options) {
    const { entryProtocol, exitProtocol } = options;
    if ((entryProtocol !== undefined && entryProtocol !== "awg" && !isMixedPairEntry(entryProtocol)) ||
        (exitProtocol !== undefined && exitProtocol !== "awg" && !isMixedPairExit(exitProtocol)))
      throw new PairDeploymentError("review-mismatch", "preflight");
    if (typeof options.login !== "string" || !loginPattern.test(options.login))
      throw new PairDeploymentError("invalid-login", "preflight");
    return withNodes(options, readTimeoutMs, async (context) => {
      const { probes, recipe, nodes, fail } = context;
      if (probes.entry.owner !== null || probes.exit.owner !== null) fail("occupied");
      const review = {
        version,
        pairId: randomBytes(16).toString("hex"),
        bundle: recipe.digest,
        login: options.login,
        ...(isMixedPairEntry(entryProtocol) && { entryProtocol }),
        ...(isMixedPairExit(exitProtocol) && { exitProtocol }),
        entry: reviewNode(probes.entry, nodes.entry),
        exit: reviewNode(probes.exit, nodes.exit),
      };
      await preflight(context, review);
      await checkedRuntimeArchives(context, review);
      return review;
    });
  }

  async function deployPair(options) {
    const { review, resume = false, password } = options;
    if (typeof resume !== "boolean")
      throw new PairDeploymentError("review-mismatch", "preflight");
    if (review?.entryProtocol === "ikev2" ? !validVpnPassword(password) : password !== undefined)
      throw new PairDeploymentError("invalid-password", "preflight");
    return withNodes({ ...options, review }, deploymentTimeoutMs, async (context) => {
      const { probes, fail, setStage } = context;
      expectedReview(review, context);
      if (!resume && (probes.entry.owner || probes.exit.owner)) fail("resume-required");
      if (resume && !probes.exit.owner) fail("ownership-mismatch");
      await preflight(context, review);
      await prepareRuntime(context, review, await checkedRuntimeArchives(context, review));

      const step = (role, action, data) =>
        finishRecipeStep(context, review, role, action, { resume, data });

      setStage("exit-bootstrap");
      await step("exit", "bootstrap");
      setStage("exit-dns");
      const exitDns = await query(context, review, "exit", "health");
      if (exitDns.services?.adguard !== true) fail("exit-dns-unavailable");

      setStage("entry-bootstrap");
      await step("entry", "bootstrap", {
        login: review.login,
        password: password ?? randomBytes(24).toString("base64url"),
        statistics: false,
      });

      setStage("exit-configure");
      const transport = await query(context, review, "exit", "material");
      await confirmEntryResolver(context, review, transport);
      await step("exit", "configure");
      setStage("entry-configure");
      await step("entry", "configure", { transport });

      setStage("verify");
      const exitIp = await verifiedExitAddress(context, review);
      await step("entry", "verify", { expected_exit_ip: exitIp, repeat: true });
      setStage("activate");
      // The pinned native recipe runs the same egress and DNS checks again before opening forwarding.
      await step("entry", "activate", { expected_exit_ip: exitIp, repeat: true });

      setStage("health");
      await verifyPairHealth(context, review);
      return { state: "installed", pairId: review.pairId, exitIp };
    });
  }

  async function exportPairProfile(options) {
    const { review, login = review?.login } = options;
    if (!validLogin(login)) throw new PairDeploymentError("invalid-login", "preflight");
    return withNodes({ ...options, review }, readTimeoutMs, async (context) => {
      const snapshot = await ownedNodes(context, review);
      if (!snapshot.entry.users.includes(login)) context.fail("account-unavailable");
      const profile = await managedRequest(context, review, "entry", "management", "profile", {
        bridge: snapshot.entry.bridge, login,
      });
      if (!validProfile(profile, review, login)) context.fail("invalid-profile");
      return { configuration: profile.content, filename: `rookstride-${login}.${pairProfileExtension(review.entryProtocol)}` };
    });
  }

  function managedRequest(context, review, role, mode, action, fields = {}) {
    return context.send(role, { mode, request: { ...envelope(review, role), action, ...fields } });
  }

  async function ownedNodes(context, review, { adopting = false } = {}) {
    const { probes, fail, setStage } = context;
    expectedReview(review, context);
    if (!probes.entry.owner || !probes.exit.owner) fail("ownership-mismatch");
    setStage("health");
    const [entry, exit] = await Promise.all(roles.map((role) =>
      managedRequest(context, review, role, "management", "node")));
    if (
      entry.pairId !== review.pairId || exit.pairId !== review.pairId ||
      entry.role !== "entry" || exit.role !== "exit" ||
      !hex64.test(entry.bridge ?? "") || exit.bridge !== entry.bridge ||
      !Number.isSafeInteger(entry.topologyRevision) || entry.topologyRevision < 1 ||
      entry.topologyRevision !== exit.topologyRevision ||
      typeof entry.healthy !== "boolean" || typeof exit.healthy !== "boolean" ||
      typeof exit.dnsHealthy !== "boolean" || !validRoster(entry) ||
      (!adopting && entry.owner !== review.login)
    ) fail("ownership-mismatch");
    return { entry, exit };
  }

  function managementView({ entry, exit }) {
    return {
      owner: entry.owner,
      users: entry.users,
      revision: entry.revision,
      entryHealthy: entry.healthy,
      exitHealthy: exit.healthy,
      dnsHealthy: exit.dnsHealthy,
    };
  }

  async function adoptPair(options) {
    return withNodes(options, readTimeoutMs, async (context) => {
      const { fail, nodes, probes, recipe } = context;
      const pairId = probes.entry.owner?.pairId;
      const entryProtocol = probes.entry.owner?.entryProtocol;
      const exitProtocol = probes.entry.owner?.exitProtocol;
      if (!hex32.test(pairId ?? "") || (entryProtocol !== undefined && !isMixedPairEntry(entryProtocol)) ||
          (exitProtocol !== undefined && !isMixedPairExit(exitProtocol)))
        fail("ownership-mismatch");
      const review = {
        version, pairId, bundle: recipe.digest,
        ...(entryProtocol && { entryProtocol }),
        ...(exitProtocol && { exitProtocol }),
        entry: reviewNode(probes.entry, nodes.entry),
        exit: reviewNode(probes.exit, nodes.exit),
      };
      const { entry } = await ownedNodes(context, review, { adopting: true });
      return { ...review, login: entry.owner };
    });
  }

  async function readPairManagement(options) {
    const { review } = options;
    return withNodes({ ...options, review }, readTimeoutMs, async (context) =>
      managementView(await ownedNodes(context, review)));
  }

  async function changePairAccount(options) {
    const { review, operation, login, revision, password } = options;
    if (!["grant", "revoke"].includes(operation) || !validLogin(login) ||
        typeof revision !== "string" || !hex64.test(revision))
      throw new PairDeploymentError("invalid-account", "preflight");
    if (review?.entryProtocol === "ikev2" && operation === "grant" ? !validVpnPassword(password) : password !== undefined)
      throw new PairDeploymentError("invalid-password", "preflight");
    return withNodes({ ...options, review }, managementTimeoutMs, async (context) => {
      const snapshot = await ownedNodes(context, review);
      if (revision !== snapshot.entry.revision) context.fail("roster-changed");
      if (login === snapshot.entry.owner || (operation === "grant") === snapshot.entry.users.includes(login))
        context.fail("account-unavailable");
      context.beginMutation();
      const roster = await managedRequest(context, review, "entry", "management", operation, {
        login, revision, bridge: snapshot.entry.bridge, ...(password !== undefined && { password }),
      });
      if (!validRoster(roster) || roster.owner !== review.login || roster.revision === revision ||
          (operation === "grant") !== roster.users.includes(login))
        context.fail("invalid-account-result");
      const updated = await ownedNodes(context, review);
      if (updated.entry.revision !== roster.revision) context.fail("roster-changed");
      return managementView(updated);
    });
  }

  async function reviewPairRemoval(options) {
    const { review } = options;
    return withNodes({ ...options, review }, managementTimeoutMs, async (context) => {
      const snapshot = await ownedNodes(context, review);
      const [entry, exit] = await Promise.all(roles.map((role) =>
        managedRequest(context, review, role, "reset", "plan", { bridge: snapshot.entry.bridge })));
      if (!validRemoval(entry, "entry", review.pairId) || !validRemoval(exit, "exit", review.pairId))
        context.fail("invalid-removal-review");
      return { pairId: review.pairId, entry, exit };
    });
  }

  async function removePair(options) {
    const { review, removal } = options;
    if (removal?.pairId !== review?.pairId || !roles.every((role) =>
      validRemoval(removal?.[role], role, review?.pairId)))
      throw new PairDeploymentError("invalid-removal-review", "preflight");
    return withNodes({ ...options, review }, removeTimeoutMs, async (context) => {
      const snapshot = await ownedNodes(context, review);
      function reset(role, action) {
        const { token, configuration } = removal[role];
        return managedRequest(context, review, role, "reset", action, {
          bridge: snapshot.entry.bridge, token, configuration,
        });
      }
      const checks = await Promise.all(roles.map((role) => reset(role, "check")));
      if (checks.some((result, index) => result.ready !== true || result.role !== roles[index]))
        context.fail("removal-review-stale");
      for (const role of roles) {
        context.setStage(role + "-remove");
        context.beginMutation();
        const result = await reset(role, "apply");
        if (result.reset !== true || result.role !== role) context.fail("removal-unconfirmed");
      }
      return { state: "removed" };
    });
  }

  async function capturePairRecovery(options) {
    const { review } = options;
    return withNodes({ ...options, review }, managementTimeoutMs, async (context) => {
      const { entry } = await ownedNodes(context, review);
      const snapshots = await Promise.all(roles.map((role) =>
        managedRequest(context, review, role, "recovery", "export", { bridge: entry.bridge })));
      const archive = {
        schema: 1, purpose: "rookstride-owner-recovery",
        deployment: review.pairId, revision: entry.topologyRevision, created: Date.now(),
        nodes: { entry: snapshots[0], exit: snapshots[1] },
      };
      if (!archiveMatches(archive, review)) context.fail("invalid-recovery");
      return archive;
    });
  }

  async function rehearsePairRecovery(options) {
    const { review, archive } = options;
    if (!review || !archiveMatches(archive, review))
      throw new PairDeploymentError("invalid-recovery", "preflight");
    return withNodes({ ...options, review }, managementTimeoutMs, async (context) => {
      const { entry } = await ownedNodes(context, review);
      if (archive.revision !== entry.topologyRevision) context.fail("invalid-recovery");
      const report = await managedRequest(context, review, "entry", "recovery", "rehearse-pair", {
        archive, bridge: entry.bridge,
      });
      if (
        report?.readiness_schema !== 2 || report.verified !== true ||
        report.deployment !== review.pairId || report.live_restore_tested !== false ||
        report.entry_users !== archive.nodes.entry.state.users.length ||
        report.exit_users !== archive.nodes.exit.state.users.length
      ) context.fail("invalid-recovery-result");
      return {
        readiness_schema: 2, verified: true, deployment: review.pairId,
        entry_users: report.entry_users, exit_users: report.exit_users, live_restore_tested: false,
      };
    });
  }

  async function restorePair(options) {
    const { archive, operation, archiveDigest, expectedBundle, resume = false } = options;
    const owner = archive?.nodes?.entry?.initial_user;
    const filtering = archive?.nodes?.exit?.filter_policy;
    const archivedEntry = archive?.nodes?.entry?.plan?.entry_protocol;
    const archivedExit = archive?.nodes?.entry?.plan?.exit_protocol;
    const endpoints = {
      pairId: archive?.deployment,
      ...(isMixedPairEntry(archivedEntry) && { entryProtocol: archivedEntry }),
      ...(isMixedPairExit(archivedExit) && { exitProtocol: archivedExit }),
      entry: { address: options.entry?.address },
      exit: { address: options.exit?.address },
    };
    if (
      !hex32.test(operation ?? "") || !hex32.test(endpoints.pairId ?? "") || !hex64.test(archiveDigest ?? "") ||
      (archivedEntry !== "awg" && !isMixedPairEntry(archivedEntry)) ||
      (archivedExit !== "awg" && !isMixedPairExit(archivedExit)) ||
      typeof resume !== "boolean" || !archiveMatches(archive, endpoints) ||
      !validLogin(owner?.login) || !validVpnPassword(owner.password) ||
      (owner.statistics !== undefined && typeof owner.statistics !== "boolean") ||
      typeof filtering?.enabled !== "boolean" || !Number.isSafeInteger(archive.revision + 1) ||
      roles.some((role) => !hex32.test(archive.nodes[role].state.instance ?? "")) ||
      pairArchiveDigest(archive) !== archiveDigest
    ) throw new PairDeploymentError("invalid-recovery", "preflight");
    return withNodes(options, restoreTimeoutMs, async (context) => {
      const { probes, recipe, nodes, fail, setStage } = context;
      if (expectedBundle !== undefined && recipe.digest !== expectedBundle) fail("review-mismatch");
      const revision = archive.revision + 1;
      const review = {
        ...endpoints, version, bundle: recipe.digest, login: owner.login,
        entry: reviewNode(probes.entry, nodes.entry),
        exit: reviewNode(probes.exit, nodes.exit),
      };
      expectedReview(review, context);
      if (!resume && roles.some((role) => probes[role].owner))
        fail("restore-resume-required");
      const binding = { operation, archiveDigest, revision };
      const rpc = (role, action, fields, installerArchive) => context.send(role, {
        mode: "restore", request: { ...envelope(review, role), ...binding, action, ...fields },
        archive: installerArchive,
      });
      const [entry, exit] = await Promise.all(roles.map((role) => rpc(role, "inspect")));
      const prior = { entry, exit };
      if (roles.some((role) => {
        const report = prior[role];
        return typeof report.recorded !== "boolean" || !report.jobs || Array.isArray(report.jobs) ||
          typeof report.jobs !== "object" || (probes[role].owner && !report.recorded);
      })) fail("restore-ownership-mismatch");
      if (!resume && (entry.recorded || exit.recorded)) fail("restore-resume-required");

      await preflight(context, review);
      const check = await rpc("entry", "validate", { archive }, recipe.archive);
      if (
        check?.readiness_schema !== 2 || check.deployment !== review.pairId ||
        check.verified !== true || check.live_restore_tested !== false ||
        check.entry_users !== archive.nodes.entry.state.users.length ||
        check.exit_users !== archive.nodes.exit.state.users.length
      ) fail("invalid-recovery");
      await prepareRuntime(context, review, await checkedRuntimeArchives(context, review));
      const missing = roles.filter((role) => !prior[role].recorded);
      if (missing.length) {
        context.beginMutation();
        const enrolled = await Promise.all(missing.map((role) => rpc(role, "enroll")));
        if (enrolled.some((report) => report.recorded !== true)) fail("restore-ownership-mismatch");
      }

      const step = (role, action, data) => finishRecipeStep(context, review, role, action, {
        resume, data, knownJob: prior[role].jobs[action],
      });
      async function identity(role) {
        setStage(role + "-identity");
        context.beginMutation();
        const snapshot = archive.nodes[role];
        const report = await rpc(role, "identity", { snapshot, resume });
        if (
          report?.restored !== true || !hex32.test(report.usage_generation ?? "") ||
          (report.usage_generation === snapshot.state.instance) !== (snapshot.state.protocol === "ikev2") ||
          report.users !== snapshot.state.users.length
        ) fail("restore-incomplete");
        return report.usage_generation;
      }

      setStage("exit-bootstrap");
      await step("exit", "bootstrap");
      const exitGeneration = await identity("exit");
      setStage("exit-configure");
      await step("exit", "configure");

      setStage("entry-bootstrap");
      await step("entry", "bootstrap", {
        login: owner.login, password: owner.password, statistics: owner.statistics ?? false,
      });
      setStage("entry-configure");
      const transport = await query(context, review, "exit", "material");
      await confirmEntryResolver(context, review, transport);
      await step("entry", "configure", { transport });
      const entryGeneration = await identity("entry");

      setStage("verify");
      const exitIp = await verifiedExitAddress(context, review);
      const checks = { expected_exit_ip: exitIp, filtering_enabled: filtering.enabled };
      await step("entry", "verify", checks);
      setStage("activate");
      await step("entry", "activate", checks);
      setStage("health");
      await verifyPairHealth(context, review);

      setStage("revision");
      context.beginMutation();
      const recorded = await Promise.all(roles.map((role) => rpc(role, "revision")));
      if (recorded.some((report) => report.revision !== revision)) fail("restore-incomplete");
      return {
        state: "restored", pairId: review.pairId, exitIp, revision,
        usageGenerations: { entry: entryGeneration, exit: exitGeneration }, review,
      };
    });
  }

  return {
    reviewPair, deployPair, exportPairProfile, adoptPair, readPairManagement, changePairAccount,
    reviewPairRemoval, removePair, capturePairRecovery, rehearsePairRecovery, reviewPairRestoreRuntime, restorePair,
  };
}

export const {
  reviewPair, deployPair, exportPairProfile, adoptPair, readPairManagement, changePairAccount,
  reviewPairRemoval, removePair, capturePairRecovery, rehearsePairRecovery, reviewPairRestoreRuntime, restorePair,
} = createPairRuntime();
