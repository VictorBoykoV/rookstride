import {
  openSsh,
  executeGateway,
  executeJson,
  recipeFiles,
  verifiedRouteArchive,
} from "./gateway-ssh.mjs";
import { readScopedAdministration } from "./gateway-access.mjs";
import {
  hostedServerMatches,
  matchesUbuntuJob,
} from "../src/lib/hosted-ubuntu.mjs";

let client;
let address;
let rootPassword;
let routePlan;
const pilot = process.env.ROOKSTRIDE_WORKER_ENROLLMENT
  ? JSON.parse(process.env.ROOKSTRIDE_WORKER_ENROLLMENT)
  : null;
const pairRebuild = process.env.ROOKSTRIDE_WORKER_PAIR_REBUILD
  ? JSON.parse(process.env.ROOKSTRIDE_WORKER_PAIR_REBUILD)
  : null;
const reinstall = process.env.ROOKSTRIDE_GATEWAY_OS_REINSTALL === "1";
const pairedReinstallActions = ["pairUbuntuReview", "pairUbuntuPlan", "pairUbuntuApply"];

function allowsPairRebuild(input) {
  const { action } = input;
  const { server, role, pair, operation, purpose, recovery } = pairRebuild;
  if (action === "ubuntuResume")
    return purpose === "resume" && matchesUbuntuJob(recovery, {
      server: input.server, fingerprint: input.fingerprint, job: input.job, ubuntu: input.ubuntu,
    });
  if (action === "inspect")
    return !client && ["review", "dispatch"].includes(purpose) && hostedServerMatches(server, input);
  if (input.role !== role || input.pair !== pair || input.operation !== operation || address !== server.address)
    return false;
  if (action === "pairUbuntuReview")
    return purpose === "review" && input.ubuntu === pairRebuild.ubuntu;
  return purpose === "dispatch" && ["pairUbuntuPlan", "pairUbuntuApply"].includes(action) &&
    recovery && input.job === recovery.job && input.fingerprint === recovery.fingerprint && input.ubuntu === recovery.ubuntu;
}

// The temporary installer runs Alpine and may not have Python. Its receipt
// is available over the planned host key at the same fixed path as Ubuntu's.
const readUbuntuReceipt =
  'for file in /etc/rookstride-reinstall-error.json /etc/rookstride-reinstall-result.json; do if [ -f "$file" ] && [ ! -L "$file" ]; then head -c 32769 "$file"; exit $?; fi; done; printf "%s\\n" "{}"';

async function resumeUbuntu({ server, fingerprint, job, ubuntu, password }) {
  let next;
  let pinMismatch = false;
  try {
    next = await openSsh({
      ...server,
      fingerprint,
      keyType: "ecdsa-sha2-nistp256",
      password,
    });
    const receipt = await executeJson(next, readUbuntuReceipt);
    if (receipt.job !== job) return { state: "waiting" };
    if (receipt.state === "failed") return { state: "failed" };
    if (receipt.state !== "complete" || receipt.version !== ubuntu)
      return { state: "unverified" };
    const current = await executeGateway(next, {
      action: "ubuntuVerify",
      address: server.address,
      job,
      ubuntu,
    });
    if (current.state !== "returned") return { state: "waiting" };
    return { state: current.ubuntu === ubuntu ? "complete" : "unverified" };
  } catch (error) {
    if (next) return { state: "waiting" };
    pinMismatch = error.message === "pin" && error.presentedFingerprint !== server.fingerprint;
  } finally {
    next?.destroy();
  }
  let old;
  try {
    old = await openSsh({ ...server, password });
    const status = await executeGateway(old, {
      action: "ubuntuStatus",
      address: server.address,
      job,
    });
    if (
      status.job === job &&
      status.fingerprint === fingerprint &&
      status.ubuntu === ubuntu
    )
      return { state: status.state, original: true };
    return { state: "waiting" };
  } catch (error) {
    if (old) return { state: "waiting" };
    const unknownKey = error.message === "pin" && error.presentedFingerprint !== fingerprint;
    return { state: pinMismatch || unknownKey ? "keyMismatch" : "waiting" };
  } finally {
    old?.destroy();
  }
}

process.on("disconnect", () => {
  client?.destroy();
  process.exit(0);
});
process.on("message", async (input) => {
  try {
    if (pairRebuild && (!reinstall || pilot || !allowsPairRebuild(input)))
      throw new Error("connection");
    const pairedReinstall = pairedReinstallActions.includes(input.action);
    if (pairedReinstall && (!reinstall || pilot || !client || !address || !rootPassword))
      throw new Error("connection");
    if (["ubuntuApply", "ubuntuReview", "ubuntuResume"].includes(input.action) && !reinstall)
      throw new Error("connection");
    if (input.action === "ubuntuResume") {
      if (pilot && !matchesUbuntuJob(pilot.pending, {
        server: input.server,
        fingerprint: input.fingerprint,
        ubuntu: input.ubuntu,
        job: input.job,
      }))
        throw new Error("connection");
      const result = await resumeUbuntu(input);
      process.send({ ok: true, result });
      return;
    }
    if (input.action === "administrationStatus") {
      if (pilot || !client || !address) throw new Error("connection");
      const result = await readScopedAdministration(client, address, input.method);
      process.send({ ok: true, result });
      return;
    }
    if (input.action === "inspect" || input.action === "inspectPairNode") {
      if (
        pilot &&
        (input.action !== "inspect" || pilot.pending ||
          !hostedServerMatches(pilot.current, input))
      )
        throw new Error("connection");
      client = await openSsh(input);
      address = input.address;
      if (reinstall && input.action === "inspect" && !/[\u0000\r\n]/.test(input.password))
        rootPassword = input.password;
      client.once("close", () => process.exit(0));
    }
    const request = { action: input.action, address };
    if (pairedReinstall) {
      Object.assign(request, {
        pair: input.pair,
        role: input.role,
        operation: input.operation,
      });
      if (input.action !== "pairUbuntuApply") request.ubuntu = input.ubuntu;
      if (input.action === "pairUbuntuReview")
        request.snapshot = input.snapshot;
      if (input.action === "pairUbuntuPlan") {
        request.job = input.job;
        request.fingerprint = input.fingerprint;
      }
    }
    if (input.action === "install") {
      Object.assign(request, {
        login: input.login,
        vpnPassword: input.vpnPassword,
        files: await recipeFiles(),
      });
    }
    if (
      ["guests", "grant", "rotate", "revoke", "profile", "filter", "usage"].includes(
        input.action,
      )
    ) {
      request.files = await recipeFiles("accounts");
      if (input.login !== undefined) request.login = input.login;
      if (input.revision !== undefined) request.revision = input.revision;
      if (input.action === "grant" || input.action === "rotate")
        request.vpnPassword = input.vpnPassword;
      if (input.level !== undefined) request.level = input.level;
    }
    if (["removeReview", "removeApply", "ubuntuCheck", "ubuntuReview", "pairUbuntuReview", "pairUbuntuPlan"].includes(input.action)) {
      request.files = await recipeFiles("lifecycle");
      if (input.action === "ubuntuReview") {
        if (!rootPassword) throw new Error("connection");
        request.ubuntu = input.ubuntu;
      }
      if (input.action === "removeApply") {
        request.token = input.token;
        request.confirmation = input.confirmation;
      }
    }
    if (input.action === "ubuntuApply" || input.action === "pairUbuntuApply") {
      Object.assign(request, {
        job: input.job,
        fingerprint: input.fingerprint,
        token: input.token,
        confirmation: input.confirmation,
        password: rootPassword,
      });
      rootPassword = undefined;
      if (!request.password) throw new Error("connection");
      request.files = await recipeFiles("reinstall");
    }
    if (
      [
        "protocolReview",
        "protocolApply",
        "protocolProfile",
        "protocolUsers",
        "protocolGrant",
        "protocolRevoke",
        "protocolFilter",
        "protocolUsage",
        "protocolRemoveReview",
        "protocolRemoveApply",
      ].includes(input.action)
    ) {
      request.files = await recipeFiles("single");
      if (input.login !== undefined) request.login = input.login;
      if (input.revision !== undefined) request.revision = input.revision;
      if (input.action === "protocolApply") request.port = input.port;
      if (input.method !== undefined) request.method = input.method;
      if (input.action === "protocolFilter") {
        if (input.level !== undefined) request.level = input.level;
        if (input.enabled !== undefined) request.enabled = input.enabled;
      }
      if (input.action === "protocolRemoveApply") {
        request.token = input.token;
        request.confirmation = input.confirmation;
      }
    }
    let archive;
    if (input.action === "protocolReview") routePlan = undefined;
    if (input.action === "protocolApply" && routePlan) {
      const { method, port, login, architecture } = routePlan;
      routePlan = undefined;
      if (input.method !== method || input.port !== port || input.login !== login)
        throw new Error("plan");
      archive = await verifiedRouteArchive(architecture);
      if (!archive) {
        process.send({ ok: true, result: { state: "runtimeUnavailable" } });
        return;
      }
      request.runtimeArchitecture = architecture;
    }
    const result = await executeGateway(client, request, archive);
    if (input.action === "protocolReview" && result.runtimeArchitecture) {
      const architecture = result.runtimeArchitecture;
      if (!(await verifiedRouteArchive(architecture))) {
        process.send({ ok: true, result: { state: "runtimeUnavailable" } });
        return;
      }
      routePlan = {
        method: input.method,
        port: result.port,
        login: input.login,
        architecture,
      };
      delete result.runtimeArchitecture;
    }
    process.send({ ok: true, result });
  } catch (error) {
    process.send?.({
      ok: false,
      error: error.message === "pin" ? "pin" : "connection",
    });
  }
});
