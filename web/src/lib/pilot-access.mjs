import { createHash, timingSafeEqual } from "node:crypto";
import { isAbsolute } from "node:path";
import { readServerRecord, singleProtocolCatalog } from "./gateway-input.mjs";
import { gatewayHeaders, handleGateway } from "./gateway-http.mjs";
import { createGatewayService } from "./gateway-service.mjs";
import { hostedServerMatches } from "./hosted-ubuntu.mjs";
import { createWorkbenchPair } from "./workbench-pair.mjs";
import { createPairRebuild } from "./pair-rebuild.mjs";

const initialMethods = ["xray", "xhttp"];
const roles = ["entry", "exit"];

export function parsePilotEnrollments(records, eligibleTarget) {
  if (!Array.isArray(records) || records.length < 1 || records.length > 4)
    throw new Error("The hosted pilot needs one to four enrollments.");
  const addresses = new Set();
  const pins = new Set();
  const digests = new Set();
  function reserve(candidate) {
    const server = readServerRecord(candidate);
    if (
      !server || !eligibleTarget(server.address) || server.sshPort !== 22 ||
      addresses.has(server.address) || pins.has(server.fingerprint) || addresses.size >= 4
    ) throw new Error("Invalid or duplicate hosted pilot target.");
    addresses.add(server.address);
    pins.add(server.fingerprint);
    return server;
  }
  return records.map((record) => {
    const hash = record?.inviteHash;
    if (typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash) || digests.has(hash))
      throw new Error("Invalid or duplicate hosted pilot enrollment.");
    digests.add(hash);
    const invitationDigest = Buffer.from(hash, "hex");
    if (Object.keys(record).length === 2 && Object.hasOwn(record, "server"))
      return { server: reserve(record.server), invitationDigest };
    if (Object.keys(record).length === 3 && Object.hasOwn(record, "entry") && Object.hasOwn(record, "exit"))
      return { pair: { entry: reserve(record.entry), exit: reserve(record.exit) }, invitationDigest };
    throw new Error("Invalid hosted pilot enrollment shape.");
  });
}

export function isolatedPairEnrollment(enrollments) {
  return enrollments.length === 1 && Boolean(enrollments[0].pair);
}

export function isolatedPairRebuild(enrollments, directory) {
  return directory === undefined ||
    (typeof directory === "string" && isAbsolute(directory) && isolatedPairEnrollment(enrollments));
}

function enrolledReviewMatches(server, node) {
  return hostedServerMatches(server, node?.keyType === "ssh-ed25519"
    ? { ...node, keyType: undefined }
    : node);
}

export function createEnrolledPairService(pair, factory = createWorkbenchPair, {
  rebuildDirectory,
  openPairWorker,
  createRebuild = createPairRebuild,
  allowMixedExits = rebuildDirectory !== undefined,
} = {}) {
  const eligible = (address) => roles.some((role) => pair[role].address === address);
  let rebuild;
  if (rebuildDirectory !== undefined) {
    if (typeof openPairWorker !== "function") throw new Error("A scoped pair rebuild worker is required.");
    const coordinator = createRebuild({
      directory: rebuildDirectory,
      eligible,
      openWorker(scope) {
        if (!roles.includes(scope.role) || !hostedServerMatches(pair[scope.role], scope.server))
          throw new Error("Pair rebuild worker enrollment mismatch.");
        return openPairWorker(scope);
      },
    });
    const journalStatus = () => {
      const status = coordinator.journalStatus();
      if (status && roles.some((role) => !enrolledReviewMatches(pair[role], status.record.review[role])))
        throw new Error("Pair rebuild journal enrollment mismatch.");
      return status;
    };
    journalStatus();
    rebuild = { review: coordinator.review, run: coordinator.run, journalStatus };
  }
  return createGatewayService(undefined, eligible, {
    pairOnly: true,
    allowEcdsa: true,
    pairFactory: (options) => factory({
      ...options,
      ...(rebuild && { rebuild }),
      allowMixedExits,
      validateOriginalNode: (node, role) =>
        options.validateNode(node) && hostedServerMatches(pair[role], node),
      validateNode(node, role) {
        const restored = rebuild?.journalStatus()?.restored;
        const enrolled = restored?.review[role] ?? pair[role];
        return options.validateNode(node) && hostedServerMatches(enrolled, node);
      },
    }),
  });
}

export function pilotEnrollment(headers, method, origin, enrollments) {
  let selected;
  let status = 401;
  for (const enrollment of enrollments) {
    const candidate = pilotRequestStatus(headers, method, origin, enrollment.invitationDigest);
    if (candidate === 403) return { status: candidate };
    if (candidate !== 401) {
      selected = enrollment;
      status = candidate;
    }
  }
  return { status, enrollment: selected };
}

export function handleHostedGateway(request, origin, enrollments) {
  const { status, enrollment } = pilotEnrollment(request.headers, request.method, origin, enrollments);
  if (status) {
    return new Response(null, {
      status,
      headers: {
        ...gatewayHeaders,
        ...(status === 204 && enrollment?.hostedUbuntu && { "X-Rookstride-Ubuntu-Reinstall": "1" }),
        ...(status === 204 && enrollment?.server?.keyType && { "X-Rookstride-ECDSA": "1" }),
        ...(status === 204 && enrollment?.pair && { "X-Rookstride-Pair": "1" }),
        ...(status === 204 && enrollment?.pair && enrollment?.pairExitChoices && { "X-Rookstride-Pair-Exit-Choices": "1" }),
        ...(status === 204 && enrollment?.pairRebuild && { "X-Rookstride-Pair-Rebuild": "1" }),
      },
    });
  }
  return handleGateway(request, enrollment.service);
}

export function configuredPilotMethods(extra, runtimeDirectory) {
  if (extra === undefined) return [...initialMethods];
  const admitted = extra.split(",");
  if (
    new Set(admitted).size !== admitted.length ||
    admitted.some(
      (id) =>
        initialMethods.includes(id) ||
        !Object.hasOwn(singleProtocolCatalog, id),
    ) ||
    (admitted.some((id) => singleProtocolCatalog[id].extension === "rookvpn") &&
      !(runtimeDirectory && isAbsolute(runtimeDirectory)))
  )
    return;
  return [...initialMethods, ...admitted];
}

export function pilotRequestStatus(headers, method, origin, invitationDigest) {
  if (
    headers.get("host") !== origin.host ||
    ((method === "POST" || headers.has("origin")) &&
      headers.get("origin") !== origin.origin)
  )
    return 403;
  const invite = headers.get("x-rookstride-invite") || "";
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(invite) ||
    !timingSafeEqual(
      createHash("sha256").update(invite).digest(),
      invitationDigest,
    )
  )
    return 401;
  if (method === "GET" && !headers.has("authorization")) return 204;
  return 0;
}
