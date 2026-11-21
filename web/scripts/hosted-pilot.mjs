import { createServer } from "node:http";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  createGatewayService,
  publicDestination,
  startWorker,
} from "../src/lib/gateway-service.mjs";
import { gatewayHeaders } from "../src/lib/gateway-http.mjs";
import { configuredPublicOrigin } from "../src/lib/web-runtime.mjs";
import {
  configuredPilotMethods,
  createEnrolledPairService,
  handleHostedGateway,
  isolatedPairEnrollment,
  isolatedPairRebuild,
  parsePilotEnrollments,
} from "../src/lib/pilot-access.mjs";
import {
  createHostedUbuntu,
  hostedServerMatches,
} from "../src/lib/hosted-ubuntu.mjs";

const origin = configuredPublicOrigin();
const address = process.env.ROOKSTRIDE_PILOT_TARGET;
const fingerprint = process.env.ROOKSTRIDE_PILOT_PIN;
const inviteHash = process.env.ROOKSTRIDE_PILOT_INVITE_HASH;
const enrollmentsFile = process.env.ROOKSTRIDE_PILOT_ENROLLMENTS_FILE;
const stateDirectory = process.env.ROOKSTRIDE_PILOT_REINSTALL_STATE;
const pairRebuildDirectory = process.env.ROOKSTRIDE_PILOT_PAIR_REBUILD_STATE_DIR;
const pairExitSetting = process.env.ROOKSTRIDE_PILOT_PAIR_EXIT_CHOICES;
const pairExitChoices = pairExitSetting === "1" || pairRebuildDirectory !== undefined;
const port = Number(process.env.ROOKSTRIDE_PILOT_PORT ?? "3102");
const availableMethods = configuredPilotMethods(
  process.env.ROOKSTRIDE_PILOT_EXTRA_METHODS,
  process.env.ROOKSTRIDE_ROUTE_ASSETS,
);
if (
  process.getuid?.() === 0 ||
  !origin ||
  !availableMethods ||
  (pairExitSetting !== undefined && pairExitSetting !== "1") ||
  !Number.isInteger(port) || port < 1024 || port > 65535 ||
  (pairRebuildDirectory !== undefined && enrollmentsFile === undefined) ||
  (enrollmentsFile !== undefined &&
    (!isAbsolute(enrollmentsFile) || [address, fingerprint, inviteHash, stateDirectory].some((value) => value !== undefined)))
)
  throw new Error(
    "Configure an unprivileged pilot with an HTTPS origin, approved destination and invitation digest.",
  );

const dir = fileURLToPath(new URL("../", import.meta.url));
function readEnrollments(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== 0 || stat.nlink !== 1 || stat.mode & 0o037 || stat.size > 4096)
      throw new Error("The hosted enrollment file needs restricted root ownership.");
    return JSON.parse(readFileSync(fd, "utf8"));
  } finally {
    closeSync(fd);
  }
}
const admissions = parsePilotEnrollments(
  enrollmentsFile === undefined
    ? [{ server: { version: 1, address, sshPort: 22, fingerprint }, inviteHash }]
    : readEnrollments(enrollmentsFile),
  publicDestination,
);
if (!isolatedPairRebuild(admissions, pairRebuildDirectory))
  throw new Error("Paired rebuild needs an isolated enrollment and an absolute private state directory.");
if (pairExitChoices && !isolatedPairEnrollment(admissions))
  throw new Error("Paired exit choices need an isolated enrollment.");
const enrollments = admissions.map((enrollment) => {
  if (enrollment.pair) return {
    ...enrollment,
    pairRebuild: pairRebuildDirectory !== undefined,
    pairExitChoices,
    service: createEnrolledPairService(enrollment.pair, undefined, {
      allowMixedExits: pairExitChoices,
      rebuildDirectory: pairRebuildDirectory,
      openPairWorker: (pairRebuild) => startWorker({ dir, reinstall: true, pairRebuild }),
    }),
  };
  const { server } = enrollment;
  const hostedUbuntu = stateDirectory ? createHostedUbuntu(stateDirectory, server) : undefined;
  const current = () => hostedUbuntu?.load() ?? { current: server };
  const service = createGatewayService(
    () => startWorker({ dir, pilot: current(), reinstall: Boolean(hostedUbuntu) }),
    (target, request) => target === server.address && hostedServerMatches(current().current, request),
    { availableMethods, hostedUbuntu, allowEcdsa: Boolean(server.keyType || hostedUbuntu) },
  );
  return { ...enrollment, hostedUbuntu, service };
});

async function gatewayRequest(incoming) {
  const method = incoming.method;
  if (incoming.url !== "/vpn/api" || !["GET", "POST"].includes(method))
    return new Response(null, { status: 404, headers: gatewayHeaders });
  const body =
    method === "POST" ? { body: Readable.toWeb(incoming), duplex: "half" } : {};
  return handleHostedGateway(
    new Request(new URL("/vpn/api", origin), { method, headers: incoming.headers, ...body }),
    origin,
    enrollments,
  );
}

const server = createServer(async (incoming, outgoing) => {
  try {
    const response = await gatewayRequest(incoming);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    if (!outgoing.headersSent) outgoing.writeHead(503, gatewayHeaders);
    outgoing.end();
  }
});
server.headersTimeout = 10_000;
server.requestTimeout = 20_000;
server.maxConnections = 24;
server.listen(port, "127.0.0.1");
