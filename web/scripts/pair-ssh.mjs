import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { executeJson, executeJsonWithLimit } from "./gateway-ssh.mjs";

const maxArchiveBytes = 4 * 1024 * 1024;
const maxSourceBytes = 8 * 1024 * 1024;
const maxRecoveryRequest = 2 * 1024 * 1024;
const maxRecoveryResponse = 1_572_864 + 4096;
export const pairRemoteRejections = new Set([
  "ownership-mismatch", "inactive-pair", "account-unavailable",
  "roster-changed", "removal-review-stale",
  "invalid-recovery", "restore-ownership-mismatch", "restore-incomplete", "restore-resume-required",
]);
const command =
  "/usr/bin/python3 -I -B -c \"import sys,base64;exec(compile(base64.b64decode(sys.stdin.buffer.readline(131072).strip(),validate=True),'<rookstride-pair>','exec'))\"";

function webRoot() {
  return process.env.ROOKSTRIDE_WEB_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

export async function loadPairRecipe() {
  // Keep this list byte-equivalent to the Android gateway bundle. Additions
  // require updating the reviewed manifest and digest together.
  const root = webRoot();
  const { digest, paths } = JSON.parse(
    await readFile(resolve(root, "src/lib/pair-recipe.json"), "utf8"),
  );
  if (
    !/^[a-f0-9]{64}$/.test(digest) ||
    !Array.isArray(paths) || paths.length < 1 || paths.length > 256
  ) throw new Error("pair recipe");
  const hash = createHash("sha256");
  const files = [];
  let size = 0;
  for (const name of paths) {
    if (
      typeof name !== "string" ||
      !/^(server|twohop|gateway|single)\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/.test(name) ||
      name.split("/").some((part) => part === "." || part === "..")
    ) throw new Error("pair recipe");
    const bytes = await readFile(resolve(root, "..", name));
    size += bytes.length;
    if (size > maxSourceBytes) throw new Error("pair recipe");
    hash.update(name).update(bytes);
    files.push([name, bytes.toString("base64")]);
  }
  const source = Buffer.from(JSON.stringify(files));
  const archive = gzipSync(source);
  if (
    hash.digest("hex") !== digest ||
    source.length > maxSourceBytes ||
    archive.length > maxArchiveBytes
  ) throw new Error("pair recipe");
  return { digest, archive };
}

export async function executePairRequest(client, { mode = "recipe", bundle, request, archive }) {
  if (archive && (!Buffer.isBuffer(archive) || archive.length > maxArchiveBytes))
    throw new Error("pair transport");
  const source = await readFile(resolve(webRoot(), "scripts/pair_remote.py"));
  const header = JSON.stringify({ mode, bundle, request }) + "\n";
  const largeRequest = mode === "recovery" && request?.action === "rehearse-pair" ||
    mode === "restore" && ["validate", "identity"].includes(request?.action);
  const recoveryExport = mode === "recovery" && request?.action === "export";
  if (Buffer.byteLength(header) > (largeRequest ? maxRecoveryRequest : 65536))
    throw new Error("pair transport");
  const parts = [source.toString("base64") + "\n", header, ...(archive ? [archive] : [])];
  const reply = recoveryExport
    ? await executeJsonWithLimit(client, command, maxRecoveryResponse, ...parts)
    : await executeJson(client, command, ...parts);
  if (reply.ok === false && pairRemoteRejections.has(reply.code))
    throw Object.assign(new Error("pair recipe"), { code: reply.code });
  if (reply.ok !== true || !reply.result || typeof reply.result !== "object" || Array.isArray(reply.result))
    throw new Error("pair recipe");
  return reply.result;
}
