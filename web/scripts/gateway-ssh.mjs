import {
  recipePaths,
  accountPaths,
  lifecyclePaths,
  routeArchitectures,
  reinstallPaths,
  singlePaths,
} from "../src/lib/gateway-files.mjs";
import ssh2 from "ssh2";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const project = resolve(scripts, "../..");
const maxArchiveBytes = 16 * 1024 * 1024;

export async function verifiedRouteArchive(architecture) {
  const directory = process.env.ROOKSTRIDE_ROUTE_ASSETS;
  if (!directory || !routeArchitectures.includes(architecture)) return null;
  let file;
  try {
    const pins = JSON.parse(
      await readFile(resolve(project, "single/routes-pins.json"), "utf8"),
    );
    const { archive_bytes: size, archive_sha256: digest } =
      pins.assets[architecture];
    if (!Number.isInteger(size) || size <= 0 || size > maxArchiveBytes)
      return null;
    file = await open(
      resolve(directory, architecture + ".tar.gz"),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const metadata = await file.stat();
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size !== size)
      return null;
    const content = Buffer.alloc(size + 1);
    let total = 0;
    while (total < content.length) {
      const { bytesRead } = await file.read(
        content,
        total,
        content.length - total,
        total,
      );
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total !== size) return null;
    const archive = content.subarray(0, size);
    return createHash("sha256").update(archive).digest("hex") === digest
      ? archive
      : null;
  } catch {
    return null;
  } finally {
    await file?.close();
  }
}

export async function recipeFiles(scope = "install") {
  const paths = {
    install: recipePaths,
    accounts: accountPaths,
    lifecycle: lifecyclePaths,
    reinstall: reinstallPaths,
    single: singlePaths,
  };
  const files = {};
  for (const path of paths[scope]) {
    files[path] = (await readFile(resolve(project, path))).toString("base64");
  }
  if (scope === "reinstall") {
    const upstream = JSON.parse(
      Buffer.from(files["reinstall/upstream.json"], "base64"),
    );
    for (const path of Object.keys(upstream.files)) {
      if (!path.split("/").every((part) => /^[A-Za-z0-9._-]+$/.test(part) && part !== "." && part !== ".."))
        throw new Error("recipe");
      const name = "reinstall/vendor/" + path;
      files[name] = (await readFile(resolve(project, name))).toString("base64");
    }
  }
  return scope === "single" || scope === "reinstall"
    ? gzipSync(JSON.stringify(files)).toString("base64")
    : files;
}

export function openSsh({ address, sshPort, password, fingerprint, keyType = "ssh-ed25519" }) {
  return new Promise((resolveClient, reject) => {
    if (!["ssh-ed25519", "ecdsa-sha2-nistp256"].includes(keyType)) {
      reject(new Error("connection"));
      return;
    }
    const client = new ssh2.Client();
    let unexpectedFingerprint;
    client.once("ready", () => resolveClient(client));
    client.on("error", () => {
      client.destroy();
      const error = new Error(unexpectedFingerprint ? "pin" : "connection");
      if (unexpectedFingerprint) error.presentedFingerprint = unexpectedFingerprint;
      reject(error);
    });
    client.once("close", () => reject(new Error("connection")));
    client.connect({
      host: address,
      port: sshPort,
      username: "root",
      password,
      readyTimeout: 12000,
      keepaliveInterval: 15000,
      keepaliveCountMax: 2,
      algorithms: { serverHostKey: [keyType] },
      hostVerifier(key) {
        const received =
          "SHA256:" +
          createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
        if (received === fingerprint) return true;
        unexpectedFingerprint = received;
        return false;
      },
    });
  });
}

export async function executeGateway(client, request, archive) {
  if (archive && (!Buffer.isBuffer(archive) || archive.length > maxArchiveBytes))
    throw new Error("transport");
  // The SSH command is constant. Only local source supplies the first stdin line.
  const code = (await readFile(resolve(scripts, "gateway_remote.py"))).toString(
    "base64",
  );
  const command =
    "/usr/bin/python3 -I -B -c \"import sys,base64;exec(compile(base64.b64decode(sys.stdin.buffer.readline(131072),validate=False),'<rookstride>','exec'))\"";
  const header = code + "\n" + JSON.stringify(request) + "\n";
  return executeJson(client, command, header, ...(archive ? [archive] : []));
}

export function executeJson(client, command, ...parts) {
  return executeJsonWithLimit(client, command, 32768, ...parts);
}

export function executeJsonWithLimit(client, command, maxBytes, ...parts) {
  return new Promise((resolveResult, reject) => {
    let settled = false;
    function fail() {
      if (settled) return;
      settled = true;
      client.removeListener("close", fail);
      reject(new Error("transport"));
    }
    client.once("close", fail);
    client.exec(command, { pty: false }, (error, channel) => {
      if (error) return fail();
      let size = 0;
      const chunks = [];
      channel.stderr.resume();
      channel.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          channel.destroy();
          fail();
        } else chunks.push(chunk);
      });
      channel.on("error", fail);
      channel.once("close", (status, signal) => {
        if (settled) return;
        if (status !== 0 || signal) return fail();
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!result || Array.isArray(result) || typeof result !== "object")
            return fail();
          settled = true;
          client.removeListener("close", fail);
          resolveResult(result);
        } catch {
          fail();
        }
      });
      for (const part of parts) channel.write(part);
      channel.end();
    });
  });
}
