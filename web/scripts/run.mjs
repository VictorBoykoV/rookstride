import { randomBytes } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [major, minor, patch] = process.versions.node.split(".").map(Number);
if (
  major < 24 ||
  (major === 24 && (minor < 22 || (minor === 22 && patch < 1)))
) {
  throw new Error(
    "Use Node 24.22.1 or newer. scripts/local.sh can use the project-local runtime.",
  );
}
const mode = process.argv[2] || "dev";
if (!["dev", "build", "start", "check", "http-check"].includes(mode))
  throw new Error("Choose dev, build, start, check or http-check.");
if (mode === "check" || mode === "http-check") {
  const commands =
    mode === "check"
      ? [
          ["node_modules/typescript/bin/tsc", "--noEmit"],
          [
            "--test",
            "--test-concurrency=1",
            "tests/preview.test.mjs",
            "tests/mcp.test.mjs",
            "tests/language.test.mjs",
            "tests/gateway-service.test.mjs",
            "tests/protocol-lifecycle.test.mjs",
            "tests/pair-deployment.test.mjs",
            "tests/pair-rebuild.test.mjs",
            "tests/pair-recovery.test.mjs",
            "tests/workbench-pair.test.mjs",
            "tests/gateway-ssh.test.mjs",
            "tests/hosted-gateway-jobs.test.mjs",
            "tests/hosted-cms.test.mjs",
            "tests/scoped-administration.test.mjs",
            "tests/web-runtime.test.mjs",
          ],
        ]
      : [["tests/http-smoke.mjs"]];
  for (const args of commands) {
    const code = await new Promise((done, reject) => {
      const task = spawn(process.execPath, args, {
        cwd: root,
        stdio: "inherit",
        env: {
          ...process.env,
          NODE_OPTIONS: process.env.NODE_OPTIONS || "--max-old-space-size=1536",
        },
      });
      task.on("error", reject);
      task.on("exit", done);
    });
    if (code !== 0) process.exit(typeof code === "number" ? code : 1);
  }
  if (mode === "check") {
    const code = await new Promise((done, reject) => {
      const task = spawn("python3", [
        "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_gateway*.py",
      ], {
        cwd: root,
        stdio: "inherit",
      });
      task.on("error", reject);
      task.on("exit", done);
    });
    if (code !== 0) process.exit(typeof code === "number" ? code : 1);
  }
  process.exit(0);
}
const data = resolve(root, ".private");
mkdirSync(data, { recursive: true, mode: 0o700 });
const secretFile = resolve(data, "payload-secret");
try {
  writeFileSync(secretFile, randomBytes(48).toString("hex"), {
    flag: "wx",
    mode: 0o600,
  });
} catch (error) {
  if (error.code !== "EEXIST") throw error;
}
const args = [
  mode,
  ...(mode === "dev" || mode === "build" ? ["--webpack"] : []),
  ...(mode === "build" ? [] : ["--hostname", "127.0.0.1", "--port", "3100"]),
];
let entry = resolve(root, "node_modules/next/dist/bin/next");
if (mode === "start") {
  entry = resolve(root, ".next/standalone/server.js");
  if (!existsSync(entry)) throw new Error("Build the local application first.");
  cpSync(resolve(root, "public"), resolve(root, ".next/standalone/public"), {
    recursive: true,
  });
  cpSync(
    resolve(root, ".next/static"),
    resolve(root, ".next/standalone/.next/static"),
    { recursive: true },
  );
}
process.env.ROOKSTRIDE_WEB_ROOT = root;
process.env.NODE_OPTIONS ||= "--max-old-space-size=1536";
const child = spawn(
  process.execPath,
  [entry, ...(mode === "start" ? [] : args)],
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      NODE_OPTIONS: process.env.NODE_OPTIONS || "--max-old-space-size=1536",
      ROOKSTRIDE_WEB_ROOT: root,
      ROOKSTRIDE_PERSONAL_WEB: mode === "build" ? "" : "1",
      HOSTNAME: "127.0.0.1",
      PORT: "3100",
      PAYLOAD_SECRET:
        process.env.PAYLOAD_SECRET || readFileSync(secretFile, "utf8").trim(),
      ROOKSTRIDE_DATA_DIR: data,
      NEXT_TELEMETRY_DISABLED: "1",
      PAYLOAD_TELEMETRY_DISABLED: "1",
    },
  },
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill(signal));
child.on("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
