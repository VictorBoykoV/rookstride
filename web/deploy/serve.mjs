import { accessSync } from "node:fs";
import { join } from "node:path";
import { readReadyState, statePath } from "./cms-state.mjs";

const mode = process.argv[2];
if (!["private", "public"].includes(mode) || process.argv.length !== 3)
  throw new Error("Use serve.mjs private or serve.mjs public.");
if (process.getuid?.() === 0)
  throw new Error("Run the website as an unprivileged service user.");

process.umask(0o077);
const data = statePath();
const server = new URL("../server.js", import.meta.url);
accessSync(server);
accessSync(new URL("../.next/BUILD_ID", import.meta.url));
accessSync(new URL("../.next/static/", import.meta.url));
accessSync(new URL("../public/brand/rook-bridge-team.webp", import.meta.url));
const secret = readReadyState(data);
for (const key of [
  "PAYLOAD_DROP_DATABASE",
  "PAYLOAD_MIGRATING",
  "ROOKSTRIDE_PERSONAL_WEB",
  "ROOKSTRIDE_WEB_ROOT",
])
  delete process.env[key];
Object.assign(process.env, {
  NODE_ENV: "production",
  HOSTNAME: "127.0.0.1",
  PORT: mode === "private" ? "3100" : "3101",
  NEXT_TELEMETRY_DISABLED: "1",
  PAYLOAD_TELEMETRY_DISABLED: "1",
  PAYLOAD_SECRET: secret,
  ROOKSTRIDE_DATA_DIR: data,
  ROOKSTRIDE_HOSTED_SITE: mode === "private" ? "1" : "public",
});
await import(server.href);
