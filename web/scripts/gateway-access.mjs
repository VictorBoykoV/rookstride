import { readFile } from "node:fs/promises";
import { cleanScopedAdministration } from "../src/lib/scoped-administration.mjs";
import { executeJson } from "./gateway-ssh.mjs";

// Only the checked-in inspector supplies executable source to the pinned SSH session.
const command =
  "/usr/bin/python3 -I -B -c \"import sys,base64;exec(compile(base64.b64decode(sys.stdin.buffer.readline(131072),validate=False),'<rookstride-access-status>','exec'))\"";

export async function readScopedAdministration(client, address, method) {
  const code = (
    await readFile(new URL("./gateway_access.py", import.meta.url))
  ).toString("base64");
  const request = JSON.stringify({ address, method });
  return cleanScopedAdministration(
    await executeJson(client, command, `${code}\n${request}\n`),
  );
}
