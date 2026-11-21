import { createHash, generateKeyPairSync } from "node:crypto";
import { constants, rmSync } from "node:fs";
import { mkdtemp, open, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  createGatewayService,
  startWorker,
} from "../src/lib/gateway-service.mjs";
import {
  createOperatorMcp,
  describeOperation,
  operatorPlanSchema,
} from "../src/lib/operator-mcp.mjs";
import {
  createPairOperatorMcp,
  openPairRebuildApproval,
  operatorPairPlanSchema,
  operatorPairRebuildKinds,
  operatorPairTargets,
  sealPairRebuildApproval,
} from "../src/lib/pair-operator-mcp.mjs";
import { maxPairRecoveryBytes } from "../src/lib/pair-recovery.mjs";
import { createPairRebuild, pairRebuildConfirmation } from "../src/lib/pair-rebuild.mjs";
import { recoveryPassword } from "../src/lib/workbench-pair.mjs";
import {
  readUbuntuRecovery,
  ubuntuEraseConfirmation,
  validVpnPassword,
} from "../src/lib/gateway-input.mjs";

const expectedFields = {
  address: z.ipv4(),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/),
};

async function ownerFile(path, limit, privateMode) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error("Invalid local file");
  const file = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      (privateMode && stat.mode & 0o077) ||
      stat.size > limit
    )
      throw new Error("Invalid private file");
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== stat.size) throw new Error("Local file changed while reading");
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}

async function privateFile(path) {
  return (await ownerFile(path, 4096, true)).toString("utf8");
}

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

async function approve(path) {
  if (!process.stdin.isTTY || !process.stdout.isTTY || !isAbsolute(path))
    throw new Error("Use a terminal with the absolute review path");
  const contents = await privateFile(path);
  const input = JSON.parse(contents);
  const pair = operatorPairPlanSchema.safeParse(input);
  const plan = pair.success ? pair.data : operatorPlanSchema.parse(input);
  if (Date.now() >= plan.expiresAt) throw new Error("Expired review");
  const confirmations = {
    install: "INSTALL VPN",
    remove: "DELETE VPN",
    export: "EXPORT VPN PROFILE",
    reinstall: ubuntuEraseConfirmation,
  };
  let expected;
  if (pair.success) {
    const { entry, exit, login, bundle, exitProtocol } = plan.review;
    const exitMethod = {
      awg: "AmneziaWG UDP 443",
      openvpn: "OpenVPN TCP 1194",
      ikev2: "IKEv2 UDP 500 and 4500",
      xray: "VLESS TCP/REALITY 443",
    }[exitProtocol ?? "awg"];
    console.log(
      `Entry ${entry.address}:${entry.sshPort} – ${entry.keyType} ${entry.fingerprint} – Ubuntu ${entry.ubuntu}`,
    );
    console.log(
      `Exit ${exit.address}:${exit.sshPort} – ${exit.keyType} ${exit.fingerprint} – Ubuntu ${exit.ubuntu}`,
    );
    console.log(`AmneziaWG UDP 51820 entry and ${exitMethod} exit. Recipe ${bundle}.`);
    const description = {
      "pair-install": [`Install the reviewed Double VPN for ${login}.`, "INSTALL DOUBLE VPN"],
      "pair-export": [`Save ${plan.login ?? login}'s private Double VPN profile on this computer.`, "EXPORT DOUBLE VPN PROFILE"],
      "pair-account": [plan.account && `${plan.account.operation === "grant" ? "Add" : "Revoke"} ${plan.account.login} on the entry using the reviewed roster.`, "CHANGE DOUBLE VPN ACCOUNT"],
      "pair-remove": ["Remove the owned entry and then the exit, including their VPN profiles and keys. Ubuntu and SSH stay installed.", "DELETE PAIR"],
      "pair-backup": ["Save the encrypted owner recovery file on this computer.", "EXPORT DOUBLE VPN RECOVERY"],
      "pair-rehearse": ["Check the encrypted file against both owned roles without restoring it.", "REHEARSE DOUBLE VPN RECOVERY"],
      "pair-rebuild-review": [
        `Review Ubuntu ${plan.ubuntu?.entry} on the entry and Ubuntu ${plan.ubuntu?.exit} on the exit.`,
        "PREPARE DOUBLE VPN REBUILD",
      ],
      "pair-rebuild-start": ["Erase the reviewed system disk on each server, exit first, and restore the VPN identity.", pairRebuildConfirmation],
      "pair-rebuild-resume": ["Continue the recorded disk rebuild and restore from its verified job receipts.", pairRebuildConfirmation],
    }[plan.kind];
    if (plan.rebuild) {
      console.log(`Recorded pair rebuild ${plan.rebuild.operation}`);
      for (const role of ["exit", "entry"]) {
        const { ubuntu, boot, diskBytes, fingerprint, job } = plan.rebuild[role];
        console.log(`${role}: Ubuntu ${ubuntu}, ${boot}, ${diskBytes} bytes, planned ECDSA key ${fingerprint}, installer job ${job}`);
      }
    }
    console.log(description[0]);
    expected = description[1];
  } else {
    console.log(
      `Server ${plan.address}:${plan.sshPort} – ${plan.keyType ?? "ssh-ed25519"} ${plan.fingerprint}`,
    );
    console.log(describeOperation(plan.operation));
    expected = confirmations[plan.operation.kind] ?? "APPROVE CHANGE";
  }
  let hideInput = false;
  const terminalOutput = new Writable({
    write(chunk, encoding, done) {
      if (!hideInput) process.stdout.write(chunk);
      done();
    },
  });
  const terminal = createInterface({
    input: process.stdin,
    output: terminalOutput,
    terminal: true,
    historySize: 0,
  });
  async function hidden(prompt) {
    process.stdout.write(prompt);
    hideInput = true;
    try {
      return await terminal.question("");
    } finally {
      hideInput = false;
      process.stdout.write("\n");
    }
  }
  try {
    const confirmation = await terminal.question(
      `Type ${expected} to approve this plan: `,
    );
    if (confirmation !== expected || Date.now() >= plan.expiresAt)
      throw new Error("Review not approved");
    const approval = { digest: digest(contents) };
    if (plan.needsPassword) {
      approval.vpnPassword = await hidden("VPN password (hidden): ");
      if (!validVpnPassword(approval.vpnPassword))
        throw new Error("Invalid VPN password");
    }
    if (pair.success && (plan.kind === "pair-backup" || plan.kind === "pair-rehearse")) {
      if (plan.kind === "pair-rehearse") {
        approval.archivePath = await terminal.question("Absolute path to the encrypted owner recovery file: ");
        if (Buffer.byteLength(approval.archivePath) > 2048) throw new Error("Invalid recovery path");
        approval.archiveDigest = digest(await ownerFile(approval.archivePath, maxPairRecoveryBytes, false));
      }
      approval.recoveryPassword = await hidden("Owner recovery passphrase (hidden): ");
      if (!recoveryPassword(approval.recoveryPassword)) throw new Error("Invalid owner recovery passphrase");
    }
    if (pair.success && operatorPairRebuildKinds.includes(plan.kind)) {
      const archivePath = await terminal.question("Absolute path to the encrypted owner recovery file: ");
      if (Buffer.byteLength(archivePath) > 1024) throw new Error("Invalid recovery path");
      const archiveDigest = digest(await ownerFile(archivePath, maxPairRecoveryBytes, false));
      if (plan.rebuild && plan.rebuild.encryptedDigest !== archiveDigest)
        throw new Error("Use the encrypted archive recorded in this rebuild plan");
      const passphrase = await hidden("Owner recovery passphrase (hidden): ");
      approval.sealedPairRebuild = sealPairRebuildApproval(plan.approvalKey, approval.digest, {
        archivePath, archiveDigest, recoveryPassword: passphrase,
      });
    }
    if (Date.now() >= plan.expiresAt) throw new Error("Review not approved");
    await writeFile(`${path}.approved`, JSON.stringify(approval), {
      mode: 0o600,
      flag: "wx",
    });
    console.log("Approved. Return to your assistant to apply this review.");
  } finally {
    terminal.close();
  }
}

async function run() {
  if (
    typeof process.getuid !== "function" ||
    process.getuid() === 0 ||
    process.env.ROOKSTRIDE_HOSTED_SITE !== undefined
  )
    throw new Error("Use a standard local account");
  const args = process.argv.slice(2);
  if (args.length === 2 && args[0] === "approve") return approve(args[1]);
  if (args.length) throw new Error("Unexpected arguments");
  const targetPath = process.env.ROOKSTRIDE_MCP_TARGET_FILE;
  const pairPath = process.env.ROOKSTRIDE_MCP_PAIR_TARGET_FILE;
  const pairRebuildDirectory = process.env.ROOKSTRIDE_MCP_PAIR_REBUILD_STATE_DIR;
  const allowPairRebuild = process.env.ROOKSTRIDE_MCP_PAIR_REBUILD === "1";
  const allowReinstall = process.env.ROOKSTRIDE_MCP_UBUNTU_REINSTALL === "1";
  const recoveryPath = process.env.ROOKSTRIDE_MCP_RECOVERY_FILE;
  if (
    (pairPath !== undefined && (targetPath !== undefined || allowReinstall || recoveryPath !== undefined)) ||
    (pairRebuildDirectory !== undefined && pairPath === undefined) ||
    (allowPairRebuild && (pairPath === undefined || pairRebuildDirectory === undefined))
  )
    throw new Error("Choose one local connector mode");
  const path = pairPath ?? targetPath;
  if (!path || !isAbsolute(path)) throw new Error("Missing target file");
  const config = JSON.parse(await privateFile(path));
  const directory = await mkdtemp(join(tmpdir(), "rookstride-operator-"));
  const terminalKey = allowPairRebuild ? generateKeyPairSync("rsa", { modulusLength: 2048 }) : undefined;
  process.once("exit", () =>
    rmSync(directory, { recursive: true, force: true }),
  );
  const approval = {
    async stage(plan) {
      const path = join(directory, `${plan.id}.json`);
      const content = JSON.stringify(plan);
      await writeFile(path, content, { flag: "wx", mode: 0o600 });
      setTimeout(
        () => {
          void Promise.allSettled([unlink(path), unlink(`${path}.approved`)]);
        },
        Math.max(0, plan.expiresAt - Date.now()),
      ).unref();
      return { path, digest: digest(content), rebuild: operatorPairRebuildKinds.includes(plan.kind) };
    },
    async consume(receipt) {
      try {
        const path = `${receipt.path}.approved`;
        const data = JSON.parse(await privateFile(path));
        if (data.digest !== receipt.digest) return;
        await unlink(path);
        if (receipt.rebuild)
          return openPairRebuildApproval(terminalKey?.privateKey, receipt.digest, data.sealedPairRebuild);
        return data;
      } catch {
        return undefined;
      }
    },
    async saveProfile(filename, contents) {
      const exports = await mkdtemp(join(tmpdir(), "rookstride-profile-"));
      const path = join(exports, filename);
      await writeFile(path, contents, { flag: "wx", mode: 0o600 });
      return path;
    },
    async readRecovery(path, expected) {
      const bytes = await ownerFile(path, maxPairRecoveryBytes, false);
      if (digest(bytes) !== expected) throw new Error("Approved recovery file changed");
      return bytes;
    },
  };
  if (pairPath !== undefined) {
    const web = fileURLToPath(new URL("../", import.meta.url));
    const rebuild = pairRebuildDirectory === undefined ? undefined :
      createPairRebuild({
        directory: pairRebuildDirectory,
        openWorker: (pairRebuild) => startWorker({ dir: web, reinstall: true, pairRebuild }),
      });
    const server = createPairOperatorMcp(
      operatorPairTargets.parse(config),
      approval,
      undefined,
      {
        rebuildStatus: rebuild?.journalStatus,
        ...(allowPairRebuild && {
          rebuild,
          approvalKey: terminalKey.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
        }),
      },
    );
    return server.connect(new StdioServerTransport());
  }
  const target = z
    .object({
      ...expectedFields,
      sshPort: z.number().int().min(1).max(65535),
      keyType: z.literal("ecdsa-sha2-nistp256").optional(),
      password: z.string().min(1).max(256),
    })
    .strict()
    .parse(config);
  let initial;
  if (recoveryPath !== undefined) {
    if (!allowReinstall || !isAbsolute(recoveryPath))
      throw new Error(
        "Enable Ubuntu reinstall and use the absolute saved recovery path",
      );
    const recovery = readUbuntuRecovery(
      JSON.parse(await privateFile(recoveryPath)),
    );
    if (
      !recovery ||
      recovery.server.address !== target.address ||
      recovery.server.sshPort !== target.sshPort ||
      recovery.server.fingerprint !== target.fingerprint ||
      recovery.server.keyType !== target.keyType
    )
      throw new Error("Recovery does not match the configured SSH identity");
    initial = { recovery, file: recoveryPath };
  }
  process.env.ROOKSTRIDE_PERSONAL_WEB = "1";
  const dir = fileURLToPath(new URL("../", import.meta.url));
  const service = createGatewayService(
    () => startWorker({ dir, reinstall: allowReinstall }),
    undefined,
    { ubuntuReinstall: allowReinstall, allowEcdsa: Boolean(target.keyType) },
  );
  const ubuntu = allowReinstall
    ? {
        initial,
        async saveRecovery(record) {
          const directory = await mkdtemp(
            join(dirname(targetPath), "rookstride-recovery-"),
          );
          const path = join(directory, "rookstride-ubuntu-recovery.json");
          const file = await open(path, "wx", 0o600);
          try {
            await file.writeFile(JSON.stringify(record, null, 2) + "\n");
            await file.sync();
          } finally {
            await file.close();
          }
          return path;
        },
      }
    : undefined;
  const server = createOperatorMcp(service, target, approval, ubuntu);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

try {
  await run();
} catch {
  console.error(
    "Rookstride could not open the local target or approval. Check the private file, permissions, and review expiry.",
  );
  process.exitCode = 1;
}
