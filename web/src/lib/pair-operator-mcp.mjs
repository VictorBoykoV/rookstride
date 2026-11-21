import {
  constants, createCipheriv, createDecipheriv, createPublicKey, privateDecrypt,
  publicEncrypt, randomBytes, randomUUID,
} from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  adoptPair,
  capturePairRecovery,
  changePairAccount,
  deployPair,
  exportPairProfile,
  pairRestoreStages,
  pairStages,
  PairDeploymentError,
  readPairManagement,
  rehearsePairRecovery,
  removePair,
  reviewPair,
  reviewPairRemoval,
} from "./pair-deployment.mjs";
import { decryptPairRecovery, encryptPairRecovery } from "./pair-recovery.mjs";
import { recoveryPassword } from "./workbench-pair.mjs";
import { mixedPairEntries, mixedPairExits, pairProfileExtension, ubuntuVersions, validVpnPassword } from "./gateway-input.mjs";
import { pairRebuildConfirmation } from "./pair-rebuild.mjs";

const idSchema = z.string().uuid();
const loginSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/);
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const mixedExitSchema = z.enum(mixedPairExits).optional();
const mixedEntrySchema = z.enum(mixedPairEntries).optional();
const pin = {
  address: z.ipv4(),
  sshPort: z.number().int().min(1).max(65535),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/),
  keyType: z.enum(["ssh-ed25519", "ecdsa-sha2-nistp256"]),
};
const authority = z.strictObject({
  ...pin,
  keyType: pin.keyType.default("ssh-ed25519"),
  password: z
    .string()
    .min(1)
    .refine(
      (value) => Buffer.byteLength(value) <= 1024 && !/[\x00\r\n]/.test(value),
    ),
});
const reviewedNode = z.strictObject({
  ...pin,
  machine: digestSchema,
  ubuntu: z.string().regex(/^\d{2}\.\d{2}(?:\.\d+)?$/),
});
const distinct = ({ entry, exit }) =>
  entry.address !== exit.address && entry.fingerprint !== exit.fingerprint;
const samePin = (target, node) =>
  target.address === node.address &&
  target.sshPort === node.sshPort &&
  target.fingerprint === node.fingerprint &&
  (target.keyType ?? "ssh-ed25519") === node.keyType;

export const operatorPairTargets = z
  .strictObject({ entry: authority, exit: authority })
  .refine(distinct);
export const operatorPairReview = z
  .strictObject({
    version: z.literal(1),
    pairId: z.string().regex(/^[a-f0-9]{32}$/),
    entryProtocol: mixedEntrySchema,
    exitProtocol: mixedExitSchema,
    bundle: digestSchema,
    login: loginSchema,
    entry: reviewedNode,
    exit: reviewedNode,
  })
  .refine((pair) => distinct(pair) && pair.entry.machine !== pair.exit.machine);
const accountInput = z.strictObject({
  operation: z.enum(["grant", "revoke"]),
  login: loginSchema,
  revision: digestSchema,
});
const planBase = z.strictObject({
  id: idSchema,
  expiresAt: z.number().int(),
  review: operatorPairReview,
});
const rebuildApprovalKey = z.string().min(350).max(512).regex(/^[A-Za-z0-9+/]+={0,2}$/);
const rebuildUbuntu = z.enum(ubuntuVersions);
const rebuildStageInput = z.strictObject({ entry: rebuildUbuntu, exit: rebuildUbuntu });
const rebuildOperation = z.string().regex(/^[a-f0-9]{32}$/);
const rebuildMember = z.strictObject({
  ubuntu: rebuildUbuntu,
  boot: z.enum(["BIOS", "EFI"]),
  diskBytes: z.number().safe().min(6 * 1024 ** 3),
  fingerprint: pin.fingerprint,
  job: rebuildOperation,
});
const rebuildScope = z.strictObject({
  operation: rebuildOperation,
  encryptedDigest: digestSchema,
  entry: rebuildMember,
  exit: rebuildMember,
});
export const operatorPairRebuildKinds = Object.freeze([
  "pair-rebuild-review", "pair-rebuild-start", "pair-rebuild-resume",
]);
export const operatorPairPlanSchema = z.union([
  planBase.extend({ kind: z.enum(["pair-install", "pair-remove", "pair-backup", "pair-rehearse"]) }),
  planBase.extend({ kind: z.literal("pair-export"), login: loginSchema.optional() }),
  planBase.extend({ kind: z.literal("pair-account"), account: accountInput }),
  planBase.extend({ kind: z.literal("pair-rebuild-review"), ubuntu: rebuildStageInput, approvalKey: rebuildApprovalKey }),
  planBase.extend({
    kind: z.enum(["pair-rebuild-start", "pair-rebuild-resume"]),
    rebuild: rebuildScope,
    approvalKey: rebuildApprovalKey,
  }),
]);

const encryptedRebuildApproval = z.strictObject({
  wrapped: z.string().length(344),
  nonce: z.string().length(16),
  tag: z.string().length(24),
  ciphertext: z.string().min(1).max(3072),
});
const recoveryInputs = z.strictObject({
  archivePath: z.string().refine((path) => path.length > 0 && Buffer.byteLength(path) <= 1024),
  archiveDigest: digestSchema,
  recoveryPassword: z.string().refine(recoveryPassword),
});

function decodeApproval(value, size) {
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (size !== undefined && bytes.length !== size))
    throw new Error("Invalid terminal approval encoding.");
  return bytes;
}

export function sealPairRebuildApproval(publicKey, approvalDigest, input) {
  const key = createPublicKey({
    key: decodeApproval(rebuildApprovalKey.parse(publicKey)), format: "der", type: "spki",
  });
  if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength !== 2048)
    throw new Error("Invalid terminal approval key.");
  const plaintext = Buffer.from(JSON.stringify(recoveryInputs.parse(input)));
  const sessionKey = randomBytes(32);
  const nonce = randomBytes(12);
  try {
    const cipher = createCipheriv("aes-256-gcm", sessionKey, nonce);
    cipher.setAAD(Buffer.from(digestSchema.parse(approvalDigest), "hex"));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return encryptedRebuildApproval.parse({
      wrapped: publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, sessionKey).toString("base64"),
      nonce: nonce.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    });
  } finally {
    plaintext.fill(0);
    sessionKey.fill(0);
  }
}

export function openPairRebuildApproval(privateKey, approvalDigest, envelope) {
  const { wrapped, nonce, tag, ciphertext } = encryptedRebuildApproval.parse(envelope);
  const sessionKey = privateDecrypt({
    key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256",
  }, decodeApproval(wrapped, 256));
  let first;
  let last;
  let plaintext;
  try {
    const decipher = createDecipheriv("aes-256-gcm", sessionKey, decodeApproval(nonce, 12));
    decipher.setAAD(Buffer.from(digestSchema.parse(approvalDigest), "hex"));
    decipher.setAuthTag(decodeApproval(tag, 16));
    first = decipher.update(decodeApproval(ciphertext));
    last = decipher.final();
    plaintext = Buffer.concat([first, last]);
    return recoveryInputs.parse(JSON.parse(plaintext.toString("utf8")));
  } finally {
    sessionKey.fill(0);
    first?.fill(0);
    last?.fill(0);
    plaintext?.fill(0);
  }
}

function response(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data,
  };
}

function failed(message) {
  return { isError: true, content: [{ type: "text", text: message }] };
}

const readOnly = { readOnlyHint: true, openWorldHint: false };
const change = { destructiveHint: true, openWorldHint: false };
const noInput = z.strictObject({});
const planInput = z.strictObject({ id: idSchema });
const reviewLifetime = 5 * 60_000;
const defaultRuntime = {
  reviewPair, deployPair, exportPairProfile, adoptPair, readPairManagement,
  changePairAccount, reviewPairRemoval, removePair, capturePairRecovery, rehearsePairRecovery,
};
const rebuildTools = new Set([
  "pair_rebuild_status", "review_pair_rebuild", "apply_pair_rebuild_review",
  "review_pair_rebuild_erase", "apply_pair_rebuild_erase",
  "review_pair_rebuild_resume", "apply_pair_rebuild_resume",
]);

function reviewedRebuildScope(record) {
  const members = Object.fromEntries(["entry", "exit"].map((role) => {
    const { ubuntu, boot, diskBytes, fingerprint, job } = record.members[role];
    return [role, { ubuntu, boot, diskBytes, fingerprint, job }];
  }));
  return rebuildScope.parse({ operation: record.operation, encryptedDigest: record.encryptedDigest, ...members });
}

export function createPairOperatorMcp(
  targets,
  approvals,
  runtime = defaultRuntime,
  { rebuild, approvalKey, rebuildStatus = rebuild?.journalStatus } = {},
) {
  const server = new McpServer({
    name: "rookstride-operator-pair",
    version: "0.2.0",
  });
  const applied = new Map();
  let pending;
  let inspected;
  let deployed;
  let deployment;
  let rebuildJob;
  let busy = false;

  function configuredReview(value) {
    const review = operatorPairReview.parse(value);
    return samePin(targets.entry, review.entry) && samePin(targets.exit, review.exit) ? review : null;
  }

  function rebuildView() {
    const status = rebuildStatus();
    if (!status) return { state: "unreviewed" };
    const { record, started, restored } = status;
    const review = configuredReview(record.review) ||
      (restored && configuredReview(restored.review));
    if (!review) return null;
    return {
      operation: record.operation,
      state: restored ? "restored" : rebuildJob?.state === "running" ? "running" : started ? "waiting" : "reviewed",
      entryUbuntu: record.members.entry.ubuntu,
      exitUbuntu: record.members.exit.ubuntu,
      ...(review.entryProtocol && { entryProtocol: review.entryProtocol }),
      ...(review.exitProtocol && { exitProtocol: review.exitProtocol }),
      ...(rebuildJob?.progress && { progress: rebuildJob.progress }),
    };
  }

  function register(name, description, inputSchema, annotations, run) {
    server.registerTool(
      name,
      { description, inputSchema, annotations },
      async (input) => {
        if (busy) return failed("Another Double VPN request is running.");
        busy = true;
        try {
          if (rebuildStatus && !rebuildTools.has(name) && !["pair_status", "cancel_review"].includes(name)) {
            const view = rebuildView();
            if (!view || ["waiting", "reviewed", "running"].includes(view.state))
              return failed("Check the recorded rebuild in the local operator workflow first.");
          }
          return await run(input);
        } catch (error) {
          if (error instanceof PairDeploymentError && error.code === "entry-dns-conflict")
            return failed("The entry server has existing private DNS state. Use a clean entry server or review its VPN and DNS setup first.");
          return failed(
            "Rookstride could not confirm this Double VPN operation. Check both pinned servers before retrying.",
          );
        } finally {
          busy = false;
        }
      },
    );
  }

  async function stage(kind, fields = {}, approvedReview) {
    if (pending && Date.now() < pending.expiresAt)
      return failed("Approve or cancel the outstanding review first.");
    if (deployment?.state === "running" || deployment?.uncertain)
      return failed("Inspect the pair before reviewing another operation.");
    const install = kind === "pair-install";
    const review = approvedReview ?? (install ? inspected?.review : deployed);
    const expiresAt = install
      ? inspected?.expiresAt
      : Date.now() + reviewLifetime;
    if (!review || Date.now() >= expiresAt)
      return failed(
        install
          ? "Inspect both fresh servers first."
          : "Finish installing the Double VPN first.",
      );
    const id = randomUUID();
    const plan = { id, kind, review, expiresAt, ...fields };
    const removal = kind === "pair-remove" ? await runtime.reviewPairRemoval({ ...targets, review }) : undefined;
    const receipt = await approvals.stage(plan);
    pending = { ...plan, receipt, removal };
    return response({ id, kind, expiresAt, approvalFile: receipt.path });
  }

  function currentEraseScope(kind, operation) {
    const status = rebuildStatus();
    if (
      !status || status.restored || status.record.operation !== operation ||
      Boolean(status.started) !== (kind === "pair-rebuild-resume") ||
      rebuildJob?.state === "running"
    ) return null;
    const review = configuredReview(status.record.review);
    if (!review) return null;
    return { review, scope: reviewedRebuildScope(status.record) };
  }

  async function applyRebuild(plan, approval) {
    const credentials = recoveryInputs.safeParse(approval);
    if (!credentials.success)
      return failed("Approve this rebuild in a separate terminal with the encrypted archive and its passphrase.");
    const { archivePath, archiveDigest, recoveryPassword: passphrase } = credentials.data;
    if (plan.kind === "pair-rebuild-review") {
      if (rebuildStatus()) return failed("The configured journal already contains a reviewed rebuild.");
      const encrypted = await approvals.readRecovery(archivePath, archiveDigest);
      try {
        const record = await rebuild.review({
          targets, ubuntu: plan.ubuntu, encrypted, passphrase, expectedReview: plan.review,
        });
        const { encryptedDigest: _digest, ...summary } = reviewedRebuildScope(record);
        return response({ state: "reviewed", ...summary });
      } finally {
        encrypted.fill(0);
      }
    }

    const current = currentEraseScope(plan.kind, plan.rebuild.operation);
    if (
      !current || archiveDigest !== current.scope.encryptedDigest ||
      JSON.stringify(current.scope) !== JSON.stringify(plan.rebuild) ||
      JSON.stringify(current.review) !== JSON.stringify(plan.review)
    ) return failed("The paired Ubuntu journal or reviewed archive changed. Review it again in the terminal.");
    const encrypted = await approvals.readRecovery(archivePath, archiveDigest);
    const job = { operation: plan.rebuild.operation, state: "running", progress: { stage: "preflight" } };
    rebuildJob = job;
    applied.set(plan.id, { kind: plan.kind, result: () => response({ ...job }) });
    void (async () => {
      try {
        const result = await rebuild.run({
          targets, encrypted, passphrase, confirmation: pairRebuildConfirmation,
          resumeRestore: plan.kind === "pair-rebuild-resume",
          onProgress({ role, state, stage }) {
            if (["entry", "exit"].includes(role) && [
              "issuing", "waiting", "preparing", "rebooting", "complete", "failed",
              "cancelled", "expired", "keyMismatch", "unverified",
            ].includes(state)) job.progress = { role, state };
            else if (pairRestoreStages.includes(stage)) job.progress = { stage };
          },
        });
        if (result?.operation !== job.operation || rebuildStatus()?.restored?.operation !== job.operation)
          throw new Error("Unverified rebuild result.");
        deployed = undefined;
        deployment = undefined;
        job.state = "restored";
      } catch {
        job.state = "needsAttention";
      } finally {
        encrypted.fill(0);
      }
    })();
    return response({ ...job });
  }

  async function apply(id, kind) {
    const previous = applied.get(id);
    if (previous)
      return previous.kind === kind
        ? previous.result()
        : failed("Use the apply tool for the original operation.");
    const plan = pending;
    if (
      !plan ||
      plan.id !== id ||
      plan.kind !== kind ||
      Date.now() >= plan.expiresAt
    )
      return failed("Prepare a current review for this operation first.");
    const approval = await approvals.consume(plan.receipt);
    if (!approval)
      return failed(
        "The operator must approve this review in a separate terminal.",
      );
    if (Date.now() >= plan.expiresAt)
      return failed("The approval expired. Prepare a new review.");
    pending = undefined;
    if (applied.size === 128) applied.delete(applied.keys().next().value);
    let result = failed(
      "This request was already sent. Check the current state before making another change.",
    );
    applied.set(id, { kind, result: () => result });

    const options = { ...targets, review: plan.review };
    const needsPassword = plan.review.entryProtocol === "ikev2" &&
      (kind === "pair-install" || kind === "pair-account" && plan.account.operation === "grant");
    if (needsPassword && !validVpnPassword(approval.vpnPassword))
      return failed("Approve with the new VPN password in a separate terminal.");
    if (operatorPairRebuildKinds.includes(kind)) {
      result = await applyRebuild(plan, approval);
      return result;
    }
    if (kind === "pair-export") {
      const login = plan.login ?? plan.review.login;
      const profile = await runtime.exportPairProfile({
        ...options,
        ...(plan.login && { login }),
      });
      const filename = `rookstride-${login}.${pairProfileExtension(plan.review.entryProtocol)}`;
      if (profile.filename !== filename) return result;
      const contents = profile.configuration.trimEnd() + "\n";
      result = response({
        filename,
        file: await approvals.saveProfile(filename, contents),
      });
      return result;
    }

    if (kind === "pair-account") {
      result = response(await runtime.changePairAccount({ ...options, ...plan.account,
        ...(needsPassword && { password: approval.vpnPassword }) }));
      return result;
    }

    if (kind === "pair-backup" || kind === "pair-rehearse") {
      if (!recoveryPassword(approval.recoveryPassword)) return failed("Approve again in a terminal with the owner recovery passphrase.");
      if (kind === "pair-backup") {
        const archive = await runtime.capturePairRecovery(options);
        const encrypted = await encryptPairRecovery(archive, approval.recoveryPassword, plan.review);
        const filename = "rookstride-owner-recovery.rookrec";
        result = response({ filename, file: await approvals.saveProfile(filename, encrypted) });
      } else {
        const bytes = await approvals.readRecovery(approval.archivePath, approval.archiveDigest);
        const archive = await decryptPairRecovery(bytes, approval.recoveryPassword, plan.review);
        await runtime.rehearsePairRecovery({ ...options, archive });
        result = response({ ready: true });
      }
      return result;
    }

    inspected = undefined;
    const removing = kind === "pair-remove";
    const job = { state: "running", stage: removing ? "remove" : "preflight" };
    if (plan.review.entryProtocol) job.entryProtocol = plan.review.entryProtocol;
    if (plan.review.exitProtocol) job.exitProtocol = plan.review.exitProtocol;
    deployment = job;
    applied.set(id, { kind, result: () => response({ ...job }) });
    void (async () => {
      try {
        if (removing) {
          const report = await runtime.removePair({ ...options, removal: plan.removal });
          if (report?.state !== "removed") throw new Error("Invalid removal receipt");
          deployed = undefined;
          job.state = "removed";
          return;
        }
        const report = await runtime.deployPair({
          ...options,
          ...(needsPassword && { password: approval.vpnPassword }),
          onProgress({ stage }) {
            if (pairStages.includes(stage)) job.stage = stage;
          },
        });
        if (
          report.state !== "installed" ||
          report.pairId !== plan.review.pairId
        )
          throw new Error("Invalid deployment receipt");
        deployed = plan.review;
        job.state = "installed";
      } catch (error) {
        job.state = "failed";
        if (error instanceof PairDeploymentError) {
          job.reason = error.code;
          job.uncertain = error.uncertain;
        } else {
          job.uncertain = true;
        }
      }
    })();
    return response({ ...job });
  }

  register(
    "open_pair",
    "Reopen the existing owned Double VPN using both configured SSH pins.",
    noInput,
    readOnly,
    async () => {
      if (deployment?.state === "running" || pending && Date.now() < pending.expiresAt)
        return failed("Wait for the current operation or cancel its review before opening the pair.");
      const review = configuredReview(await runtime.adoptPair(targets));
      if (!review)
        return failed("The existing pair does not match both configured roles.");
      inspected = undefined;
      deployed = review;
      deployment = { state: "installed", stage: "health", ...(review.entryProtocol && { entryProtocol: review.entryProtocol }), ...(review.exitProtocol && { exitProtocol: review.exitProtocol }) };
      return response({ ...deployment });
    },
  );
  register(
    "read_pair",
    "Read the verified Double VPN account roster and service health.",
    noInput,
    readOnly,
    async () => {
      if (!deployed || deployment?.state !== "installed") return failed("Open the installed Double VPN first.");
      return response(await runtime.readPairManagement({ ...targets, review: deployed }));
    },
  );
  register(
    "inspect_pair",
    "Inspect both configured SSH identities and review the selected entry and exit methods.",
    z.strictObject({ login: loginSchema, entryProtocol: mixedEntrySchema, exitProtocol: mixedExitSchema }),
    readOnly,
    async ({ login, entryProtocol, exitProtocol }) => {
      if (deployment?.state === "running" || deployed || deployment?.uncertain)
        return failed(
          "Check the existing Double VPN deployment before starting another.",
        );
      if (pending && Date.now() < pending.expiresAt)
        return failed("Approve or cancel the outstanding review first.");
      inspected = undefined;
      const review = configuredReview(
        await runtime.reviewPair({ ...targets, login, ...(entryProtocol && { entryProtocol }), ...(exitProtocol && { exitProtocol }) }),
      );
      if (
        !review ||
        review.login !== login ||
        review.entryProtocol !== entryProtocol || review.exitProtocol !== exitProtocol
      )
        return failed(
          "The review does not match the configured pair and owner.",
        );
      deployment = undefined;
      inspected = { review, expiresAt: Date.now() + reviewLifetime };
      const { entry, exit } = review;
      return response({
        state: "ready",
        entry: { ubuntu: entry.ubuntu },
        exit: { ubuntu: exit.ubuntu },
        method: entryProtocol ?? "awg",
        ...(entryProtocol && { entryProtocol }),
        ...(review.exitProtocol && { exitProtocol: review.exitProtocol }),
      });
    },
  );
  register(
    "review_pair_install",
    "Prepare the exact reviewed Double VPN installation for terminal approval.",
    noInput,
    change,
    () => stage("pair-install"),
  );
  register(
    "apply_pair_install",
    "Start a terminal-approved Double VPN installation once.",
    planInput,
    change,
    ({ id }) => apply(id, "pair-install"),
  );
  register(
    "pair_status",
    "Read deployment progress for the Double VPN in this local session.",
    noInput,
    readOnly,
    () =>
      response(
        deployment
          ? { ...deployment }
          : {
              state:
                inspected && Date.now() < inspected.expiresAt
                  ? "ready"
                  : "uninspected",
            },
      ),
  );
  if (rebuildStatus) register(
    "pair_rebuild_status",
    "Read the verified local paired Ubuntu rebuild journal for the two configured servers.",
    noInput,
    readOnly,
    () => {
      const view = rebuildView();
      return view ? response(view) : failed("The rebuild journal does not match both configured server identities.");
    },
  );
  if (rebuild && approvalKey) {
    register("review_pair_rebuild", "Prepare a separate terminal approval for inspecting both Ubuntu disk replacements.",
      rebuildStageInput, change, (ubuntu) => {
        if (rebuildStatus()) return failed("The configured journal already contains a rebuild.");
        return stage("pair-rebuild-review", { ubuntu, approvalKey });
      });
    register("apply_pair_rebuild_review", "Prepare the two Ubuntu disk plans after terminal approval.",
      planInput, change, ({ id }) => apply(id, "pair-rebuild-review"));
    for (const [kind, suffix] of [["pair-rebuild-start", "erase"], ["pair-rebuild-resume", "resume"]]) {
      register("review_pair_rebuild_" + suffix,
        "Prepare a second terminal approval for the exact recorded paired disk operation.",
        z.strictObject({ operation: rebuildOperation }), change, ({ operation }) => {
          const current = currentEraseScope(kind, operation);
          return current
            ? stage(kind, { rebuild: current.scope, approvalKey }, current.review)
            : failed("The requested rebuild operation or phase does not match the configured journal.");
        });
      register("apply_pair_rebuild_" + suffix,
        "Use the terminal-approved archive and recorded disk job IDs to run the paired rebuild.",
        planInput, change, ({ id }) => apply(id, kind));
    }
  }
  register(
    "review_pair_export",
    "Prepare a private export of an installed Double VPN client profile for terminal approval.",
    z.strictObject({ login: loginSchema.optional() }),
    change,
    ({ login }) => stage("pair-export", login ? { login } : {}),
  );
  register(
    "review_pair_account",
    "Prepare a grant or revocation tied to the current Double VPN account roster.",
    accountInput,
    change,
    (account) => stage("pair-account", { account }),
  );
  for (const [suffix, kind, description] of [
    ["remove", "pair-remove", "the owned, entry-first Double VPN removal"],
    ["backup", "pair-backup", "an encrypted owner recovery export saved locally"],
    ["rehearsal", "pair-rehearse", "a read-only rehearsal of the approved encrypted owner recovery file"],
  ]) {
    register(`review_pair_${suffix}`, `Prepare ${description} for terminal approval.`, noInput, change, () => stage(kind));
    register(`apply_pair_${suffix}`, `Run ${description} after terminal approval.`, planInput, change, ({ id }) => apply(id, kind));
  }
  register(
    "apply_pair_account",
    "Apply the approved, revision-bound Double VPN account change.",
    planInput,
    change,
    ({ id }) => apply(id, "pair-account"),
  );
  register(
    "apply_pair_export",
    "Save the approved Double VPN profile locally and return its path.",
    planInput,
    change,
    ({ id }) => apply(id, "pair-export"),
  );
  register(
    "cancel_review",
    "Discard the pending Double VPN review without contacting the servers.",
    planInput,
    change,
    ({ id }) => {
      if (pending?.id !== id) return failed("There is no matching review.");
      pending = undefined;
      return response({ state: "cancelled" });
    },
  );
  return server;
}
