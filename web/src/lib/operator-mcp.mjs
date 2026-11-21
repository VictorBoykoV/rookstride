import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  filterPresets,
  readServerRecord,
  readUbuntuRecovery,
  singleProtocolCatalog,
  ubuntuEraseConfirmation,
  ubuntuVersions,
  validLogin,
  validVpnPassword,
} from "./gateway-input.mjs";
import { isGatewayError } from "./gateway-service.mjs";

const methods = {
  ikev2: { name: "IKEv2", transport: "udp", extension: "sswan" },
  ...singleProtocolCatalog,
};
const methodSchema = z.enum(Object.keys(methods));
const idSchema = z.string().uuid();
const loginSchema = z.string().min(1).max(64).refine(validLogin);
const loginChange = (kind) =>
  z.strictObject({ kind: z.literal(kind), login: loginSchema });
const emptyInput = z.strictObject({});
const changeSchema = z.discriminatedUnion("kind", [
  loginChange("grant"),
  loginChange("revoke"),
  loginChange("rotate"),
  loginChange("export"),
  z.strictObject({ kind: z.literal("filter"), level: z.enum(filterPresets) }),
  z.strictObject({
    kind: z.literal("filter-protection"),
    enabled: z.boolean(),
  }),
  z.strictObject({ kind: z.literal("remove") }),
]);
const installSchema = z.strictObject({
  method: methodSchema,
  login: loginSchema,
});
const installPlan = installSchema.extend({
  kind: z.literal("install"),
  port: z.number().int().min(1).max(65535),
});
const ubuntuInput = z.strictObject({ ubuntu: z.enum(ubuntuVersions) });
const ubuntuPlan = ubuntuInput.extend({
  kind: z.literal("reinstall"),
  diskBytes: z
    .number()
    .int()
    .min(6 * 1024 ** 3),
  boot: z.enum(["EFI", "BIOS"]),
  replacementFingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/),
});
export const operatorPlanSchema = z.strictObject({
  id: idSchema,
  address: z.ipv4(),
  sshPort: z.number().int().min(1).max(65535),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/),
  keyType: z.literal("ecdsa-sha2-nistp256").optional(),
  expiresAt: z.number().int(),
  operation: z.union([installPlan, changeSchema, ubuntuPlan]),
  needsPassword: z.boolean(),
});

const busyStates = [
  "running",
  "removing",
  "protocolRunning",
  "ubuntuReinstalling",
];

function response(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data,
  };
}

function failed(message) {
  return { isError: true, content: [{ type: "text", text: message }] };
}

function status(report) {
  return {
    state: report.state,
    os: report.os,
    method:
      report.method ?? (report.state === "installed" ? "ikev2" : undefined),
    messageKey: report.messageKey,
  };
}

export function describeOperation(operation) {
  const { kind, login, method, port, level } = operation;
  switch (kind) {
    case "install":
      return `Install ${methods[method].name} for ${login} on ${method === "ikev2" ? "UDP 500 and 4500" : methods[method].transport.toUpperCase() + " " + port}.`;
    case "grant":
      return `Create VPN account ${login}.`;
    case "revoke":
      return `Revoke VPN access for ${login}.`;
    case "rotate":
      return `Replace the VPN password for ${login}.`;
    case "export":
      return `Save a private VPN profile for ${login} on this computer.`;
    case "filter":
      return `Apply the ${level} DNS filter preset to VPNs using this server’s filter.`;
    case "filter-protection":
      return `${operation.enabled ? "Resume" : "Pause"} ad blocking for VPNs using this server’s filter.`;
    case "remove":
      return "Remove this Rookstride VPN and its managed components.";
    case "reinstall":
      return `Erase the ${(operation.diskBytes / 1024 ** 3).toFixed(2)} GiB system disk and install Ubuntu ${operation.ubuntu} (${operation.boot}).\nReplacement ECDSA SSH fingerprint: ${operation.replacementFingerprint}`;
  }
}

export function createOperatorMcp(service, target, approvals, ubuntu) {
  const server = new McpServer({
    name: "rookstride-operator",
    version: "0.2.0",
  });
  const applied = new Map();
  let session;
  let pending;
  let activeAttempt;
  let working = false;
  let rebuilding = ubuntu?.initial;
  let lastReinstall;

  const readOnly = { readOnlyHint: true, openWorldHint: false };
  const change = { destructiveHint: true, openWorldHint: false };
  const safe = (run) => async (input) => {
    try {
      return await run(input);
    } catch (error) {
      return failed(
        isGatewayError(error)
          ? error.message
          : "Rookstride could not confirm this operation. Check the pinned gateway and read its current state before retrying.",
      );
    }
  };
  function register(name, description, inputSchema, annotations, run) {
    server.registerTool(
      name,
      { description, inputSchema, annotations },
      safe(run),
    );
  }
  const send = (action, input = {}) =>
    service.post({ action, ...input }, session);
  function observe(report) {
    if (!activeAttempt) return report;
    const attempt = applied.get(activeAttempt);
    attempt.reply = response(status(report));
    if (!busyStates.includes(report.state)) activeAttempt = undefined;
    return report;
  }
  const current = () => observe(service.get(session));
  async function progress() {
    const report = current();
    return report.state === "protocolRunning"
      ? observe(await send("protocolStatus"))
      : report;
  }

  async function exclusive(run) {
    if (working) return failed("Another gateway request is running.");
    working = true;
    try {
      return await run();
    } finally {
      working = false;
    }
  }

  async function roster(protocol) {
    const result = await send(protocol ? "protocolUsers" : "guests");
    return protocol
      ? result
      : {
          owner: result.owner,
          users: [result.owner, ...result.guests],
          revision: result.revision,
        };
  }

  async function stage(operation, request, needsPassword, expiresAt, recovery) {
    const { address, sshPort, fingerprint, keyType } = target;
    const id = randomUUID();
    const receipt = await approvals.stage({
      id,
      address,
      sshPort,
      fingerprint,
      keyType,
      expiresAt,
      operation,
      needsPassword,
    });
    pending = {
      id,
      operation,
      receipt,
      request,
      needsPassword,
      expiresAt,
      recovery,
    };
    const { replacementFingerprint, ...summary } = operation;
    return response({
      id,
      ...summary,
      expiresAt,
      approvalFile: receipt.path,
      needsPassword,
    });
  }

  function review(proposal) {
    return exclusive(async () => {
      if (rebuilding) return failed("Check the outstanding Ubuntu job first.");
      if (!session) return failed("Inspect the gateway first.");
      if (pending && Date.now() < pending.expiresAt)
        return failed("Approve or cancel the outstanding review first.");
      pending = undefined;
      const expiresAt = Date.now() + 5 * 60_000;
      const report = current();
      const { kind, login, method, level } = proposal;
      const protocol = report.state === "protocolInstalled";
      if (kind === "install") {
        if (
          report.state !== "ready" &&
          !(report.state === "removed" && method !== "ikev2")
        )
          return failed(
            "Inspect a fresh gateway before reviewing installation.",
          );
        if (method === "ikev2")
          return stage(
            { ...proposal, port: 500 },
            { action: "install", login, confirmed: true },
            true,
            expiresAt,
          );
        const { review, port } = await send("protocolReview", {
          method,
          login,
        });
        return stage(
          { ...proposal, port },
          { action: "protocolApply", review, confirmed: true },
          false,
          expiresAt,
        );
      }
      if (!protocol && report.state !== "installed")
        return failed("A verified VPN installation is required.");
      if (kind === "remove") {
        const { review } = await send("removeReview");
        return stage(
          proposal,
          { action: "removeApply", review, confirmation: "DELETE VPN" },
          false,
          expiresAt,
        );
      }
      if (kind === "filter") {
        return stage(
          proposal,
          {
            action: protocol ? "protocolFilter" : "filter",
            level,
            confirmed: true,
          },
          false,
          expiresAt,
        );
      }
      if (kind === "filter-protection") {
        if (!protocol)
          return failed(
            "Pause and resume are available for standalone VPNs with a private DNS filter.",
          );
        return stage(
          proposal,
          {
            action: "protocolFilter",
            enabled: proposal.enabled,
            confirmed: true,
          },
          false,
          expiresAt,
        );
      }
      if (kind === "rotate" && protocol)
        return failed(
          "Password rotation is available for IKEv2 guest accounts.",
        );
      const accounts = await roster(protocol);
      const exists = accounts.users.includes(login);
      if (
        kind === "grant"
          ? exists
          : !exists || (kind !== "export" && login === accounts.owner)
      )
        return failed("This action is unavailable for the selected account.");
      if (kind === "export")
        return stage(
          proposal,
          { action: protocol ? "protocolProfile" : "profile", login },
          false,
          expiresAt,
        );
      const action = protocol
        ? kind === "grant"
          ? "protocolGrant"
          : "protocolRevoke"
        : kind;
      return stage(
        proposal,
        {
          action,
          login,
          revision: accounts.revision,
          ...(kind !== "grant" && { confirmed: true }),
        },
        !protocol && (kind === "grant" || kind === "rotate"),
        expiresAt,
      );
    });
  }

  async function reviewUbuntu({ ubuntu: version }) {
    return exclusive(async () => {
      if (rebuilding) return failed("Check the outstanding Ubuntu job first.");
      if (!session) return failed("Inspect the gateway first.");
      if (pending && Date.now() < pending.expiresAt)
        return failed("Approve or cancel the outstanding review first.");
      pending = undefined;
      const expiresAt = Date.now() + 5 * 60_000;
      current();
      const planned = await send("ubuntuReview", { ubuntu: version });
      const recovery = readUbuntuRecovery(planned.recovery);
      if (
        !recovery ||
        recovery.server.address !== target.address ||
        recovery.server.sshPort !== target.sshPort ||
        recovery.server.fingerprint !== target.fingerprint ||
        recovery.server.keyType !== target.keyType ||
        recovery.ubuntu !== version
      )
        return failed("The reinstall plan did not match the pinned server.");
      const operation = ubuntuPlan.parse({
        kind: "reinstall",
        ubuntu: version,
        diskBytes: planned.diskBytes,
        boot: planned.boot,
        replacementFingerprint: recovery.fingerprint,
      });
      return stage(
        operation,
        {
          action: "ubuntuApply",
          review: planned.review,
          confirmation: ubuntuEraseConfirmation,
        },
        false,
        expiresAt,
        recovery,
      );
    });
  }

  async function checkUbuntu() {
    return exclusive(async () => {
      if (!rebuilding)
        return lastReinstall ?? failed("No Ubuntu recovery record is open.");
      const { recovery, file: recoveryFile } = rebuilding;
      const result = await service.post({
        action: "ubuntuResume",
        recovery,
        password: target.password,
      });
      const data = { state: result.state, recoveryFile };
      if (result.state === "complete") {
        const server = readServerRecord(result.server);
        if (
          !server ||
          server.version !== 2 ||
          server.address !== target.address ||
          server.sshPort !== target.sshPort ||
          server.fingerprint !== recovery.fingerprint ||
          result.ubuntu !== recovery.ubuntu
        )
          return failed(
            "The returned Ubuntu release or SSH key did not match the saved recovery.",
          );
        data.ubuntu = result.ubuntu;
        data.serverFile = await approvals.saveProfile(
          "rookstride-server.json",
          JSON.stringify(server, null, 2) + "\n",
        );
        target = {
          address: server.address,
          sshPort: server.sshPort,
          fingerprint: server.fingerprint,
          keyType: server.keyType,
          password: target.password,
        };
      }
      if (
        ["complete", "failed", "cancelled", "expired"].includes(result.state)
      ) {
        session = undefined;
        rebuilding = undefined;
        activeAttempt = undefined;
        lastReinstall = response(data);
      }
      return response(data);
    });
  }

  async function apply(id, install) {
    return exclusive(async () => {
      const previous = applied.get(id);
      if (previous) {
        if (previous.install !== install)
          return failed("Use the apply tool for the original operation.");
        if (id === activeAttempt) await progress();
        return previous.reply;
      }
      const plan = pending;
      if (
        !plan ||
        plan.id !== id ||
        (plan.operation.kind === "install") !== install ||
        Date.now() >= plan.expiresAt
      )
        return failed("Prepare a current review for this operation first.");
      const approval = await approvals.consume(plan.receipt);
      if (!approval)
        return failed(
          "The operator must approve this review in a separate terminal.",
        );
      if (
        Date.now() >= plan.expiresAt ||
        (plan.needsPassword && !validVpnPassword(approval.vpnPassword))
      )
        return failed("The review expired or its private approval is invalid.");
      pending = undefined;
      if (applied.size === 128) applied.delete(applied.keys().next().value);
      applied.set(id, {
        install,
        reply: failed(
          "This request was already sent. Check the gateway state before making another change.",
        ),
      });
      if (plan.recovery) {
        const file = await ubuntu.saveRecovery(plan.recovery);
        rebuilding = { recovery: plan.recovery, file };
      }
      const result = await service.post(
        {
          ...plan.request,
          ...(plan.needsPassword && { vpnPassword: approval.vpnPassword }),
        },
        session,
      );
      let data;
      if (plan.recovery) {
        data = { state: result.state, recoveryFile: rebuilding.file };
      } else if (plan.operation.kind === "export") {
        const { login } = plan.operation;
        const filename = result.filename ?? `rookstride-${login}.sswan`;
        const contents = result.profile
          ? JSON.stringify(result.profile)
          : result.configuration + "\n";
        data = {
          file: await approvals.saveProfile(filename, contents),
          filename,
        };
      } else {
        data = "state" in result ? status(result) : result;
      }
      const reply = response(data);
      applied.set(id, { install, reply });
      if (!plan.recovery && busyStates.includes(result.state))
        activeAttempt = id;
      return reply;
    });
  }

  register(
    "list_methods",
    "List the single-server VPN methods and their client export formats.",
    emptyInput,
    readOnly,
    () =>
      response({
        methods: Object.entries(methods).map(([id, info]) => ({ id, ...info })),
      }),
  );
  register(
    "inspect_gateway",
    "Inspect the operator-configured VPS over pinned SSH. Returns readiness and OS details.",
    emptyInput,
    readOnly,
    () =>
      exclusive(async () => {
        if (rebuilding)
          return failed("Use reinstall_status to check the saved Ubuntu job.");
        if (session) {
          try {
            return response(status(current()));
          } catch (error) {
            if (!isGatewayError(error) || error.messageKey !== "sessionEnded")
              throw error;
            session = undefined;
            pending = undefined;
            activeAttempt = undefined;
          }
        }
        const report = await service.post({ ...target, action: "inspect" });
        session = report.session;
        return response(status(report));
      }),
  );
  register(
    "install_status",
    "Read the pinned gateway or its current installation and removal progress.",
    emptyInput,
    readOnly,
    () =>
      exclusive(async () => {
        if (!session) return failed("Inspect the gateway first.");
        return response(status(await progress()));
      }),
  );
  register(
    "review_install",
    "Prepare an installation review for any of the ten single-server VPN methods. Requires terminal approval.",
    installSchema,
    change,
    (input) => review({ ...input, kind: "install" }),
  );
  register(
    "apply_install",
    "Apply a terminal-approved installation once.",
    z.strictObject({ id: idSchema }),
    change,
    ({ id }) => apply(id, true),
  );
  register(
    "read_gateway",
    "Read VPN accounts, service health for IKEv2, scoped traffic estimates, DNS settings, or Ubuntu reinstall eligibility.",
    z.strictObject({
      section: z.enum(["accounts", "health", "usage", "dns", "ubuntu"]),
    }),
    readOnly,
    ({ section }) =>
      exclusive(async () => {
        if (!session) return failed("Inspect the gateway first.");
        const protocol = current().state === "protocolInstalled";
        if (section === "accounts") return response(await roster(protocol));
        const actions = {
          health: "health",
          usage: protocol ? "protocolUsage" : "usage",
          dns: protocol ? "protocolFilter" : "filter",
          ubuntu: "ubuntuCheck",
        };
        return response(await send(actions[section]));
      }),
  );
  register(
    "review_change",
    "Review an account change, private profile export, DNS filter preset, ad blocking pause or resume for a supported VPN, or managed VPN removal.",
    z.strictObject({ operation: changeSchema }),
    change,
    ({ operation }) => review(operation),
  );
  register(
    "apply_change",
    "Apply the exact maintenance or export operation approved in a separate terminal.",
    z.strictObject({ id: idSchema }),
    change,
    ({ id }) => apply(id, false),
  );
  register(
    "cancel_review",
    "Discard the pending review without contacting the VPS.",
    z.strictObject({ id: idSchema }),
    change,
    ({ id }) =>
      exclusive(() => {
        if (pending?.id !== id) return failed("There is no matching review.");
        pending = undefined;
        return response({ state: "cancelled" });
      }),
  );
  if (ubuntu) {
    register(
      "review_ubuntu_reinstall",
      "Review erasing the pinned server and installing Ubuntu. The terminal displays the disk and planned replacement key.",
      ubuntuInput,
      change,
      reviewUbuntu,
    );
    register(
      "reinstall_status",
      "Read the saved Ubuntu job over pinned SSH. Save the verified replacement server record after completion.",
      emptyInput,
      readOnly,
      checkUbuntu,
    );
  }
  register(
    "close_gateway",
    "Close the local session after any job completes. Inspect again for a fresh session.",
    emptyInput,
    change,
    () =>
      exclusive(async () => {
        if (rebuilding)
          return failed("Use reinstall_status to check the saved Ubuntu job.");
        if (session) {
          if (busyStates.includes(current().state))
            return failed("Wait for the current job to finish.");
          await send("close");
        }
        session = undefined;
        pending = undefined;
        return response({ state: "closed" });
      }),
  );
  return server;
}
