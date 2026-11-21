"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { useMessages } from "@/i18n/client";
import { formatMessage } from "@/i18n/format";
import { isMixedPairExit, pairExitPorts } from "@/lib/gateway-input.mjs";
import {
  archiveCodeLimit,
  encodeArchive,
  isCanonicalArchiveCode,
  isRecoveryFile,
} from "./pair-management";
import styles from "./server-setup.module.css";

export const rebuildOperation = /^[a-f0-9]{32}$/;
const rebuildConfirmation = "REBUILD BOTH SERVERS AND RESTORE DOUBLE VPN";
const ubuntuVersions = ["22.04", "24.04", "26.04"] as const;
const roles = ["entry", "exit"] as const;
const rebuildStates = [
  "idle",
  "reviewed",
  "rebuilding",
  "needsAttention",
  "restored",
] as const;

export type RebuildState = (typeof rebuildStates)[number];
type RebuildRequest = { action: string; [key: string]: unknown };
type MemberReview = {
  ubuntu: string;
  boot: "BIOS" | "EFI";
  diskBytes: number;
  fingerprint: string;
};
type Review = Record<(typeof roles)[number], MemberReview>;
type MixedExit = Exclude<keyof typeof pairExitPorts, "awg">;
type RebuildStatus = {
  state: RebuildState;
  operation?: string;
  review?: Review;
  role?: (typeof roles)[number];
  nodeState?: string;
  stage?: string;
  reason?: string;
  exitProtocol?: MixedExit;
};

type Props = {
  installed: boolean;
  installedExitProtocol?: MixedExit;
  hasSession: boolean;
  busy: boolean;
  reconnectEpoch: number;
  post: (body: RebuildRequest, signal: AbortSignal) => Promise<Response>;
  run: (work: (signal: AbortSignal) => Promise<void>, fallback: string) => void;
  onState: (state: RebuildState) => void;
  reconnect: (operation: string) => void;
  finish: () => void;
};

function exitProtocol(value: unknown): MixedExit | undefined {
  if (value === undefined || isMixedPairExit(value)) return value;
  throw new Error("rebuild exit protocol");
}

function readReview(value: unknown): Review | undefined {
  if (!value || typeof value !== "object") return;
  const review = value as Partial<Review>;
  if (
    !roles.every((role) => {
      const row = review[role];
      return (
        row &&
        ubuntuVersions.some((version) => version === row.ubuntu) &&
        (row.boot === "BIOS" || row.boot === "EFI") &&
        Number.isSafeInteger(row.diskBytes) &&
        row.diskBytes > 0 &&
        typeof row.fingerprint === "string" &&
        /^SHA256:[A-Za-z0-9+/]{43}$/.test(row.fingerprint)
      );
    })
  )
    return;
  return { entry: review.entry!, exit: review.exit! };
}

async function statusFrom(response: Response): Promise<RebuildStatus> {
  if (!response.ok) throw new Error("rebuild status");
  const result = await response.json();
  const state = rebuildStates.find((value) => value === result?.state);
  if (state === "idle") return { state };
  if (
    !state ||
    typeof result.operation !== "string" ||
    !rebuildOperation.test(result.operation)
  )
    throw new Error("rebuild status");
  const review = readReview(result);
  const role = roles.find((value) => value === result.progress?.role);
  return {
    state,
    exitProtocol: exitProtocol(result.exitProtocol),
    operation: result.operation,
    review,
    role,
    nodeState:
      typeof result.progress?.state === "string"
        ? result.progress.state
        : undefined,
    stage:
      typeof result.progress?.stage === "string"
        ? result.progress.stage
        : undefined,
    reason: typeof result.reason === "string" ? result.reason : undefined,
  };
}

async function archiveFrom(data: FormData) {
  const file = data.get("rebuildArchive");
  if (isRecoveryFile(file)) return encodeArchive(file);
  const code = String(data.get("rebuildArchiveCode") ?? "").trim();
  if (isCanonicalArchiveCode(code)) return code;
  throw new Error("rebuild archive");
}

function canReadArchive(data: FormData) {
  return (
    isRecoveryFile(data.get("rebuildArchive")) ||
    isCanonicalArchiveCode(String(data.get("rebuildArchiveCode") ?? "").trim())
  );
}

export function PairRebuild({
  installed,
  installedExitProtocol,
  hasSession,
  busy,
  reconnectEpoch,
  post,
  run,
  onState,
  reconnect,
  finish,
}: Props) {
  const copy = useMessages("manage");
  const text = copy.pair.rebuild;
  const [status, setStatus] = useState<RebuildStatus>({ state: "idle" });
  const [startable, setStartable] = useState(false);
  const [statusIssue, setStatusIssue] = useState(false);
  const [note, setNote] = useState("");
  const [source, setSource] = useState<"file" | "code">("file");
  const verifiedRoute = useRef<{
    operation: string;
    exitProtocol?: MixedExit;
  } | null>(null);
  const currentOperation = status.operation;

  const record = useCallback(
    (next: RebuildStatus) => {
      const prior = verifiedRoute.current;
      if (
        prior &&
        (!next.operation ||
          next.operation !== prior.operation ||
          (next.review && next.exitProtocol !== prior.exitProtocol))
      )
        throw new Error("rebuild route changed");
      if (next.review && next.operation)
        verifiedRoute.current = {
          operation: next.operation,
          exitProtocol: next.exitProtocol,
        };
      setStatus((current) =>
        next.operation && next.operation === current.operation && !next.review
          ? {
              ...next,
              review: current.review,
              exitProtocol: current.exitProtocol,
            }
          : next,
      );
      setStatusIssue(false);
      onState(next.state);
    },
    [onState],
  );

  function lookup() {
    setNote("");
    run(async (signal) => {
      const result = await statusFrom(
        await post({ action: "pairRebuildStatus" }, signal),
      );
      if (!signal.aborted) record(result);
    }, text.statusUnavailable);
  }

  useEffect(() => {
    if (!reconnectEpoch) return;
    const controller = new AbortController();
    setStartable(false);
    const refresh = async () => {
      try {
        const result = await statusFrom(
          await post({ action: "pairRebuildStatus" }, controller.signal),
        );
        if (controller.signal.aborted) return;
        record(result);
      } catch {
        if (!controller.signal.aborted) setStatusIssue(true);
      }
    };
    void refresh();
    return () => controller.abort();
  }, [reconnectEpoch, post, record]);

  useEffect(() => {
    if (status.state !== "rebuilding") return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const result = await statusFrom(
          await post({ action: "pairRebuildStatus" }, controller.signal),
        );
        if (controller.signal.aborted) return;
        if (result.operation !== currentOperation)
          throw new Error("rebuild operation");
        record(result);
        if (result.state !== "rebuilding") return;
      } catch {
        if (controller.signal.aborted) return;
        setStatusIssue(true);
      }
      timer = setTimeout(refresh, 3000);
    };
    timer = setTimeout(refresh, 2500);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [status.state, currentOperation, post, record]);

  function archiveFields() {
    return (
      <>
        <div
          className="button-row"
          role="group"
          aria-label={copy.pair.management.archiveSource}
        >
          <button
            type="button"
            className="button secondary"
            aria-pressed={source === "file"}
            onClick={() => setSource("file")}
            disabled={busy}
          >
            {copy.pair.management.archiveFileOption}
          </button>
          <button
            type="button"
            className="button secondary"
            aria-pressed={source === "code"}
            onClick={() => setSource("code")}
            disabled={busy}
          >
            {copy.pair.management.archiveCodeOption}
          </button>
        </div>
        {source === "file" ? (
          <label className={styles.archiveDrop}>
            {copy.pair.management.archive}
            <input
              type="file"
              name="rebuildArchive"
              accept=".rookrec,application/octet-stream"
              required
              disabled={busy}
            />
          </label>
        ) : (
          <label className={styles.archiveDrop}>
            {copy.pair.management.archiveCode}
            <textarea
              className={styles.archiveCode}
              name="rebuildArchiveCode"
              maxLength={archiveCodeLimit}
              rows={3}
              wrap="off"
              autoComplete="off"
              spellCheck={false}
              required
              disabled={busy}
            />
          </label>
        )}
        <label>
          {copy.pair.management.password}
          <input
            type="password"
            name="rebuildPassword"
            minLength={12}
            maxLength={256}
            required
            autoComplete="off"
            disabled={busy}
          />
        </label>
      </>
    );
  }

  function confirmationField() {
    return (
      <label>
        {text.confirmationLabel}
        <code dir="ltr">{rebuildConfirmation}</code>
        <input
          name="rebuildConfirmation"
          dir="ltr"
          required
          pattern={rebuildConfirmation}
          maxLength={rebuildConfirmation.length}
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
        />
      </label>
    );
  }

  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !installed || !hasSession || status.state !== "idle") return;
    const data = new FormData(event.currentTarget);
    event.currentTarget.reset();
    const password = data.get("rebuildPassword");
    const entryUbuntu = data.get("entryUbuntu");
    const exitUbuntu = data.get("exitUbuntu");
    if (
      !canReadArchive(data) ||
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 256 ||
      data.get("reviewConfirmed") !== "on" ||
      !ubuntuVersions.some((v) => v === entryUbuntu) ||
      !ubuntuVersions.some((v) => v === exitUbuntu)
    ) {
      setNote(text.archiveRequired);
      return;
    }
    setNote("");
    run(async (signal) => {
      const archive = await archiveFrom(data);
      if (signal.aborted) return;
      const response = await post(
        {
          action: "pairRebuildReview",
          archive,
          password,
          confirmed: true,
          entryUbuntu,
          exitUbuntu,
        },
        signal,
      );
      if (!response.ok) throw new Error("rebuild review");
      const payload = await response.json();
      const checked = readReview(payload);
      if (
        !checked ||
        typeof payload.operation !== "string" ||
        !rebuildOperation.test(payload.operation) ||
        checked.entry.ubuntu !== entryUbuntu ||
        checked.exit.ubuntu !== exitUbuntu ||
        exitProtocol(payload.exitProtocol) !== installedExitProtocol
      )
        throw new Error("rebuild review");
      if (signal.aborted) return;
      setStartable(true);
      record({
        state: "reviewed",
        operation: payload.operation,
        review: checked,
        exitProtocol: installedExitProtocol,
      });
    }, text.reviewUnavailable);
  }

  function change(event: FormEvent<HTMLFormElement>, resume: boolean) {
    event.preventDefault();
    if (
      busy ||
      !hasSession ||
      statusIssue ||
      !currentOperation ||
      !status.review ||
      (resume
        ? !["reviewed", "needsAttention"].includes(status.state)
        : !(status.state === "reviewed" && startable))
    )
      return;
    const data = new FormData(event.currentTarget);
    event.currentTarget.reset();
    const confirmation = data.get("rebuildConfirmation");
    const password = data.get("rebuildPassword");
    if (confirmation !== rebuildConfirmation) return;
    if (
      resume &&
      (!canReadArchive(data) ||
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 256)
    ) {
      setNote(text.archiveRequired);
      return;
    }
    setStartable(false);
    setNote("");
    run(async (signal) => {
      const body: RebuildRequest = {
        action: resume ? "pairRebuildResume" : "pairRebuildStart",
        operation: currentOperation,
        confirmation,
      };
      if (resume) {
        body.archive = await archiveFrom(data);
        body.password = password;
      }
      if (signal.aborted) return;
      try {
        const result = await statusFrom(await post(body, signal));
        if (result.operation !== currentOperation)
          throw new Error("rebuild operation");
        if (!signal.aborted) record(result);
      } catch {
        if (signal.aborted) return;
        setStatusIssue(true);
        setNote(text.dispatchUnconfirmed);
        const result = await statusFrom(
          await post({ action: "pairRebuildStatus" }, signal),
        );
        if (result.operation !== currentOperation)
          throw new Error("rebuild operation");
        if (!signal.aborted) record(result);
      }
    }, text.statusUnavailable);
  }

  const resuming =
    hasSession && (!startable || status.state === "needsAttention");
  const reviewing = hasSession && status.state === "reviewed" && startable;
  const canContinue =
    !statusIssue &&
    status.review &&
    ((resuming && ["reviewed", "needsAttention"].includes(status.state)) ||
      reviewing);
  const nodeState = status.nodeState as
    keyof typeof text.nodeStates | undefined;
  const stage = status.stage as keyof typeof text.restoreStages | undefined;
  const reason = status.reason as keyof typeof text.blockers | undefined;
  return (
    <details
      className={styles.pairManagementPanel}
      open={status.state !== "idle" || undefined}
    >
      <summary>{text.heading}</summary>
      <p>
        {installed && status.state === "idle" ? text.intro : text.lookupIntro}
      </p>
      <button
        className="button secondary"
        type="button"
        onClick={lookup}
        disabled={busy}
      >
        {text.status}
      </button>
      {status.state !== "idle" && (
        <section className={styles.rebuildReceipt} aria-label={text.receipt}>
          <h4>{text.receipt}</h4>
          <div>
            {text.jobId} <code dir="ltr">{currentOperation}</code>
          </div>
          <p role="status">
            {text.states[status.state]}{" "}
            {status.state === "rebuilding" && status.role
              ? copy.pair[status.role]
              : ""}
            {status.state === "rebuilding" &&
              nodeState &&
              Object.hasOwn(text.nodeStates, nodeState) &&
              ` · ${text.nodeStates[nodeState]}`}
            {status.state === "rebuilding" &&
              stage &&
              Object.hasOwn(text.restoreStages, stage) &&
              ` ${text.restoreStages[stage]}`}
            {status.state === "needsAttention" &&
              reason &&
              Object.hasOwn(text.blockers, reason) &&
              ` ${text.blockers[reason]}`}
          </p>
          {status.review && (
            <>
              <p>{text.savePins}</p>
              <div className={styles.rebuildRows}>
                {roles.map((role) => {
                  const member = status.review![role];
                  return (
                    <section key={role}>
                      <h4>{copy.pair[role]}</h4>
                      <dl>
                        <dt>{text.targetUbuntu}</dt>
                        <dd>{member.ubuntu}</dd>
                        <dt>{text.boot}</dt>
                        <dd>{member.boot}</dd>
                        <dt>{text.disk}</dt>
                        <dd>
                          {formatMessage(text.diskSize, {
                            size: new Intl.NumberFormat("en", {
                              maximumFractionDigits: 1,
                            }).format(member.diskBytes / 2 ** 30),
                          })}
                        </dd>
                        <dt>{text.replacementPin}</dt>
                        <dd>
                          <code className={styles.fingerprint} dir="ltr">
                            {member.fingerprint}
                          </code>
                        </dd>
                        <dt>{text.protocol}</dt>
                        <dd>
                          {
                            copy.pair.protocols[
                              role === "exit"
                                ? (status.exitProtocol ?? "awg")
                                : "awg"
                            ]
                          }
                        </dd>
                      </dl>
                    </section>
                  );
                })}
              </div>
            </>
          )}
          {statusIssue && <p role="status">{text.statusUnavailable}</p>}
          {!hasSession &&
            currentOperation &&
            ["reviewed", "needsAttention"].includes(status.state) && (
              <button
                className="button secondary"
                type="button"
                onClick={() => reconnect(currentOperation)}
                disabled={busy}
              >
                {text.reconnect}
              </button>
            )}
          {canContinue && (
            <form
              method="post"
              onSubmit={(event) => change(event, resuming)}
              autoComplete="off"
            >
              <p>{resuming ? text.resumeIntro : text.erase}</p>
              {resuming && archiveFields()}
              {confirmationField()}
              <button className="button primary" type="submit" disabled={busy}>
                {resuming ? text.resume : text.start}
              </button>
            </form>
          )}
          {status.state === "restored" && (
            <button
              className="button secondary"
              type="button"
              onClick={finish}
              disabled={busy}
            >
              {text.finish}
            </button>
          )}
        </section>
      )}
      {installed && hasSession && status.state === "idle" && (
        <form method="post" onSubmit={review} autoComplete="off">
          <fieldset disabled={busy}>
            <legend>{text.chooseUbuntu}</legend>
            {roles.map((role) => (
              <label key={role}>
                {copy.pair[role]}
                <select name={role + "Ubuntu"} defaultValue="" required>
                  <option value="" disabled>
                    {text.selectUbuntu}
                  </option>
                  {ubuntuVersions.map((version) => (
                    <option key={version} value={version}>
                      {formatMessage(copy.ubuntu.version, { version })}
                    </option>
                  ))}
                </select>
              </label>
            ))}
          </fieldset>
          {archiveFields()}
          <label className={styles.check}>
            <input
              name="reviewConfirmed"
              type="checkbox"
              required
              disabled={busy}
            />
            {text.reviewConfirm}
          </label>
          <button className="button secondary" type="submit" disabled={busy}>
            {text.review}
          </button>
        </form>
      )}
      {note && (
        <p className={styles.notice} role="status">
          {note}
        </p>
      )}
    </details>
  );
}
