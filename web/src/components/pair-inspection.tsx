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
import { hostedPairExits, isMixedPairEntry, isMixedPairExit, pairExitPorts, pairProfileExtension, validVpnPassword } from "@/lib/gateway-input.mjs";
import { gatewayMessage } from "@/lib/gateway-messages";
import { PairManagement, pairLogin, savePairFile } from "./pair-management";
import {
  PairRebuild,
  rebuildOperation,
  type RebuildState,
} from "./pair-rebuild";
import { ServerConnectionFields } from "./server-connection-fields";
import styles from "./server-setup.module.css";

const roles = ["entry", "exit"] as const;
type NodeState =
  "ready" | "occupied" | "unsupported" | "unavailable" | "identityMismatch";
type Inspection = Record<
  (typeof roles)[number],
  { state: NodeState; os?: string }
>;
type PairReview = Record<
  (typeof roles)[number],
  { address: string; os: string }
> & {
  login: string;
  entryProtocol?: Exclude<keyof typeof pairExitPorts, "awg">;
  exitProtocol?: Exclude<keyof typeof pairExitPorts, "awg">;
};
type Progress = {
  state:
    | "reviewed"
    | "installing"
    | "installed"
    | "removing"
    | "removed"
    | "needsAttention"
    | "unavailable"
    | "expired";
  stage?: string;
};

function postPair(
  invite: string | undefined,
  body: { action: string },
  session?: string,
  signal?: AbortSignal,
) {
  return fetch(invite ? "/vpn/api" : "/api/gateway", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(["pairRehearse", "pairRebuildReview", "pairRebuildResume"].includes(
        body.action,
      ) && { "X-Rookstride-Recovery": "1" }),
      ...(invite && { "X-Rookstride-Invite": invite }),
      ...(session && { Authorization: `Bearer ${session}` }),
    },
    body: JSON.stringify(body),
    cache: "no-store",
    signal,
  });
}

async function pairProgress(response: Response): Promise<Progress> {
  if (response.status === 401) return { state: "expired" };
  if (!response.ok) return { state: "unavailable" };
  const result = await response.json().catch(() => null);
  switch (result?.state) {
    case "reviewed":
    case "installed":
    case "removed":
    case "needsAttention":
      return { state: result.state };
    case "installing":
    case "removing":
      return {
        state: result.state,
        stage: typeof result.stage === "string" ? result.stage : undefined,
      };
    default:
      return { state: "unavailable" };
  }
}

async function checkProgress(
  invite: string | undefined,
  session: string,
  signal: AbortSignal,
) {
  const response = await postPair(
    invite,
    { action: "pairStatus" },
    session,
    signal,
  );
  return pairProgress(response);
}

export function PairInspection({
  invite,
  pairRebuild = false,
  pairExitChoices = false,
}: {
  invite?: string;
  pairRebuild?: boolean;
  pairExitChoices?: boolean;
}) {
  const copy = useMessages("manage");
  const text = copy.pair;
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState<
    | "inspect"
    | "review"
    | "adopt"
    | "apply"
    | "status"
    | "profile"
    | "manage"
    | "rebuild"
    | "remove"
    | "close"
    | null
  >(null);
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [notice, setNotice] = useState("");
  const [session, setSession] = useState("");
  const [review, setReview] = useState<PairReview | null>(null);
  const [progress, setProgress] = useState<Progress>({ state: "reviewed" });
  const [rebuildState, setRebuildState] = useState<RebuildState>("idle");
  const [reconnecting, setReconnecting] = useState("");
  const [reconnectEpoch, setReconnectEpoch] = useState(0);
  const [rebuildView, resetRebuildView] = useState(0);
  const rebuildActive = rebuildState !== "idle";
  const canChooseExit = !invite || pairExitChoices || pairRebuild;
  const request = useRef<AbortController | null>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    setReady(true);
    return () => request.current?.abort();
  }, []);
  useEffect(() => {
    if (review) reviewHeading.current?.focus();
  }, [review]);

  useEffect(() => {
    if (!session || !["installing", "removing"].includes(progress.state))
      return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      const update = await checkProgress(
        invite,
        session,
        controller.signal,
      ).catch((): Progress => ({ state: "unavailable" }));
      if (controller.signal.aborted) return;
      setProgress(update);
      if (update.state === progress.state) timer = setTimeout(poll, 2000);
    }
    timer = setTimeout(poll, 2000);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [invite, session, progress.state]);

  const postRebuild = useCallback(
    async (body: { action: string }, signal: AbortSignal) => {
      const response = await postPair(invite, body, session, signal);
      if (
        response.status !== 401 ||
        !session ||
        body.action !== "pairRebuildStatus"
      )
        return response;
      const scoped = await postPair(invite, body, undefined, signal);
      if (scoped.ok && !signal.aborted) setSession("");
      return scoped;
    },
    [invite, session],
  );

  async function perform(
    action: NonNullable<typeof busy>,
    work: (signal: AbortSignal) => Promise<void>,
    fallback: string,
  ) {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    setBusy(action);
    setNotice("");
    try {
      await work(controller.signal);
    } catch {
      if (!controller.signal.aborted) setNotice(fallback);
    } finally {
      if (!controller.signal.aborted) setBusy(null);
      request.current = null;
    }
  }

  function check(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || request.current) return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const reconnectingPair = pairRebuild && rebuildOperation.test(reconnecting);
    const adopted =
      !reconnectingPair &&
      submitter instanceof HTMLButtonElement &&
      submitter.value === "adopt";
    const applying =
      !adopted &&
      !reconnectingPair &&
      (Boolean(invite) ||
        (submitter instanceof HTMLButtonElement &&
          submitter.value === "review"));
    const form = event.currentTarget;
    const data = new FormData(form);
    const login = String(data.get("login") ?? "").trim();
    const selectedEntry = data.get("entryProtocol");
    const entryProtocol = !invite && applying && isMixedPairEntry(selectedEntry) ? selectedEntry : undefined;
    const selectedExit = data.get("exitProtocol");
    const exitProtocol = canChooseExit && applying && isMixedPairExit(selectedExit)
      ? selectedExit
      : undefined;
    if (applying && !pairLogin.test(login)) {
      setNotice(text.invalidLogin);
      (form.elements.namedItem("login") as HTMLInputElement).focus();
      return;
    }
    const nodes = Object.fromEntries(
      roles.map((role) => {
        const password = role + "-password";
        const keyType = data.get(role + "-keyType");
        const value = data.get(password);
        (form.elements.namedItem(password) as HTMLInputElement).value = "";
        data.delete(password);
        return [
          role,
          {
            address: String(data.get(role + "-address")).trim(),
            sshPort: Number(data.get(role + "-sshPort")),
            fingerprint: String(data.get(role + "-fingerprint")).trim(),
            ...(keyType === "ecdsa-sha2-nistp256" && { keyType }),
            password: value,
          },
        ];
      }),
    );
    setInspection(null);
    const fallback = reconnectingPair
      ? text.rebuild.reconnectFailed
      : adopted
        ? text.adoptFailed
        : applying
          ? text.reviewFailed
          : text.unreadable;
    void perform(
      reconnectingPair
        ? "rebuild"
        : adopted
          ? "adopt"
          : applying
            ? "review"
            : "inspect",
      async (signal) => {
        const response = await postPair(
          invite,
          {
            action: reconnectingPair
              ? "pairRebuildReconnect"
              : adopted
                ? "pairAdopt"
                : applying
                  ? "pairReview"
                  : "inspectPair",
            ...nodes,
            ...(reconnectingPair && { operation: reconnecting }),
            ...(applying && { login }),
            ...(entryProtocol && { entryProtocol }),
            ...(exitProtocol && { exitProtocol }),
          },
          undefined,
          signal,
        );
        const result = await response.json().catch(() => null);
        if (!response.ok) {
          setNotice(gatewayMessage(copy.gateway, result?.messageKey, fallback));
          return;
        }
        if (reconnectingPair) {
          if (
            result?.operation !== reconnecting ||
            typeof result?.session !== "string" ||
            !/^[A-Za-z0-9_-]{43}$/.test(result.session) ||
            (result.entryProtocol !== undefined && !isMixedPairEntry(result.entryProtocol)) ||
            (result.exitProtocol !== undefined && !isMixedPairExit(result.exitProtocol)) ||
            result.pair?.entryProtocol !== result.entryProtocol ||
            result.pair?.exitProtocol !== result.exitProtocol
          ) {
            setNotice(fallback);
            return;
          }
          setSession(result.session);
          setReconnecting("");
          setReconnectEpoch((current) => current + 1);
          return;
        }
        if (applying || adopted) {
          const state = adopted ? "installed" : "reviewed";
          if (
            result?.state !== state ||
            typeof result.session !== "string" ||
            !/^[A-Za-z0-9_-]{43}$/.test(result.session) ||
            typeof result.pair?.login !== "string" ||
            !pairLogin.test(result.pair.login) ||
            (applying && result.pair.login !== login) ||
            (result.pair.entryProtocol !== undefined && !isMixedPairEntry(result.pair.entryProtocol)) ||
            (result.pair.exitProtocol !== undefined && !isMixedPairExit(result.pair.exitProtocol)) ||
            (applying && (result.pair.entryProtocol !== entryProtocol || result.pair.exitProtocol !== exitProtocol)) ||
            !roles.every(
              (role) =>
                result.pair?.[role]?.address === nodes[role].address &&
                typeof result.pair[role].os === "string",
            )
          ) {
            setNotice(fallback);
            return;
          }
          setSession(result.session);
          setReview(result.pair);
          setProgress({ state });
          return;
        }
        if (
          !roles.every((role) =>
            Object.hasOwn(text.states, result?.[role]?.state ?? ""),
          )
        ) {
          setNotice(fallback);
          return;
        }
        setInspection(result);
      },
      fallback,
    );
  }

  function install(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    if (progress.state !== "reviewed" || data.get("confirmed") !== "on") return;
    const vpnPassword = data.get("vpnPassword");
    if (review?.entryProtocol === "ikev2" && !validVpnPassword(vpnPassword)) {
      setNotice(text.invalidVpnPassword);
      return;
    }
    event.currentTarget.reset();
    changePair("apply", { action: "pairApply", confirmed: true,
      ...(review?.entryProtocol === "ikev2" && { vpnPassword }) });
  }

  function changePair(
    action: "apply" | "remove",
    body: { action: string; [key: string]: unknown },
  ) {
    const fallback =
      action === "apply" ? text.applyFailed : text.management.removeUnconfirmed;
    void perform(
      action,
      async (signal) => {
        const outcome = await postPair(invite, body, session, signal)
          .then(pairProgress)
          .catch((): Progress => ({ state: "unavailable" }));
        const update =
          outcome.state === "unavailable" && !signal.aborted
            ? await checkProgress(invite, session, signal).catch(
                (): Progress => ({
                  state: "unavailable",
                }),
              )
            : outcome;
        if (signal.aborted) return;
        setProgress(update);
        if (
          update.state === "reviewed" ||
          (action === "remove" && update.state === "installed")
        )
          setNotice(fallback);
      },
      fallback,
    );
  }

  function refresh() {
    void perform(
      "status",
      async (signal) => {
        setProgress(await checkProgress(invite, session, signal));
      },
      text.progress.unavailable,
    );
  }

  async function managementRequest(
    body: { action: string },
    signal: AbortSignal,
  ) {
    const response = await postPair(invite, body, session, signal);
    if (response.status === 401 && !signal.aborted)
      setProgress({ state: "expired" });
    return response;
  }

  function download(login?: string) {
    if (!review || progress.state !== "installed") return;
    void perform(
      "profile",
      async (signal) => {
        const response = await managementRequest(
          { action: "pairProfile", ...(login && { login }) },
          signal,
        );
        if (response.status === 401) return;
        if (
          await savePairFile(
            response,
            `rookstride-${login ?? review.login}.${pairProfileExtension(review.entryProtocol)}`,
            signal,
          )
        )
          setNotice(text.downloading);
      },
      text.downloadFailed,
    );
  }

  function close() {
    void perform(
      "close",
      async (signal) => {
        if (progress.state !== "expired") {
          const response = await postPair(
            invite,
            { action: "pairClose" },
            session,
            signal,
          );
          if (!response.ok && response.status !== 401) {
            setNotice(text.closeFailed);
            return;
          }
        }
        setSession("");
        setReview(null);
        setProgress({ state: "reviewed" });
      },
      text.closeFailed,
    );
  }

  function finishRebuild() {
    void perform(
      "close",
      async (signal) => {
        if (session) {
          const response = await postPair(
            invite,
            { action: "pairClose" },
            session,
            signal,
          );
          if (!response.ok && response.status !== 401)
            throw new Error("close rebuild");
        }
        if (signal.aborted) return;
        setSession("");
        setReview(null);
        setProgress({ state: "reviewed" });
        setRebuildState("idle");
        setReconnectEpoch(0);
        resetRebuildView((current) => current + 1);
      },
      text.closeFailed,
    );
  }

  const stage = progress.stage as keyof typeof text.stages | undefined;
  const closeButton = (
    <button
      className="button secondary"
      type="button"
      onClick={close}
      disabled={busy !== null}
    >
      {copy.live.close}
    </button>
  );
  return (
    <section className={styles.workspace} aria-label={text.title}>
      <h2>{text.title}</h2>
      <p>{text.intro}</p>
      {((!review && !rebuildActive) || reconnecting) && (
        <form method="post" onSubmit={check} autoComplete="off">
          {reconnecting && <p>{text.rebuild.reconnectIntro}</p>}
          {roles.map((role) => (
            <fieldset key={role} disabled={!ready || busy !== null}>
              <legend>{text[role]}</legend>
              <ServerConnectionFields prefix={role + "-"} allowEcdsa />
            </fieldset>
          ))}
          {!invite && !reconnecting && (
            <label>
              {text.entryProtocol}
              <select name="entryProtocol" defaultValue="awg" disabled={!ready || busy !== null}>
                {Object.entries(text.protocols).map(([method, label]) => (
                  <option key={method} value={method}>{label}</option>
                ))}
              </select>
            </label>
          )}
          {canChooseExit && !reconnecting && (
            <label>
              {text.exitProtocol}
              <select
                name="exitProtocol"
                defaultValue="awg"
                disabled={!ready || busy !== null}
              >
                {Object.entries(text.protocols).filter(([method]) => !invite || method === "awg" || hostedPairExits.includes(method)).map(([method, label]) => (
                  <option key={method} value={method}>{label}</option>
                ))}
              </select>
              <span>{text.exitProtocolHint}</span>
            </label>
          )}
          {!reconnecting && (
            <label>
              {text.login}
              <input
                name="login"
                maxLength={48}
                autoCapitalize="none"
                spellCheck={false}
                disabled={!ready || busy !== null}
              />
              <span>{text.loginHint}</span>
            </label>
          )}
          <div className="button-row">
            {reconnecting ? (
              <>
                <button
                  className="button primary"
                  type="submit"
                  disabled={!ready || busy !== null}
                >
                  {text.rebuild.reconnectSubmit}
                </button>
                <button
                  className="button secondary"
                  type="button"
                  onClick={() => setReconnecting("")}
                  disabled={busy !== null}
                >
                  {text.management.cancel}
                </button>
              </>
            ) : (
              <>
                {!invite && (
                  <button
                    className="button secondary"
                    type="submit"
                    disabled={!ready || busy !== null}
                  >
                    {busy === "inspect" ? text.checking : text.inspect}
                  </button>
                )}
                <button
                  className="button primary"
                  type="submit"
                  value="review"
                  disabled={!ready || busy !== null}
                >
                  {busy === "review" ? text.checking : text.review}
                </button>
                <button
                  className="button secondary"
                  type="submit"
                  value="adopt"
                  disabled={!ready || busy !== null}
                >
                  {busy === "adopt" ? text.checking : text.adopt}
                </button>
              </>
            )}
          </div>
        </form>
      )}
      {inspection && (
        <section aria-label={text.result} role="status">
          <h3>{text.result}</h3>
          <ul className={styles.plan}>
            {roles.map((role) => (
              <li key={role}>
                <strong>{text[role]}</strong> ·{" "}
                {inspection[role].os && <>{inspection[role].os} · </>}
                {text.states[inspection[role].state]}
              </li>
            ))}
          </ul>
        </section>
      )}
      {review && !rebuildActive && (
        <section
          className={styles.guests}
          aria-label={
            progress.state === "reviewed" ? text.plan : text.pairDetails
          }
        >
          <h3 ref={reviewHeading} tabIndex={-1}>
            {progress.state === "reviewed" ? text.plan : text.pairDetails}
          </h3>
          <ul className={styles.plan}>
            {roles.map((role) => (
              <li key={role}>
                <strong>{text[role]}</strong> ·{" "}
                <bdi>{review[role].address}</bdi> · {review[role].os} ·{" "}
                {
                  text.protocols[
                    role === "exit" ? (review.exitProtocol ?? "awg") : (review.entryProtocol ?? "awg")
                  ]
                }
              </li>
            ))}
            <li>
              <strong>{text.login}</strong> · <bdi>{review.login}</bdi>
            </li>
          </ul>
          {progress.state === "reviewed" && busy !== "apply" && (
            <form onSubmit={install}>
              <p>
                {review.entryProtocol || review.exitProtocol
                  ? formatMessage(text.mixedInstallPlan, { entry: text.protocols[review.entryProtocol ?? "awg"], exit: text.protocols[review.exitProtocol ?? "awg"] })
                  : text.installPlan}
              </p>
              {review.entryProtocol === "ikev2" && (
                <label>
                  {text.vpnPassword}
                  <input type="password" name="vpnPassword" autoComplete="new-password" required maxLength={127} />
                </label>
              )}
              <label className={styles.check}>
                <input
                  type="checkbox"
                  name="confirmed"
                  required
                  disabled={busy !== null}
                />
                {text.confirm}
              </label>
              <div className="button-row">
                <button
                  className="button primary"
                  type="submit"
                  disabled={busy !== null}
                >
                  {text.install}
                </button>
                {closeButton}
              </div>
            </form>
          )}
          {busy === "apply" || busy === "remove" ? (
            <p className={styles.notice} role="status">
              {busy === "remove" ? text.progress.removing : text.starting}
            </p>
          ) : (
            progress.state !== "reviewed" && (
              <p className={styles.notice} role="status">
                {progress.state === "installing" &&
                stage &&
                Object.hasOwn(text.stages, stage)
                  ? stage === "exit-bootstrap" && review.exitProtocol
                    ? formatMessage(text.mixedExitBootstrap, { protocol: text.protocols[review.exitProtocol] })
                    : stage === "entry-bootstrap" && review.entryProtocol
                      ? formatMessage(text.mixedEntryBootstrap, { protocol: text.protocols[review.entryProtocol] })
                      : text.stages[stage]
                  : text.progress[progress.state]}
              </p>
            )
          )}
          {progress.state === "unavailable" && (
            <div className="button-row">
              <button
                className="button secondary"
                type="button"
                onClick={refresh}
                disabled={busy !== null}
              >
                {text.checkStatus}
              </button>
            </div>
          )}
          {(progress.state === "installed" ||
            progress.state === "expired" ||
            progress.state === "removed") && (
            <div className="button-row">
              {progress.state === "installed" && (
                <button
                  className="button primary"
                  type="button"
                  onClick={() => download()}
                  disabled={busy !== null}
                >
                  {review.entryProtocol ? text.downloadProfile : text.download}
                </button>
              )}
              {closeButton}
            </div>
          )}
        </section>
      )}
      {review && progress.state === "installed" && !rebuildActive && (
        <PairManagement
          owner={review.login}
          passwordForGuest={review.entryProtocol === "ikev2"}
          busy={busy !== null}
          post={managementRequest}
          run={(work, fallback) => void perform("manage", work, fallback)}
          download={download}
          remove={(token, confirmation) =>
            changePair("remove", {
              action: "pairRemoveApply",
              review: token,
              confirmation,
            })
          }
          notify={setNotice}
        />
      )}
      {invite &&
        pairRebuild &&
        (!review || progress.state === "installed" || rebuildActive) && (
          <PairRebuild
            key={rebuildView}
            installed={Boolean(review && progress.state === "installed")}
            installedEntryProtocol={review?.entryProtocol}
            installedExitProtocol={review?.exitProtocol}
            hasSession={Boolean(session)}
            busy={busy !== null || Boolean(reconnecting)}
            reconnectEpoch={reconnectEpoch}
            post={postRebuild}
            run={(work, fallback) => void perform("rebuild", work, fallback)}
            onState={setRebuildState}
            reconnect={setReconnecting}
            finish={finishRebuild}
          />
        )}
      <p className={styles.notice} role="status">
        {notice}
      </p>
    </section>
  );
}
