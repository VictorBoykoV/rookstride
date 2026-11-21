"use client";

import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import {
  readServerRecord,
  readUbuntuRecovery,
  singleProtocolCatalog,
  validLogin,
  validVpnPassword,
} from "@/lib/gateway-input.mjs";
import { ServerGuests } from "./server-guests";
import { ServerConnectionFields } from "./server-connection-fields";
import { ScopedAdministratorStatus } from "./scoped-administrator-status";
import {
  LifecycleTools,
  ProtocolTools,
  ServerTools,
  type SingleMethod,
} from "./server-tools";
import {
  UbuntuRecoveryTools,
  UbuntuReinstallTools,
  type UbuntuRecoveryRecord,
} from "./ubuntu-tools";
import { focusWorkspaceStep } from "./gateway-frame";
import { RookCharacter } from "./rook-character";
import { useMessages } from "@/i18n/client";
import { formatMessage } from "@/i18n/format";
import { gatewayMessage } from "@/lib/gateway-messages";
import {
  createPracticeGateway,
  practiceProfile,
  practiceProgressStages,
} from "@/lib/practice-gateway";
import { previewAddress } from "@/lib/preview.mjs";
import type { manage } from "@/i18n/en/manage";
import styles from "./server-setup.module.css";

const sessionKey = "rookstride.gateway.session";
const ubuntuRecoveryKey = "rookstride.gateway.ubuntu-recovery";
const sampleOwner = "demo-owner";

const serverStates = [
  "ready",
  "occupied",
  "unsupported",
  "running",
  "removing",
  "installed",
  "removed",
  "protocolRunning",
  "protocolInstalled",
  "protocolFailed",
  "ubuntuReinstalling",
  "failed",
  "indeterminate",
] as const;
type ServerState = (typeof serverStates)[number];
type View = {
  state: ServerState | "restoring" | "unavailable";
  messageKey?: string;
  os?: string;
  address?: string;
  connection?: ReturnType<typeof readServerRecord>;
  method?: SingleMethod;
  availableMethods?: SingleMethod[];
  progress?: number;
};
function isSingleMethod(value: unknown): value is SingleMethod {
  return (
    typeof value === "string" && Object.hasOwn(singleProtocolCatalog, value)
  );
}

function readView(
  body: Record<string, unknown>,
  text: typeof manage.live,
): View {
  if (!serverStates.some((state) => state === body.state)) {
    throw new Error(text.notices.unexpectedState);
  }
  return {
    state: body.state as ServerState,
    messageKey:
      typeof body.messageKey === "string" ? body.messageKey : undefined,
    address: typeof body.address === "string" ? body.address : undefined,
    os: typeof body.os === "string" ? body.os : undefined,
    connection: readServerRecord(body.connection),
    method: isSingleMethod(body.method) ? body.method : undefined,
    availableMethods: Array.isArray(body.availableMethods)
      ? body.availableMethods.filter(isSingleMethod)
      : undefined,
    progress: typeof body.progress === "number" ? body.progress : undefined,
  };
}

function headers(
  token: string,
  post = false,
  invite?: string,
): Record<string, string> {
  return {
    ...(post ? { "Content-Type": "application/json" } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(invite ? { "X-Rookstride-Invite": invite } : {}),
  };
}

async function responseBody(
  response: Response,
  text: typeof manage.live,
): Promise<Record<string, unknown>> {
  const data: unknown = await response.json().catch(() => null);
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(text.notices.unreadable);
  }
  return data as Record<string, unknown>;
}

export function ServerSetup({
  invite,
  practice = false,
  hostedReinstall = false,
  hostedEcdsa = false,
}: {
  invite?: string;
  practice?: boolean;
  hostedReinstall?: boolean;
  hostedEcdsa?: boolean;
}) {
  const api = invite ? "/vpn/api" : "/api/gateway";
  const canReinstall = !invite || hostedReinstall;
  const canUseEcdsa = canReinstall || hostedEcdsa;
  const copy = useMessages("manage");
  const text = copy.live;
  const example = copy.practice;
  const [simulation] = useState(() =>
    practice ? createPracticeGateway() : null,
  );
  function errorText(body: Record<string, unknown>, fallback: string) {
    return gatewayMessage(copy.gateway, body.messageKey, fallback);
  }
  const [initialized, setInitialized] = useState(false);
  const [token, setToken] = useState("");
  const [serverView, setServerView] = useState<View | null>(null);
  const [practiceReview, setPracticeReview] = useState<View | null>(null);
  const [practiceScreen, setPracticeScreen] = useState<number | null>(null);
  const [selectedMethod, selectMethod] = useState<"ikev2" | SingleMethod>(
    "ikev2",
  );
  const installed =
    serverView?.state === "installed" ||
    serverView?.state === "protocolInstalled";
  const view =
    practiceScreen === 0
      ? null
      : practiceScreen === 1
        ? practiceReview
        : serverView;
  const reviewOnly = practiceScreen === 1 && installed;

  function setView(next: View | null) {
    setPracticeScreen(null);
    setServerView(next);
  }
  const [recovery, setRecovery] = useState<UbuntuRecoveryRecord | null>(null);
  const [nextServer, setNextServer] =
    useState<ReturnType<typeof readServerRecord>>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  useEffect(() => setNotice(""), [text]);
  const locked = useRef(false);
  const workspace = useRef<HTMLElement>(null);
  const connectionForm = useRef<HTMLFormElement>(null);
  const priorPhase = useRef<string | undefined>(undefined);

  function remember(value: string) {
    setToken(value);
    if (invite || practice) return;
    try {
      if (value) sessionStorage.setItem(sessionKey, value);
      else sessionStorage.removeItem(sessionKey);
    } catch {
      // The current page can keep the session in memory if storage is disabled.
    }
  }

  useEffect(() => {
    if (practice) {
      setInitialized(true);
      return;
    }
    if (invite && hostedReinstall) {
      const controller = new AbortController();
      void (async () => {
        try {
          const response = await fetch(api, {
            method: "POST",
            headers: headers("", true, invite),
            body: JSON.stringify({ action: "ubuntuRecovery" }),
            cache: "no-store",
            signal: controller.signal,
          });
          if (!response.ok) throw new Error();
          const { recovery, server } = await response.json();
          if (!controller.signal.aborted) {
            setRecovery(readUbuntuRecovery(recovery));
            setNextServer(readServerRecord(server));
          }
        } catch {
          if (!controller.signal.aborted) setNotice(text.notices.inspectFailed);
        } finally {
          if (!controller.signal.aborted) setInitialized(true);
        }
      })();
      return () => controller.abort();
    }
    try {
      const existing = invite ? null : sessionStorage.getItem(sessionKey);
      if (existing) {
        setToken(existing);
        setServerView({ state: "restoring" });
      }
      if (!invite) {
        const saved = sessionStorage.getItem(ubuntuRecoveryKey);
        if (saved) setRecovery(readUbuntuRecovery(JSON.parse(saved)));
      }
    } catch {
      // Browser storage is optional.
    }
    setInitialized(true);
  }, [api, hostedReinstall, invite, practice, text.notices.inspectFailed]);

  const phase = recovery ? "ubuntuRecovery" : view?.state;
  useEffect(() => {
    if (phase !== priorPhase.current && phase !== "restoring") {
      focusWorkspaceStep(workspace.current?.querySelector<HTMLElement>("h2"));
    }
    priorPhase.current = phase;
  }, [phase]);
  useEffect(() => {
    if (
      !token ||
      busy ||
      !["restoring", "running", "removing", "protocolRunning"].includes(
        phase ?? "",
      )
    )
      return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const protocol = phase === "protocolRunning";
        const response =
          simulation?.request({
            action: protocol ? "protocolStatus" : "status",
          }) ??
          (await fetch(api, {
            ...(protocol && {
              method: "POST",
              body: JSON.stringify({ action: "protocolStatus" }),
            }),
            headers: headers(token, protocol, invite),
            cache: "no-store",
            signal: controller.signal,
          }));
        if (controller.signal.aborted) return;
        if ([401, 404, 410].includes(response.status)) {
          remember("");
          setView(null);
          setNotice(text.notices.sessionEnded);
          return;
        }
        if (!response.ok) throw new Error();
        const next = readView(await responseBody(response, text), text);
        if (controller.signal.aborted) return;
        setView(next);
        setNotice("");
        if (["running", "removing", "protocolRunning"].includes(next.state))
          timer = setTimeout(refresh, simulation ? 900 : 2500);
      } catch {
        if (controller.signal.aborted) return;
        setView({ state: "unavailable" });
        setNotice(text.notices.statusUnknown);
      }
    }
    if (phase === "restoring") void refresh();
    else timer = setTimeout(refresh, simulation ? 900 : 2500);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [api, invite, phase, token, busy, text, simulation]);

  async function perform(
    task: () => Promise<void>,
    onError?: (message: string) => void,
  ) {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    setNotice("");
    try {
      await task();
    } catch (error) {
      const message =
        error instanceof Error && error.name !== "TypeError"
          ? error.message
          : text.notices.offline;
      if (onError) onError(message);
      else setNotice(message);
    } finally {
      locked.current = false;
      setBusy(false);
    }
  }

  async function post(payload: Record<string, unknown>) {
    if (simulation) return simulation.request(payload);
    return fetch(api, {
      method: "POST",
      headers: headers(token, true, invite),
      body: JSON.stringify(payload),
      cache: "no-store",
    });
  }

  function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    void perform(async () => {
      if (simulation) {
        const response = await post({
          action: "inspect",
          scenario: data.get("scenario"),
        });
        const body = await responseBody(response, text);
        remember("");
        setPracticeReview(null);
        setView(null);
        if (!response.ok)
          throw new Error(errorText(body, text.notices.inspectFailed));
        const result = readView(body, text);
        if (result.state === "ready") setPracticeReview(result);
        selectMethod("ikev2");
        if (typeof body.session === "string") remember(body.session);
        setView(result);
        return;
      }
      (form.elements.namedItem("password") as HTMLInputElement).value = "";
      const pending = post({
        action: "inspect",
        address: String(data.get("address")).trim(),
        sshPort: Number(data.get("sshPort")),
        fingerprint: String(data.get("fingerprint")).trim(),
        ...(canUseEcdsa &&
          data.get("keyType") === "ecdsa-sha2-nistp256" && {
            keyType: data.get("keyType"),
          }),
        password: data.get("password"),
      });
      data.delete("password");
      const response = await pending;
      const body = await responseBody(response, text);
      if (!response.ok)
        throw new Error(errorText(body, text.notices.inspectFailed));
      const next = readView(body, text);
      if (
        [
          "ready",
          "installed",
          "removed",
          "protocolRunning",
          "protocolInstalled",
          "protocolFailed",
        ].includes(next.state) &&
        (typeof body.session !== "string" || !body.session)
      ) {
        throw new Error(text.notices.sessionMissing);
      }
      if (typeof body.session === "string") remember(body.session);
      selectMethod("ikev2");
      setView({ ...next, address: String(data.get("address")).trim() });
    });
  }

  function install(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const login = practice ? sampleOwner : String(data.get("login")).trim();
    if (!validLogin(login)) {
      setNotice(text.notices.invalidUsername);
      return;
    }
    const password = String(data.get("vpnPassword"));
    if (!practice && !validVpnPassword(password)) {
      setNotice(text.notices.invalidPassword);
      return;
    }
    void perform(
      async () => {
        const responsePromise = post({
          action: "install",
          login,
          ...(!practice && { vpnPassword: password }),
          confirmed: practice || data.get("confirmed") === "on",
        });
        form.reset();
        const response = await responsePromise;
        const body = await responseBody(response, text);
        if (!response.ok) {
          if (
            response.status >= 400 &&
            response.status < 500 &&
            response.status !== 409
          ) {
            setNotice(errorText(body, text.notices.invalidFields));
            if ([401, 404, 410].includes(response.status))
              setView({ state: "restoring" });
            return;
          }
          throw new Error(text.notices.unconfirmed);
        }
        setView(readView(body, text));
      },
      () => {
        setView({ state: "restoring" });
        setNotice(text.notices.checking);
      },
    );
  }

  function close() {
    void perform(async () => {
      if (token || simulation) {
        const response = await post({ action: "close" });
        if (!response.ok && ![401, 404, 410].includes(response.status)) {
          throw new Error(
            errorText(
              await responseBody(response, text),
              text.notices.closeFailed,
            ),
          );
        }
      }
      remember("");
      setPracticeReview(null);
      selectMethod("ikev2");
      setView(null);
      if (!practice) setNotice(text.notices.closed);
    });
  }

  function cancelPractice() {
    void perform(async () => {
      const response = await post({ action: "cancel" });
      const body = await responseBody(response, text);
      if (!response.ok)
        throw new Error(errorText(body, text.notices.closeFailed));
      setView(readView(body, text));
      setNotice(example.cancelled);
    });
  }

  function goToPracticeStep(step: number) {
    setNotice("");
    setPracticeScreen(step < 2 ? step : null);
  }

  function openManagementSection(id: string) {
    const heading = document.getElementById(id);
    heading?.focus({ preventScroll: true });
    heading?.scrollIntoView({ block: "start" });
  }

  async function saveProfile(file: Blob, filename: string) {
    if (!practice) {
      saveFile(file, filename);
      return;
    }
    const sample = JSON.parse(await file.text()) as {
      method: "ikev2" | SingleMethod;
      login: string;
    };
    saveFile(
      new Blob([practiceProfile(sample.method, sample.login) + "\n"], {
        type: "application/octet-stream",
      }),
      `sample-${filename}`,
    );
  }

  function download(login?: string) {
    void perform(async () => {
      const method = practice ? view?.method : undefined;
      const response = await post({
        action: method ? "protocolProfile" : "profile",
        ...(login && { login }),
      });
      if (!response.ok)
        throw new Error(
          errorText(
            await responseBody(response, text),
            text.notices.downloadFailed,
          ),
        );
      if (
        !response.headers
          .get("content-type")
          ?.toLowerCase()
          .startsWith("application/octet-stream")
      ) {
        throw new Error(text.notices.invalidFile);
      }
      const extension = method
        ? singleProtocolCatalog[method].extension
        : "sswan";
      await saveProfile(
        await response.blob(),
        login ? `rookstride-${login}.${extension}` : `rookstride.${extension}`,
      );
      setNotice(text.notices.downloading);
    });
  }

  function saveServer() {
    const connection = view?.connection;
    if (!connection) return;
    saveFile(
      new Blob([JSON.stringify(connection, null, 2) + "\n"], {
        type: "application/octet-stream",
      }),
      practice ? "practice-server.json" : "rookstride-server.json",
    );
    setNotice(text.notices.serverRecordSaved);
  }

  function importServer(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    const form = connectionForm.current;
    if (!file || !form) return;
    void perform(
      async () => {
        const record =
          file.size <= 1024
            ? readServerRecord(JSON.parse(await file.text()))
            : null;
        if (!record || (!canUseEcdsa && record.version !== 1)) throw new Error();
        for (const name of ["address", "sshPort", "fingerprint"] as const) {
          (form.elements.namedItem(name) as HTMLInputElement).value = String(
            record[name],
          );
        }
        const keyType = form.elements.namedItem(
          "keyType",
        ) as HTMLSelectElement | null;
        if (keyType) keyType.value = record.keyType ?? "ssh-ed25519";
        const password = form.elements.namedItem(
          "password",
        ) as HTMLInputElement;
        password.value = "";
        setNotice(text.notices.serverRecordLoaded);
      },
      () => setNotice(text.notices.serverRecordInvalid),
    );
  }

  function rememberRecovery(record: UbuntuRecoveryRecord) {
    if (practice || hostedReinstall) {
      setRecovery(record);
      return;
    }
    try {
      sessionStorage.setItem(ubuntuRecoveryKey, JSON.stringify(record));
    } catch {
      throw new Error(copy.ubuntu.storage);
    }
    setRecovery(record);
  }

  function clearRecovery() {
    if (!practice && !hostedReinstall) {
      try {
        sessionStorage.removeItem(ubuntuRecoveryKey);
      } catch {
        // Browser storage may be unavailable after the job was verified.
      }
    }
    setRecovery(null);
  }

  function openRecoveredSetup(
    server?: NonNullable<ReturnType<typeof readServerRecord>>,
  ) {
    clearRecovery();
    remember("");
    setPracticeReview(null);
    selectMethod("ikev2");
    setNextServer(server ?? null);
    setView(null);
  }

  function importUbuntuRecovery(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    void perform(async () => {
      const data = file.size <= 2048 ? await file.text() : "";
      let record;
      try {
        record = readUbuntuRecovery(JSON.parse(data));
      } catch {
        throw new Error(copy.ubuntu.invalidFile);
      }
      if (!record) throw new Error(copy.ubuntu.invalidFile);
      rememberRecovery(record);
    });
  }

  const applying = practice && typeof view?.progress === "number";
  const practiceStage =
    practiceScreen ??
    (view?.state === "ready" || applying
      ? 1
      : installed || view?.state === "removed" || view?.state === "removing"
        ? 2
        : 0);
  const methods: SingleMethod[] = view?.availableMethods ?? ["xray"];

  return (
    <section
      className={styles.workspace}
      aria-label={text.label}
      ref={workspace}
      id={practice ? "practice" : undefined}
    >
      {practice && (
        <div className={styles.practiceGuide}>
          <p>{example.intro}</p>
          <div className={styles.practiceToolbar}>
            <nav aria-label={example.label} className="button-row">
              {example.steps.map((label, index) => (
                <button
                  key={label}
                  type="button"
                  className="button secondary"
                  aria-current={practiceStage === index ? "step" : undefined}
                  disabled={
                    busy ||
                    !!recovery ||
                    applying ||
                    view?.state === "removing" ||
                    (index === 1 && !practiceReview) ||
                    (index === 2 &&
                      !installed &&
                      serverView?.state !== "removed")
                  }
                  onClick={() => goToPracticeStep(index)}
                >
                  {label}
                </button>
              ))}
            </nav>
            <button
              className="button secondary"
              type="button"
              disabled={busy || !!recovery}
              onClick={close}
            >
              {example.restart}
            </button>
          </div>
        </div>
      )}
      {!initialized || phase === "restoring" ? (
        <p role="status">{text.restoring}</p>
      ) : recovery && canReinstall ? (
        <UbuntuRecoveryTools
          key={recovery.job}
          busy={busy}
          post={post}
          perform={perform}
          recovery={recovery}
          practice={practice}
          save={saveFile}
          openSetup={openRecoveredSetup}
        />
      ) : !view ? (
        <form
          ref={connectionForm}
          method="post"
          onSubmit={inspect}
          autoComplete="off"
        >
          <h2 tabIndex={-1}>{practice ? example.deploy : text.inspectTitle}</h2>
          {practice ? (
            <>
              <p>{example.sampleDetails}</p>
              {installed && <p>{example.checkStartsNew}</p>}
            </>
          ) : (
            <>
              <p>{invite ? text.hostedOverview : text.overview}</p>
              <p>{text.inspectIntro}</p>
            </>
          )}
          <fieldset disabled={busy}>
            {practice ? (
              <>
                <label>
                  {example.serverAddress}
                  <input value={previewAddress} readOnly dir="ltr" />
                </label>
                <div className={styles.addressRow}>
                  <label>
                    {example.serverLogin}
                    <input value="root" readOnly />
                  </label>
                  <label>
                    {example.serverPassword}
                    <input value={example.examplePassword} readOnly />
                  </label>
                </div>
                <details className={styles.scenario}>
                  <summary>{example.changeCondition}</summary>
                  <label>
                    {example.condition}
                    <select name="scenario" defaultValue="fresh">
                      {Object.entries(example.conditions).map(
                        ([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ),
                      )}
                    </select>
                  </label>
                </details>
              </>
            ) : (
              <>
                <label>
                  {text.reopen}
                  <input
                    type="file"
                    accept=".json,application/json"
                    onChange={importServer}
                  />
                </label>
                <ServerConnectionFields
                  allowEcdsa={canUseEcdsa}
                  initial={nextServer}
                />
              </>
            )}
            <button className="button primary" type="submit">
              {busy ? text.checking : practice ? example.review : text.inspect}
            </button>
            {!invite && !practice && (
              <label>
                {copy.ubuntu.import}
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={importUbuntuRecovery}
                />
              </label>
            )}
          </fieldset>
        </form>
      ) : view.state === "ready" ? (
        <div>
          <h2 tabIndex={-1}>{text.review}</h2>
          <p>
            {view.address && <strong dir="ltr">{view.address} · </strong>}
            {view.os
              ? formatMessage(text.ready, { os: view.os })
              : text.readyWithoutOs}
          </p>
          {methods.length > 0 && (
            <label>
              {copy.protocol.choose}
              <select
                value={selectedMethod}
                disabled={busy}
                onChange={(event) =>
                  selectMethod(event.target.value as "ikev2" | SingleMethod)
                }
              >
                <option value="ikev2">{copy.protocol.ikev2}</option>
                {methods.map((method) => (
                  <option key={method} value={method}>
                    {singleProtocolCatalog[method].name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {reviewOnly && <p>{example.reviewOnly}</p>}
          {selectedMethod === "ikev2" ? (
            <form method="post" onSubmit={install} autoComplete="off">
              <ul className={styles.plan}>
                <li>{text.installPlan}</li>
                <li>{text.portsPlan}</li>
                {!practice && <li>{text.accessPlan}</li>}
              </ul>
              <fieldset disabled={busy || reviewOnly}>
                {!practice && (
                  <>
                    <label>
                      {text.username}
                      <input
                        name="login"
                        required
                        maxLength={64}
                        autoCapitalize="none"
                        spellCheck={false}
                      />
                    </label>
                    <label>
                      {text.password}
                      <input
                        name="vpnPassword"
                        type="password"
                        required
                        maxLength={127}
                        autoComplete="off"
                        aria-describedby="vpn-password-help"
                      />
                    </label>
                    <p className={styles.hint} id="vpn-password-help">
                      {text.passwordHint}
                    </p>
                    <label className={styles.check}>
                      <input type="checkbox" name="confirmed" required />
                      {text.approve}
                    </label>
                  </>
                )}
                <div className="button-row">
                  <button type="submit" className="button primary">
                    {busy ? text.waiting : text.install}
                  </button>
                </div>
              </fieldset>
            </form>
          ) : (
            <ProtocolTools
              key={selectedMethod}
              busy={busy || reviewOnly}
              post={post}
              perform={perform}
              installed={false}
              methods={methods}
              fixedMethod={selectedMethod}
              practice={practice}
              sampleOwner={practice ? sampleOwner : undefined}
              onInstall={(body) => setView(readView(body, text))}
              save={saveProfile}
            />
          )}
          <button
            type="button"
            className="button quiet"
            disabled={busy}
            onClick={practice ? () => goToPracticeStep(0) : close}
          >
            {practice ? example.back : text.close}
          </button>
        </div>
      ) : (
        <div>
          <h2 tabIndex={-1}>
            {practice && installed
              ? example.installed
              : text.titles[view.state as keyof typeof text.titles]}
          </h2>
          {view.address && (
            <p className={styles.hint}>
              {text.server} <strong dir="ltr">{view.address}</strong>
            </p>
          )}
          {installed && (
            <dl className={styles.vpnDetails} aria-label={example.vpnDetails}>
              <div>
                <dt>{copy.protocol.choose}</dt>
                <dd>
                  {view.method
                    ? singleProtocolCatalog[view.method].name
                    : copy.protocol.ikev2}
                </dd>
              </div>
              {view.os && (
                <div>
                  <dt>{example.operatingSystem}</dt>
                  <dd>{view.os}</dd>
                </div>
              )}
            </dl>
          )}
          {applying ? (
            <PracticeProgress view={view} busy={busy} cancel={cancelPractice} />
          ) : practice && installed ? (
            <div className={styles.practiceStatus}>
              <div className={styles.stageRook}>
                <RookCharacter action="share" />
              </div>
              <p role="status">{example.complete}</p>
            </div>
          ) : (
            <p role="status">
              {practice && view.state === "removing"
                ? example.removing
                : practice && view.state === "removed"
                  ? example.removed
                  : gatewayMessage(
                      copy.gateway,
                      view.messageKey,
                      gatewayMessage(copy.gateway, view.state),
                    )}
            </p>
          )}
          {view.state === "installed" && (
            <p>{practice ? example.sampleProfile : text.profileHelp}</p>
          )}
          {practice && view.state === "protocolInstalled" && (
            <>
              <p>{example.sampleProfile}</p>
            </>
          )}
          {view.state === "protocolInstalled" && (
            <div className="button-row">
              {practice && (
                <button
                  type="button"
                  className="button primary"
                  disabled={busy}
                  onClick={() => download()}
                >
                  {example.download}
                </button>
              )}
              {view.connection && (
                <button
                  type="button"
                  className="button secondary"
                  disabled={busy}
                  onClick={saveServer}
                >
                  {text.saveServer}
                </button>
              )}
            </div>
          )}
          {practice && installed && (
            <nav className={styles.manageLinks} aria-label={example.vpnDetails}>
              <button
                type="button"
                className="button quiet"
                onClick={() =>
                  openManagementSection(
                    view.method ? "gateway-protocol" : "guest-access-title",
                  )
                }
              >
                {copy.guests.title}
              </button>
              <button
                type="button"
                className="button quiet"
                onClick={() => openManagementSection("gateway-tools")}
              >
                {example.dnsSettings}
              </button>
              <button
                type="button"
                className="button quiet"
                onClick={() => openManagementSection("gateway-lifecycle")}
              >
                {example.serverTools}
              </button>
              <button
                type="button"
                className="button quiet"
                onClick={() => openManagementSection("reinstall-ubuntu")}
              >
                {copy.ubuntu.title}
              </button>
            </nav>
          )}
          {view.state === "installed" && (
            <>
              <div className="button-row">
                <button
                  type="button"
                  className="button primary"
                  disabled={busy}
                  onClick={() => download()}
                >
                  {practice ? example.download : text.download}
                </button>
                {view.connection && (
                  <button
                    type="button"
                    className="button secondary"
                    aria-describedby="saved-server-record-help"
                    disabled={busy}
                    onClick={saveServer}
                  >
                    {text.saveServer}
                  </button>
                )}
              </div>
              {view.connection && (
                <p
                  id="saved-server-record-help"
                  className={styles.savedServerHint}
                >
                  {practice ? example.sampleRecord : text.savedServerHint}
                </p>
              )}
              <ServerTools busy={busy} post={post} perform={perform} />
            </>
          )}
          {view.state === "installed" && (
            <ServerGuests
              busy={busy}
              post={post}
              perform={perform}
              download={download}
              practice={practice}
            />
          )}
          {view.state === "unavailable" && (
            <button
              type="button"
              className="button secondary"
              disabled={busy}
              onClick={() => {
                setNotice("");
                setView({ state: "restoring" });
              }}
            >
              {text.checkAgain}
            </button>
          )}
          {!practice &&
            view.state !== "running" &&
            view.state !== "removing" &&
            view.state !== "unavailable" && (
              <div className="button-row">
                <button
                  type="button"
                  className="button secondary"
                  disabled={busy}
                  onClick={close}
                >
                  {token ? text.close : text.checkAnother}
                </button>
              </div>
            )}
        </div>
      )}
      {!recovery &&
        view &&
        (invite ||
          view.state === "installed" ||
          view.state === "protocolInstalled") &&
        ["ready", "installed", "removed", "protocolInstalled"].includes(
          view.state,
        ) && (
          <LifecycleTools
            busy={busy}
            post={post}
            perform={perform}
            canRemove={
              view.state === "installed" || view.state === "protocolInstalled"
            }
            isSingleProtocol={view.state === "protocolInstalled"}
            compatibilityOnly={Boolean(invite && !hostedReinstall)}
            onRemoval={(body) => setView(readView(body, text))}
          />
        )}
      {canReinstall &&
        !recovery &&
        view?.connection &&
        [
          "ready",
          "installed",
          "removed",
          "protocolInstalled",
          "occupied",
        ].includes(view.state) && (
          <UbuntuReinstallTools
            busy={busy}
            post={post}
            perform={perform}
            practice={practice}
            rememberRecovery={rememberRecovery}
            discardRejectedRecovery={clearRecovery}
          />
        )}
      {!recovery &&
        view &&
        ["removed", "protocolInstalled"].includes(view.state) && (
          <ProtocolTools
            busy={busy}
            post={post}
            perform={perform}
            installed={view.state === "protocolInstalled"}
            method={
              view.method ??
              (view.state === "protocolInstalled" ? "xray" : undefined)
            }
            methods={view.availableMethods ?? ["xray"]}
            practice={practice}
            sampleOwner={practice ? sampleOwner : undefined}
            onInstall={(body) => setView(readView(body, text))}
            save={saveProfile}
          />
        )}
      {!invite && !practice && !recovery && token &&
        view?.state === "protocolInstalled" && (
          <ScopedAdministratorStatus
            key={`${token}:${view.method}`}
            busy={busy}
            post={post}
            perform={perform}
            copy={copy.administrators}
          />
        )}
      {token && !invite && !practice && !recovery && (
        <div className="button-row">
          <a
            className="button quiet"
            href="/manage/server"
            target="_blank"
            rel="noopener noreferrer"
          >
            {text.openAnother}
          </a>
        </div>
      )}
      <p aria-live="polite" role="status" className={styles.notice}>
        {notice}
      </p>
    </section>
  );
}

function PracticeProgress({
  view,
  busy,
  cancel,
}: {
  view: View;
  busy: boolean;
  cancel: () => void;
}) {
  const { practice: text, protocol } = useMessages("manage");
  const current = view.progress ?? 0;
  const poses = ["look", "carry", "build", "build", "look"] as const;
  const method = view.method
    ? singleProtocolCatalog[view.method].name
    : protocol.ikev2;
  return (
    <div className={styles.practiceProgress}>
      <div className={styles.practiceStatus}>
        <div className={styles.stageRook}>
          <RookCharacter action={poses[current]} />
        </div>
        <p role="status">
          {formatMessage(text.progressCount, {
            step: current + 1,
            total: practiceProgressStages,
          })}
        </p>
      </div>
      <ol>
        {text.progress.map((label, index) => (
          <li key={label} aria-current={index === current ? "step" : undefined}>
            {formatMessage(label, {
              method,
              filter: view.method ? text.otherFilter : text.ikeFilter,
            })}
            <span>
              {index < current
                ? text.done
                : index === current
                  ? text.current
                  : text.pending}
            </span>
          </li>
        ))}
      </ol>
      <button
        className="button secondary"
        type="button"
        disabled={busy}
        onClick={cancel}
      >
        {text.cancel}
      </button>
    </div>
  );
}

function saveFile(file: Blob, filename: string) {
  const href = URL.createObjectURL(file);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
