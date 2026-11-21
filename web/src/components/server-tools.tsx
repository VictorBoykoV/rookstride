"use client";

import { useState, type FormEvent } from "react";
import { useMessages } from "@/i18n/client";
import { filterPresets, singleProtocolCatalog } from "@/lib/gateway-input.mjs";
import { gatewayMessage } from "@/lib/gateway-messages";
import { formatMessage } from "@/i18n/format";
import styles from "./server-setup.module.css";

type Service = "vpn" | "filter" | "resolver" | "firewall";
type Preset = "standard" | "strong" | "strict";
type FilterReport = {
  presets: Preset[];
  queries: number;
  blocked: number;
  protectionEnabled?: boolean;
};
type UsageReport =
  | { available: false }
  | { available: true; sessions: number; upload: number; download: number }
  | {
      available: true;
      kind: "sessions" | "handshake" | "traffic";
      scope: "active-sessions" | "interface" | "daemon";
      profiles: number | null;
      upload: number;
      download: number;
    };
const usageNumber = new Intl.NumberFormat();
type Props = {
  busy: boolean;
  post: (payload: Record<string, unknown>) => Promise<Response>;
  perform: (task: () => Promise<void>) => Promise<void>;
};

type LifecycleProps = Props & {
  compatibilityOnly: boolean;
  canRemove: boolean;
  isSingleProtocol: boolean;
  onRemoval: (body: Record<string, unknown>) => void;
};

type ProtocolProps = Props & {
  installed: boolean;
  method?: SingleMethod;
  fixedMethod?: SingleMethod;
  practice?: boolean;
  sampleOwner?: string;
  methods: SingleMethod[];
  onInstall: (body: Record<string, unknown>) => void;
  save: (blob: Blob, filename: string) => void | Promise<void>;
};
export type SingleMethod = keyof typeof singleProtocolCatalog;

export function ProtocolTools({
  busy,
  post,
  perform,
  installed,
  method,
  fixedMethod,
  practice = false,
  sampleOwner,
  methods,
  onInstall,
  save,
}: ProtocolProps) {
  const copy = useMessages("manage");
  const text = copy.protocol;
  const [choice, setSelected] = useState(
    methods.includes("xray") ? "xray" : methods[0],
  );
  const selected = fixedMethod ?? choice;
  const namedMethod = method ?? fixedMethod;
  const [review, setReview] = useState<{
    code: string;
    port: number;
    login: string;
    method: SingleMethod;
  } | null>(null);
  const [roster, setRoster] = useState<{
    owner: string;
    users: string[];
    revision: string;
  } | null>(null);
  const [revoking, setRevoking] = useState("");

  async function request(payload: Record<string, unknown>) {
    const result = await post(payload);
    if (!result.ok) {
      const body = await result.json().catch(() => null);
      throw new Error(
        gatewayMessage(copy.gateway, body?.messageKey, text.unavailable),
      );
    }
    return result;
  }

  function updateRoster(action: string, login?: string) {
    void perform(async () => {
      const body = await (
        await request({
          action,
          ...(login && { login }),
          ...(login && { revision: roster?.revision }),
          ...(action === "protocolRevoke" && { confirmed: true }),
        })
      ).json();
      if (
        !Array.isArray(body.users) ||
        typeof body.owner !== "string" ||
        typeof body.revision !== "string"
      )
        throw new Error(text.unavailable);
      setRoster(body);
      setRevoking("");
    });
  }

  function readLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    return String(new FormData(event.currentTarget).get("login") ?? "").trim();
  }

  function reviewInstall(event: FormEvent<HTMLFormElement>) {
    const entered = readLogin(event);
    const login = sampleOwner ?? entered;
    void perform(async () => {
      const body = await (
        await request({ action: "protocolReview", login, method: selected })
      ).json();
      if (typeof body.review !== "string" || !Number.isInteger(body.port))
        throw new Error(text.unavailable);
      setReview({
        code: body.review,
        port: body.port,
        login,
        method: selected,
      });
    });
  }

  function install(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const confirmed =
      practice || new FormData(event.currentTarget).get("confirmed") === "on";
    if (!review) return;
    void perform(async () => {
      const response = await request({
        action: "protocolApply",
        review: review.code,
        confirmed,
      });
      onInstall(await response.json());
    });
  }

  return (
    <section className={styles.guests} aria-labelledby="gateway-protocol">
      <h3 id="gateway-protocol" tabIndex={-1}>
        {namedMethod ? singleProtocolCatalog[namedMethod].name : text.title}
      </h3>
      {!installed && !review && (
        <form method="post" onSubmit={reviewInstall}>
          <fieldset disabled={busy}>
            {!fixedMethod && (
              <label>
                {text.choose}
                <select
                  value={selected}
                  onChange={(event) =>
                    setSelected(event.target.value as SingleMethod)
                  }
                >
                  {methods.map((choice) => (
                    <option key={choice} value={choice}>
                      {singleProtocolCatalog[choice].name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {!sampleOwner && (
              <label>
                {text.owner}
                <input
                  name="login"
                  required
                  pattern="[A-Za-z0-9][A-Za-z0-9_\-]{0,47}"
                  maxLength={48}
                />
              </label>
            )}
            <button className="button secondary" type="submit">
              {text.review}
            </button>
          </fieldset>
        </form>
      )}
      {!installed && review && (
        <form method="post" onSubmit={install}>
          <fieldset disabled={busy}>
            <p>
              {formatMessage(text.plan, {
                port: String(review.port),
                login: review.login,
                method: singleProtocolCatalog[review.method].name,
                transport:
                  singleProtocolCatalog[review.method].transport.toUpperCase(),
              })}
            </p>
            {!practice && (
              <label className={styles.check}>
                <input type="checkbox" name="confirmed" required />
                {text.confirmed}
              </label>
            )}
            <div className="button-row">
              <button className="button primary" type="submit">
                {text.install}
              </button>
              <button
                className="button secondary"
                type="button"
                onClick={() => setReview(null)}
              >
                {text.cancel}
              </button>
            </div>
          </fieldset>
        </form>
      )}
      {installed && (
        <button
          className="button secondary"
          type="button"
          disabled={busy}
          onClick={() => updateRoster("protocolUsers")}
        >
          {text.users}
        </button>
      )}
      {installed && roster && method && (
        <>
          <ul className={styles.guestList}>
            {roster.users.map((login) => (
              <li key={login}>
                <strong>
                  {login === roster.owner ? copy.guests.owner + " " : ""}
                  {login}
                </strong>
                <div className="button-row">
                  <button
                    className="button secondary"
                    type="button"
                    disabled={busy}
                    aria-label={formatMessage(
                      practice ? copy.practice.downloadFor : text.downloadFor,
                      { login },
                    )}
                    onClick={() =>
                      void perform(async () => {
                        const response = await request({
                          action: "protocolProfile",
                          login,
                        });
                        if (
                          !response.headers
                            .get("content-type")
                            ?.startsWith("application/octet-stream")
                        )
                          throw new Error(text.unavailable);
                        await save(
                          await response.blob(),
                          `rookstride-${login}.${singleProtocolCatalog[method].extension}`,
                        );
                      })
                    }
                  >
                    {practice ? copy.practice.download : text.download}
                  </button>
                  {login !== roster.owner && revoking !== login && (
                    <button
                      className="button quiet"
                      type="button"
                      disabled={busy}
                      onClick={() => setRevoking(login)}
                    >
                      {text.remove}
                    </button>
                  )}
                  {revoking === login && (
                    <>
                      <span>{text.confirmRemove}</span>
                      <button
                        className="button primary"
                        type="button"
                        disabled={busy}
                        onClick={() => updateRoster("protocolRevoke", login)}
                      >
                        {text.remove}
                      </button>
                      <button
                        className="button secondary"
                        type="button"
                        disabled={busy}
                        onClick={() => setRevoking("")}
                      >
                        {text.cancel}
                      </button>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <form
            method="post"
            onSubmit={(event) =>
              updateRoster("protocolGrant", readLogin(event))
            }
          >
            <fieldset disabled={busy}>
              <label>
                {text.account}
                <input
                  name="login"
                  required
                  pattern="[A-Za-z0-9][A-Za-z0-9_\-]{0,47}"
                  maxLength={48}
                />
              </label>
              <button className="button secondary" type="submit">
                {text.create}
              </button>
            </fieldset>
          </form>
        </>
      )}
      {installed && (
        <ServerTools busy={busy} post={post} perform={perform} nativeProtocol />
      )}
    </section>
  );
}

export function LifecycleTools({
  compatibilityOnly,
  busy,
  post,
  perform,
  canRemove,
  isSingleProtocol,
  onRemoval,
}: LifecycleProps) {
  const copy = useMessages("manage");
  const text = copy.lifecycle;
  const [review, setReview] = useState("");
  const [notice, setNotice] = useState("");

  async function request(payload: Record<string, unknown>) {
    const response = await post(payload);
    const body = await response.json().catch(() => null);
    if (!response.ok || !body)
      throw new Error(
        gatewayMessage(copy.gateway, body?.messageKey, text.unavailable),
      );
    return body;
  }

  function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const confirmation = new FormData(event.currentTarget).get("confirmation");
    void perform(async () => {
      const body = await request({
        action: "removeApply",
        review,
        confirmation,
      });
      setReview("");
      onRemoval(body);
    });
  }

  return (
    <section className={styles.guests} aria-labelledby="gateway-lifecycle">
      <h3 id="gateway-lifecycle" tabIndex={-1}>
        {text.title}
      </h3>
      <div className="button-row">
        {canRemove && !review && (
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void perform(async () => {
                const body = await request({ action: "removeReview" });
                if (typeof body.review !== "string")
                  throw new Error(text.unavailable);
                setReview(body.review);
              })
            }
          >
            {text.review}
          </button>
        )}
        {compatibilityOnly && (
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void perform(async () => {
                setNotice("");
                const body = await request({ action: "ubuntuCheck" });
                setNotice(
                  body.eligible === true ? text.eligible : text.ineligible,
                );
              })
            }
          >
            {text.checkUbuntu}
          </button>
        )}
      </div>
      {canRemove && review && (
        <form onSubmit={remove}>
          <fieldset disabled={busy}>
            <legend>{text.reviewTitle}</legend>
            <p>{isSingleProtocol ? text.singleProtocolScope : text.scope}</p>
            <label>
              {text.confirmation}
              <input
                name="confirmation"
                required
                pattern="DELETE VPN"
                autoComplete="off"
              />
            </label>
            <div className="button-row">
              <button className="button primary" type="submit">
                {text.remove}
              </button>
              <button
                className="button secondary"
                type="button"
                onClick={() => setReview("")}
              >
                {text.cancel}
              </button>
            </div>
          </fieldset>
        </form>
      )}
      <p className={styles.notice} role="status">
        {notice}
      </p>
    </section>
  );
}

export function ServerTools({
  busy,
  post,
  perform,
  nativeProtocol = false,
}: Props & { nativeProtocol?: boolean }) {
  const copy = useMessages("manage");
  const text = copy.serverTools;
  const filterAction = nativeProtocol ? "protocolFilter" : "filter";
  const usageAction = nativeProtocol ? "protocolUsage" : "usage";
  const [services, setServices] = useState<Record<Service, boolean> | null>(
    null,
  );
  const [filter, setFilter] = useState<FilterReport | null>(null);
  const [usage, setUsage] = useState<UsageReport | null>(null);
  const [notice, setNotice] = useState("");

  async function request(payload: Record<string, unknown>) {
    const response = await post(payload);
    const body = await response.json().catch(() => null);
    if (!response.ok || !body) {
      throw new Error(
        gatewayMessage(copy.gateway, body?.messageKey, text.unreadable),
      );
    }
    return body;
  }

  function changeFilter(update: Record<string, unknown>) {
    void perform(async () => {
      setNotice("");
      setFilter(null);
      const { filtering } = await request({
        action: filterAction,
        ...update,
      });
      setFilter(filtering);
      setNotice(text.saved);
    });
  }

  function applyPreset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    changeFilter({
      level: fields.get("preset"),
      confirmed: fields.get("confirmed") === "on",
    });
  }

  function applyProtection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (typeof filter?.protectionEnabled !== "boolean") return;
    changeFilter({
      enabled: !filter.protectionEnabled,
      confirmed: new FormData(event.currentTarget).get("confirmed") === "on",
    });
  }

  return (
    <section className={styles.guests} aria-labelledby="gateway-tools">
      <h3 id="gateway-tools" tabIndex={-1}>
        {nativeProtocol ? text.protocolTitle : text.title}
      </h3>
      <div className="button-row">
        {!nativeProtocol && (
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void perform(async () => {
                setNotice("");
                setServices(null);
                setServices((await request({ action: "health" })).services);
              })
            }
          >
            {text.checkHealth}
          </button>
        )}
        <button
          className="button secondary"
          type="button"
          disabled={busy}
          onClick={() =>
            void perform(async () => {
              setNotice("");
              setFilter(null);
              setFilter((await request({ action: filterAction })).filtering);
            })
          }
        >
          {text.loadFilter}
        </button>
        <button
          className="button secondary"
          type="button"
          disabled={busy}
          onClick={() =>
            void perform(async () => {
              setUsage(null);
              setUsage((await request({ action: usageAction })).usage);
            })
          }
        >
          {text.loadUsage}
        </button>
      </div>
      {services && (
        <ul className={styles.plan}>
          {(Object.keys(text.services) as Service[]).map((key) => (
            <li key={key}>
              {text.services[key]} ·{" "}
              {services[key] ? text.active : text.inactive}
            </li>
          ))}
        </ul>
      )}
      {usage &&
        (usage.available ? (
          <ul className={styles.plan}>
            {"sessions" in usage ? (
              <li>
                {text.usageSessions} · {usageNumber.format(usage.sessions)}
              </li>
            ) : (
              usage.profiles !== null && (
                <li>
                  {usage.kind === "handshake"
                    ? text.usageRecentProfiles
                    : text.usageActiveProfiles}{" "}
                  · {usageNumber.format(usage.profiles)}
                </li>
              )
            )}
            <li>
              {text.usageUpload} · {usageNumber.format(usage.upload)}
            </li>
            <li>
              {text.usageDownload} · {usageNumber.format(usage.download)}
            </li>
          </ul>
        ) : (
          <p role="status">{text.usageUnavailable}</p>
        ))}
      {usage?.available && "scope" in usage && (
        <p>{text.usageScopes[usage.scope]}</p>
      )}
      {filter && (
        <>
          <p>
            {filter.presets.length ? (
              <>
                {text.runningPresets} ·{" "}
                {filter.presets.map((key) => text.presets[key]).join(", ")}
              </>
            ) : (
              text.noPreset
            )}
          </p>
          <p>
            {text.queries} · {filter.queries} <br />
            {text.blocked} · {filter.blocked}
          </p>
          {nativeProtocol && typeof filter.protectionEnabled === "boolean" && (
            <form method="post" onSubmit={applyProtection}>
              <fieldset disabled={busy}>
                <p>
                  {filter.protectionEnabled
                    ? text.protectionActive
                    : text.protectionPaused}
                </p>
                <label className={styles.check}>
                  <input type="checkbox" name="confirmed" required />
                  {text.confirmProtection}
                </label>
                <button className="button secondary" type="submit">
                  {filter.protectionEnabled
                    ? text.pauseProtection
                    : text.resumeProtection}
                </button>
              </fieldset>
            </form>
          )}
        </>
      )}
      <form method="post" onSubmit={applyPreset}>
        <fieldset disabled={busy}>
          <label>
            {text.choose}
            <select name="preset" required defaultValue="">
              <option value="" disabled>
                {text.chooseOption}
              </option>
              {filterPresets.map((key) => (
                <option key={key} value={key}>
                  {text.presets[key as Preset]}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.check}>
            <input type="checkbox" name="confirmed" required />
            {nativeProtocol ? text.confirmSharedPreset : text.confirm}
          </label>
          <button className="button secondary" type="submit">
            {text.apply}
          </button>
        </fieldset>
      </form>
      <p className={styles.notice} role="status">
        {notice}
      </p>
    </section>
  );
}
