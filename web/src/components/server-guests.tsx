"use client";

import { useEffect, useState, type FormEvent } from "react";
import { validLogin, validVpnPassword } from "@/lib/gateway-input.mjs";
import { useMessages } from "@/i18n/client";
import { formatMessage } from "@/i18n/format";
import { gatewayMessage } from "@/lib/gateway-messages";
import type { manage } from "@/i18n/en/manage";
import styles from "./server-setup.module.css";

type Roster = { owner: string; guests: string[]; revision: string };
type Props = {
  busy: boolean;
  post: (payload: Record<string, unknown>) => Promise<Response>;
  perform: (task: () => Promise<void>) => Promise<void>;
  download: (login: string) => void;
  practice?: boolean;
};

function readRoster(
  body: Record<string, unknown>,
  text: typeof manage.guests,
): Roster {
  if (
    typeof body.owner !== "string" ||
    !validLogin(body.owner) ||
    !Array.isArray(body.guests) ||
    !body.guests.every(
      (guest) =>
        typeof guest === "string" && validLogin(guest) && guest !== body.owner,
    ) ||
    typeof body.revision !== "string" ||
    !body.revision
  ) {
    throw new Error(text.invalidList);
  }
  return { owner: body.owner, guests: body.guests, revision: body.revision };
}

async function jsonResult(
  response: Response,
  copy: typeof manage,
): Promise<Record<string, unknown>> {
  const text = copy.guests;
  const body = await response.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw new Error(text.unreadable);
  if (
    !response.ok ||
    body.state === "indeterminate" ||
    body.state === "failed"
  ) {
    throw new Error(
      gatewayMessage(copy.gateway, body.messageKey, text.uncertainChange),
    );
  }
  return body;
}

export function ServerGuests({
  busy,
  post,
  perform,
  download,
  practice = false,
}: Props) {
  const copy = useMessages("manage");
  const text = copy.guests;
  const example = copy.practice;
  const [roster, setRoster] = useState<Roster | null>(null);
  const [review, setReview] = useState<{
    action: "rotate" | "revoke";
    login: string;
  } | null>(null);
  const [notice, setNotice] = useState("");
  useEffect(() => setNotice(""), [text]);

  async function refresh() {
    setReview(null);
    const result = await jsonResult(await post({ action: "guests" }), copy);
    setRoster(readRoster(result, text));
  }

  async function change(payload: Record<string, unknown>, success: string) {
    if (!roster) return;
    try {
      const result = await jsonResult(
        await post({ ...payload, revision: roster.revision }),
        copy,
      );
      setRoster(readRoster(result, text));
      setReview(null);
      setNotice(
        result.activeSessionsUncertain === true
          ? formatMessage(text.sessionsUncertain, { result: success })
          : success,
      );
    } catch (error) {
      const reason =
        error instanceof Error && error.name !== "TypeError"
          ? error.message
          : text.uncertainChange;
      setRoster(null);
      try {
        await refresh();
        setNotice(formatMessage(text.refreshed, { reason }));
      } catch {
        setNotice(formatMessage(text.reloadNeeded, { reason }));
      }
    }
  }

  function grant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!roster) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const login = String(data.get("login")).trim();
    const vpnPassword = String(data.get("vpnPassword"));
    if (!validLogin(login)) {
      setNotice(text.invalidUsername);
      return;
    }
    if (!practice && !validVpnPassword(vpnPassword)) {
      setNotice(text.invalidPassword);
      return;
    }
    if (login === roster.owner || roster.guests.includes(login)) {
      setNotice(text.nameTaken);
      return;
    }
    void perform(async () => {
      form.reset();
      setNotice("");
      await change(
        { action: "grant", login, ...(!practice && { vpnPassword }) },
        formatMessage(text.granted, { login }),
      );
    });
  }

  function rotate(event: FormEvent<HTMLFormElement>, login: string) {
    event.preventDefault();
    const form = event.currentTarget;
    const vpnPassword = new FormData(form).get("vpnPassword");
    if (!practice && !validVpnPassword(vpnPassword)) {
      setNotice(text.invalidPassword);
      return;
    }
    void perform(async () => {
      form.reset();
      setNotice("");
      await change(
        {
          action: "rotate",
          login,
          ...(!practice && { vpnPassword }),
          confirmed: true,
        },
        formatMessage(practice ? example.passwordChanged : text.rotated, {
          login,
        }),
      );
    });
  }

  return (
    <section className={styles.guests} aria-labelledby="guest-access-title">
      <h3 id="guest-access-title" tabIndex={-1}>
        {text.title}
      </h3>
      <p>{text.intro}</p>
      <button
        type="button"
        className="button secondary"
        disabled={busy}
        onClick={() => {
          void perform(async () => {
            setNotice("");
            setRoster(null);
            await refresh();
          });
        }}
      >
        {roster ? text.refresh : text.load}
      </button>
      {roster && (
        <>
          <p className={styles.owner}>
            {text.owner} <strong dir="auto">{roster.owner}</strong>
          </p>
          {roster.guests.length ? (
            <ul className={styles.guestList}>
              {roster.guests.map((login) => (
                <li key={login}>
                  <strong dir="auto">{login}</strong>
                  {review?.login === login && review.action === "revoke" ? (
                    <>
                      <p>{formatMessage(text.confirmFor, { login })}</p>
                      <div className="button-row">
                        <button
                          type="button"
                          className="button secondary"
                          disabled={busy}
                          onClick={() => {
                            void perform(async () => {
                              setNotice("");
                              await change(
                                { action: "revoke", login, confirmed: true },
                                formatMessage(text.revoked, { login }),
                              );
                            });
                          }}
                        >
                          {text.confirm}
                        </button>
                        <button
                          type="button"
                          className="button quiet"
                          disabled={busy}
                          onClick={() => setReview(null)}
                        >
                          {text.keep}
                        </button>
                      </div>
                    </>
                  ) : review?.login === login && review.action === "rotate" ? (
                    <form
                      method="post"
                      onSubmit={(event) => rotate(event, login)}
                      autoComplete="off"
                    >
                      <p>{formatMessage(text.rotateFor, { login })}</p>
                      <fieldset disabled={busy}>
                        {!practice && (
                          <label>
                            {text.newPassword}
                            <input
                              name="vpnPassword"
                              type="password"
                              required
                              maxLength={127}
                              autoComplete="new-password"
                            />
                          </label>
                        )}
                        <div className="button-row">
                          <button className="button secondary" type="submit">
                            {practice
                              ? example.changePassword
                              : text.confirmRotation}
                          </button>
                          <button
                            className="button quiet"
                            type="button"
                            onClick={() => setReview(null)}
                          >
                            {text.keep}
                          </button>
                        </div>
                      </fieldset>
                    </form>
                  ) : (
                    <div className="button-row">
                      <button
                        type="button"
                        className="button quiet"
                        aria-label={formatMessage(text.rotateFor, { login })}
                        disabled={busy}
                        onClick={() => setReview({ action: "rotate", login })}
                      >
                        {text.rotate}
                      </button>
                      <button
                        type="button"
                        className="button secondary"
                        aria-label={formatMessage(
                          practice ? example.downloadFor : text.downloadFor,
                          { login },
                        )}
                        disabled={busy}
                        onClick={() => download(login)}
                      >
                        {practice ? example.download : text.download}
                      </button>
                      <button
                        type="button"
                        className="button quiet"
                        aria-label={formatMessage(text.revokeFor, { login })}
                        disabled={busy}
                        onClick={() => setReview({ action: "revoke", login })}
                      >
                        {text.revoke}
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p>{text.onlyOwner}</p>
          )}
          <form method="post" onSubmit={grant} autoComplete="off">
            <h4>{text.add}</h4>
            <fieldset disabled={busy}>
              <label>
                {practice ? example.guestUsername : text.username}
                <input
                  name="login"
                  required
                  maxLength={64}
                  spellCheck={false}
                  autoCapitalize="none"
                />
              </label>
              {!practice && (
                <>
                  <label>
                    {text.password}
                    <input
                      name="vpnPassword"
                      type="password"
                      required
                      maxLength={127}
                      autoComplete="off"
                      aria-describedby="guest-password-help"
                    />
                  </label>
                  <p id="guest-password-help" className={styles.hint}>
                    {text.passwordHint}
                  </p>
                </>
              )}
              <button className="button secondary" type="submit">
                {text.create}
              </button>
            </fieldset>
          </form>
        </>
      )}
      <p role="status" className={styles.notice}>
        {notice}
      </p>
    </section>
  );
}
