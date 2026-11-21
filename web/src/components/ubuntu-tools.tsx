"use client";

import { useState, type FormEvent } from "react";
import { useMessages } from "@/i18n/client";
import { formatMessage } from "@/i18n/format";
import { gatewayMessage } from "@/lib/gateway-messages";
import {
  readServerRecord,
  readUbuntuRecovery,
  ubuntuEraseConfirmation,
  ubuntuVersions,
} from "@/lib/gateway-input.mjs";
import styles from "./server-setup.module.css";

export type UbuntuRecoveryRecord = NonNullable<
  ReturnType<typeof readUbuntuRecovery>
>;
type ServerRecord = NonNullable<ReturnType<typeof readServerRecord>>;

type Transport = {
  busy: boolean;
  post: (payload: Record<string, unknown>) => Promise<Response>;
  perform: (task: () => Promise<void>) => Promise<void>;
};

function useUbuntuRequest(post: Transport["post"]) {
  const copy = useMessages("manage");

  return async (payload: Record<string, unknown>, onRejected?: () => void) => {
    const response = await post(payload);
    const body = await response.json().catch(() => null);
    if (!response.ok || !body) {
      if (
        [
          "invalidUbuntuReinstall",
          "ubuntuReviewExpired",
          "operationBusy",
          "sessionEnded",
        ].includes(body?.messageKey)
      )
        onRejected?.();
      throw new Error(
        gatewayMessage(
          copy.gateway,
          body?.messageKey,
          copy.gateway.ubuntuStatusUnavailable,
        ),
      );
    }
    return body;
  };
}

export function UbuntuReinstallTools({
  busy,
  post,
  perform,
  practice = false,
  rememberRecovery,
  discardRejectedRecovery,
}: Transport & {
  rememberRecovery: (record: UbuntuRecoveryRecord) => void;
  discardRejectedRecovery: () => void;
  practice?: boolean;
}) {
  const copy = useMessages("manage");
  const text = copy.ubuntu;
  const request = useUbuntuRequest(post);
  const [review, setReview] = useState<{
    code: string;
    recovery: UbuntuRecoveryRecord;
    diskBytes: number;
    boot: string;
  } | null>(null);

  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const ubuntu = new FormData(event.currentTarget).get("ubuntu");
    void perform(async () => {
      const body = await request({ action: "ubuntuReview", ubuntu });
      const recovery = readUbuntuRecovery(body.recovery);
      if (
        !recovery ||
        typeof body.review !== "string" ||
        !Number.isSafeInteger(body.diskBytes) ||
        !["EFI", "BIOS"].includes(body.boot)
      )
        throw new Error(text.invalidFile);
      setReview({
        code: body.review,
        recovery,
        diskBytes: body.diskBytes,
        boot: body.boot,
      });
    });
  }

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!review) return;
    const confirmation = practice
      ? ubuntuEraseConfirmation
      : new FormData(event.currentTarget).get("confirmation");
    if (confirmation !== ubuntuEraseConfirmation) return;
    void perform(async () => {
      // Store the verified future key before the request that may erase the disk.
      rememberRecovery(review.recovery);
      await request(
        { action: "ubuntuApply", review: review.code, confirmation },
        discardRejectedRecovery,
      );
    });
  }

  return (
    <section className={styles.guests} aria-labelledby="reinstall-ubuntu">
      <h3 id="reinstall-ubuntu" tabIndex={-1}>{text.title}</h3>
      {practice && <p>{copy.practice.simulatedUbuntuScope}</p>}
      {review ? (
        <form method="post" onSubmit={apply} autoComplete="off">
          <fieldset disabled={busy}>
            <legend>
              {formatMessage(text.version, { version: review.recovery.ubuntu })}
            </legend>
            <p>
              {formatMessage(text.scope, {
                size: (review.diskBytes / 1024 ** 3).toLocaleString(undefined, {
                  maximumFractionDigits: 2,
                }),
              })}
            </p>
            <p>
              {formatMessage(text.plan, {
                server: review.recovery.server.address,
                boot: review.boot,
              })}
            </p>
            <p>
              {text.fingerprint}{" "}
              <code dir="ltr" className={styles.fingerprint}>
                {review.recovery.fingerprint}
              </code>
            </p>
            {!practice && (
              <label>
                {text.confirm}
                <input
                  name="confirmation"
                  required
                  pattern={ubuntuEraseConfirmation}
                />
              </label>
            )}
            <div className="button-row">
              <button className="button primary" type="submit">
                {practice ? copy.practice.simulateUbuntu : text.apply}
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
      ) : (
        <form method="post" onSubmit={prepare}>
          <fieldset disabled={busy}>
            <label>
              {text.choose}
              <select name="ubuntu" defaultValue="24.04">
                {ubuntuVersions.map((version) => (
                  <option key={version} value={version}>
                    {formatMessage(text.version, { version })}
                  </option>
                ))}
              </select>
            </label>
            <button className="button secondary" type="submit">
              {text.review}
            </button>
          </fieldset>
        </form>
      )}
    </section>
  );
}

type RecoveryState =
  | "waiting"
  | "preparing"
  | "rebooting"
  | "failed"
  | "cancelled"
  | "expired"
  | "unverified"
  | "keyMismatch"
  | "providerRecovery"
  | "complete";

export function UbuntuRecoveryTools({
  busy,
  post,
  perform,
  practice = false,
  recovery,
  save,
  openSetup,
}: Transport & {
  recovery: UbuntuRecoveryRecord;
  practice?: boolean;
  save: (blob: Blob, filename: string) => void;
  openSetup: (server?: ServerRecord) => void;
}) {
  const copy = useMessages("manage");
  const text = copy.ubuntu;
  const request = useUbuntuRequest(post);
  const [state, setState] = useState<RecoveryState>("waiting");
  const [server, setServer] = useState<ServerRecord | null>(null);
  const finished = ["failed", "cancelled", "expired", "complete"].includes(
    state,
  );

  function download(
    value: ServerRecord | UbuntuRecoveryRecord,
    filename: string,
  ) {
    save(
      new Blob([JSON.stringify(value, null, 2) + "\n"], {
        type: "application/json",
      }),
      practice ? `sample-${filename}` : filename,
    );
  }

  function check(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const field = form.elements.namedItem(
      "password",
    ) as HTMLInputElement | null;
    const password = field?.value;
    if (field) field.value = "";
    void perform(async () => {
      const result = await request({
        action: "ubuntuResume",
        recovery,
        ...(!practice && { password }),
      });
      const reported = result.state;
      if (
        typeof reported !== "string" ||
        ![
          "waiting",
          "preparing",
          "rebooting",
          "failed",
          "cancelled",
          "expired",
          "unverified",
          "keyMismatch",
          "providerRecovery",
          "complete",
        ].includes(reported)
      )
        throw new Error(copy.gateway.ubuntuStatusUnavailable);
      if (reported === "complete") {
        const updated = readServerRecord(result.server);
        if (
          !updated ||
          updated.version !== 2 ||
          updated.fingerprint !== recovery.fingerprint ||
          result.ubuntu !== recovery.ubuntu ||
          updated.address !== recovery.server.address ||
          updated.sshPort !== recovery.server.sshPort
        )
          throw new Error(copy.gateway.ubuntuStatusUnavailable);
        setServer(updated);
      }
      setState(reported as RecoveryState);
    });
  }

  return (
    <section aria-labelledby="ubuntu-progress" className={styles.guests}>
      <h2 id="ubuntu-progress" tabIndex={-1}>
        {text.recoveryTitle}
      </h2>
      <p>
        {practice
          ? copy.practice.simulatedUbuntuScope
          : formatMessage(text.recoveryScope, {
              version: recovery.ubuntu,
              server: recovery.server.address,
            })}
      </p>
      <p role="status">
        {practice && state === "complete"
          ? copy.practice.simulatedUbuntuComplete
          : practice && ["waiting", "rebooting"].includes(state)
            ? copy.practice.simulatedUbuntuProgress
            : text[state]}
      </p>
      {!finished && (
        <form method="post" onSubmit={check} autoComplete="off">
          <fieldset disabled={busy}>
            {!practice && (
              <label>
                {copy.live.rootPassword}
                <input
                  type="password"
                  name="password"
                  required
                  autoComplete="off"
                />
              </label>
            )}
            <button className="button primary" type="submit">
              {text.check}
            </button>
          </fieldset>
        </form>
      )}
      <div className="button-row">
        {server ? (
          <button
            className="button secondary"
            type="button"
            onClick={() => download(server, "rookstride-server.json")}
          >
            {text.keep}
          </button>
        ) : (
          <button
            className="button secondary"
            type="button"
            onClick={() =>
              download(recovery, "rookstride-ubuntu-recovery.json")
            }
          >
            {text.save}
          </button>
        )}
        {finished && (
          <button
            className="button primary"
            type="button"
            onClick={() => openSetup(server ?? undefined)}
          >
            {server ? text.continue : text.dismiss}
          </button>
        )}
      </div>
      {!practice && <p>{text.savedHint}</p>}
    </section>
  );
}
