"use client";

import { useId, useRef, useState, type DragEvent, type FormEvent } from "react";
import { useMessages } from "@/i18n/client";
import styles from "./server-setup.module.css";

export const pairLogin = /^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/;
const archiveLimit = 2 * 1024 * 1024;
export const archiveCodeLimit = 4 * Math.ceil(archiveLimit / 3);
const archiveMagic = "ROOKREC1";
const archiveFilename = "rookstride-owner-recovery.rookrec";
const removalConfirmation = "DELETE PAIR";

type PairView = {
  owner: string;
  users: string[];
  revision: string;
  entryHealthy: boolean;
  exitHealthy: boolean;
  dnsHealthy: boolean;
};

type Props = {
  owner: string;
  busy: boolean;
  post: (
    body: { action: string; [key: string]: unknown },
    signal: AbortSignal,
  ) => Promise<Response>;
  run: (work: (signal: AbortSignal) => Promise<void>, fallback: string) => void;
  download: (login: string) => void;
  remove: (review: string, confirmation: string) => void;
  notify: (message: string) => void;
};

async function readView(response: Response, owner: string): Promise<PairView> {
  if (!response.ok) throw new Error("pair view");
  const view = (await response.json()) as Partial<PairView> | null;
  if (
    view?.owner !== owner ||
    !Array.isArray(view.users) ||
    !view.users.every(
      (login) => typeof login === "string" && pairLogin.test(login),
    ) ||
    typeof view.revision !== "string" ||
    !/^[a-f0-9]{64}$/.test(view.revision) ||
    typeof view.entryHealthy !== "boolean" ||
    typeof view.exitHealthy !== "boolean" ||
    typeof view.dnsHealthy !== "boolean"
  )
    throw new Error("pair view");
  return {
    owner,
    users: [...new Set(view.users)].filter((login) => login !== owner),
    revision: view.revision,
    entryHealthy: view.entryHealthy,
    exitHealthy: view.exitHealthy,
    dnsHealthy: view.dnsHealthy,
  };
}

export async function savePairFile(
  response: Response,
  filename: string,
  signal: AbortSignal,
  maximum = 128 * 1024,
) {
  const file = await readPairFile(response, signal, maximum);
  if (!file) return false;
  const address = URL.createObjectURL(file);
  const anchor = document.createElement("a");
  anchor.href = address;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(address), 1000);
  return true;
}

async function readPairFile(
  response: Response,
  signal: AbortSignal,
  maximum: number,
) {
  if (
    !response.ok ||
    response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      .toLowerCase()
      .trim() !== "application/octet-stream"
  )
    throw new Error("pair download");
  const length = response.headers.get("content-length");
  if (length !== null && Number(length) > maximum)
    throw new Error("pair download");
  const file = await response.blob();
  if (signal.aborted) return;
  if (!file.size || file.size > maximum) throw new Error("pair download");
  return file;
}

export async function encodeArchive(file: Blob) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!bytes.length || bytes.length > archiveLimit)
    throw new Error("pair archive");
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16384)
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 16384)));
  const binary = chunks.join("");
  if (!binary.startsWith(archiveMagic)) throw new Error("pair archive format");
  return btoa(binary);
}

export function isRecoveryFile(file: FormDataEntryValue | null): file is File {
  return (
    file instanceof File &&
    file.name.toLowerCase().endsWith(".rookrec") &&
    file.size > 0 &&
    file.size <= archiveLimit
  );
}

export function isCanonicalArchiveCode(code: string) {
  if (!code.length || code.length > archiveCodeLimit) return false;
  try {
    const bytes = atob(code);
    return (
      bytes.startsWith(archiveMagic) &&
      bytes.length <= archiveLimit &&
      btoa(bytes) === code
    );
  } catch {
    return false;
  }
}

export function PairManagement({
  owner,
  busy,
  post,
  run,
  download,
  remove,
  notify,
}: Props) {
  const copy = useMessages("manage");
  const text = copy.pair.management;
  const [view, setView] = useState<PairView | null>(null);
  const [revoke, setRevoke] = useState("");
  const [removal, setRemoval] = useState("");
  const [archiveSource, setArchiveSource] = useState<"file" | "code">("file");
  const [droppedArchive, setDroppedArchive] = useState<File | null>(null);
  const [recoveryCode, setRecoveryCode] = useState("");
  const recoveryPanel = useRef<HTMLDetailsElement>(null);
  const archiveInput = useRef<HTMLInputElement>(null);
  const codeOutput = useRef<HTMLTextAreaElement>(null);
  const archiveHint = useId();

  function refresh() {
    setView(null);
    setRevoke("");
    run(async (signal) => {
      const result = await readView(
        await post({ action: "pairManage" }, signal),
        owner,
      );
      if (!signal.aborted) setView(result);
    }, text.unavailable);
  }

  function account(operation: "grant" | "revoke", login: string) {
    if (busy || !view || login === owner || !pairLogin.test(login)) return;
    const revision = view.revision;
    setView(null);
    setRevoke("");
    setRemoval("");
    run(async (signal) => {
      const response = await post(
        { action: "pairAccount", operation, login, revision, confirmed: true },
        signal,
      );
      const result = await readView(response, owner);
      if (signal.aborted) return;
      setView(result);
      notify(text.saved);
    }, text.refreshAfterChange);
  }

  function grant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const login = String(new FormData(form).get("login") ?? "").trim();
    if (!pairLogin.test(login)) {
      notify(copy.pair.invalidLogin);
      return;
    }
    account("grant", login);
  }

  function reviewRemoval() {
    setRemoval("");
    run(async (signal) => {
      const response = await post({ action: "pairRemoveReview" }, signal);
      const result = await response.json().catch(() => null);
      if (
        !response.ok ||
        typeof result?.review !== "string" ||
        !/^[A-Za-z0-9_-]{32}$/.test(result.review)
      )
        throw new Error("pair removal review");
      if (!signal.aborted) setRemoval(result.review);
    }, text.removeReviewFailed);
  }

  function applyRemoval(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const confirmation = new FormData(form).get("confirmation");
    if (busy || !removal || confirmation !== removalConfirmation) return;
    form.reset();
    setRemoval("");
    remove(removal, confirmation);
  }

  function selectArchiveSource(source: "file" | "code") {
    if (source === archiveSource) return;
    setDroppedArchive(null);
    setArchiveSource(source);
  }

  function dropArchive(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    if (busy) return;
    const files = event.dataTransfer.files;
    const file = files.item(0);
    if (archiveInput.current) archiveInput.current.value = "";
    setDroppedArchive(null);
    if (files.length !== 1 || !isRecoveryFile(file)) {
      notify(text.archiveInvalid);
      return;
    }
    setDroppedArchive(file);
    notify("");
  }

  async function copyRecoveryCode() {
    if (!recoveryCode) return;
    try {
      await navigator.clipboard.writeText(recoveryCode);
      notify(text.archiveCodeCopied);
    } catch {
      codeOutput.current?.focus();
      codeOutput.current?.select();
      notify(text.archiveCodeSelected);
    }
  }

  function recovery(event: FormEvent<HTMLFormElement>, rehearse = false) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const formData = new FormData(form);
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const showCode =
      !rehearse &&
      submitter instanceof HTMLButtonElement &&
      submitter.value === "code";
    const password = formData.get("password");
    const file = droppedArchive ?? formData.get("archive");
    const pastedCode = String(formData.get("archiveCode") ?? "").trim();
    form.reset();
    if (
      formData.get("confirmed") !== "on" ||
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 256
    )
      return;
    if (rehearse) {
      setDroppedArchive(null);
      if (archiveSource === "file" && !isRecoveryFile(file)) {
        notify(text.archiveInvalid);
        return;
      }
      if (archiveSource === "code" && !isCanonicalArchiveCode(pastedCode)) {
        notify(text.archiveCodeInvalid);
        return;
      }
    }
    if (showCode) setRecoveryCode("");
    run(
      async (signal) => {
        if (rehearse) {
          const archive = isRecoveryFile(file)
            ? await encodeArchive(file)
            : pastedCode;
          if (signal.aborted) return;
          const response = await post(
            { action: "pairRehearse", password, archive, confirmed: true },
            signal,
          );
          const result = await response.json().catch(() => null);
          if (!response.ok || result?.ready !== true)
            throw new Error("pair recovery check");
          if (!signal.aborted) notify(text.rehearseReady);
          return;
        }
        const response = await post(
          { action: "pairBackup", password, confirmed: true },
          signal,
        );
        if (showCode) {
          const encrypted = await readPairFile(response, signal, archiveLimit);
          if (!encrypted) return;
          const code = await encodeArchive(encrypted);
          if (!signal.aborted && recoveryPanel.current?.open) {
            setRecoveryCode(code);
            notify(text.archiveCodeReady);
          }
          return;
        }
        if (await savePairFile(response, archiveFilename, signal, archiveLimit))
          notify(text.backupStarted);
      },
      rehearse ? text.rehearseFailed : text.backupFailed,
    );
  }

  return (
    <section className={styles.guests} aria-label={text.heading}>
      <h3>{text.heading}</h3>
      <button
        className="button secondary"
        type="button"
        onClick={refresh}
        disabled={busy}
      >
        {text.refresh}
      </button>
      {view && (
        <>
          <h4>{text.health}</h4>
          <ul className={styles.plan}>
            {(
              [
                [copy.pair.entry, view.entryHealthy],
                [copy.pair.exit, view.exitHealthy],
                [text.dns, view.dnsHealthy],
              ] as const
            ).map(([label, healthy]) => (
              <li key={label}>
                <strong>{label}</strong> ·{" "}
                {healthy ? text.healthy : text.unhealthy}
              </li>
            ))}
          </ul>
          <h4>{text.users}</h4>
          <p>
            {text.owner} · <bdi>{view.owner}</bdi>
          </p>
          <ul className={styles.guestList}>
            {view.users.map((login) => (
              <li key={login}>
                <strong>
                  <bdi>{login}</bdi>
                </strong>
                {revoke === login ? (
                  <>
                    <p>
                      {text.revokePrompt} <bdi>{login}</bdi>?
                    </p>
                    <p>{text.revokeImpact}</p>
                    <div className="button-row">
                      <button
                        className="button primary"
                        type="button"
                        onClick={() => account("revoke", login)}
                        disabled={busy}
                      >
                        {text.confirmRevoke}
                      </button>
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => setRevoke("")}
                        disabled={busy}
                      >
                        {text.cancel}
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="button-row">
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => download(login)}
                      disabled={busy}
                    >
                      {text.exportUser}
                    </button>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => setRevoke(login)}
                      disabled={busy}
                    >
                      {text.revoke}
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
          <form method="post" onSubmit={grant} autoComplete="off">
            <label>
              {text.username}
              <input
                name="login"
                maxLength={48}
                required
                autoCapitalize="none"
                spellCheck={false}
                disabled={busy}
              />
            </label>
            <button className="button secondary" type="submit" disabled={busy}>
              {text.grant}
            </button>
          </form>
        </>
      )}
      <details
        className={styles.pairManagementPanel}
        ref={recoveryPanel}
        onToggle={(event) => {
          if (!event.currentTarget.open) setRecoveryCode("");
        }}
      >
        <summary>{text.recovery}</summary>
        {[false, true].map((rehearse) => (
          <form
            key={String(rehearse)}
            method="post"
            onSubmit={(event) => recovery(event, rehearse)}
            autoComplete="off"
          >
            <h4>{rehearse ? text.rehearse : text.backup}</h4>
            <p>{rehearse ? text.rehearseIntro : text.backupIntro}</p>
            {rehearse && (
              <>
                <div
                  className="button-row"
                  role="group"
                  aria-label={text.archiveSource}
                >
                  <button
                    type="button"
                    className="button secondary"
                    aria-pressed={archiveSource === "file"}
                    onClick={() => selectArchiveSource("file")}
                    disabled={busy}
                  >
                    {text.archiveFileOption}
                  </button>
                  <button
                    type="button"
                    className="button secondary"
                    aria-pressed={archiveSource === "code"}
                    onClick={() => selectArchiveSource("code")}
                    disabled={busy}
                  >
                    {text.archiveCodeOption}
                  </button>
                </div>
                {archiveSource === "file" ? (
                  <label
                    className={styles.archiveDrop}
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={dropArchive}
                  >
                    {text.archive}
                    <span id={archiveHint}>{text.archiveDrop}</span>
                    <input
                      ref={archiveInput}
                      type="file"
                      name="archive"
                      accept=".rookrec,application/octet-stream"
                      aria-describedby={archiveHint}
                      onChange={() => setDroppedArchive(null)}
                      disabled={busy}
                    />
                    {droppedArchive && (
                      <span role="status">
                        {text.archiveSelected} <bdi>{droppedArchive.name}</bdi>
                      </span>
                    )}
                  </label>
                ) : (
                  <label className={styles.archiveDrop}>
                    {text.archiveCode}
                    <textarea
                      className={styles.archiveCode}
                      name="archiveCode"
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
              </>
            )}
            <label>
              {text.password}
              <input
                type="password"
                name="password"
                minLength={12}
                maxLength={256}
                required
                autoComplete="off"
                disabled={busy}
              />
              <span>{text.passwordHint}</span>
            </label>
            <label className={styles.check}>
              <input
                type="checkbox"
                name="confirmed"
                required
                disabled={busy}
              />
              {rehearse ? text.rehearseConfirm : text.backupConfirm}
            </label>
            <div className="button-row">
              <button
                className="button secondary"
                type="submit"
                disabled={busy}
              >
                {rehearse ? text.rehearse : text.backup}
              </button>
              {!rehearse && (
                <button
                  className="button secondary"
                  type="submit"
                  value="code"
                  disabled={busy}
                >
                  {text.showArchiveCode}
                </button>
              )}
            </div>
            {!rehearse && recoveryCode && (
              <div className={styles.archiveCodeOutput}>
                <p>{text.archiveCodeIntro}</p>
                <label>
                  {text.archiveCode}
                  <textarea
                    className={styles.archiveCode}
                    ref={codeOutput}
                    value={recoveryCode}
                    readOnly
                    rows={3}
                    wrap="off"
                    spellCheck={false}
                  />
                </label>
                <div className="button-row">
                  <button
                    className="button secondary"
                    type="button"
                    onClick={copyRecoveryCode}
                  >
                    {text.copyArchiveCode}
                  </button>
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => setRecoveryCode("")}
                  >
                    {text.hideArchiveCode}
                  </button>
                </div>
              </div>
            )}
          </form>
        ))}
      </details>
      <details className={styles.pairManagementPanel}>
        <summary>{text.removal}</summary>
        <p>{text.removalSummary}</p>
        {removal ? (
          <form method="post" onSubmit={applyRemoval} autoComplete="off">
            <label>
              {text.removeConfirmation}
              <input
                name="confirmation"
                required
                pattern={removalConfirmation}
                maxLength={removalConfirmation.length}
                spellCheck={false}
                disabled={busy}
              />
            </label>
            <div className="button-row">
              <button className="button primary" type="submit" disabled={busy}>
                {text.removeNow}
              </button>
              <button
                className="button secondary"
                type="button"
                disabled={busy}
                onClick={() => setRemoval("")}
              >
                {text.cancel}
              </button>
            </div>
          </form>
        ) : (
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={reviewRemoval}
          >
            {text.reviewRemoval}
          </button>
        )}
      </details>
    </section>
  );
}
