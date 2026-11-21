"use client";

import { useId, useState } from "react";
import type { scopedAdministratorStatus } from "@/i18n/en/administrators";
import { cleanScopedAdministration } from "@/lib/scoped-administration.mjs";
import styles from "./server-setup.module.css";

type Props = {
  busy: boolean;
  post: (payload: Record<string, unknown>) => Promise<Response>;
  perform: (
    task: () => Promise<void>,
    onError?: (message: string) => void,
  ) => Promise<void>;
  copy: typeof scopedAdministratorStatus;
};

export function ScopedAdministratorStatus({
  busy,
  post,
  perform,
  copy,
}: Props) {
  const heading = useId();
  const [status, setStatus] = useState<ReturnType<
    typeof cleanScopedAdministration
  > | null>(null);

  function check() {
    void perform(
      async () => {
        setStatus(null);
        const response = await post({ action: "administrationStatus" });
        setStatus(
          cleanScopedAdministration(response.ok ? await response.json() : null),
        );
      },
      () => setStatus({ state: "unavailable" }),
    );
  }

  return (
    <section aria-labelledby={heading} className={styles.guests}>
      <h3 id={heading}>{copy.title}</h3>
      <button
        type="button"
        className="button secondary"
        disabled={busy}
        onClick={check}
      >
        {copy.check}
      </button>
      <p role="status" className={styles.notice}>
        {status && copy.states[status.state]}
      </p>
      {status?.state === "enabled" && (
        <ul className={styles.guestList}>
          {status.roles.map(({ role, devices, invitations }) => (
            <li key={role}>
              <strong>{copy.roles[role]}</strong>
              <dl className={styles.vpnDetails}>
                <div>
                  <dt>{copy.devices}</dt>
                  <dd>{devices}</dd>
                </div>
                <div>
                  <dt>{copy.invitations}</dt>
                  <dd>{invitations}</dd>
                </div>
              </dl>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
