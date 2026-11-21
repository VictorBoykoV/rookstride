"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMessages } from "@/i18n/client";
import { GatewayFrame } from "./gateway-frame";
import { PairInspection } from "./pair-inspection";
import { ServerSetup } from "./server-setup";
import styles from "./server-setup.module.css";

export function HostedSetup() {
  const copy = useMessages("manage").hosted;
  const [admission, setAdmission] = useState<{
    invite: string;
    ubuntuReinstall: boolean;
    ecdsa: boolean;
    pair: boolean;
    pairRebuild: boolean;
  } | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const invitationField = useRef<HTMLInputElement>(null);

  useEffect(() => setReady(true), []);

  async function admit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy) return;
    const form = event.currentTarget;
    const entered = invitationField.current?.value.trim();
    if (!entered) {
      setNotice(copy.rejected);
      return;
    }
    setBusy(true);
    setNotice("");
    try {
      const response = await fetch("/vpn/api", {
        headers: { "X-Rookstride-Invite": entered },
        cache: "no-store",
      });
      if (response.status === 204) {
        form.reset();
        setAdmission({
          invite: entered,
          ubuntuReinstall:
            response.headers.get("X-Rookstride-Ubuntu-Reinstall") === "1",
          ecdsa: response.headers.get("X-Rookstride-ECDSA") === "1",
          pair: response.headers.get("X-Rookstride-Pair") === "1",
          pairRebuild:
            response.headers.get("X-Rookstride-Pair-Rebuild") === "1",
        });
      } else
        setNotice(response.status === 401 ? copy.rejected : copy.unavailable);
    } catch {
      setNotice(copy.unavailable);
    } finally {
      setBusy(false);
    }
  }

  return (
    <GatewayFrame personal={false} hosted>
      {admission ? (
        admission.pair ? (
          <PairInspection
            invite={admission.invite}
            pairRebuild={admission.pairRebuild}
          />
        ) : (
          <ServerSetup
            invite={admission.invite}
            hostedReinstall={admission.ubuntuReinstall}
            hostedEcdsa={admission.ecdsa}
          />
        )
      ) : (
        <section className={styles.workspace}>
          <h2>{copy.heading}</h2>
          <p>{copy.intro}</p>
          <form method="post" onSubmit={admit} autoComplete="off">
            <fieldset disabled={!ready || busy}>
              <label>
                {copy.invitation}
                <input
                  ref={invitationField}
                  type="password"
                  required
                  maxLength={64}
                />
              </label>
              <button className="button primary" type="submit">
                {copy.open}
              </button>
            </fieldset>
          </form>
          <p className={styles.notice} role="status">
            {notice}
          </p>
        </section>
      )}
    </GatewayFrame>
  );
}
