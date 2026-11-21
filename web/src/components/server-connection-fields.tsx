"use client";

import { useMessages } from "@/i18n/client";
import type { readServerRecord } from "@/lib/gateway-input.mjs";
import styles from "./server-setup.module.css";

export function ServerConnectionFields({
  prefix = "",
  allowEcdsa = false,
  initial,
}: {
  prefix?: string;
  allowEcdsa?: boolean;
  initial?: ReturnType<typeof readServerRecord>;
}) {
  const text = useMessages("manage").live;
  return (
    <>
      <div className={styles.addressRow}>
        <label>
          {text.address}
          <input
            name={prefix + "address"}
            dir="ltr"
            inputMode="decimal"
            required
            pattern={"[0-9]{1,3}(\\.[0-9]{1,3}){3}"}
            placeholder="203.0.113.10"
            maxLength={15}
            defaultValue={initial?.address}
          />
        </label>
        <label>
          {text.port}
          <input
            name={prefix + "sshPort"}
            dir="ltr"
            type="number"
            required
            min={1}
            max={65535}
            defaultValue={initial?.sshPort ?? 22}
          />
        </label>
      </div>
      {allowEcdsa && (
        <label>
          {text.keyType}
          <select
            name={prefix + "keyType"}
            defaultValue={initial?.keyType ?? "ssh-ed25519"}
          >
            <option value="ssh-ed25519">{text.ed25519}</option>
            <option value="ecdsa-sha2-nistp256">{text.ecdsa}</option>
          </select>
        </label>
      )}
      <label>
        {text.fingerprint}
        <input
          name={prefix + "fingerprint"}
          dir="ltr"
          required
          placeholder="SHA256:…"
          minLength={50}
          maxLength={50}
          pattern={String.raw`SHA256:[A-Za-z0-9+\/]{43}`}
          title={text.fingerprintFormat}
          autoCapitalize="none"
          spellCheck={false}
          defaultValue={initial?.fingerprint}
        />
      </label>
      <label>
        {text.rootPassword}
        <input
          name={prefix + "password"}
          type="password"
          required
          autoComplete="off"
        />
      </label>
    </>
  );
}
