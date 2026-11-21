"use client";

import { useMessages } from "@/i18n/client";
import { useState } from "react";
import { Icon } from "./icons";

export function PartnerBrief() {
  const copy = useMessages("site").pilot;
  const brief = [
    copy.brief,
    "https://github.com/VictorBoykoV/rookstride/releases",
    "https://github.com/VictorBoykoV/rookstride",
  ].join("\n");
  const [status, setStatus] = useState("");

  async function copyBrief() {
    try {
      await navigator.clipboard.writeText(brief);
      setStatus(copy.copied);
    } catch {
      setStatus(copy.failed);
    }
  }

  return (
    <section
      className="partner-brief"
      id="pilot-brief"
      aria-labelledby="brief-title"
    >
      <h2 id="brief-title">{copy.title}</h2>
      <p>{copy.lead}</p>
      <button type="button" className="button primary" onClick={copyBrief}>
        <Icon name="copy" />
        {copy.copy}
      </button>
      <p role="status">{status}</p>
      <details>
        <summary>{copy.read}</summary>
        <pre tabIndex={0}>{brief}</pre>
      </details>
    </section>
  );
}
