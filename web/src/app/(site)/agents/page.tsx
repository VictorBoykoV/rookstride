import { getMessages } from "@/i18n/messages";
import { resolve } from "node:path";
import Link from "next/link";
import { AgentSetup, type Host } from "@/components/agent-setup";
import { publicSiteOrigin, webRuntimeRole } from "@/lib/web-runtime.mjs";
import { publicPageMetadata } from "@/lib/site-discovery";
const copy = getMessages("site").agents;

export const dynamic = "force-dynamic";
export function generateMetadata() {
  return publicPageMetadata("/agents", copy.metaTitle, copy.lead);
}
const hostNames = new Map<string, Host>([
  ["codex", "Codex"],
  ["claude", "Claude Code"],
  ["cursor", "Cursor"],
  ["gemini", "Gemini CLI"],
]);
export default async function Agents({
  searchParams,
}: {
  searchParams: Promise<{ client?: string | string[] }>;
}) {
  const { client } = await searchParams;
  const root = process.env.ROOKSTRIDE_WEB_ROOT;
  const localConnector = webRuntimeRole() === "workstation" && root;
  const remoteOrigin = publicSiteOrigin();
  const connector = remoteOrigin
    ? { url: new URL("/mcp", remoteOrigin).href }
    : localConnector
      ? {
          nodePath: process.execPath,
          runnerPath: resolve(localConnector, "scripts/mcp-preview.mjs"),
        }
      : undefined;
  const initialHost =
    hostNames.get(typeof client === "string" ? client : "") || "Codex";
  return (
    <main className="page-width inner-page">
      <div className="page-intro">
        <Link className="back-link" href="/start">
          {copy.back}
        </Link>
        <h1>{copy.title}</h1>
        <p>{copy.lead}</p>
      </div>
      {connector ? (
        <AgentSetup connector={connector} initialHost={initialHost} />
      ) : (
        <section>
          <p>{copy.hostedConnector}</p>
          <Link className="button secondary" href="/manage?mode=practice">
            {copy.openPractice}
          </Link>
        </section>
      )}
      <div className="agent-notes">
        {connector && (
          <section>
            <h2>{copy.how}</h2>
            <p>{copy.tools}</p>
          </section>
        )}
        <section>
          <h2>{copy.operatorTitle}</h2>
          <p>{copy.operatorBody}</p>
        </section>
        <section>
          <h2>{copy.own}</h2>
          <p>{localConnector ? copy.chooseBody : copy.hostedChooseBody}</p>
          <Link className="text-link" href="/start">
            {copy.choose}
          </Link>
          {connector && (
            <details>
              <summary>{copy.details}</summary>
              <p>{remoteOrigin ? copy.remoteCompatible : copy.compatible}</p>
            </details>
          )}
        </section>
      </div>
    </main>
  );
}
