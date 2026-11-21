"use client";
import { useMessages } from "@/i18n/client";
import { formatMessage } from "@/i18n/format";
import { RichMessage } from "@/i18n/rich-message";
import { useRef, useState } from "react";
import { Icon } from "./icons";

export type Host = "Codex" | "Claude Code" | "Cursor" | "Gemini CLI";
const hosts: Host[] = ["Codex", "Claude Code", "Cursor", "Gemini CLI"];
const slugs: Record<Host, string> = {
  Codex: "codex",
  "Claude Code": "claude",
  Cursor: "cursor",
  "Gemini CLI": "gemini",
};
const clients: Record<Host, { file: string; url: string; icon: string }> = {
  Codex: {
    file: "~/.codex/config.toml",
    url: "https://learn.chatgpt.com/docs/extend/mcp",
    icon: "codex.webp",
  },
  "Claude Code": {
    file: ".mcp.json",
    url: "https://code.claude.com/docs/en/mcp",
    icon: "claude-code.webp",
  },
  Cursor: {
    file: ".cursor/mcp.json",
    url: "https://cursor.com/docs/mcp",
    icon: "cursor-cube.svg",
  },
  "Gemini CLI": {
    file: ".gemini/settings.json",
    url: "https://geminicli.com/docs/tools/mcp-server/",
    icon: "gemini-cli.svg",
  },
};
type Connector = { url: string } | { nodePath: string; runnerPath: string };

function connectionSettings(host: Host, connector: Connector) {
  if (host === "Codex") {
    const settings =
      "url" in connector
        ? `url = ${JSON.stringify(connector.url)}`
        : `command = ${JSON.stringify(connector.nodePath)}\nargs = [${JSON.stringify(connector.runnerPath)}]`;
    return `[mcp_servers.rookstride-preview]\n${settings}`;
  }
  let settings;
  if (!("url" in connector))
    settings = { command: connector.nodePath, args: [connector.runnerPath] };
  else if (host === "Claude Code")
    settings = { type: "http", url: connector.url };
  else if (host === "Gemini CLI") settings = { httpUrl: connector.url };
  else settings = { url: connector.url };
  return JSON.stringify(
    { mcpServers: { "rookstride-preview": settings } },
    null,
    2,
  );
}

export function AgentSetup({
  connector,
  initialHost = "Codex",
}: {
  connector: Connector;
  initialHost?: Host;
}) {
  const copy = useMessages("site").assistant;
  const task = copy.task;
  const [host, setHost] = useState<Host>(initialHost),
    [feedback, setFeedback] = useState("");
  const instructions = useRef<HTMLHeadingElement>(null);
  const feedbackVersion = useRef(0);
  const config = connectionSettings(host, connector);
  function choose(name: Host) {
    feedbackVersion.current++;
    setHost(name);
    setFeedback("");
    const url = new URL(location.href);
    url.searchParams.set("client", slugs[name]);
    history.replaceState(null, "", url);
    requestAnimationFrame(() => instructions.current?.focus());
  }
  async function copyText(text: string, success: string) {
    const version = ++feedbackVersion.current;
    try {
      await navigator.clipboard.writeText(text);
      if (version === feedbackVersion.current) setFeedback(success);
    } catch {
      if (version === feedbackVersion.current) setFeedback(copy.copyFailed);
    }
  }
  return (
    <div className="agent-setup">
      <div className="assistant-picker">
        <h2>{copy.choose}</h2>
        <p>{copy.lead}</p>
        <div className="assistant-buttons">
          {hosts.map((name) => (
            <button
              type="button"
              key={name}
              aria-label={formatMessage(copy.show, { host: name })}
              aria-pressed={host === name}
              onClick={() => choose(name)}
            >
              <span className="assistant-symbol" aria-hidden="true">
                <img
                  src={`/brand/assistants/${clients[name].icon}`}
                  width="32"
                  height="32"
                  alt=""
                />
              </span>
              <strong>{name}</strong>
              <span>
                {copy.steps}
                <Icon name="arrow" />
              </span>
            </button>
          ))}
        </div>
      </div>
      <div className="agent-instructions">
        <p className="section-kicker">{copy.tools}</p>
        <h2 ref={instructions} tabIndex={-1}>
          {formatMessage(copy.connect, { host })}
        </h2>
        <p>{copy.practice}</p>
        <ol className="connection-steps">
          <li>
            <RichMessage
              text={copy.open}
              values={{
                host,
                file: (
                  <bdi dir="ltr" className="config-location">
                    {clients[host].file}
                  </bdi>
                ),
              }}
            />
          </li>
          <li>{copy.merge}</li>
          <li>{copy.reload}</li>
        </ol>
        <div className="code-block">
          <div className="code-toolbar">
            <span>{formatMessage(copy.settings, { host })}</span>
            <button
              type="button"
              className="copy-button"
              onClick={() =>
                copyText(config, formatMessage(copy.settingsCopied, { host }))
              }
            >
              <Icon name="copy" />
              {copy.copySettings}
            </button>
          </div>
          <pre
            dir="ltr"
            tabIndex={0}
            aria-label={formatMessage(copy.settingsLabel, { host })}
          >
            <code>{config}</code>
          </pre>
        </div>
        <p className="config-feedback" role="status" aria-live="polite">
          {feedback || copy.feedback}
        </p>
        <p className="agent-help">
          {"url" in connector ? copy.remoteHelp : copy.help}{" "}
          <a href={clients[host].url} target="_blank" rel="noreferrer">
            {formatMessage(copy.docs, { host })}
            <Icon name="external" />
          </a>
        </p>
        <section className="agent-task">
          <h3>{copy.taskHeading}</h3>
          <p className="prepared-task" tabIndex={0}>
            {task}
          </p>
          <button
            type="button"
            className="copy-button"
            onClick={() => copyText(task, copy.taskCopied)}
          >
            <Icon name="copy" />
            {copy.copyTask}
          </button>
          {host === "Codex" && (
            <div className="draft-launch">
              <a
                className="button secondary"
                href={`codex://new?prompt=${encodeURIComponent(task)}`}
              >
                {copy.draft}
                <Icon name="external" />
              </a>
              <p>{copy.draftHelp}</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
