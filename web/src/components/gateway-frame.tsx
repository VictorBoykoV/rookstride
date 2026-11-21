"use client";

import { useMessages } from "@/i18n/client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useSyncExternalStore, type ReactNode } from "react";

function watchLocation(notify: () => void) {
  window.addEventListener("hashchange", notify);
  window.addEventListener("popstate", notify);
  return () => {
    window.removeEventListener("hashchange", notify);
    window.removeEventListener("popstate", notify);
  };
}

const readHash = () => window.location.hash;
const serverHash = () => null;

export function useWorkspaceMode(personal = true) {
  const path = usePathname();
  const hash = useSyncExternalStore(watchLocation, readHash, serverHash);
  if (!personal) return "practice";
  if (path === "/manage/server") return "server";
  if (path === "/manage/pair") return "pair";
  if (hash === null) return null;
  return hash === "#practice" ? "practice" : "server";
}

export function focusWorkspaceStep(heading: HTMLElement | null | undefined) {
  if (!heading) return;
  const panel = heading.closest<HTMLElement>(".gateway-panel");
  if (panel && getComputedStyle(panel).overflowY === "auto") {
    panel.scrollTop = 0;
    heading.focus({ preventScroll: true });
  } else {
    heading.focus();
  }
}

export function GatewayFrame({
  children,
  personal,
  hosted = false,
}: {
  children: ReactNode;
  personal: boolean;
  hosted?: boolean;
}) {
  const copy = useMessages("manage");
  const text = copy.frame;
  const path = usePathname();
  const mode = useWorkspaceMode(personal);
  const panel = useRef<HTMLDivElement>(null);
  const previousMode = useRef(mode);

  useEffect(() => {
    if (previousMode.current && mode && mode !== previousMode.current) {
      if (panel.current) {
        panel.current.scrollTop = 0;
        panel.current.focus({ preventScroll: true });
      }
    }
    previousMode.current = mode;
  }, [mode]);

  return (
    <main className="gateway-app">
      <div className="gateway-frame">
        <header className="gateway-toolbar">
          <div className="gateway-title">
            <img src="/brand/rook-map.svg" width="36" height="40" alt="" />
            <h1>{personal || hosted ? text.title : text.practice}</h1>
          </div>
          {personal && (
            <nav className="gateway-modes" aria-label={text.mode}>
              <Link
                href="/manage/server"
                scroll={false}
                aria-current={mode === "server" ? "page" : undefined}
                onNavigate={
                  mode === "server"
                    ? (event) => event.preventDefault()
                    : undefined
                }
              >
                {text.server}
              </Link>
              <Link
                href="/manage/pair"
                scroll={false}
                aria-current={mode === "pair" ? "page" : undefined}
              >
                {copy.pair.navigation}
              </Link>
              {path === "/manage" ? (
                <a
                  href="#practice"
                  aria-current={mode === "practice" ? "page" : undefined}
                >
                  {text.practice}
                </a>
              ) : (
                <Link href="/manage#practice" scroll={false}>
                  {text.practice}
                </Link>
              )}
            </nav>
          )}
        </header>
        <div
          className="gateway-panel"
          ref={panel}
          tabIndex={0}
          role="region"
          aria-label={text.panel}
        >
          {children}
        </div>
      </div>
    </main>
  );
}
