"use client";

import { createContext, useContext, type ReactNode } from "react";
import {
  getLanguage,
  getMessages,
  portalLanguages,
  type LanguagePreferences,
  type MessageScope,
} from "./messages";

const Languages = createContext<LanguagePreferences>(portalLanguages);

export function useLanguage(scope: MessageScope) {
  return getLanguage(scope, useContext(Languages));
}

export function useMessages<S extends MessageScope>(scope: S) {
  return getMessages(scope, useContext(Languages));
}

// An embedded workspace can receive its own language without changing its
// enclosing page or remounting a running operation.
export function ModuleLanguage({
  scope,
  language,
  children,
}: {
  scope: MessageScope;
  language?: string;
  children: ReactNode;
}) {
  const inherited = useContext(Languages);
  const preferences = language
    ? { ...inherited, [scope]: language }
    : inherited;
  const { tag, dir } = getLanguage(scope, preferences);
  return (
    <Languages.Provider value={preferences}>
      <div lang={tag} dir={dir} style={{ display: "contents" }}>
        {children}
      </div>
    </Languages.Provider>
  );
}
