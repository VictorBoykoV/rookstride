import { site } from "./en/site";
import { route } from "./en/route";
import { manage } from "./en/manage";

import {
  portalLanguages,
  resolveLanguage,
  type MessageScope,
} from "./language";

export {
  portalLanguages,
  type LanguagePreferences,
  type MessageScope,
} from "./language";

const english = { site, route, manage };
// Only complete, reviewed module catalogs belong in this registry. A future
// language can ship for the workspace before the editorial portal is ready.
type Catalog = {
  direction: "ltr" | "rtl";
  messages: Partial<typeof english>;
};
const catalogs: Record<string, Catalog | undefined> = {
  en: { direction: "ltr", messages: english },
};

export function getLanguage(
  scope: MessageScope,
  preferences = portalLanguages,
) {
  return resolveLanguage(scope, preferences, catalogs);
}

export function getMessages<S extends MessageScope>(
  scope: S,
  preferences = portalLanguages,
): (typeof english)[S] {
  const { tag } = getLanguage(scope, preferences);
  return catalogs[tag]?.messages[scope] ?? english[scope];
}
