export type MessageScope = "site" | "route" | "manage";
export type LanguagePreferences = {
  site: string;
  route?: string;
  manage?: string;
};

export const portalLanguages: LanguagePreferences = { site: "en" };

type Edition = {
  direction: "ltr" | "rtl";
  messages: Partial<Record<MessageScope, object>>;
};

export function resolveLanguage(
  scope: MessageScope,
  preferences: LanguagePreferences,
  editions: Record<string, Edition | undefined>,
) {
  const requested = preferences[scope] ?? preferences.site;
  const available =
    Object.hasOwn(editions, requested) && editions[requested]?.messages[scope];
  const tag = available ? requested : "en";
  return { tag, dir: editions[tag]!.direction };
}
