// Only the typed operation response determines the visible status. Diagnostic
// text from an upstream service is never interpreted as a translation key.
export function gatewayMessage(
  messages: Record<string, string>,
  key: unknown,
  fallback = "",
) {
  return typeof key === "string" && Object.hasOwn(messages, key)
    ? messages[key]
    : fallback;
}
