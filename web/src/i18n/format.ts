// Replace only keys in the original template; user-provided values stay literal.
export function formatMessage(
  template: string,
  values: Record<string, string | number>,
) {
  return template.replace(
    /\{([A-Za-z][A-Za-z0-9_]*)\}/g,
    (match, name: string) =>
      Object.hasOwn(values, name) ? String(values[name]) : match,
  );
}
