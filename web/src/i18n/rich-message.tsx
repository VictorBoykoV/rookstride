import { Fragment, type ReactNode } from "react";

// Named slots let translators move an emphasized phrase or a technical value.
// React escapes the values. Catalog entries contain no HTML.
export function RichMessage({
  text,
  values,
}: {
  text: string;
  values: Record<string, ReactNode>;
}) {
  return text.split(/(\{[A-Za-z][A-Za-z0-9_]*\})/).map((part, index) => {
    const key = part.slice(1, -1);
    return part.startsWith("{") && Object.hasOwn(values, key) ? (
      <Fragment key={index}>{values[key]}</Fragment>
    ) : (
      part
    );
  });
}
