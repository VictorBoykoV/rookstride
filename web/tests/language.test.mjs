import test from "node:test";
import assert from "node:assert/strict";
import { portalLanguages, resolveLanguage } from "../src/i18n/language.ts";
import { formatMessage } from "../src/i18n/format.ts";

test("a module inherits the site language, can select its own and falls back independently", () => {
  const editions = {
    en: { direction: "ltr", messages: { site: {}, route: {}, manage: {} } },
    ar: { direction: "rtl", messages: { manage: {} } }, // Test fixture only.
  };
  const preferences = { site: "en", manage: "ar" };
  assert.deepEqual(resolveLanguage("manage", preferences, editions), {
    tag: "ar",
    dir: "rtl",
  });
  assert.deepEqual(resolveLanguage("site", preferences, editions), {
    tag: "en",
    dir: "ltr",
  });
  assert.equal(resolveLanguage("manage", { site: "ar" }, editions).tag, "ar");
  assert.equal(resolveLanguage("route", { site: "ar" }, editions).tag, "en");
  for (const requested of ["fa", "constructor", "__proto__"]) {
    assert.equal(
      resolveLanguage("manage", { site: "en", manage: requested }, editions)
        .tag,
      "en",
    );
  }
  assert.deepEqual(portalLanguages, { site: "en" });
});

test("translated phrases can reorder slots and user values remain literal", () => {
  assert.equal(
    formatMessage("{file} — {user}", { user: "$& {file}", file: "A" }),
    "A — $& {file}",
  );
});

test("public JSX takes visitor copy and accessible labels from resources", async () => {
  const { readdir, readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const { default: ts } = await import("typescript");
  const literalAttributes = new Set([
    "aria-label",
    "title",
    "alt",
    "placeholder",
  ]);
  const allowedTechnicalValues = new Set([
    "AmneziaWG",
    "203.0.113.10",
    "SHA256:…",
  ]);
  const unexpected = [];
  for (const folder of ["app/(site)", "components"]) {
    const root = new URL("../src/" + folder + "/", import.meta.url);
    const files = await readdir(root, { recursive: true });
    for (const file of files.filter((name) => name.endsWith(".tsx"))) {
      const path = fileURLToPath(new URL(file, root));
      const doc = ts.createSourceFile(
        path,
        await readFile(path, "utf8"),
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
      );
      function visit(node) {
        let value = "";
        if (ts.isJsxText(node)) value = node.getText(doc).trim();
        if (
          ts.isJsxAttribute(node) &&
          literalAttributes.has(node.name.getText(doc)) &&
          node.initializer &&
          ts.isStringLiteral(node.initializer)
        )
          value = node.initializer.text;
        if (/[A-Za-z]/.test(value) && !allowedTechnicalValues.has(value)) {
          unexpected.push(file + ": " + value);
        }
        ts.forEachChild(node, visit);
      }
      visit(doc);
    }
  }
  assert.deepEqual(unexpected, []);
});
