/// <reference types="node" />
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const src = path.resolve(import.meta.dirname, "../src");
const messages = JSON.parse(readFileSync(path.join(src, "_locales/en/messages.json"), "utf8")) as Record<string, { message: string }>;
const files = readdirSync(src, { recursive: true, encoding: "utf8" })
  .filter((file) => /\.(ts|html|css|json)$/.test(file) && !file.startsWith("_locales"))
  .map((file) => readFileSync(path.join(src, file), "utf8"));

// Keys in t("key"), h(cond ? "a" : "b"), plural("key", n) and __MSG_key__.
function usedKeys(): { plain: Set<string>; counted: Set<string> } {
  const plain = new Set<string>();
  const counted = new Set<string>();
  for (const text of files) {
    for (const [, key] of text.matchAll(/__MSG_(\w+)__/g)) plain.add(key!);
    for (const call of text.matchAll(/\b(t|h|plural)\(/g)) {
      // The first argument runs to the first comma or closing parenthesis at its own depth.
      let depth = 0;
      let end = call.index + call[0].length;
      for (; end < text.length; end++) {
        const char = text[end];
        if (char === "(") depth++;
        else if (char === ")" && depth-- === 0) break;
        else if (char === "," && depth === 0) break;
      }
      const argument = text.slice(call.index + call[0].length, end);
      // Keys start the argument or follow ? and : (so `a === "json" ? "x" : "y"` yields x and y).
      for (const [, key] of argument.matchAll(/(?:^|[?:])\s*"(\w+)"/g)) (call[1] === "plural" ? counted : plain).add(key!);
    }
  }
  return { plain, counted };
}

describe("localization", () => {
  const { plain, counted } = usedKeys();

  it("defines every message the extension uses", () => {
    const missing = [
      ...[...plain].filter((key) => !messages[key]),
      ...[...counted].flatMap((key) => [`${key}_one`, `${key}_other`]).filter((key) => !messages[key]),
    ];
    expect(missing).toEqual([]);
  });

  it("has no unused messages", () => {
    const unused = Object.keys(messages).filter((key) => !plain.has(key) && !counted.has(key.replace(/_(zero|one|two|few|many|other)$/, "")));
    expect(unused).toEqual([]);
  });

  it("translates every message, with the same substitutions, in every language", () => {
    const substitutions = (text: string) => (text.match(/\$\d/g) ?? []).sort().join();
    for (const language of readdirSync(path.join(src, "_locales"))) {
      const translated = JSON.parse(readFileSync(path.join(src, "_locales", language, "messages.json"), "utf8")) as Record<string, { message: string }>;
      const missing = Object.keys(messages).filter((key) => !translated[key]);
      // Extra keys may only be plural forms the language needs, such as `name_few`.
      const extra = Object.keys(translated).filter((key) => !messages[key] && !messages[key.replace(/_(zero|one|two|few|many)$/, "_other")]);
      expect({ missing, extra }, language).toEqual({ missing: [], extra: [] });
      const mismatched = Object.keys(messages).filter((key) => substitutions(translated[key]!.message) !== substitutions(messages[key]!.message));
      expect(mismatched, language).toEqual([]);
    }
  });

  it("keeps substitutions apart so Chrome does not read them as named placeholders", () => {
    expect(Object.values(messages).filter(({ message }) => /\$\d\$/.test(message))).toEqual([]);
  });
});
