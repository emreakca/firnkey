// Refreshes src/passkey/public-suffixes.txt from the Public Suffix List (MPL-2.0).
// Rules are written in punycode, as Chrome reports hostnames, one per line.
import { writeFile } from "node:fs/promises";
import path from "node:path";

const source = "https://publicsuffix.org/list/public_suffix_list.dat";
const response = await fetch(source);
if (!response.ok) throw new Error(`Could not download the Public Suffix List: HTTP ${response.status}`);

const rules = (await response.text())
  .split("\n")
  .map((line) => line.trim().split(/\s/)[0])
  .filter((line) => line && !line.startsWith("//"))
  .map((rule) => {
    const prefix = rule.match(/^(\*\.|!)?/)[0];
    return prefix + new URL(`https://${rule.slice(prefix.length)}`).hostname;
  });

const header = `// Public Suffix List, ${source}, MPL-2.0 (https://mozilla.org/MPL/2.0/). Run pnpm update:psl to refresh.`;
await writeFile(path.resolve(import.meta.dirname, "../src/passkey/public-suffixes.txt"), `${header}\n${rules.join("\n")}\n`);
console.log(`Wrote ${rules.length} public suffix rules.`);
