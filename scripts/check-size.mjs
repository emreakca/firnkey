import { stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");

const budgets = [
  ["dist/background.js", 250 * 1024],
  ["dist/popup/index.js", 200 * 1024],
  ["dist/popup/styles.css", 32 * 1024],
  ["dist/offscreen/index.js", 96 * 1024],
  ["dist/site.js", 48 * 1024],
  ["dist/passkey-page.js", 8 * 1024],
  ["dist/passkey-bridge.js", 2 * 1024],
  ["dist/passkey/index.js", 16 * 1024],
];

let failed = false;

for (const [relativePath, maximumBytes] of budgets) {
  const file = path.join(root, relativePath);
  const { size } = await stat(file);
  const state = size <= maximumBytes ? "PASS" : "FAIL";
  console.log(
    `${state} ${relativePath}: ${(size / 1024).toFixed(1)} KiB / ${(maximumBytes / 1024).toFixed(0)} KiB`,
  );
  failed ||= size > maximumBytes;
}

if (failed) {
  console.error("One or more extension bundles exceed their memory-conscious size budget.");
  process.exitCode = 1;
}
