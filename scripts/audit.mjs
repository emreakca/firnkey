// Release audit: shipped dependencies use permissive licenses, a CycloneDX SBOM is written to
// artifacts/, and building twice gives byte-identical files. Run after `pnpm build`.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const dist = path.join(root, "dist");
const ALLOWED_LICENSES = new Set(["MIT", "ISC", "0BSD", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0"]);
const pnpm = (...args) => execFileSync("pnpm", args, { cwd: root, encoding: "utf8" });

const licenses = JSON.parse(pnpm("licenses", "list", "--prod", "--json"));
const refused = Object.entries(licenses).filter(([license]) => !ALLOWED_LICENSES.has(license));
for (const [license, packages] of refused) console.error(`FAIL ${packages.map((entry) => entry.name).join(", ")}: ${license}`);
const shipped = Object.values(licenses).flat().map((entry) => `${entry.name}@${entry.versions.join(",")}`);
console.log(`${refused.length ? "FAIL" : "PASS"} licenses: ${shipped.join(", ")}`);

pnpm("sbom", "--sbom-format", "cyclonedx", "--sbom-type", "application", "--prod", "--out", path.join("artifacts", "sbom.cdx.json"));
console.log("PASS SBOM: artifacts/sbom.cdx.json");

const before = await hashTree(dist);
pnpm("build");
const after = await hashTree(dist);
const changed = [...new Set([...before.keys(), ...after.keys()])].filter((file) => before.get(file) !== after.get(file));
for (const file of changed) console.error(`FAIL not reproducible: dist/${file}`);
console.log(`${changed.length ? "FAIL" : "PASS"} reproducible build: ${after.size} files`);

if (refused.length || changed.length) process.exit(1);

async function hashTree(directory) {
  const hashes = new Map();
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const file = path.join(entry.parentPath, entry.name);
    hashes.set(path.relative(directory, file), createHash("sha256").update(await readFile(file)).digest("hex"));
  }
  return hashes;
}
