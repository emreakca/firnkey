import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const dist = path.join(root, "dist");
const manifest = JSON.parse(await readFile(path.join(dist, "manifest.json"), "utf8"));
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

if (manifest.version !== packageJson.version) {
  throw new Error(`Version mismatch: manifest ${manifest.version}, package ${packageJson.version}.`);
}

if (manifest.manifest_version !== 3) {
  throw new Error("The production manifest must use Manifest V3.");
}

if (manifest.background?.type !== "module") {
  throw new Error("The background service worker must be an ES module.");
}

const referencedFiles = [
  manifest.background?.service_worker,
  manifest.action?.default_popup,
  ...Object.values(manifest.icons ?? {}),
  ...Object.values(manifest.action?.default_icon ?? {}),
];
for (const relativePath of referencedFiles) {
  if (typeof relativePath !== "string") {
    throw new Error("The manifest is missing a required extension entry point.");
  }
  await access(path.join(dist, relativePath));
}

const files = (await readdir(dist, { recursive: true, withFileTypes: true }))
  .filter((entry) => entry.isFile())
  .map((entry) => path.relative(dist, path.join(entry.parentPath, entry.name)));
const forbidden = files.filter((file) => file.endsWith(".map") || file.endsWith(".wasm"));
if (forbidden.length > 0) {
  throw new Error(`Unexpected production artifacts: ${forbidden.join(", ")}`);
}

const permanentPermissions = new Set(manifest.permissions ?? []);
const expectedPermissions = new Set([
  "storage",
  "activeTab",
  "scripting",
  "offscreen",
  "alarms",
  "idle",
  "clipboardWrite",
  "favicon",
  "contextMenus",
]);
if (
  permanentPermissions.size !== expectedPermissions.size ||
  [...permanentPermissions].some((permission) => !expectedPermissions.has(permission))
) {
  throw new Error(`Unexpected permanent permissions: ${[...permanentPermissions].join(", ")}`);
}

console.log(
  `PASS dist manifest: MV3, ${files.length} files, scoped runtime permissions, no debug/WASM files`,
);
