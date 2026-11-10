import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import * as esbuild from "esbuild";

const root = path.resolve(import.meta.dirname, "..");
const watch = process.argv.includes("--watch");
// --firefox builds dist-firefox/: no offscreen document (the background is a page there) and a
// Firefox manifest. The source is shared; __FIREFOX__ picks the few places that differ.
const firefox = process.argv.includes("--firefox");
const dist = path.join(root, firefox ? "dist-firefox" : "dist");
const artifacts = path.join(root, "artifacts", firefox ? "firefox" : "");

await rm(dist, { recursive: true, force: true });
await mkdir(artifacts, { recursive: true });

// cp creates the missing dist folders.
await Promise.all(
  ["manifest.json", "_locales", "popup/index.html", "popup/styles.css", ...(firefox ? [] : ["offscreen/index.html"]), "passkey/index.html", "passkey/public-suffixes.txt", "icons"].map((file) =>
    cp(path.join(root, "src", file), path.join(dist, file), { recursive: true })),
);

// [name, entry under src/, output under dist/, format]
const builds = [
  ["background", "background/index.ts", "background.js", "esm"],
  ["popup", "popup/index.ts", "popup/index.js", "esm"],
  ...(firefox ? [] : [["offscreen", "offscreen/index.ts", "offscreen/index.js", "esm"]]),
  ["site", "site/index.ts", "site.js", "iife"],
  ["passkey-page", "site/passkey-page.ts", "passkey-page.js", "iife"],
  ["passkey-bridge", "site/passkey-bridge.ts", "passkey-bridge.js", "iife"],
  ["passkey-window", "passkey/index.ts", "passkey/index.js", "esm"],
].map(([name, entry, outfile, format]) => ({
  name,
  options: {
    bundle: true,
    minify: !watch,
    sourcemap: watch ? "inline" : false,
    target: firefox ? "firefox140" : "chrome140",
    define: { __FIREFOX__: String(firefox) },
    logLevel: "info",
    legalComments: "none",
    metafile: true,
    entryPoints: [path.join(root, "src", entry)],
    outfile: path.join(dist, outfile),
    format,
  },
}));

if (watch) {
  for (const build of builds) await (await esbuild.context(build.options)).watch();
  console.log("Watching extension sources. Press Ctrl+C to stop.");
} else {
  for (const build of builds) {
    const result = await esbuild.build(build.options);
    await writeFile(path.join(artifacts, `${build.name}-metafile.json`), JSON.stringify(result.metafile, null, 2));
  }

  const manifest = JSON.parse(await readFile(path.join(dist, "manifest.json"), "utf8"));
  if (firefox) await writeFile(path.join(dist, "manifest.json"), `${JSON.stringify(firefoxManifest(manifest), null, 2)}\n`);
  console.log(`Built ${manifest.name} ${manifest.version} in ${path.relative(root, dist)}/`);
}

// Firefox runs the background as an event page and has no offscreen or favicon API. It answers
// basic-auth dialogs through webRequestBlocking, and asks every add-on to declare what data it sends.
function firefoxManifest(chromeManifest) {
  const { minimum_chrome_version: _, background, permissions, optional_permissions: optional, ...rest } = chromeManifest;
  return {
    ...rest,
    background: { scripts: [background.service_worker], type: "module" },
    permissions: permissions.filter((permission) => permission !== "offscreen" && permission !== "favicon"),
    optional_permissions: optional.map((permission) => (permission === "webRequestAuthProvider" ? "webRequestBlocking" : permission)),
    browser_specific_settings: {
      gecko: {
        id: "firnkey@emreakca.github.io",
        strict_min_version: "140.0",
        // Sent only to the user's own server (and opt-in services), the same as the Chrome Web Store answers.
        data_collection_permissions: {
          required: ["authenticationInfo", "personallyIdentifyingInfo", "financialAndPaymentInfo", "personalCommunications", "websiteContent", "browsingActivity"],
        },
      },
    },
  };
}
