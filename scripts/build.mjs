import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import * as esbuild from "esbuild";

const root = path.resolve(import.meta.dirname, "..");
const dist = path.join(root, "dist");
const artifacts = path.join(root, "artifacts");
const watch = process.argv.includes("--watch");

await rm(dist, { recursive: true, force: true });
await mkdir(artifacts, { recursive: true });

// cp creates the missing dist folders.
await Promise.all(
  ["manifest.json", "_locales", "popup/index.html", "popup/styles.css", "offscreen/index.html", "passkey/index.html", "passkey/public-suffixes.txt", "icons"].map((file) =>
    cp(path.join(root, "src", file), path.join(dist, file), { recursive: true })),
);

// [name, entry under src/, output under dist/, format]
const builds = [
  ["background", "background/index.ts", "background.js", "esm"],
  ["popup", "popup/index.ts", "popup/index.js", "esm"],
  ["offscreen", "offscreen/index.ts", "offscreen/index.js", "esm"],
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
    target: "chrome140",
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
  console.log(`Built ${manifest.name} ${manifest.version} in ${path.relative(root, dist)}/`);
}
