// Runs tests/vaultwarden.compat.test.ts against each supported Vaultwarden release, one throwaway
// Docker container at a time. Usage: pnpm compat [version ...]
import { execFileSync, spawnSync } from "node:child_process";

// The newest patch of each supported minor release. Update when Vaultwarden ships a new one.
const SUPPORTED = ["1.34.3", "1.35.8", "1.36.0", "1.37.4"];
const versions = process.argv.length > 2 ? process.argv.slice(2) : SUPPORTED;
const port = 8199;
const failed = [];

for (const version of versions) {
  const name = `firnkey-compat-${version}`;
  const url = `http://localhost:${port}`;
  execFileSync("docker", [
    "run", "-d", "--rm", "--name", name, "-p", `${port}:80`,
    "-e", "SIGNUPS_ALLOWED=true", "-e", `DOMAIN=${url}`, "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true",
    `vaultwarden/server:${version}`,
  ], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    await waitForServer(`${url}/api/config`);
    const result = spawnSync("pnpm", ["exec", "vitest", "run", "tests/vaultwarden.compat.test.ts"], {
      stdio: "inherit",
      env: { ...process.env, VAULTWARDEN_URL: url },
    });
    if (result.status !== 0) failed.push(version);
    console.log(`${result.status === 0 ? "PASS" : "FAIL"} Vaultwarden ${version}`);
  } finally {
    execFileSync("docker", ["rm", "-f", name], { stdio: "ignore" });
  }
}

if (failed.length > 0) {
  console.error(`Incompatible with Vaultwarden ${failed.join(", ")}`);
  process.exit(1);
}

async function waitForServer(url) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // Still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`${url} did not start within a minute.`);
}
