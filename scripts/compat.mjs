// Runs tests/server.compat.test.ts against each supported server release, one throwaway
// Docker container at a time. Usage: pnpm compat [version ...]
import { execFileSync, spawnSync } from "node:child_process";

// The server's Docker image (without a tag) comes from COMPAT_IMAGE: a repository variable in CI,
// .env.local on your machine.
const IMAGE = process.env.COMPAT_IMAGE;
if (!IMAGE) {
  console.error("Set COMPAT_IMAGE to the server's Docker image, without a tag (see docs/STORE.md#releasing).");
  process.exit(1);
}

// The newest patch of each supported minor release. Update when a new one ships.
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
    `${IMAGE}:${version}`,
  ], { stdio: ["ignore", "ignore", "inherit"] });
  try {
    await waitForServer(`${url}/api/config`);
    const result = spawnSync("pnpm", ["exec", "vitest", "run", "tests/server.compat.test.ts"], {
      stdio: "inherit",
      env: throwawayEnv(url),
    });
    if (result.status !== 0) failed.push(version);
    console.log(`${result.status === 0 ? "PASS" : "FAIL"} server ${version}`);
  } finally {
    execFileSync("docker", ["rm", "-f", name], { stdio: "ignore" });
  }
}

if (failed.length > 0) {
  console.error(`Incompatible with server ${failed.join(", ")}`);
  process.exit(1);
}

// The throwaway server gets a fresh account, never the live test account from .env.local.
function throwawayEnv(url) {
  const env = { ...process.env, FIRNKEY_SERVER_URL: url };
  delete env.FIRNKEY_EMAIL;
  delete env.FIRNKEY_PASSWORD;
  return env;
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
