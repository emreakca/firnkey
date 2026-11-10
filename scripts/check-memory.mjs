// Memory and process regression check: loads dist/ into a real headless Chrome over the DevTools
// pipe (no dependencies) and fails when the extension's idle footprint or its growth after
// repeated popup opens exceeds a budget. Run after `pnpm build`. CHROME_PATH overrides the binary.
import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const root = path.resolve(import.meta.dirname, "..");
const MiB = 1024 * 1024;
// Heap budgets are used JS heap after a forced GC; growth is over 20 popup open/close cycles.
const budgets = {
  workerHeap: 2 * MiB,
  popupHeap: 3 * MiB,
  workerGrowth: 512 * 1024,
  extraProcesses: 1,
  idleOffscreen: 0,
};

const chromePath = process.env.CHROME_PATH || [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
].find(existsSync);
if (!chromePath) throw new Error("Chrome not found; set CHROME_PATH.");

const profile = await mkdtemp(path.join(tmpdir(), "firnkey-memory-"));
const chrome = spawn(chromePath, [
  "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
  `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check", "--disable-component-extensions-with-background-pages",
  "--disable-default-apps", ...(process.env.CI ? ["--no-sandbox"] : []), "about:blank",
], { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });

let nextId = 0;
const pending = new Map();
let buffer = "";
chrome.stdio[4].on("data", (chunk) => {
  buffer += chunk;
  let end;
  while ((end = buffer.indexOf("\0")) >= 0) {
    const message = JSON.parse(buffer.slice(0, end));
    buffer = buffer.slice(end + 1);
    const waiter = pending.get(message.id);
    if (!waiter) continue;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message}`));
    else waiter.resolve(message.result);
  }
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, { resolve, reject, method });
  chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
});

const results = [];
const check = (name, value, budget, format = (v) => `${(v / MiB).toFixed(2)} MiB`) => {
  results.push(value <= budget);
  console.log(`${value <= budget ? "PASS" : "FAIL"} ${name}: ${format(value)} / ${format(budget)}`);
};
const count = (v) => String(v);

try {
  const rendererCount = async () =>
    (await send("SystemInfo.getProcessInfo")).processInfo.filter((p) => p.type === "renderer").length;
  // Chrome starts its own renderers for a few seconds after launch; wait for the count to settle.
  let baseline = -1;
  for (let attempt = 0; attempt < 20; attempt++) {
    await sleep(500);
    const now = await rendererCount();
    if (now === baseline && attempt >= 3) break;
    baseline = now;
  }

  const { id } = await send("Extensions.loadUnpacked", { path: path.join(root, "dist") });
  const targets = async () => (await send("Target.getTargets")).targetInfos.filter((t) => t.url.startsWith(`chrome-extension://${id}/`));
  let worker;
  for (let attempt = 0; attempt < 50 && !worker; attempt++) {
    worker = (await targets()).find((t) => t.type === "service_worker");
    if (!worker) await sleep(100);
  }
  if (!worker) throw new Error("Service worker did not start.");
  const { sessionId: workerSession } = await send("Target.attachToTarget", { targetId: worker.targetId, flatten: true });
  const heap = async (sessionId) => {
    await send("HeapProfiler.collectGarbage", {}, sessionId);
    return (await send("Runtime.getHeapUsage", {}, sessionId)).usedSize;
  };
  await sleep(2_000); // let startup work (alarms, storage reads) settle

  check("service worker heap at idle", await heap(workerSession), budgets.workerHeap);
  check("extra renderer processes at idle", (await rendererCount()) - baseline, budgets.extraProcesses, count);
  check("offscreen documents at idle", (await targets()).filter((t) => t.url.includes("/offscreen/")).length, budgets.idleOffscreen, count);

  const openPopup = async () => {
    const { targetId } = await send("Target.createTarget", { url: `chrome-extension://${id}/popup/index.html` });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    for (let attempt = 0; attempt < 50; attempt++) {
      const { result } = await send("Runtime.evaluate", { expression: "document.readyState", returnByValue: true }, sessionId);
      if (result.value === "complete") break;
      await sleep(50);
    }
    await sleep(300); // popup asks the worker for state after load
    return { targetId, sessionId };
  };

  const first = await openPopup();
  check("popup heap after open", await heap(first.sessionId), budgets.popupHeap);
  await send("Target.closeTarget", { targetId: first.targetId });

  const before = await heap(workerSession);
  for (let cycle = 0; cycle < 20; cycle++) {
    const popup = await openPopup();
    await send("Target.closeTarget", { targetId: popup.targetId });
  }
  await sleep(500);
  check("service worker heap growth over 20 popup opens", Math.max(0, (await heap(workerSession)) - before), budgets.workerGrowth);
} finally {
  chrome.kill();
  await new Promise((resolve) => chrome.once("exit", resolve));
  // Chrome's helper processes can still write to the profile right after exit; retry, and never let a
  // leftover temp folder fail the check.
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
    .catch((error) => console.warn(`Could not remove ${profile}: ${error.message}`));
}

if (results.includes(false)) {
  console.error("The extension exceeds a memory or process budget.");
  process.exitCode = 1;
}
