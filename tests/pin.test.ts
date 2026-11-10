import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { hasPinUnlock, unwrapPinUnlock, writePinUnlock } from "../src/shared/pin";

let local: Record<string, unknown>;
let session: Record<string, unknown>;
const storage = (data: Record<string, unknown>) => ({
  get: async (name: string) => ({ [name]: data[name] }),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});
beforeEach(() => {
  local = {};
  session = {};
  vi.stubGlobal("chrome", { storage: { local: storage(local), session: storage(session) } });
});
afterEach(() => vi.unstubAllGlobals());

const account = { baseUrl: "https://vault.example.com", email: "a@example.com" };
const key = new Uint8Array(64).fill(7);

it("unwraps the account key with the PIN, keeps it in memory by default, and gives up after five wrong PINs", async () => {
  await writePinUnlock("2468", key, account, false);
  expect(Object.keys(session)).toEqual(["pinUnlock"]);
  expect(local).toEqual({});
  expect(JSON.stringify(session)).not.toContain("2468");
  expect(await unwrapPinUnlock("2468", account)).toEqual(key);
  await expect(unwrapPinUnlock("2468", { ...account, email: "b@example.com" })).rejects.toThrow(/4 attempts left/);
  for (const left of [3, 2, 1]) await expect(unwrapPinUnlock("0000", account)).rejects.toThrow(`${left} attempts left`);
  await expect(unwrapPinUnlock("0000", account)).rejects.toThrow(/turned off/);
  expect(await hasPinUnlock()).toBe(false);
});

it("stores the PIN record on disk only when asked to keep it after a restart", async () => {
  await writePinUnlock("2468", key, account, true);
  expect(Object.keys(local)).toEqual(["pinUnlock"]);
  expect(session).toEqual({});
  expect(await unwrapPinUnlock("2468", account)).toEqual(key);
});
