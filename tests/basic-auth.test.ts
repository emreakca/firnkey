import { beforeEach, expect, it, vi } from "vitest";
import { installBasicAuth } from "../src/background/basic-auth";

type Listener = (details: { requestId: string; url: string; isProxy: boolean }, callback: (response: unknown) => void) => void;
let listener: Listener;
let options: Record<string, unknown>;

beforeEach(() => {
  options = { askAddLogin: true, askUpdateLogin: true, savePromptTimeoutSeconds: 10, excludedDomains: ["blocked.example"], fillBasicAuth: true };
  vi.stubGlobal("chrome", {
    webRequest: { onAuthRequired: { addListener: (fn: Listener) => { listener = fn; } } },
    permissions: { onAdded: { addListener: () => undefined } },
    storage: { local: { get: async () => ({ "firnkey.browserIntegrationOptions": options }) } },
  });
});

const answer = (requestId: string, url: string, isProxy = false) =>
  new Promise((resolve) => listener({ requestId, url, isProxy }, resolve));

it("fills once per request, and never for proxies, excluded sites or when turned off", async () => {
  installBasicAuth(async () => ({ username: "u", password: "p" }));
  expect(await answer("1", "https://site.example/")).toEqual({ authCredentials: { username: "u", password: "p" } });
  expect(await answer("1", "https://site.example/")).toEqual({}); // Rejected: let the user type.
  expect(await answer("2", "https://proxy.example/", true)).toEqual({});
  expect(await answer("3", "https://blocked.example/")).toEqual({});
  options.fillBasicAuth = false;
  expect(await answer("4", "https://site.example/")).toEqual({});
});
