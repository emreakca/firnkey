import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VaultController } from "../src/background/vault-controller";
vi.mock("../src/shared/persistent-session", () => ({ clearPersistentAuthSession: async () => undefined }));
beforeEach(() => { vi.stubGlobal("addEventListener", () => undefined); }); // Service-worker global Node lacks.
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.resetModules(); });
const ignored = { addListener: () => undefined };
// Shortcut, context menu and badge APIs the background registers on start.
const toolbarApis = { action: { setBadgeBackgroundColor: async () => undefined }, contextMenus: { onClicked: ignored }, commands: { onCommand: ignored }, permissions: { onAdded: ignored } };

it("restores the minute alarm and syncs without touching the inactivity alarm", async () => {
  const alarmListeners: ((alarm: chrome.alarms.Alarm) => void)[] = [];
  const alarms = new Map<string, { periodInMinutes?: number }>();
  const cleared: string[] = [];
  vi.stubGlobal("chrome", {
    storage: {
      local: { get: async () => ({}) },
      session: { get: async () => ({}), setAccessLevel: async () => undefined },
      AccessLevel: { TRUSTED_CONTEXTS: "TRUSTED_CONTEXTS" },
    },
    runtime: { onMessage: ignored, onInstalled: ignored },
    tabs: { onRemoved: ignored, onActivated: ignored, onUpdated: ignored },
    ...toolbarApis,
    idle: { onStateChanged: { addListener: () => undefined } },
    windows: { onRemoved: { addListener: () => undefined } },
    alarms: {
      get: async (name: string) => alarms.get(name),
      create: async (name: string, info: { periodInMinutes?: number }) => { alarms.set(name, info); },
      clear: async (name: string) => { cleared.push(name); },
      onAlarm: { addListener: (listener: (alarm: chrome.alarms.Alarm) => void) => alarmListeners.push(listener) },
    },
  });
  vi.spyOn(VaultController.prototype, "getState").mockResolvedValue({ phase: "unlocked" } as Awaited<ReturnType<VaultController["getState"]>>);
  const sync = vi.spyOn(VaultController.prototype, "sync").mockResolvedValue({ itemCount: 1, failures: 0 });
  await import("../src/background/index");
  await vi.waitFor(() => expect(alarms.get("firnkey-sync")?.periodInMinutes).toBe(1));
  for (const listener of alarmListeners) listener({ name: "firnkey-sync", scheduledTime: Date.now(), persistAcrossSessions: false });
  await vi.waitFor(() => expect(sync).toHaveBeenCalledOnce());
  expect(cleared).toEqual([]);
});

it("refuses popup-only requests from website content scripts", async () => {
  type Listener = (message: unknown, sender: chrome.runtime.MessageSender, respond: (value: unknown) => void) => boolean;
  let onMessage: Listener | undefined;
  vi.stubGlobal("chrome", {
    storage: {
      local: { get: async () => ({}) },
      session: { get: async () => ({}), setAccessLevel: async () => undefined },
      AccessLevel: { TRUSTED_CONTEXTS: "TRUSTED_CONTEXTS" },
    },
    runtime: {
      id: "firnkey",
      getURL: (path: string) => `chrome-extension://firnkey/${path}`,
      onMessage: { addListener: (listener: Listener) => { onMessage = listener; } },
      onInstalled: ignored,
    },
    tabs: { onRemoved: ignored, onActivated: ignored, onUpdated: ignored },
    ...toolbarApis,
    idle: { onStateChanged: { addListener: () => undefined } },
    windows: { onRemoved: { addListener: () => undefined } },
    alarms: { get: async () => ({ periodInMinutes: 1 }), create: async () => undefined, onAlarm: { addListener: () => undefined } },
  });
  // Modules are reset between tests, so spy on the copy the background will load.
  const { VaultController: Controller } = await import("../src/background/vault-controller");
  vi.spyOn(Controller.prototype, "getState").mockResolvedValue({ phase: "unlocked" } as Awaited<ReturnType<VaultController["getState"]>>);
  const list = vi.spyOn(Controller.prototype, "list").mockResolvedValue({ items: [], folders: [], collections: [] });
  await import("../src/background/index");

  const website = { id: "firnkey", tab: { id: 1 } as chrome.tabs.Tab, url: "https://evil.example/" };
  const responses: unknown[] = [];
  expect(onMessage!({ type: "vault.list", query: "" }, website, (value) => responses.push(value))).toBe(false);
  expect(responses).toEqual([{ ok: false, error: "This request is not allowed from a website." }]);
  expect(list).not.toHaveBeenCalled();

  const popup = { id: "firnkey", url: "chrome-extension://firnkey/popup/index.html" };
  expect(onMessage!({ type: "vault.list", query: "" }, popup, (value) => responses.push(value))).toBe(true);
  await vi.waitFor(() => expect(list).toHaveBeenCalledOnce());
});

it("does not let automatic page requests reset the inactivity lock", async () => {
  type Listener = (message: unknown, sender: chrome.runtime.MessageSender, respond: (value: unknown) => void) => boolean;
  let onMessage: Listener | undefined;
  const local: Record<string, unknown> = { "firnkey.vaultTimeoutMinutes": 1, "firnkey.siteIntegrationEnabled": true };
  const created: string[] = [];
  vi.stubGlobal("chrome", {
    storage: {
      local: { get: async (key: string) => ({ [key]: local[key] }), set: async (values: Record<string, unknown>) => { Object.assign(local, values); } },
      session: { get: async () => ({}), setAccessLevel: async () => undefined },
      AccessLevel: { TRUSTED_CONTEXTS: "TRUSTED_CONTEXTS" },
    },
    runtime: {
      id: "firnkey",
      getURL: (path: string) => `chrome-extension://firnkey/${path}`,
      onMessage: { addListener: (listener: Listener) => { onMessage = listener; } },
      onInstalled: ignored,
    },
    tabs: { onRemoved: ignored, onActivated: ignored, onUpdated: ignored },
    ...toolbarApis,
    idle: { onStateChanged: { addListener: () => undefined } },
    windows: { onRemoved: { addListener: () => undefined } },
    alarms: { get: async () => ({ periodInMinutes: 1 }), create: async (name: string) => { created.push(name); }, onAlarm: { addListener: () => undefined } },
    scripting: { getRegisteredContentScripts: async () => [], registerContentScripts: async () => undefined },
    permissions: { contains: async () => true, onAdded: ignored },
  });
  const { VaultController: Controller } = await import("../src/background/vault-controller");
  vi.spyOn(Controller.prototype, "getState").mockResolvedValue({ phase: "unlocked" } as Awaited<ReturnType<VaultController["getState"]>>);
  vi.spyOn(Controller.prototype, "siteSuggestions").mockResolvedValue([]);
  vi.spyOn(Controller.prototype, "lock").mockResolvedValue();
  await import("../src/background/index");

  const responses: unknown[] = [];
  const page = { id: "firnkey", tab: { id: 1 } as chrome.tabs.Tab, url: "https://example.com/login" };
  onMessage!({ type: "site.suggestions", url: page.url }, page, (value) => responses.push(value));
  await vi.waitFor(() => expect(responses).toEqual([{ ok: true, data: { type: "siteSuggestions", items: [], passkeyOffer: false, passwordPending: false } }]));
  expect(created).not.toContain("firnkey-auto-lock");

  // An explicit action from Firnkey's own UI still counts as activity.
  const popup = { id: "firnkey", url: "chrome-extension://firnkey/popup/index.html" };
  onMessage!({ type: "auth.lock" }, popup, (value) => responses.push(value));
  await vi.waitFor(() => expect(created).toContain("firnkey-auto-lock"));
});

it("fills the first unprotected matching login from the keyboard shortcut", async () => {
  let onCommand: ((command: string) => void) | undefined;
  const openPopup = vi.fn(async () => undefined);
  vi.stubGlobal("chrome", {
    storage: {
      local: { get: async () => ({}) },
      session: { get: async () => ({}), setAccessLevel: async () => undefined },
      AccessLevel: { TRUSTED_CONTEXTS: "TRUSTED_CONTEXTS" },
    },
    runtime: { onMessage: ignored, onInstalled: ignored },
    tabs: {
      onRemoved: ignored, onActivated: ignored, onUpdated: ignored,
      query: async () => [{ id: 1, url: "https://example.com/login" }],
    },
    idle: { onStateChanged: ignored },
    permissions: { onAdded: ignored },
    windows: { onRemoved: ignored },
    alarms: { get: async () => ({ periodInMinutes: 1 }), create: async () => undefined, clear: async () => undefined, onAlarm: ignored },
    action: { setBadgeBackgroundColor: async () => undefined, openPopup },
    contextMenus: { onClicked: ignored },
    commands: { onCommand: { addListener: (listener: (command: string) => void) => { onCommand = listener; } } },
  });
  const { VaultController: Controller } = await import("../src/background/vault-controller");
  const matches = vi.spyOn(Controller.prototype, "matchingLogins").mockResolvedValue([
    { id: "protected", requiresReprompt: true },
    { id: "plain", requiresReprompt: false },
  ] as Awaited<ReturnType<VaultController["matchingLogins"]>>);
  const fill = vi.spyOn(Controller.prototype, "fill").mockResolvedValue({ username: true, password: true });
  await import("../src/background/index");

  onCommand!("fill-login");
  await vi.waitFor(() => expect(fill).toHaveBeenCalledWith("plain"));
  expect(openPopup).not.toHaveBeenCalled();

  // Nothing to fill: open the popup so the user can unlock or pick.
  matches.mockRejectedValue(new Error("Vault is locked."));
  onCommand!("fill-login");
  await vi.waitFor(() => expect(openPopup).toHaveBeenCalledOnce());
});
