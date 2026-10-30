import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VaultController } from "../src/background/vault-controller";
import { DEFAULT_BROWSER_INTEGRATION_OPTIONS as options } from "../src/shared/settings";
import { createEncryptedLogin } from "../src/vault/encrypt-login";
import { decryptSymmetricBytes, encryptSymmetricString } from "../src/crypto/bitwarden-crypto";
import type { SyncResponse } from "../src/api/models";

let encrypted: SyncResponse | null;
// Records kept under another id (switched-out accounts).
let stashed: Map<string, unknown>;
vi.mock("../src/shared/database", () => ({
  readEncryptedSync: async (id?: string) => (id ? stashed.get(`sync:${id}`) ?? null : encrypted),
  writeEncryptedSync: async (payload: SyncResponse, id?: string) => { if (id) stashed.set(`sync:${id}`, payload); else encrypted = payload; },
  clearEncryptedSync: async (id?: string) => { if (id) stashed.delete(`sync:${id}`); else encrypted = null; },
}));
let persisted: unknown = null;
vi.mock("../src/shared/persistent-session", () => ({
  clearPersistentAuthSession: async (id?: string) => { if (id) stashed.delete(id); else persisted = null; },
  writePersistentAuthSession: async (value: unknown, id?: string) => { if (id) stashed.set(id, structuredClone(value)); else persisted = structuredClone(value); },
  readPersistentAuthSession: async (id?: string) => structuredClone(id ? stashed.get(id) ?? null : persisted),
}));
const key = new Uint8Array(64).fill(7);
let local: Record<string, unknown>;
let session: Record<string, unknown>;
let payload: SyncResponse;
let fetchMock: ReturnType<typeof vi.fn>;
const storage = (data: Record<string, unknown>) => ({
  get: async (name: string) => ({ [name]: data[name] }),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});
beforeEach(() => {
  local = { accountMetadata: { email: "test@example.com", baseUrl: "https://vault.example.com", itemCount: 0 }, serverSnapshot: { baseUrl: "https://vault.example.com" } };
  session = { authSession: { email: "test@example.com", baseUrl: "https://vault.example.com", accessToken: "test", userKey: [...key] } };
  encrypted = payload = { Ciphers: [] };
  persisted = null;
  stashed = new Map();
  vi.stubGlobal("chrome", { storage: { local: storage(local), session: storage(session) } });
  fetchMock = vi.fn(async () => new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

it("keeps one prompt and deadline across repeated submits and MFA navigation", async () => {
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com/login", "alice", "secret", options, 0);
  const again = await controller.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0);
  expect(again).toEqual(first);
  expect(first).toMatchObject({ expiresAt: expect.any(Number) });
  expect(await controller.pendingSitePrompt(1, "https://example.com/mfa", 0)).toEqual(first);
  expect(await controller.pendingSitePrompt(1, "https://evil.example/", 0)).toBeNull();
  expect(await controller.pendingSitePrompt(1, "https://example.com/mfa", 2)).toBeNull();
  expect(await controller.inspectSiteLogin(1, "https://example.com/login", "alice", "secret", options, 2)).toBeNull();
});

it("expires after ten seconds and suppresses the same login after a worker restart", async () => {
  vi.useFakeTimers();
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  expect(first?.expiresAt).toBe(Date.now() + 10_000);
  await vi.advanceTimersByTimeAsync(10_000);
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toBeNull();
  const restarted = new VaultController();
  expect(await restarted.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0)).toBeNull();
  expect(await restarted.inspectSiteLogin(1, "https://example.com", "alice", "changed", options, 0)).not.toBeNull();
});

it("keeps a held prompt saveable past its timeout, but not past the capture window", async () => {
  vi.useFakeTimers();
  const controller = new VaultController();
  const prompt = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  await controller.holdPendingSiteLogin(1, prompt!.id);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toMatchObject({ id: prompt!.id });
  await vi.advanceTimersByTimeAsync(240_000);
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toBeNull();
});

it("persists a configured prompt, and dismisses it without re-prompting", async () => {
  const controller = new VaultController();
  const first = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", { ...options, savePromptTimeoutSeconds: 60 }, 0);
  expect(first!.expiresAt - Date.now()).toBeGreaterThan(59_000);
  const restarted = new VaultController();
  expect(await restarted.pendingSitePrompt(1, "https://example.com/mfa", 0)).toEqual(first);
  await restarted.dismissPendingSiteLogin(1, first!.id);
  expect(await restarted.inspectSiteLogin(1, "https://example.com/mfa", "alice", "secret", options, 0)).toBeNull();
});

it("pulls a server password change into the cached vault", async () => {
  const controller = new VaultController();
  await controller.sync();
  payload = { Ciphers: [{ ...await createEncryptedLogin({ name: "Example", username: "alice", password: "new secret", uri: "https://example.com" }, key), Id: "login" }] };
  await controller.sync();
  expect(await controller.siteCredential("login", "https://example.com")).toEqual({ username: "alice", password: "new secret" });
});

it("does not repopulate decrypted credentials if locking interrupts sync", async () => {
  const controller = new VaultController();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => { started(); await waiting; return new Response(JSON.stringify({ Ciphers: [] }), { headers: { "content-type": "application/json" } }); });
  const syncing = controller.sync().catch(() => undefined);
  await began;
  await controller.lock();
  release();
  await syncing;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});

it("syncs ciphertext while locked without unlocking the vault", async () => {
  const controller = new VaultController();
  await controller.lock();
  payload = { Ciphers: [], Folders: [{ Id: "new folder" }] };
  await controller.sync();
  expect(encrypted).toEqual(payload);
  expect(await controller.getState()).toMatchObject({ phase: "locked", lastSync: expect.any(String) });
});

it("sends edits to the backend and performs a fresh sync after an older sync finishes", async () => {
  const login = { name: "Example", username: "alice", password: "old secret", uri: "https://example.com" };
  const raw = { ...await createEncryptedLogin(login, key), Id: "login" };
  payload = { Ciphers: [raw] };
  const controller = new VaultController();
  await controller.sync();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  let written!: () => void;
  const saved = new Promise<void>((resolve) => { written = resolve; });
  const requests: string[] = [];
  let holdNextSync = true;
  fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
    requests.push(`${init.method} ${url}`);
    let body: unknown = payload;
    if (init.method === "PUT") {
      payload = { Ciphers: [{ ...JSON.parse(init.body as string), Id: "login" }] };
      body = payload;
      written();
    } else if (url.endsWith("/ciphers/login")) body = raw;
    else if (holdNextSync) { holdNextSync = false; started(); await waiting; }
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  const background = controller.sync();
  await began;
  const editing = controller.updateLogin("login", { ...login, password: "new secret" });
  await saved;
  release();
  await Promise.all([background, editing]);
  expect(requests.at(-1)).toBe("GET https://vault.example.com/api/sync?excludeDomains=true");
  expect(await controller.siteCredential("login", "https://example.com")).toEqual({ username: "alice", password: "new secret" });
});

it("retains a pending login after a failed write so saving can be retried", async () => {
  const controller = new VaultController();
  const prompt = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  fetchMock.mockRejectedValueOnce(new Error("offline"));
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).rejects.toThrow();
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toEqual(prompt);
});

it("refreshes an expired token once when a sync and edit run together", async () => {
  const login = { name: "Example", username: "alice", password: "secret", uri: "https://example.com" };
  const raw = { ...await createEncryptedLogin(login, key), Id: "login" };
  payload = { Ciphers: [raw] };
  const controller = new VaultController();
  await controller.sync();
  Object.assign(session.authSession as object, { refreshToken: "refresh", accessTokenExpiresAt: 0 });
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let refreshes = 0;
  fetchMock.mockImplementation(async (url: string) => {
    let body: unknown = url.endsWith("/ciphers/login") ? raw : payload;
    if (url.endsWith("/connect/token")) {
      refreshes++;
      await waiting;
      body = { access_token: "new token", refresh_token: "new refresh", expires_in: 3600 };
    }
    return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
  });
  const tasks = Promise.all([controller.sync(), controller.updateLogin("login", login)]);
  await vi.waitFor(() => expect(refreshes).toBeGreaterThan(0));
  release();
  await tasks;
  expect(refreshes).toBe(1);
});

it("does not restore decrypted credentials when a write finishes after locking", async () => {
  const controller = new VaultController();
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => {
    started();
    await waiting;
    return new Response("{}", { headers: { "content-type": "application/json" } });
  });
  const saving = controller.createLogin({ name: "Example", username: "alice", password: "secret", uri: "https://example.com" });
  await began;
  await controller.lock();
  release();
  await saving;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});

it("consumes a committed save even if the following refresh fails", async () => {
  const controller = new VaultController();
  const prompt = await controller.inspectSiteLogin(1, "https://example.com", "alice", "secret", options, 0);
  fetchMock.mockResolvedValueOnce(new Response("{}", { headers: { "content-type": "application/json" } })).mockRejectedValueOnce(new Error("offline"));
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).resolves.toBeUndefined();
  expect(await controller.pendingSitePrompt(1, "https://example.com", 0)).toBeNull();
  await expect(controller.savePendingSiteLogin(1, prompt!.id)).rejects.toThrow("expired");
});

it("blocks a sync that starts while lock is clearing pending prompt storage", async () => {
  const controller = new VaultController();
  let finishCleanup!: () => void;
  const cleanup = new Promise<void>((resolve) => { finishCleanup = resolve; });
  let cleanupStarted!: () => void;
  const clearing = new Promise<void>((resolve) => { cleanupStarted = resolve; });
  const originalSet = chrome.storage.session.set;
  vi.spyOn(chrome.storage.session, "set").mockImplementation(async (values) => {
    if ("pendingSiteLogins" in values) { cleanupStarted(); await cleanup; }
    await originalSet(values);
  });
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  let started!: () => void;
  const began = new Promise<void>((resolve) => { started = resolve; });
  fetchMock.mockImplementationOnce(async () => {
    started(); await waiting;
    return new Response('{"Ciphers":[]}', { headers: { "content-type": "application/json" } });
  });
  const locking = controller.lock();
  await clearing;
  const syncing = controller.sync().catch(() => undefined);
  await began;
  finishCleanup();
  await locking;
  release();
  await syncing;
  await expect(controller.list({ type: "vault.list", query: "" })).rejects.toThrow("locked");
});

it("fills an authenticator code automatically only right after Firnkey filled that login in the same tab", async () => {
  const raw = await createEncryptedLogin({ name: "Example", username: "alice", password: "secret", uri: "https://example.com" }, key);
  const itemKey = await decryptSymmetricBytes(raw.key as string, key);
  (raw.login as Record<string, unknown>).totp = await encryptSymmetricString("JBSWY3DPEHPK3PXP", itemKey);
  payload = { Ciphers: [{ ...raw, Id: "login" }] };
  const controller = new VaultController();
  await controller.sync();

  expect(await controller.autoTotp(1, "https://example.com/2fa")).toBeNull(); // nothing filled yet
  expect((await controller.siteTotp("login", "https://example.com/2fa")).code).toMatch(/^\d{6}$/); // suggestion still works
  await expect(controller.siteTotp("login", "https://evil.example/2fa")).rejects.toThrow(/not mapped/);

  await controller.siteCredential("login", "https://example.com/login", 1);
  expect(await controller.autoTotp(1, "https://example.com/2fa")).toMatchObject({ code: expect.stringMatching(/^\d{6}$/), itemName: "Example" });
  expect(await controller.autoTotp(2, "https://example.com/2fa")).toBeNull(); // other tab
  expect(await controller.autoTotp(1, "https://evil.example/2fa")).toBeNull(); // other site

  vi.useFakeTimers({ now: Date.now() + 181_000 });
  expect(await controller.autoTotp(1, "https://example.com/2fa")).toBeNull(); // expired
  vi.useRealTimers();

  await controller.siteCredential("login", "https://example.com/login", 1);
  controller.forgetTab(1);
  expect(await controller.autoTotp(1, "https://example.com/2fa")).toBeNull(); // tab closed
  await controller.siteCredential("login", "https://example.com/login", 1);
  await controller.lock();
  expect(await controller.autoTotp(1, "https://example.com/2fa")).toBeNull(); // locking forgets recent fills
});

it("comes back locked after a browser restart, keeping server tokens but not the account key", async () => {
  const { writeAuthSession } = await import("../src/shared/storage");
  await writeAuthSession(session.authSession as Parameters<typeof writeAuthSession>[0]);
  expect(persisted).toMatchObject({ accessToken: "test" });
  expect(persisted).not.toHaveProperty("userKey");
  delete session.authSession; // Chrome clears session storage when the browser closes.
  expect((await new VaultController().getState()).phase).toBe("locked");
});

it("unlocks with the biometric PRF key only, and logout removes it", async () => {
  const controller = new VaultController();
  const prf = () => new Uint8Array(32).fill(9);
  await controller.enableBiometricUnlock("credential-1", prf());
  await controller.lock();
  const locked = await controller.getState();
  expect(locked).toMatchObject({ phase: "locked", biometricCredentialId: "credential-1" });
  await expect(controller.unlockWithBiometric(new Uint8Array(32).fill(8))).rejects.toThrow(/did not match/);
  await controller.unlockWithBiometric(prf());
  expect((session.authSession as { userKey: number[] }).userKey).toEqual([...key]);
  await controller.logout();
  expect(local.biometricUnlock).toBeUndefined();
});

it("lists folders and trash separately, never offers trash for autofill, and sends trash actions to the server", async () => {
  const login = await createEncryptedLogin({ name: "Example", username: "alice", password: "secret", uri: "https://example.com", folderId: "f1" }, key);
  payload = {
    Folders: [{ Id: "f1", Name: await encryptSymmetricString("Work", key) }],
    Ciphers: [{ ...login, Id: "a" }, { ...login, Id: "b", DeletedDate: "2026-01-01T00:00:00Z" }],
  };
  const controller = new VaultController();
  await controller.sync();
  const ids = async (folder?: string) =>
    (await controller.list({ type: "vault.list", query: "", ...(folder ? { folder } : {}) })).items.map((item) => item.id);
  expect(await ids()).toEqual(["a"]);
  expect(await ids("f1")).toEqual(["a"]);
  expect(await ids("none")).toEqual([]);
  expect(await ids("trash")).toEqual(["b"]);
  expect((await controller.list({ type: "vault.list", query: "" })).folders).toEqual([{ id: "f1", name: "Work" }]);
  expect((await controller.matchingLogins("https://example.com")).map((item) => item.id)).toEqual(["a"]);
  await expect(controller.siteCredential("b", "https://example.com")).rejects.toThrow("no longer exists");
  await expect(controller.restoreItem("a")).rejects.toThrow("no longer in the trash");
  await controller.trashItem("a");
  await controller.restoreItem("b");
  await controller.deleteForever("b");
  await controller.saveFolder(undefined, " Home ");
  await controller.deleteFolder("f1");
  const calls = fetchMock.mock.calls.map(([url, init]) => `${(init as RequestInit).method} ${url as string}`);
  for (const call of [
    "PUT https://vault.example.com/api/ciphers/a/delete",
    "PUT https://vault.example.com/api/ciphers/b/restore",
    "DELETE https://vault.example.com/api/ciphers/b",
    "POST https://vault.example.com/api/folders",
    "DELETE https://vault.example.com/api/folders/f1",
  ]) expect(calls).toContain(call);
});

it("switches accounts: the current one is set aside locked, with its tokens, vault copy and Touch ID record", async () => {
  const controller = new VaultController();
  const alice = { email: "test@example.com", baseUrl: "https://vault.example.com" };
  await controller.addAccount();
  expect(await controller.getState()).toMatchObject({ phase: "signed-out", accounts: [alice] });
  expect(encrypted).toBeNull();

  // Bob signs in (the server round trip is covered elsewhere).
  const bobPayload = { Ciphers: [], Profile: { Email: "bob@example.com" } };
  local.accountMetadata = { email: "bob@example.com", baseUrl: "https://bob.example.com", itemCount: 0 };
  local.serverSnapshot = { baseUrl: "https://bob.example.com" };
  local.biometricUnlock = { credentialId: "bob-passkey", iv: "", ciphertext: "" };
  session.authSession = { email: "bob@example.com", baseUrl: "https://bob.example.com", accessToken: "bob", userKey: [...key] };
  encrypted = bobPayload;
  const [saved] = (await controller.getState() as { accounts: { id: string }[] }).accounts;

  await controller.switchAccount(saved!.id);
  expect(await controller.getState()).toMatchObject({
    phase: "locked", email: "test@example.com", snapshot: { baseUrl: "https://vault.example.com" },
    accounts: [{ email: "bob@example.com", baseUrl: "https://bob.example.com" }],
  });
  expect(local.biometricUnlock).toBeUndefined();
  expect(encrypted).toEqual({ Ciphers: [] });
  const bob = (await controller.getState() as { accounts: { id: string }[] }).accounts[0]!;
  expect(stashed.get(`account:${bob.id}`)).toMatchObject({ accessToken: "bob" });
  expect(stashed.get(`account:${bob.id}`)).not.toHaveProperty("userKey");

  await controller.switchAccount(bob.id);
  expect(await controller.getState()).toMatchObject({ phase: "locked", email: "bob@example.com", biometricCredentialId: "bob-passkey" });
  expect(encrypted).toEqual(bobPayload);
  await expect(controller.switchAccount("nobody")).rejects.toThrow(/no longer saved/);

  const aliceSaved = (await controller.getState() as { accounts: { id: string }[] }).accounts[0]!;
  stashed.set(`sync:account:${aliceSaved.id}`, { Ciphers: [] });
  await controller.removeAccount(aliceSaved.id);
  expect(await controller.getState()).toMatchObject({ phase: "locked", email: "bob@example.com", accounts: [] });
  expect(stashed.size).toBe(0);
  await expect(controller.removeAccount(aliceSaved.id)).rejects.toThrow(/no longer saved/);
});

it("answers a basic-auth dialog only with one unprotected, unlocked match", async () => {
  const login = (name: string, uri: string, extra: Record<string, unknown> = {}) =>
    createEncryptedLogin({ name, username: name, password: "pw", uri }, key).then((raw) => ({ ...raw, Id: name, ...extra }));
  payload = { Ciphers: [
    await login("one", "https://one.example"),
    await login("twin-a", "https://two.example"), await login("twin-b", "https://two.example"),
    await login("guarded", "https://guarded.example", { Reprompt: 1 }),
    await login("secure", "https://secure.example"),
  ] };
  const controller = new VaultController();
  await controller.sync();
  expect(await controller.basicAuthCredential("https://one.example/admin")).toEqual({ username: "one", password: "pw" });
  expect(await controller.basicAuthCredential("https://two.example/")).toBeNull(); // ambiguous
  expect(await controller.basicAuthCredential("https://guarded.example/")).toBeNull(); // needs reprompt
  expect(await controller.basicAuthCredential("http://secure.example/")).toBeNull(); // HTTPS login over HTTP
  expect(await controller.basicAuthCredential("https://other.example/")).toBeNull();
  await controller.lock();
  expect(await controller.basicAuthCredential("https://one.example/")).toBeNull();
});

// A tiny in-memory server for attachment, import and collection requests.
function fakeServer(cipher: Record<string, unknown>) {
  const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
  const stored = new Map<string, Uint8Array>();
  const requests: { method: string; url: string; body?: unknown }[] = [];
  fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
    const method = init.method ?? "GET";
    const path = url.replace("https://vault.example.com", "");
    requests.push({ method, url: path, ...(typeof init.body === "string" ? { body: JSON.parse(init.body) } : {}) });
    if (path.startsWith("/api/sync")) return json(payload);
    if (method === "GET" && path === "/api/ciphers/a") return json(cipher);
    if (method === "POST" && path === "/api/ciphers/a/attachment/v2") {
      const body = JSON.parse(init.body as string) as { key: string; fileName: string };
      cipher.attachments = [{ id: "att1", fileName: body.fileName, key: body.key, size: "16", sizeName: "16 B" }];
      return json({ attachmentId: "att1", url: "/ciphers/a/attachment/att1" });
    }
    if (method === "POST" && path === "/api/ciphers/a/attachment/att1") {
      stored.set("att1", new Uint8Array(await ((init.body as FormData).get("data") as Blob).arrayBuffer()));
      return json({});
    }
    if (method === "GET" && path === "/api/ciphers/a/attachment/att1") return json({ url: "/attachments/a/att1?token=t" });
    if (path === "/attachments/a/att1?token=t") return new Response(stored.get("att1")!.slice());
    return json({ id: "new" });
  });
  return requests;
}

it("uploads an encrypted attachment and decrypts it again on download", async () => {
  const raw: Record<string, unknown> = { ...(await createEncryptedLogin({ name: "Example", username: "a", password: "b", uri: "" }, key)), id: "a" };
  payload = { Ciphers: [raw] };
  const requests = fakeServer(raw);
  const controller = new VaultController();
  await controller.sync();
  await controller.addAttachment("a", "notes.txt", new TextEncoder().encode("top secret notes"));
  const upload = requests.find((request) => request.url === "/api/ciphers/a/attachment/v2")!.body as Record<string, unknown>;
  expect(JSON.stringify(upload)).not.toContain("notes.txt");
  expect(upload.adminRequest).toBe(false);
  payload = { Ciphers: [raw] };
  await controller.sync();
  expect((await controller.detail("a")).attachments).toEqual([{ id: "att1", fileName: "notes.txt", size: 16, sizeName: "16 B" }]);
  const file = await controller.downloadAttachment("a", "att1");
  expect(file.fileName).toBe("notes.txt");
  expect(new TextDecoder().decode(Uint8Array.fromBase64(file.data))).toBe("top secret notes");
});

it("imports a whole file in one request and reuses folders that already exist", async () => {
  payload = { Folders: [{ Id: "f1", Name: await encryptSymmetricString("Work", key) }], Ciphers: [] };
  const requests = fakeServer({});
  const controller = new VaultController();
  await controller.sync();
  const csv = "folder,type,name,login_uri,login_username,login_password\nWork,login,Mail,https://mail.example.com,me,pw\nHome,login,Router,,admin,admin\n,login,Bank,,x,y\n";
  expect(await controller.importVault(csv, undefined, false)).toEqual({ items: 3, folders: 2 });
  expect(requests.some((request) => request.url === "/api/ciphers/import")).toBe(false);
  await controller.importVault(csv, undefined, true);
  const body = requests.find((request) => request.url === "/api/ciphers/import")!.body as {
    ciphers: Record<string, unknown>[]; folders: { id?: string }[]; folderRelationships: unknown[];
  };
  expect(body.ciphers).toHaveLength(3);
  expect(JSON.stringify(body)).not.toContain("Mail");
  expect(body.folders.map((folder) => folder.id)).toEqual(["f1", undefined]);
  expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }, { key: 1, value: 1 }]);
});

it("creates items in a writable collection under the organization key, and refuses read-only ones", async () => {
  const orgKey = crypto.getRandomValues(new Uint8Array(64));
  const rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["encrypt", "decrypt"],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsa.publicKey, orgKey));
  const { encryptSymmetricBytes } = await import("../src/crypto/bitwarden-crypto");
  payload = {
    Profile: { PrivateKey: await encryptSymmetricBytes(pkcs8, key), Organizations: [{ Id: "o1", Name: "Acme", Key: `4.${wrapped.toBase64()}` }] },
    Collections: [
      { Id: "c1", OrganizationId: "o1", Name: await encryptSymmetricString("Ops", orgKey), ReadOnly: false },
      { Id: "c2", OrganizationId: "o1", Name: await encryptSymmetricString("Audit", orgKey), ReadOnly: true },
    ],
    Ciphers: [],
  };
  const requests = fakeServer({});
  const controller = new VaultController();
  await controller.sync();
  expect((await controller.list({ type: "vault.list", query: "" })).collections.map((collection) => collection.name)).toEqual(["Audit", "Ops"]);
  await controller.createLogin({ name: "Shared", username: "team", password: "pw", uri: "" }, undefined, "c1");
  const body = requests.find((request) => request.url === "/api/ciphers/create")!.body as { cipher: Record<string, unknown>; collectionIds: string[] };
  expect(body.collectionIds).toEqual(["c1"]);
  expect(body.cipher.organizationId).toBe("o1");
  expect(await decryptSymmetricBytes(body.cipher.key as string, orgKey)).toHaveLength(64);
  await expect(controller.createLogin({ name: "x", username: "", password: "", uri: "" }, undefined, "c2")).rejects.toThrow(/not add items/);
});
