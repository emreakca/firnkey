// Runs Firnkey's real background code against a real server.
// Skipped unless FIRNKEY_SERVER_URL points at a throwaway server with SIGNUPS_ALLOWED=true;
// scripts/compat.mjs starts one per supported release in Docker and runs this file against it.
// With FIRNKEY_EMAIL and FIRNKEY_PASSWORD it uses that existing account instead (`pnpm test:live`
// reads them from .env.local). The account must start empty; the suite deletes everything it made.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { SyncResponse } from "../src/api/models";
import { ServerClient } from "../src/api/server-client";
import {
  deriveMasterPasswordHash,
  derivePbkdf2MasterKey,
  encryptSymmetricBytes,
  encryptSymmetricString,
  stretchMasterKey,
} from "../src/crypto/bitwarden-crypto";

// The project has no Node type definitions; vitest runs in Node, so `process` exists.
const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {};
const server = env.FIRNKEY_SERVER_URL;
const existing = Boolean(env.FIRNKEY_EMAIL);

let encrypted: SyncResponse | null = null;
vi.mock("../src/shared/database", () => ({
  readEncryptedSync: async () => encrypted,
  writeEncryptedSync: async (payload: SyncResponse) => { encrypted = payload; },
  clearEncryptedSync: async () => { encrypted = null; },
}));
// Argon2id normally runs in the offscreen document; here the same code runs in Node.
vi.mock("../src/crypto/argon2-service", async () => ({
  deriveArgon2idMasterKey: (await import("../src/crypto/bitwarden-argon2")).deriveBitwardenArgon2idKey,
}));
vi.mock("../src/shared/persistent-session", () => ({
  clearPersistentAuthSession: async () => undefined,
  writePersistentAuthSession: async () => undefined,
  readPersistentAuthSession: async () => null,
}));

const storage = (data: Record<string, unknown>) => ({
  get: async (names: string | string[]) => Object.fromEntries([names].flat().map((name) => [name, structuredClone(data[name])])),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});

const email = env.FIRNKEY_EMAIL ?? `compat-${Date.now()}@example.com`;
const password = env.FIRNKEY_PASSWORD ?? "correct horse battery staple";
const iterations = 600_000;

// Creates an account the way the web vault does: a random account key wrapped by the master key, plus an RSA key pair.
async function register(baseUrl: string): Promise<void> {
  const masterKey = await derivePbkdf2MasterKey(password, email, iterations);
  const userKey = crypto.getRandomValues(new Uint8Array(64));
  const rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["encrypt", "decrypt"],
  );
  const body = {
    email,
    name: "Compat",
    masterPasswordHash: await deriveMasterPasswordHash(masterKey, password),
    masterPasswordHint: null,
    key: await encryptSymmetricBytes(userKey, await stretchMasterKey(masterKey)),
    kdf: 0,
    kdfIterations: iterations,
    keys: {
      publicKey: new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey)).toBase64(),
      encryptedPrivateKey: await encryptSymmetricBytes(new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey)), userKey),
    },
  };
  const post = (path: string, value: unknown) =>
    fetch(`${baseUrl}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) });
  // Current servers: a verification token (returned directly when the server sends no mail), then "finish".
  const verification = await post("/identity/accounts/register/send-verification-email", { email, name: "Compat", receiveMarketingEmails: false });
  const response = verification.ok
    ? await post("/identity/accounts/register/finish", {
        email,
        masterPasswordHash: body.masterPasswordHash,
        masterPasswordHint: null,
        userSymmetricKey: body.key,
        userAsymmetricKeys: body.keys,
        kdf: body.kdf,
        kdfIterations: body.kdfIterations,
        emailVerificationToken: verificationToken(await verification.text()),
      })
    : await post("/api/accounts/register", body); // Older servers.
  if (!response.ok) throw new Error(`Registration failed: HTTP ${response.status} ${await response.text()}`);
}

// Older servers send the token as a JSON string, newer ones as plain text.
function verificationToken(body: string): string {
  return body.startsWith('"') ? JSON.parse(body) as string : body;
}

describe.skipIf(!server)(`Server at ${server}`, () => {
  const baseUrl = server!;
  let controller: import("../src/background/vault-controller").VaultController;

  beforeAll(async () => {
    vi.stubGlobal("chrome", { storage: { local: storage({ serverSnapshot: { baseUrl } }), session: storage({}) } });
    if (!existing) await register(baseUrl);
    const { VaultController } = await import("../src/background/vault-controller");
    controller = new VaultController();
    expect(await controller.login({ type: "auth.login", baseUrl, email, masterPassword: password })).toMatchObject({ status: "unlocked" });
    // Never touch an account with data in it: the cleanup below deletes everything.
    const { items: present, folders, collections } = await controller.list({ type: "vault.list", query: "" });
    const contents = present.length + folders.length + collections.length + (await items("trash")).length + (await items("archive")).length + (await controller.listSends()).length;
    if (existing && contents > 0) throw new Error(`${email} is not empty. Use a dedicated, empty test account.`);
  }, 60_000);

  // Empties an existing account again, so the next run starts clean. Organizations take their items with them.
  afterAll(async () => {
    if (!existing || !controller) return;
    await controller.sync();
    const session = (await controller.pushTarget())!;
    const prelogin = (controller as unknown as { prelogin(url: string, user: string, secret: string): Promise<{ masterPasswordHash: string }> }).prelogin;
    const { masterPasswordHash } = await prelogin.call(controller, baseUrl, email, password);
    const { collections } = await controller.list({ type: "vault.list", query: "" });
    for (const id of new Set(collections.map((collection) => collection.organizationId))) {
      const response = await fetch(`${baseUrl}/api/organizations/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ masterPasswordHash }),
      });
      if (!response.ok) throw new Error(`Could not delete the test organization: HTTP ${response.status}`);
    }
    await controller.sync();
    for (const item of [...(await items()), ...(await items("archive"))]) await controller.trashItem(item.id);
    for (const item of await items("trash")) await controller.deleteForever(item.id);
    for (const folder of (await controller.list({ type: "vault.list", query: "" })).folders) await controller.deleteFolder(folder.id);
    for (const send of await controller.listSends()) await controller.deleteSend(send.id);
  }, 60_000);

  const items = async (folder?: string) =>
    (await controller.list({ type: "vault.list", query: "", ...(folder ? { folder } : {}) })).items;

  it("creates, edits and trashes a login", async () => {
    await controller.createLogin({ name: "Compat login", username: "alice", password: "first", uri: "https://example.com" });
    const [login] = await items();
    expect(login).toMatchObject({ name: "Compat login", username: "alice" });
    await controller.updateLogin(login!.id, { name: "Compat login", username: "alice", password: "second", uri: "https://example.com" });
    expect((await controller.detail(login!.id)).passwordHistory?.[0]?.password).toBe("first");

    // Several websites and custom fields, then back to one website.
    await controller.updateLogin(login!.id, {
      name: "Compat login", username: "alice", password: "second", uri: "",
      uris: [{ uri: "https://example.com", match: null }, { uri: "https://login.example.org", match: 1 }],
      fields: [{ name: "PIN", value: "1234", hidden: true }, { name: "Admin", value: "true", hidden: false, boolean: true }],
    });
    const edited = await controller.detail(login!.id);
    expect(edited.uris).toEqual([{ uri: "https://example.com/" }, { uri: "https://login.example.org/", match: 1 }]);
    expect(edited.fields).toEqual([{ name: "PIN", value: "1234", hidden: true }, { name: "Admin", value: "true", hidden: false, boolean: true }]);
    await controller.updateLogin(login!.id, { name: "Compat login", username: "alice", password: "second", uri: "", uris: [{ uri: "https://example.com", match: null }], fields: [] });
    expect(await controller.detail(login!.id)).toMatchObject({ uris: [{ uri: "https://example.com/" }] });
  });

  it("uploads, downloads and deletes an attachment", async () => {
    const [login] = await items();
    const body = new TextEncoder().encode("attachment from Firnkey\n".repeat(100));
    await controller.addAttachment(login!.id, "notes.txt", body);
    const [attachment] = (await controller.detail(login!.id)).attachments ?? [];
    expect(attachment).toMatchObject({ fileName: "notes.txt", size: expect.any(Number) });
    const file = await controller.downloadAttachment(login!.id, attachment!.id);
    expect(Uint8Array.fromBase64(file.data)).toEqual(body);
    await controller.deleteAttachment(login!.id, attachment!.id);
    expect((await controller.detail(login!.id)).attachments).toBeUndefined();
  });

  it("creates, lists and deletes text and file Sends", async () => {
    const link = await controller.createSend({ type: 0, name: "Wifi", text: "hunter2", deletionDays: 1, maxAccessCount: 3 });
    expect(link).toMatch(new RegExp(`^${baseUrl}/#/send/[\\w-]+/[\\w-]+$`));
    const fileLink = await controller.createSend({ type: 1, name: "Report", fileName: "report.txt", deletionDays: 7 }, new TextEncoder().encode("report"));
    expect(fileLink).toBeTruthy();
    const sends = await controller.listSends();
    expect(sends.map((send) => [send.name, send.type])).toEqual([["Report", 1], ["Wifi", 0]]);
    const wifi = sends.find((send) => send.name === "Wifi")!;
    await controller.updateSend(wifi.id, { name: "Guest wifi", text: "hunter3", hidden: true, password: "pw" });
    const byId = async (id: string) => (await controller.listSends()).find((send) => send.id === id);
    expect(await byId(wifi.id)).toMatchObject({ name: "Guest wifi", text: "hunter3", hidden: true, hasPassword: true, link: wifi.link, deletionDate: wifi.deletionDate });
    await controller.updateSend(wifi.id, { name: "Guest wifi", text: "hunter3", removePassword: true, deletionDays: 2 });
    expect(await byId(wifi.id)).toMatchObject({ hasPassword: false });
    const report = sends.find((send) => send.name === "Report")!;
    await controller.updateSend(report.id, { name: "Q3 report" });
    expect(await byId(report.id)).toMatchObject({ name: "Q3 report", fileName: "report.txt" });
    for (const send of await controller.listSends()) await controller.deleteSend(send.id);
    expect(await controller.listSends()).toEqual([]);
  });

  it("imports a CSV file with folders, and round-trips a password-protected export", async () => {
    const csv = "folder,type,name,login_uri,login_username,login_password,notes\nWork,login,Mail,https://mail.example.com,me,pw,\nWork,note,Runbook,,,,step 1\n";
    expect(await controller.importVault(csv, undefined, true)).toEqual({ items: 2, folders: 1 });
    const { folders } = await controller.list({ type: "vault.list", query: "" });
    const work = folders.find((folder) => folder.name === "Work")!;
    expect((await items(work.id)).map((item) => item.name).sort()).toEqual(["Mail", "Runbook"]);

    const file = await controller.exportVault(password, "encrypted_json", "file password");
    expect(file).not.toContain("Mail");
    expect(await controller.importVault(file, "file password", false)).toEqual({ items: 3, folders: 1 });
  });

  it("archives, unarchives and clones a login, matches equivalent domains and reads the fingerprint phrase", async () => {
    const login = (await items()).find((item) => item.name === "Compat login")!;
    // Servers before 1.36 have no archive and don't announce it; Firnkey then hides archiving.
    if ((await new ServerClient().checkServer(baseUrl)).archive) {
      await controller.archiveItem(login.id, true);
      expect((await items()).map((item) => item.id)).not.toContain(login.id);
      expect((await items("archive")).map((item) => item.id)).toEqual([login.id]);
      await controller.archiveItem(login.id, false);
      expect((await items("archive"))).toEqual([]);
    }

    const copy = await controller.cloneItem(login.id, "Compat copy");
    expect(await controller.detail(copy)).toMatchObject({ name: "Compat copy", username: "alice", password: "second" });
    await controller.trashItem(copy);
    await controller.deleteForever(copy);

    // google.com and youtube.com share one of the server's global equivalent-domain groups.
    await controller.createLogin({ name: "Equivalent", username: "", password: "pw", uri: "https://google.com" });
    expect((await controller.matchingLogins("https://www.youtube.com/")).map((item) => item.name)).toEqual(["Equivalent"]);
    const equivalent = (await items()).find((item) => item.name === "Equivalent")!;
    await controller.trashItem(equivalent.id);
    await controller.deleteForever(equivalent.id);

    expect(await controller.fingerprint()).toMatch(/^[a-z-]+(?:-[a-z-]+){4}$/);
  });

  it("creates an organization item in a collection and moves a personal item there", async () => {
    // A new organization, the way the web vault creates one: an organization key wrapped with the user's public key.
    const session = await controller.pushTarget();
    const sync = encrypted!;
    const profile = (sync.Profile ?? sync.profile) as Record<string, unknown>;
    const keyResponse = await fetch(`${baseUrl}/api/users/${profile.id ?? profile.Id}/public-key`, { headers: { Authorization: `Bearer ${session!.accessToken}` } });
    const { publicKey } = await keyResponse.json() as { publicKey: string };
    const orgKey = crypto.getRandomValues(new Uint8Array(64));
    const userPublic = await crypto.subtle.importKey("spki", Uint8Array.fromBase64(publicKey), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
    const orgRsa = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["encrypt", "decrypt"],
    );
    const created = await fetch(`${baseUrl}/api/organizations`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session!.accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Acme",
        billingEmail: email,
        planType: 0,
        key: `4.${new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, userPublic, orgKey)).toBase64()}`,
        keys: {
          publicKey: new Uint8Array(await crypto.subtle.exportKey("spki", orgRsa.publicKey)).toBase64(),
          encryptedPrivateKey: await encryptSymmetricBytes(new Uint8Array(await crypto.subtle.exportKey("pkcs8", orgRsa.privateKey)), orgKey),
        },
        collectionName: await encryptSymmetricString("Ops", orgKey),
      }),
    });
    expect(created.status).toBe(200);
    await controller.sync();
    const [collection] = (await controller.list({ type: "vault.list", query: "" })).collections;
    expect(collection).toMatchObject({ organizationName: "Acme", name: "Ops", readOnly: false });

    await controller.createItem({ type: 2, name: "Shared note", notes: "for the team" }, collection!.id);
    const personal = (await items()).find((item) => item.name === "Compat login")!;
    await controller.moveToCollection(personal.id, collection!.id);
    const shared = (await controller.list({ type: "vault.list", query: "", collection: collection!.id })).items;
    expect(shared.map((item) => item.name).sort()).toEqual(["Compat login", "Shared note"]);
    const moved = await controller.detail(personal.id);
    expect(moved).toMatchObject({ organizationId: expect.any(String), password: "second", collectionIds: [collection!.id] });

    // A second collection: the item joins it, then leaves the first.
    const second = await fetch(`${baseUrl}/api/organizations/${moved.organizationId}/collections`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session!.accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: await encryptSymmetricString("Finance", orgKey), groups: [], users: [] }),
    });
    expect(second.status).toBe(200);
    await controller.sync();
    const finance = (await controller.list({ type: "vault.list", query: "" })).collections.find((entry) => entry.name === "Finance")!;
    await controller.setCollections(personal.id, [collection!.id, finance.id]);
    expect((await controller.detail(personal.id)).collectionIds?.sort()).toEqual([collection!.id, finance.id].sort());
    await controller.setCollections(personal.id, [finance.id]);
    expect((await controller.detail(personal.id)).collectionIds).toEqual([finance.id]);
    expect((await controller.list({ type: "vault.list", query: "", vault: moved.organizationId! })).items.map((item) => item.name).sort()).toEqual(["Compat login", "Shared note"]);
    expect((await controller.list({ type: "vault.list", query: "", vault: "personal" })).items.map((item) => item.name)).not.toContain("Compat login");
  });

  it("logs in with device once a signed-in session approves the request", async () => {
    const session = (await controller.pushTarget())!;
    const headers = { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" };
    const { fingerprint } = await controller.startDeviceLogin(baseUrl, email);
    expect(fingerprint).toMatch(/^[a-z-]+(?:-[a-z-]+){4}$/);
    expect(await controller.continueLogin({})).toEqual({ status: "pending" });

    // Approve it like an older app: the master key, RSA-encrypted to the request's public key.
    const pending = await (await fetch(`${baseUrl}/api/auth-requests`, { headers })).json() as { data: { id: string; publicKey: string }[] };
    const request = pending.data.at(-1)!;
    const prelogin = (controller as unknown as { prelogin(url: string, user: string, secret: string): Promise<{ masterKey: Uint8Array; masterPasswordHash: string }> }).prelogin;
    const { masterKey, masterPasswordHash } = await prelogin.call(controller, baseUrl, email, password);
    const requestKey = await crypto.subtle.importKey("spki", Uint8Array.fromBase64(request.publicKey), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
    const seal = async (value: Uint8Array) => `4.${new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, requestKey, value.slice())).toBase64()}`;
    const deviceIdentifier = (await chrome.storage.local.get("deviceIdentifier")).deviceIdentifier as string;
    const approved = await fetch(`${baseUrl}/api/auth-requests/${request.id}`, {
      method: "PUT",
      headers,
      body: JSON.stringify({ deviceIdentifier, key: await seal(masterKey), masterPasswordHash: await seal(new TextEncoder().encode(masterPasswordHash)), requestApproved: true }),
    });
    expect(approved.status).toBe(200);

    expect(await controller.continueLogin({})).toMatchObject({ status: "unlocked" });
    expect((await items()).some((item) => item.name === "Compat login")).toBe(true);
  }, 60_000);
});
