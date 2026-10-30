// Runs Firnkey's real background code against a real Vaultwarden server.
// Skipped unless VAULTWARDEN_URL points at a throwaway server with SIGNUPS_ALLOWED=true, e.g.:
//   docker run --rm -d -p 8099:80 -e SIGNUPS_ALLOWED=true -e DOMAIN=http://localhost:8099 vaultwarden/server:1.35.4
//   VAULTWARDEN_URL=http://localhost:8099 pnpm test tests/vaultwarden.compat.test.ts
// scripts/compat.mjs does this for every supported release.
// With VAULTWARDEN_EMAIL and VAULTWARDEN_PASSWORD it uses that existing account instead (`pnpm test:live`
// reads them from .env.local). The account must start empty; the suite deletes everything it made.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { SyncResponse } from "../src/api/models";
import {
  deriveMasterPasswordHash,
  derivePbkdf2MasterKey,
  encryptSymmetricBytes,
  encryptSymmetricString,
  stretchMasterKey,
} from "../src/crypto/bitwarden-crypto";

// The project has no Node type definitions; vitest runs in Node, so `process` exists.
const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {};
const server = env.VAULTWARDEN_URL;
const existing = Boolean(env.VAULTWARDEN_EMAIL);

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
  get: async (name: string) => ({ [name]: structuredClone(data[name]) }),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});

const email = env.VAULTWARDEN_EMAIL ?? `compat-${Date.now()}@example.com`;
const password = env.VAULTWARDEN_PASSWORD ?? "correct horse battery staple";
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

describe.skipIf(!server)(`Vaultwarden at ${server}`, () => {
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
    const contents = present.length + folders.length + collections.length + (await items("trash")).length + (await controller.listSends()).length;
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
    for (const item of await items()) await controller.trashItem(item.id);
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
    for (const send of sends) await controller.deleteSend(send.id);
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
    const shared = await items(`collection:${collection!.id}`);
    expect(shared.map((item) => item.name).sort()).toEqual(["Compat login", "Shared note"]);
    const moved = await controller.detail(personal.id);
    expect(moved).toMatchObject({ organizationId: expect.any(String), password: "second", collectionIds: [collection!.id] });
  });
});
