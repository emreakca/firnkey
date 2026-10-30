import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VaultController } from "../src/background/vault-controller";
import {
  deriveMasterPasswordHash,
  derivePbkdf2MasterKey,
  encryptSymmetricBytes,
  stretchMasterKey,
} from "../src/crypto/bitwarden-crypto";
import { fromBase64 } from "../src/crypto/bytes";
import { createEncryptedLogin } from "../src/vault/encrypt-login";

vi.mock("../src/shared/database", () => ({
  readEncryptedSync: async () => null,
  writeEncryptedSync: async () => undefined,
  clearEncryptedSync: async () => undefined,
}));
vi.mock("../src/shared/persistent-session", () => ({
  clearPersistentAuthSession: async () => undefined,
  writePersistentAuthSession: async () => undefined,
  readPersistentAuthSession: async () => null,
}));
const runBrowserTwoFactor = vi.fn(async () => "assertion-json");
vi.mock("../src/background/two-factor", () => ({
  needsBrowserStep: (provider?: number) => provider === 2 || provider === 7,
  runBrowserTwoFactor: (...args: unknown[]) => runBrowserTwoFactor(...(args as [])),
}));

// An encryption v2 user key from bitwarden/sdk-internal's tests.
const V2_USER_KEY = fromBase64(
  "pQEEAlDib+JxbqMBlcd3KTUesbufAzoAARFvBIQDBAUGIFggt79surJXmqhPhYuuqi9ZyPfieebmtw2OsmN5SDrb4yUB",
);
const EMAIL = "test@example.com";
const PASSWORD = "correct horse battery staple";
let local: Record<string, unknown>;
let session: Record<string, unknown>;
const openPopup = vi.fn(async () => undefined);
const storage = (data: Record<string, unknown>) => ({
  get: async (name: string) => ({ [name]: data[name] }),
  set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
  remove: async (name: string) => { delete data[name]; },
});

beforeEach(() => {
  local = { serverSnapshot: { baseUrl: "https://vault.example.com" } };
  session = {};
  vi.stubGlobal("chrome", {
    storage: { local: storage(local), session: storage(session) },
    windows: { getLastFocused: async () => ({ id: 9 }) },
    action: { openPopup },
  });
});
afterEach(() => { vi.unstubAllGlobals(); runBrowserTwoFactor.mockClear(); openPopup.mockClear(); });

it("signs a v2 account in with a security key and decrypts its vault", async () => {
  const masterKey = await derivePbkdf2MasterKey(PASSWORD, EMAIL, 100_000);
  const hash = await deriveMasterPasswordHash(masterKey, PASSWORD);
  const wrappedUserKey = await encryptSymmetricBytes(V2_USER_KEY, await stretchMasterKey(masterKey));
  const cipher = await createEncryptedLogin({ name: "Example", username: "alice", password: "secret", uri: "https://example.com" }, V2_USER_KEY);
  const challenge = { challenge: "AAEC", rpId: "vault.example.com", allowCredentials: [{ type: "public-key", id: "AQID" }] };
  const grants: URLSearchParams[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/accounts/prelogin/password")) return json({ kdf: 0, kdfIterations: 100_000 });
    if (url.endsWith("/connect/token")) {
      const form = new URLSearchParams(init?.body as string);
      grants.push(form);
      if (!form.get("twoFactorToken")) return json({ TwoFactorProviders: ["7"], TwoFactorProviders2: { 7: challenge } }, 400);
      return json({ access_token: "token", token_type: "Bearer", Key: wrappedUserKey, Kdf: 0, KdfIterations: 100_000 });
    }
    if (url.includes("/sync")) return json({ Ciphers: [{ ...cipher, Id: "one" }] });
    return json({});
  }));

  const result = await new VaultController().login({
    type: "auth.login", baseUrl: "https://vault.example.com", email: EMAIL, masterPassword: PASSWORD, twoFactorProvider: 7,
  });

  expect(String(cipher.key).startsWith("7.")).toBe(true); // item key wrapped by the v2 user key
  expect(result).toEqual({ status: "unlocked", itemCount: 1, failures: 0 });
  expect(runBrowserTwoFactor).toHaveBeenCalledWith(7, challenge, "https://vault.example.com");
  expect(grants.map((form) => form.get("twoFactorToken"))).toEqual([null, "assertion-json"]);
  expect(grants[1]!.get("password")).toBe(hash);
  expect(openPopup).toHaveBeenCalledWith({ windowId: 9 });
});

it("leaves the failure for the reopened popup when the security key step fails", async () => {
  runBrowserTwoFactor.mockRejectedValueOnce(new Error("Two-step login was cancelled."));
  vi.stubGlobal("fetch", vi.fn(async (url: string) => new Response(
    JSON.stringify(url.endsWith("/prelogin/password") ? { kdf: 0, kdfIterations: 100_000 } : { TwoFactorProviders2: { 2: { AuthUrl: "https://api-1.duosecurity.com/x" } } }),
    { status: url.endsWith("/prelogin/password") ? 200 : 400, headers: { "content-type": "application/json" } },
  )));
  await expect(new VaultController().login({
    type: "auth.login", baseUrl: "https://vault.example.com", email: EMAIL, masterPassword: PASSWORD, twoFactorProvider: 2,
  })).rejects.toThrow(/cancelled/);
  expect(session.loginNotice).toBe("Two-step login was cancelled.");
  expect(openPopup).toHaveBeenCalled();
});
