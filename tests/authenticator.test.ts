import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SyncResponse } from "../src/api/models";
import { VaultController } from "../src/background/vault-controller";
import { cleanLabel, generateTotp, otpauthUri, parseTotpKey, storedTotpKey } from "../src/crypto/totp";
import { isExtensionRequest } from "../src/shared/messages";
import { authenticatorEntries, authenticatorKey, exportAuthenticator, knownSecrets, previewImport } from "../src/vault/authenticator";
import { decryptVault } from "../src/vault/decrypt-vault";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";

const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const SHA256_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SHA512_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

describe("TOTP keys", () => {
  it("matches the RFC 6238 SHA-256 and SHA-512 vectors with custom digits", async () => {
    await expect(generateTotp(`otpauth://totp/T?secret=${SHA256_SEED}&algorithm=SHA256&digits=8`, 59_000)).resolves.toMatchObject({ code: "46119246" });
    await expect(generateTotp(`otpauth://totp/T?secret=${SHA512_SEED}&algorithm=SHA512&digits=8`, 59_000)).resolves.toMatchObject({ code: "90693936" });
    await expect(generateTotp(`otpauth://totp/T?secret=${SECRET}&period=60`, 61_000)).resolves.toMatchObject({ period: 60, remaining: 59 });
  });

  it("reads issuer and account and round-trips through a portable link", () => {
    const key = parseTotpKey(`otpauth://totp/ACME%20Co:jane%40example.com?secret=${SECRET.toLowerCase()}&digits=8&period=60&algorithm=sha256`);
    expect(key).toEqual({ secret: SECRET, issuer: "ACME Co", account: "jane@example.com", algorithm: "SHA256", digits: 8, period: 60, steam: false });
    expect(parseTotpKey(otpauthUri(key))).toEqual(key);
  });

  it("supports Steam keys in Bitwarden and otpauth forms", async () => {
    const forms = [`steam://${SECRET}`, `otpauth://steam/Steam:me?secret=${SECRET}`, `otpauth://totp/Steam:me?secret=${SECRET}&issuer=Steam`];
    for (const form of forms) {
      const key = parseTotpKey(form);
      expect(key).toMatchObject({ steam: true, digits: 5 });
      expect(storedTotpKey(key)).toBe(`steam://${SECRET}`);
      expect((await generateTotp(form)).code).toMatch(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
    }
  });

  it("rejects malformed QR payloads without echoing the secret", () => {
    const bad = [
      `otpauth://hotp/Example?secret=${SECRET}&counter=1`,
      `otpauth://totp/Example?secret=${SECRET}&algorithm=MD5`,
      `otpauth://totp/Example?secret=${SECRET}&digits=11`,
      `otpauth://totp/Example?secret=${SECRET}&period=0`,
      `otpauth://totp/%E0%A4%A?secret=${SECRET}`,
      "otpauth://totp/Example?issuer=NoSecret",
      `otpauth://totp/Example?secret=${SECRET.slice(0, 8)}`,
      "otpauth://totp/Example?secret=NOT*BASE32",
      `javascript:alert(1)//${SECRET}`,
      "",
      "A".repeat(3_000),
    ];
    for (const value of bad) {
      expect(() => parseTotpKey(value), value).toThrow();
      try {
        parseTotpKey(value);
      } catch (error) {
        expect((error as Error).message).not.toContain(SECRET);
      }
    }
  });

  it("strips control and bidirectional-override characters from hostile labels", () => {
    const key = parseTotpKey(`otpauth://totp/${encodeURIComponent("Bank‮\u0000​moc.live")}:${encodeURIComponent("a\nb")}?secret=${SECRET}`);
    expect(key.issuer).toBe("Bankmoc.live");
    expect(key.account).toBe("ab");
    expect(cleanLabel("x".repeat(500))).toHaveLength(200);
  });
});

describe("authenticator import", () => {
  const link = (issuer: string, secret = SECRET) => `otpauth://totp/${issuer}:me?secret=${secret}&issuer=${issuer}`;

  it("previews new, duplicate and invalid lines", () => {
    const other = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const { rows, entries } = previewImport([
      link("One"),
      "",
      link("Again"),            // same secret as line 1
      link("Known", other),     // already in the vault
      "otpauth://hotp/X?secret=" + SECRET,
      "not a link",
    ].join("\r\n"), new Set([other]));
    expect(rows.map((row) => [row.line, row.status])).toEqual([[1, "new"], [3, "duplicate"], [4, "duplicate"], [5, "invalid"], [6, "invalid"]]);
    expect(entries).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(SECRET);
  });

  it("refuses oversized imports", () => {
    expect(() => previewImport("x".repeat(262_145), new Set())).toThrow(/too large/);
    expect(() => previewImport(Array.from({ length: 501 }, () => link("A")).join("\n"), new Set())).toThrow(/at most 500/);
  });
});

describe("authenticator entries", () => {
  const key = new Uint8Array(64).fill(3);

  it("keep a nickname as a custom field and export as otpauth links", async () => {
    const created = await createEncryptedLogin({ name: "GitHub", username: "jane", password: "", uri: "https://github.com", totp: SECRET, nickname: "Work" }, key);
    const updated = await updateEncryptedLogin(created, { name: "GitHub", username: "jane", password: "", uri: "https://github.com", nickname: "Personal" }, key);
    const { items } = await decryptVault({ Ciphers: [{ ...updated, Id: "gh" }] }, key);
    const [entry] = authenticatorEntries(items, "https://github.com/login");
    expect(entry).toMatchObject({ id: "gh", name: "GitHub", nickname: "Personal", account: "jane", matched: true, digits: 6 });
    expect(items[0]!.fields?.filter((field) => field.name === "Authenticator nickname")).toHaveLength(1);
    expect(exportAuthenticator(items)).toBe(`otpauth://totp/GitHub:jane?secret=${SECRET}&issuer=GitHub`);
    expect(knownSecrets(items)).toEqual(new Set([SECRET]));
  });

  it("build the stored key from the editor, keeping the saved secret when none is typed", () => {
    const input = { name: "", nickname: "", account: "me", website: "", issuer: "ACME", algorithm: "SHA512" as const, digits: 8, period: 60 };
    expect(authenticatorKey(input, SECRET)).toMatchObject({ secret: SECRET, issuer: "ACME", algorithm: "SHA512", digits: 8, period: 60 });
    expect(() => authenticatorKey(input)).toThrow(/Enter the authenticator key/);
    expect(() => authenticatorKey({ ...input, digits: 4 }, SECRET)).toThrow(/digits/);
    expect(authenticatorKey({ ...input, issuer: "Steam" }, SECRET)).toMatchObject({ steam: true, digits: 5 });
  });

  it("validates messages", () => {
    const entry = { name: "A", nickname: "", account: "", website: "", issuer: "", algorithm: "SHA1", digits: 6, period: 30 };
    expect(isExtensionRequest({ type: "authenticator.save", entry })).toBe(true);
    expect(isExtensionRequest({ type: "authenticator.save", entry: { ...entry, algorithm: "MD5" } })).toBe(false);
    expect(isExtensionRequest({ type: "authenticator.save", entry: { ...entry, nickname: 1 } })).toBe(false);
    expect(isExtensionRequest({ type: "authenticator.import", text: "x".repeat(262_145), confirm: false })).toBe(false);
    expect(isExtensionRequest({ type: "authenticator.export", masterPassword: "" })).toBe(false);
  });
});

// Background controller: domain-bound fill, protected items, import, lock.
let encrypted: SyncResponse | null;
vi.mock("../src/shared/database", () => ({
  readEncryptedSync: async () => encrypted,
  writeEncryptedSync: async (value: SyncResponse) => { encrypted = value; },
  clearEncryptedSync: async () => { encrypted = null; },
}));
vi.mock("../src/shared/persistent-session", () => ({
  clearPersistentAuthSession: async () => undefined,
  writePersistentAuthSession: async () => undefined,
  readPersistentAuthSession: async () => null,
}));

describe("authenticator controller", () => {
  const userKey = new Uint8Array(64).fill(7);
  let payload: SyncResponse;
  let tabUrl: string;
  let executeScript: ReturnType<typeof vi.fn>;
  let posted: Record<string, unknown>[];
  const storage = (data: Record<string, unknown>) => ({
    get: async (name: string) => ({ [name]: data[name] }),
    set: async (values: Record<string, unknown>) => { Object.assign(data, structuredClone(values)); },
    remove: async (name: string) => { delete data[name]; },
  });

  beforeEach(async () => {
    const login = (name: string, uri: string, reprompt = 0) =>
      createEncryptedLogin({ name, username: "jane", password: "pw", uri, totp: SECRET }, userKey).then((raw) => ({ ...raw, reprompt }));
    payload = {
      Ciphers: [
        { ...(await login("Example", "https://example.com")), Id: "plain" },
        { ...(await login("Bank", "https://bank.example.com", 1)), Id: "protected" },
      ],
    };
    encrypted = payload;
    posted = [];
    tabUrl = "https://example.com/2fa";
    executeScript = vi.fn(async () => [{ result: 1 }]);
    vi.stubGlobal("chrome", {
      storage: {
        local: storage({ accountMetadata: { email: "jane@example.com", baseUrl: "https://vault.example.com" } }),
        session: storage({ authSession: { email: "jane@example.com", baseUrl: "https://vault.example.com", accessToken: "t", userKey: [...userKey] } }),
      },
      tabs: { query: async () => [{ id: 4, url: tabUrl }] },
      scripting: { executeScript },
    });
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      if (init.method === "POST") {
        const body = JSON.parse(init.body as string) as Record<string, unknown>;
        posted.push(body);
        (payload.Ciphers as unknown[]).push({ ...body, Id: `new-${posted.length}` });
      }
      return new Response(JSON.stringify(url.includes("/sync") ? payload : {}), { headers: { "content-type": "application/json" } });
    }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it("fills only into the tab's own origin, and never into a lookalike or downgraded site", async () => {
    const controller = new VaultController();
    await expect(controller.fillAuthenticator("plain")).resolves.toBe(1);
    expect(executeScript.mock.calls[0]![0].args.slice(1, 2)).toEqual([["https://example.com"]]);
    for (const phishing of ["https://example.com.evil.net/login", "https://examp1e.com/", "https://evil.net/?https://example.com"]) {
      tabUrl = phishing;
      await expect(controller.fillAuthenticator("plain")).rejects.toThrow(/not mapped/);
    }
    tabUrl = "http://example.com/2fa";
    await expect(controller.fillAuthenticator("plain")).rejects.toThrow(/insecure HTTP/);
    expect(executeScript).toHaveBeenCalledTimes(1);
  });

  it("keeps protected codes behind the master-password reprompt", async () => {
    tabUrl = "https://bank.example.com/";
    const controller = new VaultController();
    const entries = await controller.authenticatorList(tabUrl);
    expect(entries.find((entry) => entry.id === "protected")).toMatchObject({ requiresReprompt: true, matched: true });
    await expect(controller.fillAuthenticator("protected")).rejects.toThrow(/master password/);
    await expect(controller.saveAuthenticator("protected", { name: "Bank", nickname: "", account: "", website: "", issuer: "", algorithm: "SHA1", digits: 6, period: 30 }))
      .rejects.toThrow(/master password/);
    expect(executeScript).not.toHaveBeenCalled();
  });

  it("imports only new keys, then forgets everything on lock", async () => {
    const controller = new VaultController();
    const other = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const text = `otpauth://totp/Dup:me?secret=${SECRET}\notpauth://totp/New:me?secret=${other}&issuer=New`;
    const preview = await controller.importAuthenticator(text, false);
    expect(preview).toMatchObject({ imported: 0, rows: [{ status: "duplicate" }, { status: "new", label: "New · me" }] });
    expect(posted).toHaveLength(0);
    await expect(controller.importAuthenticator(text, true)).resolves.toMatchObject({ imported: 1 });
    expect(posted).toHaveLength(1);
    expect((await controller.authenticatorList()).map((entry) => entry.name)).toContain("New");
    await controller.lock();
    await expect(controller.authenticatorList()).rejects.toThrow(/locked/);
    await expect(controller.importAuthenticator(text, false)).rejects.toThrow(/locked/);
  });
});
