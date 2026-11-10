import { describe, expect, it } from "vitest";

import { decryptSymmetricBytes, decryptSymmetricString, encryptSymmetricString, sha256Base64 } from "../src/crypto/bitwarden-crypto";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";

describe("encrypted login writes", () => {
  it("creates an item-key protected personal cipher with a verifiable URI checksum", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const payload = await createEncryptedLogin(
      {
        name: "Example",
        username: "person@example.com",
        password: "secret",
        uri: "https://example.com/login",
        notes: "personal",
        favorite: true,
      },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(payload.key as string, userKey);
    const login = payload.login as Record<string, unknown>;
    const uri = (login.uris as Array<Record<string, string>>)[0]!;

    await expect(decryptSymmetricString(payload.name as string, itemKey)).resolves.toBe("Example");
    await expect(decryptSymmetricString(login.username as string, itemKey)).resolves.toBe("person@example.com");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("secret");
    await expect(decryptSymmetricString(uri.uri!, itemKey)).resolves.toBe("https://example.com/login");
    await expect(decryptSymmetricString(uri.uriChecksum!, itemKey)).resolves.toBe(
      await sha256Base64("https://example.com/login"),
    );
    expect(payload.organizationId).toBeNull();
  });

  it("preserves protected login metadata while updating editable fields", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const original = await createEncryptedLogin(
      { name: "Old", username: "old", password: "old-pass", uri: "https://old.example" },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
    const totp = await encryptSymmetricString("otpauth://totp/test?secret=ABC", itemKey);
    const raw = { ...original, Id: "cipher-id", RevisionDate: "2026-08-01T00:00:00Z", Login: { ...(original.login as object), Totp: totp } };
    const updated = await updateEncryptedLogin(
      raw,
      { name: "New", username: "new", password: "new-pass", uri: "https://new.example" },
      userKey,
    );
    const login = updated.login as Record<string, unknown>;

    expect(login.totp).toBe(totp);
    expect(updated.lastKnownRevisionDate).toBe("2026-08-01T00:00:00Z");
    await expect(decryptSymmetricString(updated.name as string, itemKey)).resolves.toBe("New");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("new-pass");
  });

  it("updates an organization login under the organization key and keeps its organization", async () => {
    const orgKey = crypto.getRandomValues(new Uint8Array(64));
    const created = await createEncryptedLogin({ name: "Shared", username: "team", password: "old", uri: "" }, orgKey);
    const updated = await updateEncryptedLogin(
      { ...created, organizationId: "org-1" },
      { name: "Shared", username: "team", password: "new", uri: "" },
      orgKey,
    );
    const itemKey = await decryptSymmetricBytes(updated.key as string, orgKey);
    expect(updated.organizationId).toBe("org-1");
    await expect(decryptSymmetricString((updated.login as Record<string, string>).password!, itemKey)).resolves.toBe("new");
  });

  it("keeps notes, favorite, extra URIs and the old password when the save prompt updates a login", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const original = await createEncryptedLogin(
      { name: "Site", username: "alice", password: "old-pass", uri: "https://example.com", notes: "keep me", favorite: true },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
    const originalLogin = original.login as Record<string, unknown>;
    const firstUri = { ...(originalLogin.uris as Array<Record<string, unknown>>)[0], match: 3 };
    const secondUri = { uri: await encryptSymmetricString("https://second.example", itemKey), match: null };
    const raw = { ...original, login: { ...originalLogin, uris: [firstUri, secondUri] } };

    // The website prompt only sends name, username, password and URI.
    const updated = await updateEncryptedLogin(
      raw,
      { name: "Site", username: "alice", password: "new-pass", uri: "https://example.com" },
      userKey,
    );
    const login = updated.login as Record<string, unknown>;

    expect(updated.notes).toBe(original.notes);
    expect(updated.favorite).toBe(true);
    expect(login.uris).toEqual([firstUri, secondUri]);
    const history = updated.passwordHistory as Array<{ password: string; lastUsedDate: string }>;
    expect(history).toHaveLength(1);
    await expect(decryptSymmetricString(history[0]!.password, itemKey)).resolves.toBe("old-pass");
    expect(login.passwordRevisionDate).toEqual(expect.any(String));

    // Editing the primary URI replaces only that entry; clearing notes from the popup still works.
    const edited = await updateEncryptedLogin(
      updated,
      { name: "Site", username: "alice", password: "new-pass", uri: "https://new.example.com", notes: "", favorite: false },
      userKey,
    );
    const editedUris = (edited.login as Record<string, unknown>).uris as Array<Record<string, unknown>>;
    await expect(decryptSymmetricString(editedUris[0]!.uri as string, itemKey)).resolves.toBe("https://new.example.com/");
    expect(editedUris[1]).toEqual(secondUri);
    expect(edited.notes).toBeNull();
    expect(edited.favorite).toBe(false);
    expect(edited.passwordHistory).toEqual(history);
  });

  it("keeps a login's passkey on ordinary updates and removes it only when asked", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const passkey = { credentialId: "id", keyValue: "key", rpId: "example.com", counter: 0, discoverable: true, creationDate: "2026-01-01T00:00:00Z" };
    const input = { name: "Site", username: "alice", password: "pw", uri: "https://example.com" };
    const original = await createEncryptedLogin(input, userKey, passkey);
    const passkeys = (payload: Record<string, unknown>) => (payload.login as Record<string, unknown[]>).fido2Credentials;

    expect(passkeys(await updateEncryptedLogin(original, input, userKey))).toHaveLength(1);
    expect(passkeys(await updateEncryptedLogin(original, input, userKey, null))).toEqual([]);
  });
});


describe("authenticator keys", () => {
  const key = crypto.getRandomValues(new Uint8Array(64));
  const base = { name: "Site", username: "alice", password: "pw", uri: "" };
  const totpOf = async (payload: Record<string, unknown>) => {
    const value = (payload.login as Record<string, unknown>).totp;
    return typeof value === "string"
      ? decryptSymmetricString(value, await decryptSymmetricBytes(payload.key as string, key))
      : value;
  };

  it("adds, keeps, replaces and removes the key, and rejects invalid ones", async () => {
    const created = await createEncryptedLogin({ ...base, totp: " JBSWY3DPEHPK3PXP " }, key);
    expect(await totpOf(created)).toBe("JBSWY3DPEHPK3PXP");
    expect(await totpOf(await updateEncryptedLogin(created, base, key))).toBe("JBSWY3DPEHPK3PXP");
    const link = "otpauth://totp/Site:alice?secret=GEZDGNBVGY3TQOJQ&period=30";
    expect(await totpOf(await updateEncryptedLogin(created, { ...base, totp: link }, key))).toBe(link);
    expect(await totpOf(await updateEncryptedLogin(created, { ...base, totp: "" }, key))).toBeNull();
    await expect(createEncryptedLogin({ ...base, totp: "not a key!" }, key)).rejects.toThrow(/authenticator key/);
    await expect(createEncryptedLogin({ ...base, totp: "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP" }, key)).rejects.toThrow(/authenticator key/);
  });
  it("sets, keeps and changes a website's match rule, and stores a regular expression as written", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const login = { name: "Example", username: "", password: "", uri: "https://example.com/" };
    const created = await createEncryptedLogin({ ...login, uriMatch: 3 }, userKey);
    const uris = (raw: Record<string, unknown>) => (raw.login as { uris: Record<string, unknown>[] }).uris;
    expect(uris(created)[0]!.match).toBe(3);
    const stored = { ...created, Login: { Uris: uris(created).map(({ uri, uriChecksum, match }) => ({ Uri: uri, UriChecksum: uriChecksum, Match: match })) } };
    const kept = await updateEncryptedLogin(stored, login, userKey);
    expect(uris(kept)[0]).toMatchObject({ Match: 3 });
    const changed = await updateEncryptedLogin(stored, { ...login, uriMatch: null }, userKey);
    expect(uris(changed)[0]!.match).toBeNull();
    expect(Object.keys(uris(changed)[0]!)).not.toContain("Match");
    const pattern = await createEncryptedLogin({ ...login, uri: "^https://(www\\.)?example\\.com/", uriMatch: 4 }, userKey);
    const itemKey = await decryptSymmetricBytes(pattern.key as string, userKey);
    expect(await decryptSymmetricString(uris(pattern)[0]!.uri as string, itemKey)).toBe("^https://(www\\.)?example\\.com/");
    await expect(createEncryptedLogin({ ...login, uri: "(", uriMatch: 4 }, userKey)).rejects.toThrow(/regular expression/);
    await expect(createEncryptedLogin({ ...login, uriMatch: 9 }, userKey)).rejects.toThrow(/match rule/);
  });
  it("keeps an item's archive date, so an edit does not unarchive it", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const stored = { ...(await createEncryptedLogin({ name: "Old", username: "", password: "", uri: "" }, userKey)), ArchivedDate: "2026-10-01T00:00:00.000Z" };
    const updated = await updateEncryptedLogin(stored, { name: "Older", username: "", password: "", uri: "" }, userKey);
    expect(updated.archivedDate).toBe("2026-10-01T00:00:00.000Z");
  });
  it("sets the per-login page-load autofill choice and keeps it when not given", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const login = { name: "Example", username: "", password: "", uri: "" };
    const created = await createEncryptedLogin({ ...login, autofillOnPageLoad: false }, userKey);
    expect((created.login as Record<string, unknown>).autofillOnPageLoad).toBe(false);
    const stored = { ...created, Login: { AutofillOnPageLoad: false } };
    expect(((await updateEncryptedLogin(stored, login, userKey)).login as Record<string, unknown>).autofillOnPageLoad).toBe(false);
    expect(((await updateEncryptedLogin(stored, { ...login, autofillOnPageLoad: null }, userKey)).login as Record<string, unknown>).autofillOnPageLoad).toBeNull();
  });

  it("replaces every website and custom field, keeping linked fields and the authenticator nickname", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const original = await createEncryptedLogin(
      { name: "Multi", username: "u", password: "p", uri: "https://one.example", nickname: "Work", fields: [{ name: "Old", value: "x", hidden: false }] },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
    const linked = { type: 3, name: await encryptSymmetricString("Linked", itemKey), value: null, linkedId: 100 };
    original.fields = [...(original.fields as unknown[]), linked];
    const updated = await updateEncryptedLogin(original, {
      name: "Multi", username: "u", password: "p", uri: "",
      uris: [{ uri: "two.example", match: 1 }, { uri: "", match: null }, { uri: "^https://three\\.example/", match: 4 }],
      fields: [{ name: "PIN", value: "1234", hidden: true }, { name: "Admin", value: "true", hidden: false, boolean: true }, { name: "", value: "", hidden: false }],
    }, userKey);

    const uris = (updated.login as { uris: { uri: string; match: number | null }[] }).uris;
    expect(await Promise.all(uris.map((entry) => decryptSymmetricString(entry.uri, itemKey)))).toEqual(["https://two.example/", "^https://three\\.example/"]);
    expect(uris.map((entry) => entry.match)).toEqual([1, 4]);
    const fields = updated.fields as { type: number; name: string | null; value: string | null }[];
    const read = await Promise.all(fields.map(async (field) => [field.type, field.name && await decryptSymmetricString(field.name, itemKey), field.value && await decryptSymmetricString(field.value, itemKey)]));
    expect(read).toEqual([[0, "Authenticator nickname", "Work"], [3, "Linked", null], [1, "PIN", "1234"], [2, "Admin", "true"]]);
  });
});
