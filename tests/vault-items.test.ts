import { describe, expect, it } from "vitest";
import { createEncryptedItem, updateEncryptedItem } from "../src/vault/encrypt-login";
import { decryptVault, getVaultItemDetail, listVaultItems } from "../src/vault/decrypt-vault";
import { cardFormValues, identityFormValues } from "../src/background/fill";
import { isExtensionRequest } from "../src/shared/messages";
import { ItemType } from "../src/vault/models";
import { encryptSymmetricString } from "../src/crypto/bitwarden-crypto";

const userKey = new Uint8Array(64).fill(3);
const card = { cardholderName: "Jane Doe", brand: "Visa", number: "4111 1111-1111 1111", expMonth: "03", expYear: "27", code: "123" };

describe("cards, identities and secure notes", () => {
  it("round-trips all three types and normalizes card input", async () => {
    const ciphers = [
      { ...(await createEncryptedItem({ type: ItemType.Card, name: "Visa", card }, userKey)), id: "card" },
      { ...(await createEncryptedItem({ type: ItemType.Identity, name: "Me", identity: { firstName: "Jane", lastName: "Doe", country: "DE" } }, userKey)), id: "identity" },
      { ...(await createEncryptedItem({ type: ItemType.SecureNote, name: "Wifi", notes: "pass: hunter2" }, userKey)), id: "note" },
    ];
    expect(ciphers[2]).toMatchObject({ type: 2, secureNote: { type: 0 } });
    const { items, failures } = await decryptVault({ Ciphers: ciphers }, userKey);
    expect(failures).toBe(0);
    const byId = Object.fromEntries(items.map((item) => [item.id, item]));
    expect(byId.card?.card).toEqual({ ...card, number: "4111111111111111", expMonth: "3", expYear: "2027" });
    expect(byId.identity?.identity).toEqual({ firstName: "Jane", lastName: "Doe", country: "DE" });
    expect(byId.note).toMatchObject({ type: 2, notes: "pass: hunter2" });

    // The list shows only the last digits; search finds the brand and the name.
    expect(listVaultItems(items, "visa").map((item) => item.subtitle)).toEqual(["Visa *1111"]);
    expect(listVaultItems(items, "jane doe")[0]).toMatchObject({ id: "identity", subtitle: "Jane Doe" });
  });

  it("hides card secrets for reprompt and organization-hidden items", async () => {
    const raw = { ...(await createEncryptedItem({ type: ItemType.Card, name: "Visa", card }, userKey)), id: "card", reprompt: 1 };
    const [item] = (await decryptVault({ Ciphers: [raw] }, userKey)).items;
    expect(getVaultItemDetail(item!).card).toBeUndefined();
    expect(getVaultItemDetail(item!, undefined, true).card?.number).toBe("4111111111111111");
    const [hidden] = (await decryptVault({ Ciphers: [{ ...raw, viewPassword: false }] }, userKey)).items;
    expect(hidden?.card).toEqual({ cardholderName: "Jane Doe", brand: "Visa", expMonth: "3", expYear: "2027" });
  });

  it("keeps unknown fields and refuses a type change on update", async () => {
    const raw: Record<string, unknown> = { ...(await createEncryptedItem({ type: ItemType.Card, name: "Visa", card }, userKey)), id: "card" };
    (raw.card as Record<string, unknown>).Future = "kept";
    const updated = await updateEncryptedItem(raw, { type: ItemType.Card, name: "Renamed", card: { ...card, code: "" } }, userKey);
    expect(updated.card).toMatchObject({ future: "kept", code: null });
    const [item] = (await decryptVault({ Ciphers: [{ ...updated, id: "card" }] }, userKey)).items;
    expect(item).toMatchObject({ name: "Renamed", card: { number: "4111111111111111" } });
    expect(item?.card?.code).toBeUndefined();
    await expect(updateEncryptedItem(raw, { type: ItemType.Identity, name: "x" }, userKey)).rejects.toThrow(/type/);
    await expect(createEncryptedItem({ type: ItemType.Card, name: "x", card: { expMonth: "13" } }, userKey)).rejects.toThrow(/month/);
  });

  it("splits trashed items from the vault, decrypts folders and keeps an item's folder on edit", async () => {
    const note = await createEncryptedItem({ type: ItemType.SecureNote, name: "Wifi", folderId: "f1" }, userKey);
    expect(note.folderId).toBe("f1");
    const { items, trash, folders, failures } = await decryptVault({
      Folders: [{ Id: "f1", Name: await encryptSymmetricString("Home", userKey) }, { Id: "damaged", Name: "junk" }],
      Ciphers: [{ ...note, id: "note" }, { ...note, id: "old", deletedDate: "2026-01-01T00:00:00Z" }],
    }, userKey);
    expect(failures).toBe(0);
    expect(folders).toEqual([{ id: "f1", name: "Home" }]);
    expect(items.map((item) => item.id)).toEqual(["note"]);
    expect(trash.map((item) => item.id)).toEqual(["old"]);
    expect(listVaultItems(items, "")[0]?.folderId).toBe("f1");
    const raw = { ...note, id: "note" };
    expect((await updateEncryptedItem(raw, { type: ItemType.SecureNote, name: "Wifi" }, userKey)).folderId).toBe("f1");
    expect((await updateEncryptedItem(raw, { type: ItemType.SecureNote, name: "Wifi", folderId: "" }, userKey)).folderId).toBeNull();
  });

  it("validates item messages", () => {
    expect(isExtensionRequest({ type: "vault.createItem", item: { type: 3, name: "Visa", card: { number: "4111" } } })).toBe(true);
    expect(isExtensionRequest({ type: "vault.createItem", item: { type: 1, name: "Login" } })).toBe(false);
    expect(isExtensionRequest({ type: "vault.createItem", item: { type: 3, name: "Visa", card: { pin: "1234" } } })).toBe(false);
    expect(isExtensionRequest({ type: "vault.updateItem", id: "a", item: { type: 4, name: "Me", identity: { email: 5 } } })).toBe(false);
    expect(isExtensionRequest({ type: "vault.removePasskey", id: "a" })).toBe(true);
  });

  it("offers the date and country forms that payment and address fields expect", () => {
    const values = cardFormValues({ expMonth: "3", expYear: "2027", number: "4111" });
    expect(values["cc-exp-month"]).toEqual(["03", "3", "March", "Mar"]);
    expect(values["cc-exp-year"]).toEqual(["2027", "27"]);
    expect(values["cc-exp"]).toEqual(["03/27", "03/2027", "0327"]);
    expect(values["cc-csc"]).toBeUndefined();
    const identity = identityFormValues({ firstName: "Jane", lastName: "Doe", country: "de" });
    expect(identity.name).toEqual(["Jane Doe"]);
    expect(identity.country).toEqual(["de", "Germany"]);
  });
});

describe("SSH keys, custom fields and password history", () => {
  const enc = (text: string) => encryptSymmetricString(text, userKey);
  const sshCipher = async () => ({
    id: "ssh",
    type: ItemType.SshKey,
    name: await enc("Server"),
    sshKey: { privateKey: await enc("PRIVATE"), publicKey: await enc("ssh-ed25519 AAAA"), keyFingerprint: await enc("SHA256:abc") },
    fields: [
      { type: 0, name: await enc("Host"), value: await enc("example.com") },
      { type: 1, name: await enc("PIN"), value: await enc("1234") },
      { type: 2, name: await enc("Root"), value: await enc("true") },
      { type: 3, name: await enc("Linked"), value: null, linkedId: 101 },
    ],
    passwordHistory: [{ password: await enc("old-pass"), lastUsedDate: "2026-01-02T00:00:00Z" }],
  });

  it("decrypts SSH keys, text/hidden/boolean fields and history, skipping linked fields", async () => {
    const { items, failures } = await decryptVault({ Ciphers: [await sshCipher()] }, userKey);
    expect(failures).toBe(0);
    expect(items[0]).toMatchObject({
      sshKey: { privateKey: "PRIVATE", publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:abc" },
      fields: [
        { name: "Host", value: "example.com", hidden: false },
        { name: "PIN", value: "1234", hidden: true },
        { name: "Root", value: "true", hidden: false },
      ],
      passwordHistory: [{ password: "old-pass", lastUsedDate: "2026-01-02T00:00:00Z" }],
    });
    expect(listVaultItems(items, "sha256")[0]).toMatchObject({ id: "ssh", subtitle: "SHA256:abc" });
  });

  it("hides the new secrets behind reprompt and organization-hidden passwords", async () => {
    const [item] = (await decryptVault({ Ciphers: [{ ...(await sshCipher()), reprompt: 1 }] }, userKey)).items;
    const locked = getVaultItemDetail(item!);
    expect([locked.sshKey, locked.fields, locked.passwordHistory]).toEqual([undefined, undefined, undefined]);
    expect(getVaultItemDetail(item!, undefined, true).sshKey?.privateKey).toBe("PRIVATE");

    const [hidden] = (await decryptVault({ Ciphers: [{ ...(await sshCipher()), viewPassword: false }] }, userKey)).items;
    expect(hidden?.sshKey).toEqual({ publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:abc" });
    expect(hidden?.fields?.map((field) => field.name)).toEqual(["Host", "Root"]);
    expect(hidden?.passwordHistory).toBeUndefined();
  });
});
