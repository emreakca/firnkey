import { describe, expect, it } from "vitest";
import {
  decryptFile,
  decryptSymmetricBytes,
  derivePbkdf2MasterKey,
  encryptFile,
  encryptSymmetricBytes,
  encryptSymmetricString,
} from "../src/crypto/bitwarden-crypto";
import { decryptVault } from "../src/vault/decrypt-vault";
import { createEncryptedCipher } from "../src/vault/encrypt-login";
import { ItemType } from "../src/vault/models";
import { decryptSends, encryptSend, sendPasswordHash } from "../src/vault/send";
import { exportEncryptedJson, exportJson, parseCsv, parseImport, type DeriveKey } from "../src/vault/transfer";
import { isExtensionRequest } from "../src/shared/messages";

const userKey = new Uint8Array(64).fill(5);
const derive: DeriveKey = (password, salt, kdf) => derivePbkdf2MasterKey(password, salt, kdf.iterations);

describe("encrypted files", () => {
  it("round-trips Bitwarden's binary layout and rejects tampering", async () => {
    const key = crypto.getRandomValues(new Uint8Array(64));
    const data = new TextEncoder().encode("attachment body");
    const encrypted = await encryptFile(data, key);
    expect(encrypted[0]).toBe(2);
    expect(await decryptFile(encrypted, key)).toEqual(data);
    encrypted[encrypted.length - 1]! ^= 1;
    await expect(decryptFile(encrypted, key)).rejects.toThrow(/integrity/);
  });
});

describe("Sends", () => {
  it("encrypt to a payload the owner can list with a working link", async () => {
    const { payload } = await encryptSend({ type: 0, name: "Wifi", text: "hunter2", password: "open sesame", deletionDays: 7 }, userKey);
    expect(payload).toMatchObject({ type: 0, text: { hidden: false }, file: null, maxAccessCount: null });
    expect(Date.parse(payload.deletionDate as string) - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    const seed = await decryptSymmetricBytes(payload.key as string, userKey);
    expect(seed).toHaveLength(16);
    expect(payload.password).toBe(await sendPasswordHash("open sesame", seed));

    const [send] = await decryptSends([{ ...payload, id: "s1", accessId: "abc", password: "hash", accessCount: 2 }], userKey, "https://vault.example.com");
    expect(send).toMatchObject({ id: "s1", name: "Wifi", hasPassword: true, accessCount: 2 });
    expect(send!.link).toBe(`https://vault.example.com/#/send/abc/${seed.toBase64({ alphabet: "base64url", omitPadding: true })}`);
  });

  it("encrypts file Sends and validates input", async () => {
    const file = new TextEncoder().encode("report");
    const result = await encryptSend({ type: 1, name: "Report", fileName: "report.pdf", deletionDays: 1 }, userKey, file);
    expect(result.payload.fileLength).toBe(result.file!.length);
    const [send] = await decryptSends([{ ...result.payload, id: "f", accessId: "x" }], userKey, "https://v");
    expect(send).toMatchObject({ type: 1, fileName: "report.pdf" });
    await expect(encryptSend({ type: 0, name: "x", text: "", deletionDays: 7 }, userKey)).rejects.toThrow(/text/);
    await expect(encryptSend({ type: 0, name: "x", text: "y", deletionDays: 5 }, userKey)).rejects.toThrow(/deleted/);
    expect(isExtensionRequest({ type: "send.create", send: { type: 0, name: "x", text: "y", deletionDays: 7 } })).toBe(true);
    expect(isExtensionRequest({ type: "send.create", send: { type: 0, name: "x", deletionDays: 4 } })).toBe(false);
  });
});

describe("collections and attachments", () => {
  it("decrypts collection names, item collections and attachment names", async () => {
    const orgKey = crypto.getRandomValues(new Uint8Array(64));
    const rsa = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["encrypt", "decrypt"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsa.publicKey, orgKey));
    const cipher = await createEncryptedCipher({ type: ItemType.SecureNote, name: "Runbook", username: "", password: "", favorite: false, reprompt: false, uris: [] }, orgKey);
    const itemKey = await decryptSymmetricBytes(cipher.key as string, orgKey);
    const { items, collections, failures } = await decryptVault({
      Profile: { PrivateKey: await encryptSymmetricBytes(pkcs8, userKey), Organizations: [{ Id: "o1", Name: "Acme", Key: `4.${wrapped.toBase64()}` }] },
      Collections: [{ Id: "c1", OrganizationId: "o1", Name: await encryptSymmetricString("Ops", orgKey), ReadOnly: true }],
      Ciphers: [{
        ...cipher, id: "n1", organizationId: "o1", collectionIds: ["c1"],
        attachments: [{ id: "a1", fileName: await encryptSymmetricString("plan.pdf", itemKey), size: "2048", sizeName: "2 KB" }],
      }],
    }, userKey);
    expect(failures).toBe(0);
    expect(collections).toEqual([{ id: "c1", organizationId: "o1", organizationName: "Acme", name: "Ops", readOnly: true }]);
    expect(items[0]).toMatchObject({ collectionIds: ["c1"], attachments: [{ id: "a1", fileName: "plan.pdf", size: 2048, sizeName: "2 KB" }] });
  });
});

describe("import and export", () => {
  it("round-trips every item type through Bitwarden JSON", async () => {
    const login = await createEncryptedCipher({
      type: ItemType.Login, name: "Mail", username: "me", password: "pw", favorite: true, reprompt: true, totp: "JBSWY3DPEHPK3PXP",
      uris: [{ uri: "https://mail.example.com", match: 1 }, { uri: "https://webmail.example.com" }],
      fields: [{ name: "PIN", value: "1234", hidden: true }],
      passwordHistory: [{ password: "old", lastUsedDate: "2025-01-01T00:00:00.000Z" }],
      notes: "line 1\nline 2",
    }, userKey);
    const card = await createEncryptedCipher({ type: ItemType.Card, name: "Visa", username: "", password: "", favorite: false, reprompt: false, uris: [], card: { number: "4111", code: "123" } }, userKey);
    const { items } = await decryptVault({ Ciphers: [{ ...login, id: "l", folderId: "f1" }, { ...card, id: "c" }] }, userKey);
    const json = exportJson(items, [{ id: "f1", name: "Work" }, { id: "unused", name: "Empty" }]);
    expect(JSON.parse(json).folders).toEqual([{ id: "f1", name: "Work" }]);

    const imported = await parseImport(json, undefined, derive);
    expect(imported).toHaveLength(2);
    const mail = imported.find((item) => item.name === "Mail")!;
    expect(mail).toMatchObject({
      type: 1, username: "me", password: "pw", favorite: true, reprompt: true, totp: "JBSWY3DPEHPK3PXP", folder: "Work", notes: "line 1\nline 2",
      uris: [{ uri: "https://mail.example.com", match: 1 }, { uri: "https://webmail.example.com" }],
      fields: [{ name: "PIN", value: "1234", hidden: true }],
      passwordHistory: [{ password: "old" }],
    });
    expect(imported.find((item) => item.name === "Visa")?.card).toEqual({ number: "4111", code: "123" });
  });

  it("protects an export with a file password", async () => {
    const note = await createEncryptedCipher({ type: ItemType.SecureNote, name: "Secret", username: "", password: "", favorite: false, reprompt: false, uris: [], notes: "x" }, userKey);
    const { items } = await decryptVault({ Ciphers: [{ ...note, id: "n" }] }, userKey);
    const file = await exportEncryptedJson(items, [], "correct horse", derive);
    expect(file).not.toContain("Secret");
    expect(JSON.parse(file)).toMatchObject({ encrypted: true, passwordProtected: true, kdfType: 0, kdfIterations: 600_000 });
    await expect(parseImport(file, undefined, derive)).rejects.toThrow(/password-protected/);
    await expect(parseImport(file, "wrong horse", derive)).rejects.toThrow(/incorrect/);
    expect(await parseImport(file, "correct horse", derive)).toMatchObject([{ name: "Secret", notes: "x" }]);
    await expect(parseImport('{"encrypted":true,"items":[]}', undefined, derive)).rejects.toThrow(/locked to the account/);
  });

  it("reads Chrome and Bitwarden CSV files", async () => {
    expect(parseCsv('a,"b ""q""","c\nd"\r\n1,2,3')).toEqual([["a", 'b "q"', "c\nd"], ["1", "2", "3"]]);
    const chrome = "﻿name,url,username,password,note\nExample,https://example.com/login,alice,\"p,w\",\n,https://www.other.org,bob,x,\n";
    expect(await parseImport(chrome, undefined, derive)).toMatchObject([
      { type: 1, name: "Example", username: "alice", password: "p,w", uris: [{ uri: "https://example.com/login" }] },
      { name: "other.org", username: "bob" },
    ]);
    const bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
      'Work,1,login,Mail,,"PIN: 1234",0,https://mail.example.com,me,pw,JBSWY3DPEHPK3PXP\n,,note,Wifi,hunter2,,,,,,\n';
    expect(await parseImport(bitwarden, undefined, derive)).toMatchObject([
      { name: "Mail", folder: "Work", favorite: true, fields: [{ name: "PIN", value: "1234" }], totp: "JBSWY3DPEHPK3PXP" },
      { type: 2, name: "Wifi", notes: "hunter2", uris: [] },
    ]);
    await expect(parseImport("a,b\n1,2", undefined, derive)).rejects.toThrow(/no password, URL or notes column/);
  });
});
