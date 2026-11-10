import { describe, expect, it } from "vitest";

import { encryptSymmetricBytes } from "../src/crypto/bitwarden-crypto";
import { decryptOrganizationKey, decryptVault } from "../src/vault/decrypt-vault";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";

describe("organization items", () => {
  it("are editable only with edit and view access, and update under the organization key", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const orgKey = crypto.getRandomValues(new Uint8Array(64));
    const rsa = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
      true,
      ["encrypt", "decrypt"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey));
    const wrappedOrgKey = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsa.publicKey, orgKey));
    const sync = {
      Profile: {
        PrivateKey: await encryptSymmetricBytes(pkcs8, userKey),
        Organizations: [{ Id: "org-1", Key: `4.${wrappedOrgKey.toBase64()}` }],
      },
      Ciphers: [] as Record<string, unknown>[],
    };
    const login = await createEncryptedLogin({ name: "Shared", username: "team", password: "old", uri: "" }, orgKey);
    sync.Ciphers = [
      { ...login, id: "can-edit", organizationId: "org-1", edit: true, viewPassword: true },
      { ...login, id: "read-only", organizationId: "org-1", edit: false, viewPassword: true },
      { ...login, id: "hidden-password", organizationId: "org-1", edit: true, viewPassword: false },
    ];

    const { items, failures } = await decryptVault(sync, userKey);
    expect(failures).toBe(0);
    expect(Object.fromEntries(items.map((item) => [item.id, item.editable]))).toEqual({
      "can-edit": true, "read-only": false, "hidden-password": false,
    });

    const key = await decryptOrganizationKey(sync, userKey, undefined, "org-1");
    expect(key).toEqual(orgKey);
    const updated = await updateEncryptedLogin(sync.Ciphers[0]!, { name: "Shared", username: "team", password: "new", uri: "" }, key);
    const [item] = (await decryptVault({ ...sync, Ciphers: [{ ...updated, id: "can-edit", edit: true }] }, userKey)).items;
    expect(item).toMatchObject({ organizationId: "org-1", password: "new" });
    await expect(decryptOrganizationKey(sync, userKey, undefined, "other-org")).rejects.toThrow(/organization/);
  });
});
