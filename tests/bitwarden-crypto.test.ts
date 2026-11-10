import { describe, expect, it } from "vitest";

import {
  decryptSymmetricString,
  encryptSymmetricString,
  deriveMasterPasswordHash,
  derivePbkdf2MasterKey,
  parseEncString,
  stretchMasterKey,
} from "../src/crypto/bitwarden-crypto";

describe("Bitwarden-compatible cryptography", () => {
  it("matches fixed PBKDF2, server-hash, and HKDF-expand vectors", async () => {
    const password = "correct horse battery staple";
    const key = await derivePbkdf2MasterKey(password, "person@example.com", 5_000);

    expect(key.toBase64()).toBe("LusIMSfrgST7B75nVfJUyGmXUJv6L21vDCPHAYJmUNk=");
    await expect(deriveMasterPasswordHash(key, password)).resolves.toBe(
      "b5aus5YCJ+i2DiXZS9hEXyvkM+UUTZf5jB8obJrLw2Y=",
    );
    await expect(stretchMasterKey(key).then((value) => value.toBase64())).resolves.toBe(
      "elSWCH+q/NpelRNqdRjtfvyPRPlV+g2UskNXPVg/1Z2cELgcMG9hopVpD8HYXx2ehbu/D7hL+xowLSXfoVFPeg==",
    );
  });

  it("decrypts an authenticated AES-CBC fixture", async () => {
    const key = new Uint8Array([...Array(64).keys()]);
    const encrypted =
      "2.AAECAwQFBgcICQoLDA0ODw==|JAfY/6/1BdhMCOcOQP171A==|Yq3HOrR5PBrvNVCT8NPUBe0N9i6A6uFdu64SoCvr0EU=";

    await expect(decryptSymmetricString(encrypted, key)).resolves.toBe("secret-value");
  });

  it("round-trips authenticated encryption and rejects a modified MAC", async () => {
    const key = crypto.getRandomValues(new Uint8Array(64));
    const encrypted = await encryptSymmetricString("new credential", key);

    await expect(decryptSymmetricString(encrypted, key)).resolves.toBe("new credential");
    const tampered = `${encrypted.slice(0, -2)}AA`;
    await expect(decryptSymmetricString(tampered, key)).rejects.toThrow(/integrity|shape/);
  });

  it("rejects tampered and unsupported ciphertext", async () => {
    const key = new Uint8Array([...Array(64).keys()]);
    await expect(
      decryptSymmetricString(
        "2.AAECAwQFBgcICQoLDA0ODw==|JAfY/6/1BdhMCOcOQP171A==|Aq3HOrR5PBrvNVCT8NPUBe0N9i6A6uFdu64SoCvr0EU=",
        key,
      ),
    ).rejects.toThrow(/integrity/);
    expect(() => parseEncString("7.AA==")).not.toThrow();
    await expect(decryptSymmetricString("7.AA==", key)).rejects.toThrow(/v2 data/);
  });

  it("rejects unauthenticated type 0 ciphertext", async () => {
    const key = new Uint8Array([...Array(64).keys()]);
    await expect(
      decryptSymmetricString("0.AAECAwQFBgcICQoLDA0ODw==|JAfY/6/1BdhMCOcOQP171A==", key),
    ).rejects.toThrow(/not authenticated/);
  });
});

it("derives Bitwarden's fingerprint phrase (the SDK's test vector) and a public key from a private key", async () => {
  const { fingerprintPhrase, rsaPublicKey } = await import("../src/crypto/bitwarden-crypto");
  const spki = Uint8Array.fromBase64(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB",
  );
  expect(await fingerprintPhrase("a09726a0-9590-49d1-a5f5-afe300b6a515", spki)).toBe("turban-deftly-anime-chatroom-unselfish");
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["encrypt", "decrypt"],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  expect(await rsaPublicKey(pkcs8)).toEqual(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
});
