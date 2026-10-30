import { describe, expect, it } from "vitest";

import {
  decryptSymmetricBytes,
  decryptSymmetricString,
  encryptSymmetricBytes,
  encryptSymmetricString,
  isSymmetricKey,
} from "../src/crypto/bitwarden-crypto";
import { decodeUtf8, fromBase64 } from "../src/crypto/bytes";
import { decodeCoseKey, encodeCoseKey } from "../src/crypto/cose";

// Vectors from bitwarden/sdk-internal (crates/bitwarden-crypto).
const SDK_KEY = fromBase64(
  "pQEEAlDib+JxbqMBlcd3KTUesbufAzoAARFvBIQDBAUGIFggt79surJXmqhPhYuuqi9ZyPfieebmtw2OsmN5SDrb4yUB",
);
const SDK_ENCRYPT0 = new Uint8Array([
  131, 88, 28, 163, 1, 58, 0, 1, 17, 111, 3, 24, 42, 4, 80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  161, 5, 88, 24, 78, 20, 28, 157, 180, 246, 131, 220, 82, 104, 72, 73, 75, 43, 69, 139, 216, 167, 145, 220, 67,
  168, 144, 173, 88, 35, 127, 234, 194, 83, 189, 172, 65, 29, 156, 73, 98, 87, 231, 87, 129, 15, 235, 127, 125, 97,
  211, 51, 212, 211, 2, 13, 36, 123, 53, 12, 31, 191, 40, 13, 175,
]);
const VECTOR_KEY = encodeCoseKey(new Uint8Array([...Array(32).keys()]), new Uint8Array([...Array(16).keys()]));

describe("Bitwarden encryption v2 (COSE, XChaCha20-Poly1305)", () => {
  it("decodes the SDK's serialized user key", () => {
    expect(isSymmetricKey(SDK_KEY)).toBe(true);
    expect(decodeCoseKey(SDK_KEY).key).toHaveLength(32);
    expect(isSymmetricKey(new Uint8Array(64))).toBe(true);
    expect(isSymmetricKey(new Uint8Array(70))).toBe(false);
  });

  it("decrypts the SDK's COSE_Encrypt0 test vector", async () => {
    const plaintext = await decryptSymmetricBytes(`7.${SDK_ENCRYPT0.toBase64()}`, VECTOR_KEY);
    expect(decodeUtf8(plaintext)).toBe("Message test vector");
  });

  it("rejects the vector under a different key id or tampered ciphertext", async () => {
    const otherId = encodeCoseKey(new Uint8Array([...Array(32).keys()]), new Uint8Array(16).fill(1));
    await expect(decryptSymmetricBytes(`7.${SDK_ENCRYPT0.toBase64()}`, otherId)).rejects.toThrow(/different key/);
    const tampered = SDK_ENCRYPT0.slice();
    tampered[tampered.length - 1]! ^= 1;
    await expect(decryptSymmetricBytes(`7.${tampered.toBase64()}`, VECTOR_KEY)).rejects.toThrow(/integrity/);
  });

  it("round-trips padded strings, including empty ones, and item keys", async () => {
    for (const value of ["", "secret", "x".repeat(32), "ünïcødé ".repeat(9)]) {
      const encrypted = await encryptSymmetricString(value, SDK_KEY);
      expect(encrypted.startsWith("7.")).toBe(true);
      await expect(decryptSymmetricString(encrypted, SDK_KEY)).resolves.toBe(value);
    }
    const itemKey = crypto.getRandomValues(new Uint8Array(64));
    const wrapped = await encryptSymmetricBytes(itemKey, SDK_KEY);
    await expect(decryptSymmetricBytes(wrapped, SDK_KEY)).resolves.toEqual(itemKey);
  });

  it("hides string length to a 32-byte block", async () => {
    const short = await encryptSymmetricString("a", SDK_KEY);
    const longer = await encryptSymmetricString("a".repeat(31), SDK_KEY);
    expect(short.length).toBe(longer.length);
  });

  it("unwraps a v2 user key wrapped by a v1 key and uses it", async () => {
    const legacy = crypto.getRandomValues(new Uint8Array(64));
    const wrapped = await encryptSymmetricBytes(SDK_KEY, legacy);
    const userKey = await decryptSymmetricBytes(wrapped, legacy);
    expect(isSymmetricKey(userKey)).toBe(true);
    await expect(decryptSymmetricString(await encryptSymmetricString("hi", userKey), SDK_KEY)).resolves.toBe("hi");
  });
});
