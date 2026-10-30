import { describe, expect, it } from "vitest";

import {
  createPasskey,
  credentialIdBytes,
  isPublicSuffix,
  isValidRpId,
  signAssertion,
  toBase64Url,
} from "../src/passkey/webauthn";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";
import { decryptVault } from "../src/vault/decrypt-vault";
import { fromBase64 } from "../src/crypto/bytes";

// Excerpt of src/passkey/public-suffixes.txt.
const suffixes = ["// Public Suffix List", "com", "uk", "co.uk", "io", "github.io", "*.ck", "!www.ck"].join("\n");
const sha256 = async (value: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(value)));

// DER ECDSA signature -> r||s for Web Crypto verification.
function rawSignature(der: Uint8Array): Uint8Array {
  const out = new Uint8Array(64);
  let offset = 2;
  for (const half of [0, 32]) {
    const length = der[offset + 1]!;
    const value = der.subarray(offset + 2, offset + 2 + length);
    const trimmed = value.length > 32 ? value.subarray(value.length - 32) : value;
    out.set(trimmed, half + 32 - trimmed.length);
    offset += 2 + length;
  }
  return out;
}

describe("WebAuthn authenticator", () => {
  it("creates a passkey whose assertion verifies against the registered public key", async () => {
    const challenge = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const { passkey, credential } = await createPasskey({
      origin: "https://login.example.com",
      rpId: "example.com",
      rpName: "Example",
      userId: toBase64Url(Uint8Array.of(1, 2, 3)),
      userName: "alice",
      challenge,
      userVerified: true,
    });

    expect(credential.id).toBe(toBase64Url(credentialIdBytes(passkey.credentialId)));
    expect(JSON.parse(new TextDecoder().decode(fromBase64(credential.clientDataJSON)))).toEqual({
      type: "webauthn.create", challenge, origin: "https://login.example.com", crossOrigin: false,
    });
    const authData = fromBase64(credential.authenticatorData);
    expect(authData.subarray(0, 32)).toEqual(await sha256(new TextEncoder().encode("example.com")));
    expect(authData[32]).toBe(0x01 | 0x04 | 0x08 | 0x10 | 0x40); // UP, UV, BE, BS, AT
    expect(authData.subarray(55, 71)).toEqual(credentialIdBytes(passkey.credentialId)); // after rpIdHash, flags, counter, AAGUID, length
    const attestation = fromBase64(credential.attestationObject);
    expect(new TextDecoder().decode(attestation.subarray(0, 25))).toContain("fmt");
    expect(attestation.subarray(attestation.length - authData.length)).toEqual(authData);

    const getChallenge = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const assertion = await signAssertion(passkey, { origin: "https://login.example.com", challenge: getChallenge, userVerified: false });
    expect(assertion.id).toBe(credential.id);
    expect(assertion.userHandle).toBe(passkey.userHandle);
    const assertedData = fromBase64(assertion.authenticatorData);
    expect(assertedData[32]).toBe(0x01 | 0x08 | 0x10);
    const publicKey = await crypto.subtle.importKey("spki", new Uint8Array(fromBase64(credential.publicKey)),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const signed = new Uint8Array([...assertedData, ...(await sha256(fromBase64(assertion.clientDataJSON)))]);
    await expect(crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey,
      new Uint8Array(rawSignature(fromBase64(assertion.signature))), signed)).resolves.toBe(true);
  });

  it("parses GUID and imported base64url credential IDs", () => {
    expect(credentialIdBytes("00112233-4455-6677-8899-aabbccddeeff")).toEqual(
      Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    expect(credentialIdBytes("b64.AQID")).toEqual(Uint8Array.of(1, 2, 3));
    expect(() => credentialIdBytes("not-an-id")).toThrow();
  });

  it("only accepts the page host or a parent domain on a secure origin", async () => {
    const valid = (rpId: string, origin: string) => isValidRpId(rpId, origin, async () => suffixes);
    expect(await valid("example.com", "https://login.example.com")).toBe(true);
    expect(await valid("login.example.com", "https://login.example.com")).toBe(true);
    expect(await valid("other.com", "https://login.example.com")).toBe(false);
    expect(await valid("ample.com", "https://example.com")).toBe(false);
    expect(await valid("com", "https://example.com")).toBe(false);
    expect(await valid("example.com", "http://example.com")).toBe(false);
    expect(await valid("localhost", "http://localhost:8000")).toBe(true);
    expect(await valid("127.0.0.1", "https://127.0.0.1")).toBe(false);
    // Public suffixes cannot be claimed as a parent domain, but a site may be hosted on one.
    expect(await valid("github.io", "https://evil.github.io")).toBe(false);
    expect(await valid("co.uk", "https://shop.example.co.uk")).toBe(false);
    expect(await valid("example.co.uk", "https://shop.example.co.uk")).toBe(true);
    expect(await valid("github.io", "https://github.io")).toBe(true);
  });

  it("applies Public Suffix List wildcards and exceptions", () => {
    expect(isPublicSuffix("foo.ck", suffixes)).toBe(true);
    expect(isPublicSuffix("www.ck", suffixes)).toBe(false);
    expect(isPublicSuffix("example.com", suffixes)).toBe(false);
  });

  it("stores passkeys in Bitwarden's fido2Credentials format and reads them back", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const { passkey } = await createPasskey({
      origin: "https://example.com", rpId: "example.com", rpName: "Example", userId: "AQID",
      userName: "alice", challenge: "AA", userVerified: false,
    });
    const created = await createEncryptedLogin({ name: "Example", username: "alice", password: "", uri: "https://example.com" }, userKey, passkey);
    const stored = (created.login as { fido2Credentials: Record<string, unknown>[] }).fido2Credentials[0]!;
    expect(Object.keys(stored).sort()).toEqual([
      "counter", "creationDate", "credentialId", "discoverable", "keyAlgorithm", "keyCurve", "keyType",
      "keyValue", "rpId", "rpName", "userDisplayName", "userHandle", "userName",
    ]);
    expect(stored.creationDate).toBe(passkey.creationDate); // the only unencrypted field
    expect(String(stored.keyValue)).toMatch(/^2\./);

    const { items } = await decryptVault({ Ciphers: [{ ...created, id: "cipher-1" }] }, userKey);
    expect(items[0]!.passkeys).toEqual([passkey]);

    // Editing the login keeps the passkey; adding another appends it.
    const edited = await updateEncryptedLogin({ ...created, id: "cipher-1" }, { name: "Renamed", username: "alice", password: "", uri: "https://example.com" }, userKey);
    expect((edited.login as { fido2Credentials: unknown[] }).fido2Credentials).toEqual([stored]);
  });
});
