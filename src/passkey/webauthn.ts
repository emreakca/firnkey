// A minimal WebAuthn authenticator: ES256 keys, "none" attestation, synced (backup-eligible) passkeys.
// All binary values cross extension boundaries as base64url strings.
import { concatenate, fromBase64, utf8 } from "../crypto/bytes";
import type { Passkey } from "../vault/models";

export const ES256 = -7;

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const AAGUID = new Uint8Array(16); // All zeros: "none" attestation does not identify the authenticator.
const EC_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;

export interface CreatedCredential {
  id: string;
  clientDataJSON: string;
  attestationObject: string;
  authenticatorData: string;
  publicKey: string; // SPKI
  publicKeyAlgorithm: number;
  transports: string[];
}

export interface AssertedCredential {
  id: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string; // DER
  userHandle?: string;
}

export function toBase64Url(value: Uint8Array): string {
  return value.toBase64({ alphabet: "base64url", omitPadding: true });
}

// Bitwarden stores credential IDs as GUIDs (16 raw bytes), or "b64.<id>" for imported passkeys.
export function credentialIdBytes(id: string): Uint8Array {
  if (id.startsWith("b64.")) return fromBase64(id.slice(4));
  const hex = id.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error("The passkey has an invalid credential ID.");
  return Uint8Array.from(hex.match(/../g)!, (byte) => Number.parseInt(byte, 16));
}

export function credentialIdBase64Url(id: string): string {
  return toBase64Url(credentialIdBytes(id));
}

// WebAuthn requires the RP ID to be the page's host or a parent domain of it, on a secure origin.
// A parent domain must not be a public suffix: "github.io" would span every site under it.
export async function isValidRpId(rpId: string, origin: string, publicSuffixes = loadPublicSuffixes): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const host = url.hostname.toLowerCase();
  const id = rpId.toLowerCase();
  if (url.protocol !== "https:" && !(url.protocol === "http:" && host === "localhost")) return false;
  if (/^[\d.]+$|^\[/.test(host)) return false; // IP addresses cannot be RP IDs.
  if (id === host) return true;
  return id.includes(".") && host.endsWith(`.${id}`) && !isPublicSuffix(id, await publicSuffixes());
}

// Public Suffix List rules: exact names, "*.parent" wildcards, and "!name" exceptions to a wildcard.
export function isPublicSuffix(domain: string, list: string): boolean {
  const rules = new Set(list.split("\n"));
  const parent = domain.slice(domain.indexOf(".") + 1);
  return !rules.has(`!${domain}`) && (rules.has(domain) || rules.has(`*.${parent}`));
}

// Loaded only for parent-domain claims, so the ~150 KB list stays out of the worker's memory otherwise.
async function loadPublicSuffixes(): Promise<string> {
  return (await fetch(chrome.runtime.getURL("passkey/public-suffixes.txt"))).text();
}

export async function createPasskey(request: {
  origin: string;
  rpId: string;
  rpName?: string;
  userId: string;
  userName?: string;
  userDisplayName?: string;
  challenge: string;
  userVerified: boolean;
}): Promise<{ passkey: Passkey; credential: CreatedCredential }> {
  const pair = await crypto.subtle.generateKey(EC_P256, true, ["sign", "verify"]);
  const credentialId = crypto.randomUUID();
  const idBytes = credentialIdBytes(credentialId);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const attested = concatenate(AAGUID, Uint8Array.of(idBytes.length >> 8, idBytes.length & 0xff), idBytes, coseEs256(rawPublicKey));
  const authData = await authenticatorData(request.rpId, request.userVerified, 0, attested);
  const passkey: Passkey = {
    credentialId,
    keyValue: toBase64Url(pkcs8),
    rpId: request.rpId,
    userHandle: request.userId,
    counter: 0,
    discoverable: true,
    creationDate: new Date().toISOString(),
    ...(request.userName ? { userName: request.userName } : {}),
    ...(request.userDisplayName ? { userDisplayName: request.userDisplayName } : {}),
    ...(request.rpName ? { rpName: request.rpName } : {}),
  };
  pkcs8.fill(0);
  return {
    passkey,
    credential: {
      id: toBase64Url(idBytes),
      clientDataJSON: toBase64Url(clientData("webauthn.create", request.challenge, request.origin)),
      attestationObject: toBase64Url(attestationObject(authData)),
      authenticatorData: toBase64Url(authData),
      publicKey: toBase64Url(spki),
      publicKeyAlgorithm: ES256,
      transports: ["internal", "hybrid"],
    },
  };
}

export async function signAssertion(
  passkey: Passkey,
  request: { origin: string; challenge: string; userVerified: boolean },
): Promise<AssertedCredential> {
  const keyBytes = fromBase64(passkey.keyValue);
  const key = await crypto.subtle.importKey("pkcs8", new Uint8Array(keyBytes), EC_P256, false, ["sign"]);
  keyBytes.fill(0);
  // ponytail: always reports signature counter 0 ("no counter"), like other synced passkey providers.
  // Persist an incremented counter if an RP ever rejects it.
  const authData = await authenticatorData(passkey.rpId, request.userVerified, 0);
  const clientDataJSON = clientData("webauthn.get", request.challenge, request.origin);
  const signed = concatenate(authData, await sha256(clientDataJSON));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(signed)));
  return {
    id: credentialIdBase64Url(passkey.credentialId),
    clientDataJSON: toBase64Url(clientDataJSON),
    authenticatorData: toBase64Url(authData),
    signature: toBase64Url(derSignature(signature)),
    ...(passkey.userHandle ? { userHandle: passkey.userHandle } : {}),
  };
}

function clientData(type: string, challenge: string, origin: string): Uint8Array {
  // Key order follows the spec's serialization, which some strict verifiers rely on.
  return utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

async function authenticatorData(rpId: string, userVerified: boolean, counter: number, attested?: Uint8Array): Promise<Uint8Array> {
  const flags = FLAG_UP | FLAG_BE | FLAG_BS | (userVerified ? FLAG_UV : 0) | (attested ? FLAG_AT : 0);
  const count = new Uint8Array(4);
  new DataView(count.buffer).setUint32(0, counter);
  return concatenate(await sha256(utf8(rpId)), Uint8Array.of(flags), count, attested ?? new Uint8Array());
}

// CBOR COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
function coseEs256(rawPublicKey: Uint8Array): Uint8Array {
  return concatenate(
    Uint8Array.of(0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20),
    rawPublicKey.subarray(1, 33),
    Uint8Array.of(0x22, 0x58, 0x20),
    rawPublicKey.subarray(33, 65),
  );
}

// CBOR {"fmt": "none", "attStmt": {}, "authData": bytes}.
function attestationObject(authData: Uint8Array): Uint8Array {
  const text = (value: string) => concatenate(Uint8Array.of(0x60 + value.length), utf8(value));
  const length = authData.length;
  const header = length < 24 ? [0x40 + length] : length < 256 ? [0x58, length] : [0x59, length >> 8, length & 0xff];
  return concatenate(
    Uint8Array.of(0xa3), text("fmt"), text("none"), text("attStmt"), Uint8Array.of(0xa0), text("authData"),
    Uint8Array.from(header), authData,
  );
}

// Web Crypto returns r||s; WebAuthn expects an ASN.1 DER ECDSA signature.
function derSignature(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
    let value = bytes.subarray(start);
    if (value[0]! & 0x80) value = concatenate(Uint8Array.of(0), value);
    return concatenate(Uint8Array.of(0x02, value.length), value);
  };
  const body = concatenate(integer(raw.subarray(0, 32)), integer(raw.subarray(32)));
  return concatenate(Uint8Array.of(0x30, body.length), body);
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(value)));
}
