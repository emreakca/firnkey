// Bitwarden encryption v2: XChaCha20-Poly1305 COSE keys and COSE_Encrypt0 messages (EncString type 7),
// matching bitwarden/sdk-internal. Only the CBOR subset COSE uses here is supported.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatenate, equalConstantTime, utf8 } from "./bytes";

type Cbor = number | string | Uint8Array | Cbor[] | Map<number | string, Cbor>;

const XCHACHA20_POLY1305 = -70_000;
const CONTENT_TYPE_UTF8 = "application/x.bitwarden.utf8-padded";
const CONTENT_TYPE_LEGACY_KEY = "application/x.bitwarden.legacy-key";
const COAP_COSE_KEY = 101;
const COAP_OCTET_STREAM = 42;
const TEXT_PAD_BLOCK = 32;
// Serialized COSE keys are padded to at least 65 bytes so they never look like a 64-byte AES key.
const KEY_PAD_LENGTH = 65;

export interface CoseKey {
  keyId: Uint8Array;
  key: Uint8Array;
}

export type CoseContent = "utf8" | "legacy-key" | "bytes";

// Bitwarden's byte form of a symmetric key: 64 bytes is AES-CBC-HMAC, more is a padded COSE key.
export function decodeCoseKey(encoded: Uint8Array): CoseKey {
  const map = asMap(decodeCbor(unpad(encoded)));
  const keyId = map.get(2);
  const key = map.get(-1);
  if (
    map.get(1) !== 4 ||
    map.get(3) !== XCHACHA20_POLY1305 ||
    !(keyId instanceof Uint8Array) ||
    keyId.length !== 16 ||
    !(key instanceof Uint8Array) ||
    key.length !== 32
  ) {
    throw new Error("The account key is not a supported XChaCha20-Poly1305 key.");
  }
  return { keyId, key };
}

export function decryptCoseEncrypt0(message: Uint8Array, encodedKey: Uint8Array): Uint8Array {
  const value = decodeCbor(message);
  const parts = Array.isArray(value) ? value : [];
  const [protectedBytes, unprotected, ciphertext] = parts;
  if (parts.length !== 3 || !(protectedBytes instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) {
    throw new Error("Encrypted v2 data has an invalid shape.");
  }
  const header = protectedBytes.length ? asMap(decodeCbor(protectedBytes)) : new Map<number | string, Cbor>();
  const nonce = asMap(unprotected).get(5);
  const kid = header.get(4);
  if (header.get(1) !== XCHACHA20_POLY1305 || !(nonce instanceof Uint8Array) || nonce.length !== 24) {
    throw new Error("Encrypted v2 data uses an unsupported algorithm.");
  }
  const key = decodeCoseKey(encodedKey);
  if (!(kid instanceof Uint8Array) || !equalConstantTime(kid, key.keyId)) {
    throw new Error("Encrypted v2 data was made for a different key.");
  }
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(key.key, nonce, encStructure(protectedBytes)).decrypt(ciphertext);
  } catch {
    throw new Error("Encrypted data failed its integrity check.");
  }
  const contentType = header.get(3);
  if (contentType === CONTENT_TYPE_UTF8) return unpad(plaintext);
  // Keep every symmetric key in the same byte form, so callers never care which kind it is.
  if (contentType === COAP_COSE_KEY) return pad(plaintext, KEY_PAD_LENGTH);
  return plaintext;
}

export function encryptCoseEncrypt0(plaintext: Uint8Array, encodedKey: Uint8Array, content: CoseContent): Uint8Array {
  const key = decodeCoseKey(encodedKey);
  const contentType = { utf8: CONTENT_TYPE_UTF8, "legacy-key": CONTENT_TYPE_LEGACY_KEY, bytes: COAP_OCTET_STREAM }[content];
  const protectedBytes = encodeCbor(new Map<number, Cbor>([[1, XCHACHA20_POLY1305], [3, contentType], [4, key.keyId]]));
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const ciphertext = xchacha20poly1305(key.key, nonce, encStructure(protectedBytes)).encrypt(
    content === "utf8" ? pad(plaintext, TEXT_PAD_BLOCK * (1 + Math.floor(plaintext.length / TEXT_PAD_BLOCK))) : plaintext,
  );
  return encodeCbor([protectedBytes, new Map<number, Cbor>([[5, nonce]]), ciphertext]);
}

// Test and key-making helper: the padded byte form of a fresh or given XChaCha20-Poly1305 key.
export function encodeCoseKey(key: Uint8Array, keyId: Uint8Array): Uint8Array {
  const map = new Map<number, Cbor>([[1, 4], [2, keyId], [3, XCHACHA20_POLY1305], [4, [3, 4, 5, 6]], [-1, key]]);
  return pad(encodeCbor(map), KEY_PAD_LENGTH);
}

function encStructure(protectedBytes: Uint8Array): Uint8Array {
  return encodeCbor(["Encrypt0", protectedBytes, new Uint8Array()]);
}

// Bitwarden's padding: at least one byte, every padding byte holds the padding length.
function pad(value: Uint8Array, minLength: number): Uint8Array {
  const size = Math.max(minLength - value.length, 1);
  return concatenate(value, new Uint8Array(size).fill(size));
}

function unpad(value: Uint8Array): Uint8Array {
  const size = value[value.length - 1] ?? 0;
  if (size === 0 || size > value.length) throw new Error("Encrypted v2 data has invalid padding.");
  return value.subarray(0, value.length - size);
}

function asMap(value: Cbor | undefined): Map<number | string, Cbor> {
  if (!(value instanceof Map)) throw new Error("Encrypted v2 data has an invalid header.");
  return value;
}

function decodeCbor(bytes: Uint8Array): Cbor {
  let offset = 0;
  const take = (count: number): Uint8Array => {
    if (offset + count > bytes.length) throw new Error("Encrypted v2 data is truncated.");
    offset += count;
    return bytes.subarray(offset - count, offset);
  };
  const read = (depth: number): Cbor => {
    if (depth > 8) throw new Error("Encrypted v2 data is nested too deeply.");
    const initial = take(1)[0]!;
    const major = initial >> 5;
    const info = initial & 31;
    let length = info;
    if (info === 24) length = take(1)[0]!;
    else if (info === 25) length = new DataView(take(2).slice().buffer).getUint16(0);
    else if (info === 26) length = new DataView(take(4).slice().buffer).getUint32(0);
    else if (info > 24) throw new Error("Encrypted v2 data uses unsupported CBOR.");
    switch (major) {
      case 0: return length;
      case 1: return -1 - length;
      case 2: return take(length).slice();
      case 3: return new TextDecoder("utf-8", { fatal: true }).decode(take(length));
      case 4: return Array.from({ length: bounded(length) }, () => read(depth + 1));
      case 5: {
        const map = new Map<number | string, Cbor>();
        for (let index = 0, count = bounded(length); index < count; index += 1) {
          const key = read(depth + 1);
          if (typeof key !== "number" && typeof key !== "string") throw new Error("Encrypted v2 data has an invalid map key.");
          map.set(key, read(depth + 1));
        }
        return map;
      }
      case 6: return read(depth + 1); // A COSE tag such as 16 (COSE_Encrypt0) only labels the item.
      default: throw new Error("Encrypted v2 data uses unsupported CBOR.");
    }
  };
  const bounded = (length: number): number => {
    if (length > bytes.length - offset) throw new Error("Encrypted v2 data is truncated.");
    return length;
  };
  const value = read(0);
  if (offset !== bytes.length) throw new Error("Encrypted v2 data has trailing bytes.");
  return value;
}

function encodeCbor(value: Cbor): Uint8Array {
  const head = (major: number, length: number): Uint8Array => {
    if (length < 24) return new Uint8Array([(major << 5) | length]);
    if (length < 0x100) return new Uint8Array([(major << 5) | 24, length]);
    if (length < 0x10000) return new Uint8Array([(major << 5) | 25, length >> 8, length & 0xff]);
    const out = new Uint8Array(5);
    out[0] = (major << 5) | 26;
    new DataView(out.buffer).setUint32(1, length);
    return out;
  };
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const text = utf8(value);
    return concatenate(head(3, text.length), text);
  }
  if (value instanceof Uint8Array) return concatenate(head(2, value.length), value);
  if (Array.isArray(value)) return concatenate(head(4, value.length), ...value.map(encodeCbor));
  return concatenate(head(5, value.size), ...[...value].flatMap(([key, item]) => [encodeCbor(key), encodeCbor(item)]));
}
