import { KdfType, type KdfConfig } from "../shared/kdf";
import { concatenate, decodeUtf8, equalConstantTime, fromBase64, utf8 } from "./bytes";
import { decodeCoseKey, decryptCoseEncrypt0, encryptCoseEncrypt0, type CoseContent } from "./cose";

export interface ParsedEncString {
  type: number;
  parts: Uint8Array[];
}

export async function derivePbkdf2MasterKey(
  password: string,
  salt: string,
  iterations: number,
): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: utf8(salt), iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  masterPassword: string,
): Promise<string> {
  const material = await crypto.subtle.importKey("raw", masterKey.slice(), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: utf8(masterPassword), iterations: 1 },
    material,
    256,
  );
  return new Uint8Array(bits).toBase64();
}

export async function stretchMasterKey(masterKey: Uint8Array): Promise<Uint8Array> {
  if (masterKey.length !== 32) {
    throw new Error("A Bitwarden master key must contain exactly 32 bytes.");
  }
  const [encryptionKey, authenticationKey] = await Promise.all([
    hkdfExpand(masterKey, utf8("enc"), 32),
    hkdfExpand(masterKey, utf8("mac"), 32),
  ]);
  return concatenate(encryptionKey, authenticationKey);
}

export function parseEncString(value: string): ParsedEncString {
  if (!value) {
    throw new Error("Encrypted value is empty.");
  }
  const dot = value.indexOf(".");
  const type = dot === -1 ? 0 : Number.parseInt(value.slice(0, dot), 10);
  const payload = dot === -1 ? value : value.slice(dot + 1);
  if (!Number.isInteger(type)) {
    throw new Error("Encrypted value has an invalid type.");
  }
  const encodedParts = payload.split("|");
  const expectedParts: Record<number, number> = { 0: 2, 2: 3, 3: 1, 4: 1, 5: 2, 6: 2, 7: 1 };
  if (expectedParts[type] !== encodedParts.length) {
    throw new Error(`Encrypted value type ${type} has an invalid shape.`);
  }
  return { type, parts: encodedParts.map(fromBase64) };
}

// A symmetric key is 64 bytes (AES-CBC-HMAC, encryption v1) or a padded XChaCha20-Poly1305 COSE key (v2).
export function isSymmetricKey(key: Uint8Array): boolean {
  if (key.length === 64) return true;
  try {
    return key.length > 64 && Boolean(decodeCoseKey(key));
  } catch {
    return false;
  }
}

export async function decryptSymmetricBytes(value: string, key: Uint8Array): Promise<Uint8Array> {
  const encrypted = parseEncString(value);
  if (encrypted.type === 7) {
    return decryptCoseEncrypt0(encrypted.parts[0]!, key);
  }
  // Type 0 (AES-CBC without a MAC) would let a malicious server tamper with ciphertext undetected.
  if (encrypted.type !== 2) {
    throw new Error(`Encrypted value type ${encrypted.type} is not authenticated AES-CBC data.`);
  }
  return decryptAesCbcHmac(encrypted.parts[0]!, encrypted.parts[1]!, encrypted.parts[2]!, key);
}

async function decryptAesCbcHmac(iv: Uint8Array, ciphertext: Uint8Array, remoteMac: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 64) {
    throw new Error("Authenticated encrypted data requires a 64-byte key.");
  }
  const encryptionKey = key.subarray(0, 32);
  if (iv.length !== 16 || ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error("Encrypted AES-CBC data has an invalid length.");
  }

  const localMac = await hmacSha256(key.subarray(32, 64), concatenate(iv, ciphertext));
  if (!equalConstantTime(localMac, remoteMac)) {
    throw new Error("Encrypted data failed its integrity check.");
  }

  const imported = await crypto.subtle.importKey("raw", encryptionKey.slice(), "AES-CBC", false, [
    "decrypt",
  ]);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv.slice() },
        imported,
        ciphertext.slice(),
      ),
    );
  } catch {
    throw new Error("Encrypted data could not be decrypted.");
  }
}

export async function decryptSymmetricString(value: string, key: Uint8Array): Promise<string> {
  return decodeUtf8(await decryptSymmetricBytes(value, key));
}

export function encryptSymmetricBytes(value: Uint8Array, key: Uint8Array): Promise<string> {
  // Only item keys are encrypted as raw bytes; v2 tags them so official clients read them as keys.
  return encryptWithKey(value, key, value.length === 64 ? "legacy-key" : "bytes");
}

export function encryptSymmetricString(value: string, key: Uint8Array): Promise<string> {
  return encryptWithKey(utf8(value), key, "utf8");
}

async function encryptWithKey(value: Uint8Array, key: Uint8Array, content: CoseContent): Promise<string> {
  if (key.length > 64) {
    return `7.${encryptCoseEncrypt0(value, key, content).toBase64()}`;
  }
  const { iv, ciphertext, mac } = await encryptAesCbcHmac(value, key);
  return `2.${iv.toBase64()}|${ciphertext.toBase64()}|${mac.toBase64()}`;
}

// Files (attachments, file Sends) use Bitwarden's binary layout: type byte 2, IV, MAC, ciphertext.
// Their keys are always 64-byte AES keys, so there is no COSE variant.
export async function encryptFile(value: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const { iv, ciphertext, mac } = await encryptAesCbcHmac(value, key);
  return concatenate(new Uint8Array([2]), iv, mac, ciphertext);
}

export async function decryptFile(value: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (value[0] !== 2 || value.length < 65) throw new Error("The file is not authenticated AES-CBC data.");
  return decryptAesCbcHmac(value.subarray(1, 17), value.subarray(49), value.subarray(17, 49), key);
}

// Full HKDF-SHA-256 (extract and expand), as Bitwarden derives a Send's key from its seed.
export async function hkdf(ikm: Uint8Array, salt: string, info: string, length: number): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", ikm.slice(), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(salt), info: utf8(info) }, material, length * 8));
}

async function encryptAesCbcHmac(value: Uint8Array, key: Uint8Array) {
  if (key.length !== 64) {
    throw new Error("Authenticated encryption requires a 64-byte key.");
  }
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const imported = await crypto.subtle.importKey(
    "raw",
    key.slice(0, 32),
    "AES-CBC",
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv: iv.slice() }, imported, value.slice()),
  );
  const mac = await hmacSha256(key.subarray(32, 64), concatenate(iv, ciphertext));
  return { iv, ciphertext, mac };
}

export async function decryptRsaKey(value: string, privateKey: Uint8Array): Promise<Uint8Array> {
  const encrypted = parseEncString(value);
  if (encrypted.type !== 3 && encrypted.type !== 4) {
    throw new Error(`Organization key type ${encrypted.type} is not supported.`);
  }
  const hash = encrypted.type === 3 ? "SHA-256" : "SHA-1";
  const key = await crypto.subtle.importKey(
    "pkcs8",
    privateKey.slice(),
    { name: "RSA-OAEP", hash },
    false,
    ["decrypt"],
  );
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, encrypted.parts[0]!.slice()),
    );
  } catch {
    throw new Error("An organization key could not be decrypted.");
  }
}

export async function sha256Base64(value: string): Promise<string> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value))).toBase64();
}

export function kdfFingerprint(kdf: KdfConfig): string {
  return kdf.type === KdfType.Pbkdf2Sha256
    ? `pbkdf2:${kdf.iterations}`
    : `argon2id:${kdf.iterations}:${kdf.memoryMiB}:${kdf.parallelism}`;
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  if (length <= 0 || length > 32) {
    throw new Error("This HKDF expansion supports output lengths from 1 to 32 bytes.");
  }
  const block = await hmacSha256(prk, concatenate(info, new Uint8Array([1])));
  return block.subarray(0, length);
}

async function hmacSha256(key: Uint8Array, value: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    key.slice(),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, value.slice()));
}
