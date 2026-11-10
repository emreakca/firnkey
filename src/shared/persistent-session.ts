import type { AuthSession } from "./storage";
import { idbRequest } from "./database";
import { isRecord } from "./props";

const DATABASE_NAME = "firnkey-session";
const STORE = "records";
const DEVICE_KEY_ID = "device-key";
const SESSION_ID = "auth-session";
const ADDITIONAL_DATA = new TextEncoder().encode("firnkey-persistent-session-v1");

interface DeviceKeyRecord {
  id: typeof DEVICE_KEY_ID;
  key: CryptoKey;
}

interface EncryptedSessionRecord {
  id: string;
  // Raw bytes; records written by 1.0.2 and earlier hold number arrays.
  iv: Uint8Array<ArrayBuffer> | number[];
  ciphertext: ArrayBuffer | number[];
}

// `id` defaults to the active account; switched-out accounts are kept under their own id.
export async function writePersistentAuthSession(session: AuthSession, id = SESSION_ID): Promise<void> {
  const key = await getOrCreateDeviceKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(session));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: ADDITIONAL_DATA },
      key,
      plaintext,
    );
    await putRecord({ id, iv, ciphertext });
  } finally {
    plaintext.fill(0);
  }
}

export async function readPersistentAuthSession(id = SESSION_ID): Promise<AuthSession | null> {
  const [keyRecord, sessionRecord] = await Promise.all([
    getRecord<DeviceKeyRecord>(DEVICE_KEY_ID),
    getRecord<EncryptedSessionRecord>(id),
  ]);
  if (!keyRecord || !sessionRecord) return null;
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(sessionRecord.iv),
        additionalData: ADDITIONAL_DATA,
      },
      keyRecord.key,
      new Uint8Array(sessionRecord.ciphertext),
    ),
  );
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    return isAuthSession(value) ? value : null;
  } finally {
    plaintext.fill(0);
  }
}

export async function clearPersistentAuthSession(id = SESSION_ID): Promise<void> {
  await idbRequest(DATABASE_NAME, STORE, "readwrite", (store) => store.delete(id));
}

async function getOrCreateDeviceKey(): Promise<CryptoKey> {
  const existing = await getRecord<DeviceKeyRecord>(DEVICE_KEY_ID);
  if (existing) return existing.key;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  await putRecord({ id: DEVICE_KEY_ID, key } satisfies DeviceKeyRecord);
  return key;
}

async function getRecord<T>(id: string): Promise<T | null> {
  return (await idbRequest<T | undefined>(DATABASE_NAME, STORE, "readonly", (store) => store.get(id))) ?? null;
}

async function putRecord(record: DeviceKeyRecord | EncryptedSessionRecord): Promise<void> {
  await idbRequest(DATABASE_NAME, STORE, "readwrite", (store) => store.put(record));
}

function isAuthSession(session: unknown): session is AuthSession {
  if (!isRecord(session)) return false;
  return (
    typeof session.baseUrl === "string" &&
    typeof session.email === "string" &&
    typeof session.accessToken === "string" &&
    (session.refreshToken === undefined || typeof session.refreshToken === "string") &&
    (session.accessTokenExpiresAt === undefined || typeof session.accessTokenExpiresAt === "number") &&
    (session.userKey === undefined ||
      (Array.isArray(session.userKey) &&
        // 64 bytes for encryption v1; a padded COSE key for v2 (checked again when used).
        session.userKey.length >= 64 &&
        session.userKey.length <= 256 &&
        session.userKey.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)))
  );
}
