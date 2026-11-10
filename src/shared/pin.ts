// PIN unlock: the account key wrapped with AES-GCM under a key derived from the PIN (PBKDF2-SHA-256).
// By default the record lives in session storage (memory), so the PIN works until the browser
// restarts. A short PIN is easy to guess offline, which is why keeping it across restarts is opt-in.
import { fromBase64, utf8 } from "../crypto/bytes";

export const STORAGE_KEY = "pinUnlock";
const ITERATIONS = 600_000;
export const MAX_ATTEMPTS = 5;

interface PinRecord {
  salt: string;
  iv: string;
  ciphertext: string;
  attempts: number;
}

type Account = { baseUrl: string; email: string };

export async function hasPinUnlock(): Promise<boolean> {
  return Boolean(await readRecord());
}

export async function writePinUnlock(pin: string, userKey: Uint8Array, account: Account, keepAfterRestart: boolean): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = userKey.slice();
  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: additionalData(account) }, await pinKey(pin, salt), plaintext);
  } finally {
    plaintext.fill(0);
  }
  const record: PinRecord = { salt: salt.toBase64(), iv: iv.toBase64(), ciphertext: new Uint8Array(ciphertext).toBase64(), attempts: 0 };
  await clearPinUnlock();
  await (keepAfterRestart ? chrome.storage.local : chrome.storage.session).set({ [STORAGE_KEY]: record });
}

// The account key, or an error. Each wrong PIN counts; the last allowed one removes PIN unlock.
export async function unwrapPinUnlock(pin: string, account: Account): Promise<Uint8Array> {
  const found = await readRecord();
  if (!found) throw new Error("PIN unlock is not set up. Unlock with your master password.");
  const { record, area } = found;
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(record.iv), additionalData: additionalData(account) },
      await pinKey(pin, fromBase64(record.salt)),
      fromBase64(record.ciphertext),
    ));
  } catch {
    const attempts = record.attempts + 1;
    if (attempts >= MAX_ATTEMPTS) {
      await clearPinUnlock();
      throw new Error("Too many wrong PINs. PIN unlock was turned off; unlock with your master password.");
    }
    await area.set({ [STORAGE_KEY]: { ...record, attempts } });
    throw new Error(`Wrong PIN. ${MAX_ATTEMPTS - attempts} attempts left.`);
  }
}

export async function clearPinUnlock(): Promise<void> {
  await Promise.all([chrome.storage.session.remove(STORAGE_KEY), chrome.storage.local.remove(STORAGE_KEY)]);
}

async function readRecord(): Promise<{ record: PinRecord; area: chrome.storage.StorageArea } | undefined> {
  for (const area of [chrome.storage.session, chrome.storage.local]) {
    const value = (await area.get(STORAGE_KEY))[STORAGE_KEY] as PinRecord | undefined;
    if (value && typeof value.ciphertext === "string") return { record: value, area };
  }
  return undefined;
}

async function pinKey(pin: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", utf8(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function additionalData(account: Account): Uint8Array<ArrayBuffer> {
  return utf8(`firnkey-pin-v1\n${account.baseUrl}\n${account.email}`);
}
