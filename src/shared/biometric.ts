// Biometric unlock: a platform passkey (Touch ID, Windows Hello) with the WebAuthn PRF extension.
// The PRF output only exists after the user verifies on the device, and it is the AES key that
// wraps the account key, so the stored record is useless without a fingerprint or device PIN.
import { fromBase64, utf8 } from "../crypto/bytes";

export const STORAGE_KEY = "biometricUnlock";
export const PRF_SALT = utf8("firnkey-biometric-unlock-v1").slice();

interface BiometricRecord {
  credentialId: string;
  iv: string;
  ciphertext: string;
}

export async function readBiometricCredentialId(): Promise<string | undefined> {
  return (await readRecord())?.credentialId;
}

export async function writeBiometricUnlock(
  credentialId: string,
  prfOutput: Uint8Array,
  userKey: Uint8Array,
  account: { baseUrl: string; email: string },
): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = userKey.slice();
  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: additionalData(account) },
      await importKey(prfOutput, "encrypt"),
      plaintext,
    );
  } finally {
    plaintext.fill(0);
  }
  const record: BiometricRecord = { credentialId, iv: iv.toBase64(), ciphertext: new Uint8Array(ciphertext).toBase64() };
  await chrome.storage.local.set({ [STORAGE_KEY]: record });
}

// Throws when the PRF output or account does not match the stored record.
export async function unwrapBiometricUnlock(
  prfOutput: Uint8Array,
  account: { baseUrl: string; email: string },
): Promise<Uint8Array> {
  const record = await readRecord();
  if (!record) throw new Error("Biometric unlock is not set up.");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(record.iv).slice(), additionalData: additionalData(account) },
    await importKey(prfOutput, "decrypt"),
    fromBase64(record.ciphertext).slice(),
  );
  return new Uint8Array(plaintext);
}

export async function clearBiometricUnlock(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function readRecord(): Promise<BiometricRecord | undefined> {
  const value = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY] as BiometricRecord | undefined;
  return value && typeof value.credentialId === "string" ? value : undefined;
}

async function importKey(prfOutput: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (prfOutput.length !== 32) throw new Error("The authenticator returned an invalid key.");
  const raw = prfOutput.slice();
  try {
    return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
  } finally {
    raw.fill(0);
  }
}

function additionalData(account: { baseUrl: string; email: string }): Uint8Array<ArrayBuffer> {
  return utf8(`firnkey-biometric-v1\n${account.baseUrl}\n${account.email}`).slice();
}

// Runs Touch ID / Windows Hello for Firnkey's own passkey and returns its PRF output.
export async function assertBiometricPrf(credentialId: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      allowCredentials: [{ type: "public-key", id: credentialId.slice() }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  })) as PublicKeyCredential | null;
  const output = assertion ? prfOutput(assertion) : null;
  if (!output) {
    throw new Error("This device's passkey provider does not support the PRF extension that biometric unlock needs. Update Chrome and macOS, or use your master password.");
  }
  return output;
}

export function prfOutput(credential: PublicKeyCredential): Uint8Array | null {
  const first = credential.getClientExtensionResults().prf?.results?.first;
  if (!first) return null;
  return ArrayBuffer.isView(first) ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength).slice() : new Uint8Array(first);
}

export function random(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}
