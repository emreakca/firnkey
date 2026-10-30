import {
  decryptSymmetricBytes,
  decryptSymmetricString,
  encryptFile,
  encryptSymmetricBytes,
  encryptSymmetricString,
  hkdf,
} from "../crypto/bitwarden-crypto";
import { utf8 } from "../crypto/bytes";
import { asRecord, numberProp, prop, recordProp, stringProp } from "../shared/props";

export const SendType = { Text: 0, File: 1 } as const;
export type SendType = (typeof SendType)[keyof typeof SendType];

// What the popup sees of a Send. The link carries the Send's key, so it is as secret as the content.
export interface SendSummary {
  id: string;
  type: SendType;
  name: string;
  link: string;
  deletionDate: string;
  expirationDate?: string;
  maxAccessCount?: number;
  accessCount: number;
  disabled: boolean;
  hasPassword: boolean;
  fileName?: string;
}

export interface SendWriteInput {
  type: SendType;
  name: string;
  text?: string;
  hidden?: boolean;
  fileName?: string;
  password?: string;
  maxAccessCount?: number;
  // Days until the server deletes the Send.
  deletionDays: number;
}

export const SEND_DELETION_DAYS = [1, 2, 3, 7, 14, 30] as const;
// Bitwarden's limit for file Sends on a self-hosted server is higher; this keeps the popup's memory small.
// ponytail: whole file in memory and in one message; stream it if larger files are needed.
export const MAX_FILE_BYTES = 25 * 1024 * 1024;

// A Send's key is derived from a 16-byte seed that is also the secret part of its link.
function deriveSendKey(seed: Uint8Array): Promise<Uint8Array> {
  return hkdf(seed, "bitwarden-send", "send", 64);
}

export function sendLink(baseUrl: string, accessId: string, seed: Uint8Array): string {
  return `${baseUrl}/#/send/${accessId}/${seed.toBase64({ alphabet: "base64url", omitPadding: true })}`;
}

// Bitwarden hashes a Send password with PBKDF2-SHA-256 (100,000 rounds) salted by the seed.
export async function sendPasswordHash(password: string, seed: Uint8Array): Promise<string> {
  const material = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: seed.slice(), iterations: 100_000 }, material, 256);
  return new Uint8Array(bits).toBase64();
}

export async function decryptSends(raw: unknown, userKey: Uint8Array, baseUrl: string): Promise<SendSummary[]> {
  const sends: SendSummary[] = [];
  for (const entry of Array.isArray(raw) ? raw : []) {
    try {
      const send = asRecord(entry);
      const id = send && stringProp(send, "Id");
      const accessId = send && stringProp(send, "AccessId");
      const encryptedSeed = send && stringProp(send, "Key");
      const encryptedName = send && stringProp(send, "Name");
      if (!send || !id || !accessId || !encryptedSeed || !encryptedName) continue;
      const seed = await decryptSymmetricBytes(encryptedSeed, userKey);
      const key = await deriveSendKey(seed);
      try {
        const type = numberProp(send, "Type") === SendType.File ? SendType.File : SendType.Text;
        const file = recordProp(send, "File");
        const encryptedFileName = file && stringProp(file, "FileName");
        const expirationDate = stringProp(send, "ExpirationDate");
        const maxAccessCount = numberProp(send, "MaxAccessCount");
        sends.push({
          id,
          type,
          name: await decryptSymmetricString(encryptedName, key),
          link: sendLink(baseUrl, accessId, seed),
          deletionDate: stringProp(send, "DeletionDate") ?? "",
          accessCount: numberProp(send, "AccessCount") ?? 0,
          disabled: prop(send, "Disabled") === true,
          hasPassword: Boolean(prop(send, "Password")),
          ...(expirationDate ? { expirationDate } : {}),
          ...(maxAccessCount === undefined ? {} : { maxAccessCount }),
          ...(encryptedFileName ? { fileName: await decryptSymmetricString(encryptedFileName, key) } : {}),
        });
      } finally {
        seed.fill(0);
        key.fill(0);
      }
    } catch {
      // A damaged Send is skipped.
    }
  }
  return sends.sort((left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: "base" }));
}

// The server request for a new Send, plus its encrypted file when it is a file Send.
export async function encryptSend(
  input: SendWriteInput,
  userKey: Uint8Array,
  file?: Uint8Array,
): Promise<{ payload: Record<string, unknown>; file?: Uint8Array }> {
  const name = input.name.trim();
  if (!name || name.length > 1_000) throw new Error("Enter a name up to 1,000 characters.");
  if (!SEND_DELETION_DAYS.includes(input.deletionDays as (typeof SEND_DELETION_DAYS)[number])) throw new Error("Choose when the Send is deleted.");
  if (input.maxAccessCount !== undefined && (!Number.isSafeInteger(input.maxAccessCount) || input.maxAccessCount < 1)) {
    throw new Error("The access limit must be a whole number from 1.");
  }
  const text = input.text ?? "";
  if (input.type === SendType.Text && (!text.trim() || text.length > 1_000)) throw new Error("Enter the text to send, up to 1,000 characters.");
  if (input.type === SendType.File && (!file || !input.fileName)) throw new Error("Choose a file to send.");
  if (file && file.length > MAX_FILE_BYTES) throw new Error("The file is too large (25 MB at most).");

  const seed = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveSendKey(seed);
  try {
    const encrypted = file ? await encryptFile(file, key) : undefined;
    const payload = {
      type: input.type,
      name: await encryptSymmetricString(name, key),
      notes: null,
      key: await encryptSymmetricBytes(seed, userKey),
      maxAccessCount: input.maxAccessCount ?? null,
      expirationDate: null,
      deletionDate: new Date(Date.now() + input.deletionDays * 86_400_000).toISOString(),
      text: input.type === SendType.Text ? { text: await encryptSymmetricString(text, key), hidden: input.hidden === true } : null,
      file: input.type === SendType.File ? { fileName: await encryptSymmetricString(input.fileName!, key) } : null,
      password: input.password ? await sendPasswordHash(input.password, seed) : null,
      disabled: false,
      hideEmail: false,
      ...(encrypted ? { fileLength: encrypted.length } : {}),
    };
    return { payload, ...(encrypted ? { file: encrypted } : {}) };
  } finally {
    seed.fill(0);
    key.fill(0);
  }
}
