import { decryptSymmetricString, encryptSymmetricString } from "../crypto/bitwarden-crypto";

// Passwords the generator produced and the user copied or used, newest first. Kept only in this
// browser, per account, as one blob encrypted with the account key; never sent to the server.
export interface GeneratedPasswordEntry {
  password: string;
  date: string; // ISO time it was copied or used
  site?: string; // Host of the page the user was on, if any
}

export const GENERATOR_HISTORY_LIMIT = 100; // Same cap as the official clients.
const STORAGE_KEY = "generatorHistory";

async function readAll(): Promise<Record<string, string>> {
  const value = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
  return typeof value === "object" && value !== null ? (value as Record<string, string>) : {};
}

export async function readGeneratorHistory(account: string, key: Uint8Array): Promise<GeneratedPasswordEntry[]> {
  const blob = (await readAll())[account];
  if (!blob) return [];
  try {
    const parsed: unknown = JSON.parse(await decryptSymmetricString(blob, key));
    return Array.isArray(parsed) ? parsed.filter(validEntry) : [];
  } catch {
    return []; // Written under another key (the account was recreated): start over.
  }
}

export async function addGeneratorHistory(account: string, key: Uint8Array, password: string, site?: string): Promise<void> {
  const entries = await readGeneratorHistory(account, key);
  // Copying and then using the same value is one generated password, not two.
  const rest = entries[0]?.password === password ? entries.slice(1) : entries;
  const next = [{ password, date: new Date().toISOString(), ...(site ? { site } : {}) }, ...rest].slice(0, GENERATOR_HISTORY_LIMIT);
  const all = await readAll();
  await chrome.storage.local.set({ [STORAGE_KEY]: { ...all, [account]: await encryptSymmetricString(JSON.stringify(next), key) } });
}

export async function clearGeneratorHistory(account: string): Promise<void> {
  const all = await readAll();
  if (!(account in all)) return;
  delete all[account];
  await chrome.storage.local.set({ [STORAGE_KEY]: all });
}

// The host of an http(s) page, or nothing for browser and extension pages.
export function generatorSite(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.hostname : undefined;
  } catch {
    return undefined;
  }
}

function validEntry(value: unknown): value is GeneratedPasswordEntry {
  const entry = value as GeneratedPasswordEntry;
  return typeof entry === "object" && entry !== null && typeof entry.password === "string" && typeof entry.date === "string" &&
    (entry.site === undefined || typeof entry.site === "string");
}
