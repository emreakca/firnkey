import type { KdfConfig } from "./kdf";
import {
  clearPersistentAuthSession,
  readPersistentAuthSession,
  writePersistentAuthSession,
} from "./persistent-session";
import { readVaultTimeoutMinutes } from "./settings";
import { clearEncryptedSync, readEncryptedSync, writeEncryptedSync } from "./database";
import { STORAGE_KEY as BIOMETRIC_KEY } from "./biometric";

const SERVER_SNAPSHOT_KEY = "serverSnapshot";
const ACCOUNT_KEY = "accountMetadata";
const DEVICE_IDENTIFIER_KEY = "deviceIdentifier";
const SESSION_KEY = "authSession";
const KDF_PINS_KEY = "kdfPins";
const SAVED_ACCOUNTS_KEY = "savedAccounts";

export interface ServerSnapshot {
  baseUrl: string;
  serverVersion?: string;
}

// An account switched out of the active slot. Its server tokens and encrypted vault copy are kept
// encrypted in IndexedDB under `account:<id>`; the account key is never kept, so it comes back locked.
export interface SavedAccount {
  id: string;
  account: AccountMetadata;
  snapshot: ServerSnapshot;
  biometric?: unknown;
}

export interface AccountMetadata {
  baseUrl: string;
  email: string;
  kdf: KdfConfig;
  wrappedUserKey: string;
  privateKey?: string;
  lastSync?: string;
  itemCount?: number;
}

export interface AuthSession {
  baseUrl: string;
  email: string;
  accessToken: string;
  refreshToken?: string;
  accessTokenExpiresAt?: number;
  userKey?: number[];
}

interface PersistedState {
  [SERVER_SNAPSHOT_KEY]?: ServerSnapshot;
  [ACCOUNT_KEY]?: AccountMetadata;
  [DEVICE_IDENTIFIER_KEY]?: string;
}

interface SessionState {
  [SESSION_KEY]?: AuthSession;
}

export async function readServerSnapshot(): Promise<ServerSnapshot | null> {
  const result = (await chrome.storage.local.get(SERVER_SNAPSHOT_KEY)) as PersistedState;
  return result[SERVER_SNAPSHOT_KEY] ?? null;
}

export async function writeServerSnapshot(snapshot: ServerSnapshot): Promise<void> {
  await chrome.storage.local.set({ [SERVER_SNAPSHOT_KEY]: snapshot });
}

export async function readAccountMetadata(): Promise<AccountMetadata | null> {
  const result = (await chrome.storage.local.get(ACCOUNT_KEY)) as PersistedState;
  return result[ACCOUNT_KEY] ?? null;
}

export async function writeAccountMetadata(account: AccountMetadata): Promise<void> {
  await chrome.storage.local.set({ [ACCOUNT_KEY]: account });
}

export async function clearAccountMetadata(): Promise<void> {
  await chrome.storage.local.remove(ACCOUNT_KEY);
}

// Kept across logout so a compromised server cannot downgrade the KDF on the next sign-in.
export async function readKdfPin(baseUrl: string, email: string): Promise<KdfConfig | undefined> {
  const result = await chrome.storage.local.get(KDF_PINS_KEY);
  return (result[KDF_PINS_KEY] as Record<string, KdfConfig> | undefined)?.[`${baseUrl}\n${email}`];
}

export async function writeKdfPin(baseUrl: string, email: string, kdf: KdfConfig): Promise<void> {
  const result = await chrome.storage.local.get(KDF_PINS_KEY);
  const pins = (result[KDF_PINS_KEY] as Record<string, KdfConfig> | undefined) ?? {};
  await chrome.storage.local.set({ [KDF_PINS_KEY]: { ...pins, [`${baseUrl}\n${email}`]: kdf } });
}

export async function getOrCreateDeviceIdentifier(): Promise<string> {
  const result = (await chrome.storage.local.get(DEVICE_IDENTIFIER_KEY)) as PersistedState;
  const existing = result[DEVICE_IDENTIFIER_KEY];
  if (existing) {
    return existing;
  }
  const created = crypto.randomUUID();
  await chrome.storage.local.set({ [DEVICE_IDENTIFIER_KEY]: created });
  return created;
}

export async function readAuthSession(): Promise<AuthSession | null> {
  const result = (await chrome.storage.session.get(SESSION_KEY)) as SessionState;
  const active = result[SESSION_KEY];
  if (active) return active;
  try {
    // After a browser restart the account comes back locked, unless "until logout" kept the key.
    const restored = await readPersistentAuthSession();
    if (!restored) return null;
    if ((await readVaultTimeoutMinutes()) !== -1) delete restored.userKey;
    await chrome.storage.session.set({ [SESSION_KEY]: restored });
    return restored;
  } catch {
    await clearPersistentAuthSession();
    return null;
  }
}

export async function writeAuthSession(session: AuthSession): Promise<void> {
  await chrome.storage.session.set({ [SESSION_KEY]: session });
  // Server tokens survive a browser restart; the account key only in "until logout" mode.
  const persisted: AuthSession = { ...session };
  if ((await readVaultTimeoutMinutes()) !== -1) delete persisted.userKey;
  await writePersistentAuthSession(persisted);
}

export async function updateSessionUserKey(userKey: Uint8Array | null): Promise<void> {
  const session = await readAuthSession();
  if (!session) {
    throw new Error("The account session has expired. Sign in again.");
  }
  if (userKey) {
    await writeAuthSession({ ...session, userKey: [...userKey] });
  } else {
    const locked: AuthSession = { ...session };
    delete locked.userKey;
    await writeAuthSession(locked);
  }
}

export async function clearAuthSession(): Promise<void> {
  await Promise.all([chrome.storage.session.remove(SESSION_KEY), clearPersistentAuthSession()]);
}

export function accountId(account: { baseUrl: string; email: string }): string {
  return `${account.baseUrl}\n${account.email}`;
}

export async function readSavedAccounts(): Promise<SavedAccount[]> {
  const value = (await chrome.storage.local.get(SAVED_ACCOUNTS_KEY))[SAVED_ACCOUNTS_KEY];
  return Array.isArray(value) ? (value as SavedAccount[]) : [];
}

// Moves the active account aside (locked) and leaves the active slot empty. The caller locks first.
export async function stashActiveAccount(): Promise<void> {
  const [account, snapshot, session, payload, stored] = await Promise.all([
    readAccountMetadata(),
    readServerSnapshot(),
    readAuthSession(),
    readEncryptedSync(),
    chrome.storage.local.get(BIOMETRIC_KEY),
  ]);
  if (!account || !snapshot) return;
  const id = accountId(account);
  if (session) {
    const locked: AuthSession = { ...session };
    delete locked.userKey;
    await writePersistentAuthSession(locked, `account:${id}`);
  }
  if (payload) await writeEncryptedSync(payload, `account:${id}`);
  const saved: SavedAccount = { id, account, snapshot, ...(stored[BIOMETRIC_KEY] ? { biometric: stored[BIOMETRIC_KEY] } : {}) };
  await chrome.storage.local.set({ [SAVED_ACCOUNTS_KEY]: [...(await readSavedAccounts()).filter((entry) => entry.id !== id), saved] });
  await Promise.all([clearAuthSession(), clearAccountMetadata(), clearEncryptedSync(), chrome.storage.local.remove(BIOMETRIC_KEY)]);
}

// Puts a saved account into the (empty) active slot, locked.
export async function restoreSavedAccount(id: string): Promise<void> {
  const saved = (await readSavedAccounts()).find((entry) => entry.id === id);
  if (!saved) throw new Error("That account is no longer saved in Firnkey.");
  const [session, payload] = await Promise.all([
    readPersistentAuthSession(`account:${id}`).catch(() => null),
    readEncryptedSync(`account:${id}`),
  ]);
  await Promise.all([writeServerSnapshot(saved.snapshot), writeAccountMetadata(saved.account)]);
  if (session) await writeAuthSession(session);
  if (payload) await writeEncryptedSync(payload);
  if (saved.biometric) await chrome.storage.local.set({ [BIOMETRIC_KEY]: saved.biometric });
  await forgetSavedAccount(id);
}

export async function forgetSavedAccount(id: string): Promise<void> {
  const remaining = (await readSavedAccounts()).filter((entry) => entry.id !== id);
  await Promise.all([
    chrome.storage.local.set({ [SAVED_ACCOUNTS_KEY]: remaining }),
    clearPersistentAuthSession(`account:${id}`),
    clearEncryptedSync(`account:${id}`),
  ]);
}
