import { decryptSymmetricString, encryptSymmetricString, stretchMasterKey } from "../crypto/bitwarden-crypto";
import { KdfType, parseKdfConfig, type KdfConfig } from "../shared/kdf";
import { isRecord } from "../shared/props";
import type { CipherContent } from "./encrypt-login";
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ItemType,
  SSH_KEY_FIELDS,
  type CustomField,
  type Passkey,
  type VaultFolder,
  type VaultItem,
} from "./models";

export const VAULT_IMPORT_MAX_CHARACTERS = 10_000_000;
// ponytail: one server request for the whole file; split into batches if servers start refusing large imports.
export const IMPORT_MAX_ITEMS = 5_000;
const EXPORT_ITERATIONS = 600_000;

export type ExportFormat = "json" | "encrypted_json";
export type ImportItem = CipherContent & { folder?: string };
// Derives a 32-byte master key the way the account would (PBKDF2, or Argon2id with a hashed salt).
export type DeriveKey = (password: string, salt: string, kdf: KdfConfig) => Promise<Uint8Array>;

// Bitwarden's export format, so the file imports into any Bitwarden client. Personal items only, like Bitwarden.
export function exportJson(items: VaultItem[], folders: VaultFolder[]): string {
  const personal = items.filter((item) => !item.organizationId);
  const used = new Set(personal.map((item) => item.folderId));
  return JSON.stringify({
    encrypted: false,
    folders: folders.filter((folder) => used.has(folder.id)).map(({ id, name }) => ({ id, name })),
    items: personal.map(exportItem),
  }, null, 2);
}

// A password-protected export: the JSON above, encrypted under a key derived from the file password.
export async function exportEncryptedJson(items: VaultItem[], folders: VaultFolder[], password: string, derive: DeriveKey): Promise<string> {
  if (password.length < 8) throw new Error("Choose a file password of at least 8 characters.");
  const salt = crypto.getRandomValues(new Uint8Array(16)).toBase64();
  const kdf: KdfConfig = { type: KdfType.Pbkdf2Sha256, iterations: EXPORT_ITERATIONS };
  const key = await fileKey(password, salt, kdf, derive);
  try {
    return JSON.stringify({
      encrypted: true,
      passwordProtected: true,
      salt,
      kdfType: kdf.type,
      kdfIterations: kdf.iterations,
      kdfMemory: null,
      kdfParallelism: null,
      encKeyValidation_DO_NOT_EDIT: await encryptSymmetricString(crypto.randomUUID(), key),
      data: await encryptSymmetricString(exportJson(items, folders), key),
    }, null, 2);
  } finally {
    key.fill(0);
  }
}

function exportItem(item: VaultItem): Record<string, unknown> {
  const text = (value: string | undefined) => value || null;
  const record = (values: Record<string, string | undefined> | undefined, names: readonly string[]) =>
    Object.fromEntries(names.map((name) => [name, text(values?.[name])]));
  return {
    id: item.id,
    organizationId: null,
    folderId: item.folderId ?? null,
    type: item.type,
    reprompt: item.reprompt ? 1 : 0,
    name: item.name,
    notes: text(item.notes),
    favorite: item.favorite,
    fields: (item.fields ?? []).map((field) => ({ name: field.name, value: field.value, type: field.hidden ? 1 : 0, linkedId: null })),
    collectionIds: null,
    ...(item.passwordHistory?.length ? { passwordHistory: item.passwordHistory } : {}),
    ...(item.type === ItemType.Login ? {
      login: {
        uris: item.uris.map(({ uri, match }) => ({ match: match ?? null, uri })),
        username: text(item.username),
        password: text(item.password),
        totp: text(item.totp),
        fido2Credentials: (item.passkeys ?? []).map((passkey) => ({
          credentialId: passkey.credentialId,
          keyType: "public-key",
          keyAlgorithm: "ECDSA",
          keyCurve: "P-256",
          keyValue: passkey.keyValue,
          rpId: passkey.rpId,
          userHandle: passkey.userHandle ?? null,
          userName: passkey.userName ?? null,
          counter: String(passkey.counter),
          rpName: passkey.rpName ?? null,
          userDisplayName: passkey.userDisplayName ?? null,
          discoverable: String(passkey.discoverable),
          creationDate: passkey.creationDate,
        })),
      },
    } : {}),
    ...(item.type === ItemType.SecureNote ? { secureNote: { type: 0 } } : {}),
    ...(item.type === ItemType.Card ? { card: record(item.card, CARD_FIELDS) } : {}),
    ...(item.type === ItemType.Identity ? { identity: record(item.identity, IDENTITY_FIELDS) } : {}),
    ...(item.type === ItemType.SshKey ? { sshKey: record(item.sshKey, SSH_KEY_FIELDS) } : {}),
  };
}

// Bitwarden JSON (plain or password-protected), 1Password's .1pux (its export.data, unzipped by the
// popup), or a CSV export from Bitwarden, 1Password, KeePass, KeePassXC, Chrome, Firefox or Safari.
export async function parseImport(text: string, password: string | undefined, derive: DeriveKey): Promise<ImportItem[]> {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("The file is empty.");
  const items = trimmed.startsWith("{") ? await parseJson(trimmed, password, derive) : parseCsvExport(trimmed);
  if (items.length === 0) throw new Error("The file has no items to import.");
  if (items.length > IMPORT_MAX_ITEMS) throw new Error(`The file has more than ${IMPORT_MAX_ITEMS.toLocaleString()} items.`);
  return items;
}

async function parseJson(text: string, password: string | undefined, derive: DeriveKey): Promise<ImportItem[]> {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("The file is not valid JSON.");
  }
  if (!isRecord(data)) throw new Error("The file is not a Bitwarden export.");
  if (Array.isArray(data.accounts)) return parse1pux(data.accounts);
  if (data.encrypted === true) {
    if (data.passwordProtected !== true) {
      throw new Error("This export is locked to the account that made it. Export it again with a file password, or as plain JSON.");
    }
    if (!password) throw new Error("This export is password-protected. Enter its file password.");
    if (typeof data.salt !== "string" || typeof data.data !== "string" || typeof data.encKeyValidation_DO_NOT_EDIT !== "string") {
      throw new Error("The password-protected export is damaged.");
    }
    const kdf = parseKdfConfig({
      Kdf: data.kdfType, KdfIterations: data.kdfIterations, KdfMemory: data.kdfMemory, KdfParallelism: data.kdfParallelism,
    });
    const key = await fileKey(password, data.salt, kdf, derive);
    try {
      await decryptSymmetricString(data.encKeyValidation_DO_NOT_EDIT, key).catch(() => {
        throw new Error("The file password is incorrect.");
      });
      return parseJson(await decryptSymmetricString(data.data, key), undefined, derive);
    } finally {
      key.fill(0);
    }
  }
  const folders = new Map<string, string>();
  for (const folder of Array.isArray(data.folders) ? data.folders : []) {
    if (isRecord(folder) && typeof folder.id === "string" && typeof folder.name === "string") folders.set(folder.id, folder.name);
  }
  if (!Array.isArray(data.items)) throw new Error("The file is not a Bitwarden export.");
  return data.items.flatMap((raw) => {
    const item = isRecord(raw) ? jsonItem(raw) : null;
    if (!item) return [];
    const folder = typeof raw.folderId === "string" ? folders.get(raw.folderId) : undefined;
    return [folder ? { ...item, folder } : item];
  });
}

function jsonItem(raw: Record<string, unknown>): ImportItem | null {
  const type = raw.type;
  if (type !== 1 && type !== 2 && type !== 3 && type !== 4 && type !== 5) return null;
  const login = isRecord(raw.login) ? raw.login : {};
  const strings = (source: unknown, names: readonly string[]) => {
    const result: Record<string, string> = {};
    if (isRecord(source)) for (const name of names) if (typeof source[name] === "string" && source[name]) result[name] = source[name] as string;
    return result;
  };
  const fields: CustomField[] = (Array.isArray(raw.fields) ? raw.fields : []).flatMap((field) =>
    isRecord(field) && (field.type === 0 || field.type === 1 || field.type === 2)
      ? [{ name: string(field.name), value: string(field.value), hidden: field.type === 1 }]
      : []);
  const history = (Array.isArray(raw.passwordHistory) ? raw.passwordHistory : []).flatMap((entry) =>
    isRecord(entry) && typeof entry.password === "string" && entry.password
      ? [{ password: entry.password, lastUsedDate: string(entry.lastUsedDate) }]
      : []);
  const passkeys: Passkey[] = (Array.isArray(login.fido2Credentials) ? login.fido2Credentials : []).flatMap((entry) => {
    if (!isRecord(entry) || entry.keyAlgorithm !== "ECDSA" || entry.keyCurve !== "P-256") return [];
    const { credentialId, keyValue, rpId } = entry;
    if (typeof credentialId !== "string" || typeof keyValue !== "string" || typeof rpId !== "string") return [];
    const optional = strings(entry, ["userHandle", "userName", "userDisplayName", "rpName"]);
    return [{
      credentialId, keyValue, rpId, ...optional,
      counter: Number(entry.counter) || 0,
      discoverable: String(entry.discoverable) === "true",
      creationDate: string(entry.creationDate) || new Date().toISOString(),
    }];
  });
  const notes = string(raw.notes);
  const totp = string(login.totp);
  return {
    type,
    name: string(raw.name),
    username: string(login.username),
    password: string(login.password),
    favorite: raw.favorite === true,
    reprompt: raw.reprompt === 1,
    uris: (Array.isArray(login.uris) ? login.uris : []).flatMap((entry) =>
      isRecord(entry) && typeof entry.uri === "string" && entry.uri
        ? [{ uri: entry.uri, ...(typeof entry.match === "number" ? { match: entry.match } : {}) }]
        : []),
    ...(notes ? { notes } : {}),
    ...(totp ? { totp } : {}),
    ...(fields.length ? { fields } : {}),
    ...(history.length ? { passwordHistory: history } : {}),
    ...(passkeys.length ? { passkeys } : {}),
    ...(type === ItemType.Card ? { card: strings(raw.card, CARD_FIELDS) } : {}),
    ...(type === ItemType.Identity ? { identity: strings(raw.identity, IDENTITY_FIELDS) } : {}),
    ...(type === ItemType.SshKey ? { sshKey: strings(raw.sshKey, SSH_KEY_FIELDS) } : {}),
  };
}

// Column names used by Bitwarden, 1Password, KeePassXC, KeePass (1.x CSV), Chrome/Edge, Firefox and
// Safari password exports.
const CSV_COLUMNS = {
  name: ["name", "title", "account"],
  uri: ["login_uri", "url", "uri", "website", "web site"],
  username: ["login_username", "username", "user name", "login name"],
  password: ["login_password", "password"],
  totp: ["login_totp", "totp", "otpauth"],
  notes: ["notes", "note", "comments", "extra"],
  folder: ["folder", "grouping", "group"],
  favorite: ["favorite"],
  type: ["type"],
  fields: ["fields"],
  reprompt: ["reprompt"],
} as const;

function parseCsvExport(text: string): ImportItem[] {
  const [header, ...rows] = parseCsv(text);
  const names = (header ?? []).map((name) => name.trim().toLowerCase());
  const column = Object.fromEntries(Object.entries(CSV_COLUMNS).map(([key, aliases]) => [
    key, aliases.map((alias) => names.indexOf(alias)).find((index) => index >= 0) ?? -1,
  ])) as Record<keyof typeof CSV_COLUMNS, number>;
  if (column.password < 0 && column.uri < 0 && column.notes < 0) {
    throw new Error("This CSV file has no password, URL or notes column. Export it from Bitwarden, Chrome, Firefox or Safari.");
  }
  return rows.flatMap((row) => {
    const value = (key: keyof typeof CSV_COLUMNS) => (column[key] >= 0 ? row[column[key]]?.trim() ?? "" : "");
    if (row.every((cell) => !cell.trim())) return [];
    const note = value("type").toLowerCase() === "note";
    const uris = value("uri").split(",").map((uri) => uri.trim()).filter(Boolean).map((uri) => ({ uri }));
    const fields: CustomField[] = value("fields").split(/\r?\n/).flatMap((line) => {
      const split = line.indexOf(": ");
      return split > 0 ? [{ name: line.slice(0, split), value: line.slice(split + 2), hidden: false }] : [];
    });
    const notes = value("notes");
    const totp = value("totp");
    // KeePassXC writes the full group path below its root group, like "Root/Email".
    const folder = value("folder").replace(/^Root(\/|$)/, "");
    return [{
      type: note ? ItemType.SecureNote : ItemType.Login,
      name: value("name") || hostname(uris[0]?.uri) || "Untitled",
      username: note ? "" : value("username"),
      password: note ? "" : value("password"),
      favorite: ["1", "true"].includes(value("favorite").toLowerCase()),
      reprompt: value("reprompt") === "1",
      uris: note ? [] : uris,
      ...(notes ? { notes } : {}),
      ...(totp && !note ? { totp } : {}),
      ...(fields.length ? { fields } : {}),
      ...(folder ? { folder } : {}),
    }];
  });
}

// 1Password's .1pux export.data: accounts → vaults → items. The vault name becomes the folder.
// Categories without a Bitwarden type (bank accounts, licences, ...) become notes with their fields.
const ONE_PASSWORD_TYPES: Record<string, ItemType> = {
  "001": ItemType.Login, "005": ItemType.Login, "002": ItemType.Card, "003": ItemType.SecureNote, "004": ItemType.Identity, "114": ItemType.SshKey,
};
const ONE_PASSWORD_CARD: Record<string, (typeof CARD_FIELDS)[number]> = {
  cardholder: "cardholderName", ccnum: "number", cvv: "code", type: "brand",
};
const ONE_PASSWORD_IDENTITY: Record<string, (typeof IDENTITY_FIELDS)[number]> = {
  firstname: "firstName", initial: "middleName", lastname: "lastName", company: "company", email: "email",
  defphone: "phone", cellphone: "phone", username: "username",
};

function parse1pux(accounts: unknown[]): ImportItem[] {
  const vaults = accounts.flatMap((account) => (isRecord(account) && Array.isArray(account.vaults) ? account.vaults : []));
  return vaults.flatMap((vault) => {
    if (!isRecord(vault) || !Array.isArray(vault.items)) return [];
    const folder = isRecord(vault.attrs) ? string(vault.attrs.name) : "";
    return vault.items.flatMap((raw) => {
      const item = isRecord(raw) && raw.trashed !== true && raw.state !== "trashed" ? onePasswordItem(raw) : null;
      return item ? [folder ? { ...item, folder } : item] : [];
    });
  });
}

function onePasswordItem(raw: Record<string, unknown>): ImportItem | null {
  const overview = isRecord(raw.overview) ? raw.overview : {};
  const details = isRecord(raw.details) ? raw.details : {};
  const type = ONE_PASSWORD_TYPES[string(raw.categoryUuid)] ?? ItemType.SecureNote;
  const item: ImportItem = {
    type,
    name: string(overview.title) || "Untitled",
    username: "",
    password: type === ItemType.Login ? string(details.password) : "",
    favorite: Number(raw.favIndex) > 0,
    reprompt: false,
    uris: type !== ItemType.Login ? [] : [...new Set([
      string(overview.url),
      ...(Array.isArray(overview.urls) ? overview.urls : []).map((entry) => (isRecord(entry) ? string(entry.url) : "")),
    ].filter(Boolean))].map((uri) => ({ uri })),
  };
  const fields: CustomField[] = [];
  const card: Record<string, string> = {};
  const identity: Record<string, string> = {};
  for (const field of Array.isArray(details.loginFields) ? details.loginFields : []) {
    if (!isRecord(field) || !string(field.value)) continue;
    if (type === ItemType.Login && field.designation === "username" && !item.username) item.username = string(field.value);
    else if (type === ItemType.Login && field.designation === "password" && !item.password) item.password = string(field.value);
    else if (field.fieldType !== "B" && field.fieldType !== "I") { // Skip buttons and form-only inputs.
      fields.push({ name: string(field.name) || string(field.designation), value: string(field.value), hidden: field.fieldType === "P" });
    }
  }
  for (const section of Array.isArray(details.sections) ? details.sections : []) {
    for (const field of isRecord(section) && Array.isArray(section.fields) ? section.fields : []) {
      if (!isRecord(field) || !isRecord(field.value)) continue;
      const [kind, value] = Object.entries(field.value)[0] ?? [];
      const id = string(field.id);
      const name = string(field.title) || id;
      if (kind === "totp" && typeof value === "string" && value && type === ItemType.Login && !item.totp) item.totp = value;
      else if (kind === "sshKey" && isRecord(value) && type === ItemType.SshKey) {
        const metadata = isRecord(value.metadata) ? value.metadata : {};
        item.sshKey = { privateKey: string(value.privateKey), publicKey: string(metadata.publicKey), keyFingerprint: string(metadata.fingerprint) };
      } else if (kind === "monthYear" && type === ItemType.Card && id === "expiry" && /^\d{6}$/.test(String(value))) {
        card.expYear = String(value).slice(0, 4);
        card.expMonth = String(Number(String(value).slice(4)));
      } else if (kind === "address" && isRecord(value) && type === ItemType.Identity) {
        Object.assign(identity, {
          address1: string(value.street), city: string(value.city), state: string(value.state), postalCode: string(value.zip), country: string(value.country),
        });
      } else {
        const text = typeof value === "string" ? value : typeof value === "number" ? String(value) : "";
        if (!text) continue;
        if (type === ItemType.Card && ONE_PASSWORD_CARD[id] && !card[ONE_PASSWORD_CARD[id]]) card[ONE_PASSWORD_CARD[id]] = text;
        else if (type === ItemType.Identity && ONE_PASSWORD_IDENTITY[id] && !identity[ONE_PASSWORD_IDENTITY[id]]) identity[ONE_PASSWORD_IDENTITY[id]] = text;
        else if (kind !== "reference") fields.push({ name, value: text, hidden: kind === "concealed" });
      }
    }
  }
  const notes = string(details.notesPlain);
  const history = (Array.isArray(details.passwordHistory) ? details.passwordHistory : []).flatMap((entry) =>
    isRecord(entry) && string(entry.value)
      ? [{ password: string(entry.value), lastUsedDate: new Date(Number(entry.time) * 1000 || Date.now()).toISOString() }]
      : []);
  const strip = (values: Record<string, string>) => Object.fromEntries(Object.entries(values).filter(([, value]) => value));
  return {
    ...item,
    ...(notes ? { notes } : {}),
    ...(fields.length ? { fields } : {}),
    ...(history.length && type === ItemType.Login ? { passwordHistory: history } : {}),
    ...(type === ItemType.Card ? { card: strip(card) } : {}),
    ...(type === ItemType.Identity ? { identity: strip(identity) } : {}),
  };
}

// RFC 4180: quoted cells may contain commas, quotes ("") and line breaks.
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]!;
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"' && cell === "") quoted = true;
    else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text[index + 1] === "\n") index += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += char;
  }
  if (cell || row.length) rows.push([...row, cell]);
  // A UTF-8 byte-order mark (Excel) would otherwise hide the first column name.
  if (rows[0]?.[0]) rows[0][0] = rows[0][0].replace(/^﻿/, "");
  return rows;
}

async function fileKey(password: string, salt: string, kdf: KdfConfig, derive: DeriveKey): Promise<Uint8Array> {
  const masterKey = await derive(password, salt, kdf);
  try {
    return await stretchMasterKey(masterKey);
  } finally {
    masterKey.fill(0);
  }
}

function hostname(uri: string | undefined): string {
  try {
    return uri ? new URL(uri.includes("://") ? uri : `https://${uri}`).hostname.replace(/^www\./, "") : "";
  } catch {
    return "";
  }
}

function string(value: unknown): string {
  return typeof value === "string" ? value : "";
}
