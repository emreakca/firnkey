import {
  decryptSymmetricBytes,
  decryptSymmetricString,
  encryptSymmetricBytes,
  encryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import { generateTotp } from "../crypto/totp";
import { arrayProp, numberProp, prop, recordProp, stringProp } from "../shared/props";
import { CARD_FIELDS, IDENTITY_FIELDS, ItemType, SSH_KEY_FIELDS, type CardData, type IdentityData, type Passkey, type VaultItem } from "./models";

export interface LoginWriteInput {
  name: string;
  username: string;
  password: string;
  uri: string;
  notes?: string;
  favorite?: boolean;
  // "" = no folder; omitted = keep the current folder.
  folderId?: string;
  // Authenticator key: a Base32 secret or otpauth://totp/ link. "" = remove; omitted = keep the current one.
  totp?: string;
  // Authenticator tab display name, kept as a custom field. "" = remove; omitted = keep.
  nickname?: string;
}

// The custom field that holds an authenticator entry's nickname (visible in the web vault too).
export const NICKNAME_FIELD = "Authenticator nickname";

// A secure note, card or identity. Logins use LoginWriteInput.
export interface ItemWriteInput {
  type: typeof ItemType.SecureNote | typeof ItemType.Card | typeof ItemType.Identity;
  name: string;
  notes?: string;
  favorite?: boolean;
  folderId?: string;
  card?: CardData;
  identity?: IdentityData;
}

export async function createEncryptedItem(input: ItemWriteInput, userKey: Uint8Array): Promise<Record<string, unknown>> {
  const clean = validateItemInput(input);
  return newCipher(clean.type, clean, userKey, (itemKey) => encryptedTypeData(clean, itemKey, {}));
}

// `baseKey` is the account key, or the organization key for an organization item.
export async function updateEncryptedItem(
  rawCipher: Record<string, unknown>,
  input: ItemWriteInput,
  baseKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = validateItemInput(input);
  if (numberProp(rawCipher, "Type") !== clean.type) throw new Error("The item type cannot be changed.");
  const rawData = recordProp(rawCipher, TYPE_PROPERTY[clean.type]) ?? {};
  return editedCipher(rawCipher, clean, input.folderId, baseKey, (itemKey) => encryptedTypeData(clean, itemKey, rawData));
}

type CommonFields = { name: string; notes: string; favorite: boolean };
type TypeFields = (itemKey: Uint8Array) => Promise<Record<string, unknown>>;

// A new cipher under a fresh item key. `typeFields` adds the type's data and overrides defaults.
async function newCipher(type: number, clean: CommonFields & { folderId: string }, userKey: Uint8Array, typeFields: TypeFields) {
  const itemKey = crypto.getRandomValues(new Uint8Array(64));
  try {
    return {
      type,
      folderId: clean.folderId || null,
      organizationId: null,
      key: await encryptSymmetricBytes(itemKey, userKey),
      name: await encryptSymmetricString(clean.name, itemKey),
      notes: clean.notes ? await encryptSymmetricString(clean.notes, itemKey) : null,
      favorite: clean.favorite,
      reprompt: 0,
      fields: [],
      passwordHistory: [],
      ...(await typeFields(itemKey)),
    };
  } finally {
    itemKey.fill(0);
  }
}

// The stored cipher with edited common fields, encrypted with its own item key (or `baseKey` when it
// has none). Everything this client does not edit is kept; `typeFields` adds or overrides the rest.
async function editedCipher(
  rawCipher: Record<string, unknown>,
  clean: CommonFields,
  folderId: string | undefined,
  baseKey: Uint8Array,
  typeFields: TypeFields,
) {
  const encryptedKey = stringProp(rawCipher, "Key");
  const itemKey = encryptedKey ? await decryptSymmetricBytes(encryptedKey, baseKey) : baseKey;
  try {
    return {
      type: numberProp(rawCipher, "Type"),
      folderId: chosenFolder(rawCipher, folderId),
      // The server refuses an update whose organization differs from the stored item's.
      organizationId: prop(rawCipher, "OrganizationId") ?? null,
      key: encryptedKey ?? null,
      name: await encryptSymmetricString(clean.name, itemKey),
      notes: clean.notes ? await encryptSymmetricString(clean.notes, itemKey) : null,
      favorite: clean.favorite,
      reprompt: numberProp(rawCipher, "Reprompt") ?? 0,
      fields: prop(rawCipher, "Fields") ?? [],
      passwordHistory: prop(rawCipher, "PasswordHistory") ?? [],
      attachments: prop(rawCipher, "Attachments") ?? null,
      lastKnownRevisionDate: prop(rawCipher, "RevisionDate") ?? null,
      ...(await typeFields(itemKey)),
    };
  } finally {
    if (encryptedKey) itemKey.fill(0);
  }
}

const TYPE_PROPERTY = {
  [ItemType.SecureNote]: "SecureNote",
  [ItemType.Card]: "Card",
  [ItemType.Identity]: "Identity",
} as const;

// Vaultwarden rejects a cipher whose type has no matching data object, so a note sends `secureNote`.
async function encryptedTypeData(input: Required<ItemWriteInput>, key: Uint8Array, raw: Record<string, unknown>) {
  if (input.type === ItemType.SecureNote) return { secureNote: { type: 0 } };
  const [names, values, property] = input.type === ItemType.Card
    ? [CARD_FIELDS, input.card as Record<string, string | undefined>, "card"] as const
    : [IDENTITY_FIELDS, input.identity as Record<string, string | undefined>, "identity"] as const;
  // Start from the stored object so fields this client does not know about survive the edit.
  const encrypted: Record<string, unknown> = Object.fromEntries(
    Object.entries(raw).map(([name, value]) => [name[0]!.toLowerCase() + name.slice(1), value]),
  );
  for (const name of names) {
    const value = values[name];
    encrypted[name] = value ? await encryptSymmetricString(value, key) : null;
  }
  return { [property]: encrypted };
}

function validateItemInput(input: ItemWriteInput): Required<ItemWriteInput> {
  const name = input.name.trim();
  const notes = (input.notes ?? "").trim();
  if (!name || name.length > 1_000) throw new Error("Enter a name up to 1,000 characters.");
  if (notes.length > 10_000) throw new Error("Notes are too long.");
  const trimmed = (values: Record<string, string | undefined> | undefined, names: readonly string[]) => {
    const result: Record<string, string> = {};
    for (const name of names) {
      const value = values?.[name]?.trim();
      if (value && value.length > 1_000) throw new Error("A field is too long.");
      if (value) result[name] = value;
    }
    return result;
  };
  const card: CardData = input.type === ItemType.Card ? trimmed(input.card, CARD_FIELDS) : {};
  if (card.number) card.number = card.number.replace(/[\s-]/g, "");
  if (card.expMonth) {
    const month = Number(card.expMonth);
    if (!Number.isInteger(month) || month < 1 || month > 12) throw new Error("Enter an expiration month from 1 to 12.");
    card.expMonth = String(month);
  }
  if (card.expYear) {
    if (!/^\d{2}(\d{2})?$/.test(card.expYear)) throw new Error("Enter a 4-digit expiration year.");
    if (card.expYear.length === 2) card.expYear = `20${card.expYear}`;
  }
  const identity: IdentityData = input.type === ItemType.Identity ? trimmed(input.identity, IDENTITY_FIELDS) : {};
  return { type: input.type, name, notes, favorite: input.favorite === true, folderId: input.folderId ?? "", card, identity };
}

// Everything an imported item can carry: several URIs, custom fields, password history, passkeys.
export type CipherContent = Pick<VaultItem, "type" | "name" | "username" | "password" | "favorite" | "reprompt" | "uris"> &
  Partial<Pick<VaultItem, "totp" | "notes" | "passkeys" | "card" | "identity" | "sshKey" | "fields" | "passwordHistory">>;

export async function createEncryptedCipher(content: CipherContent, userKey: Uint8Array): Promise<Record<string, unknown>> {
  const name = content.name.trim() || "Untitled";
  const common = { name, notes: content.notes ?? "", favorite: content.favorite, folderId: "" };
  return newCipher(content.type, common, userKey, async (key) => {
    const encrypt = (value: string | undefined) => (value ? encryptSymmetricString(value, key) : null);
    const record = async (values: Record<string, string | undefined> | undefined, names: readonly string[]) =>
      Object.fromEntries(await Promise.all(names.map(async (field) => [field, await encrypt(values?.[field])])));
    const typeData = content.type === ItemType.Login
      ? {
          login: {
            username: await encrypt(content.username),
            password: await encrypt(content.password),
            totp: await encrypt(content.totp),
            passwordRevisionDate: null,
            autofillOnPageLoad: null,
            uris: await Promise.all(content.uris.map(async ({ uri, match }) => ({
              uri: await encrypt(uri),
              match: match ?? null,
              uriChecksum: await encrypt(await sha256Base64(uri)),
            }))),
            fido2Credentials: await Promise.all((content.passkeys ?? []).map((passkey) => encryptPasskey(passkey, key))),
          },
        }
      : content.type === ItemType.Card ? { card: await record(content.card, CARD_FIELDS) }
      : content.type === ItemType.Identity ? { identity: await record(content.identity, IDENTITY_FIELDS) }
      : content.type === ItemType.SshKey ? { sshKey: await record(content.sshKey, SSH_KEY_FIELDS) }
      : { secureNote: { type: 0 } };
    return {
      reprompt: content.reprompt ? 1 : 0,
      fields: await Promise.all((content.fields ?? []).map(async (field) => ({
        type: field.hidden ? 1 : 0,
        name: await encrypt(field.name),
        value: await encrypt(field.value),
        linkedId: null,
      }))),
      passwordHistory: await Promise.all((content.passwordHistory ?? []).map(async (entry) => ({
        password: await encrypt(entry.password),
        lastUsedDate: entry.lastUsedDate || new Date().toISOString(),
      }))),
      ...typeData,
    };
  });
}

export async function createEncryptedLogin(
  input: LoginWriteInput,
  userKey: Uint8Array,
  passkey?: Passkey,
): Promise<Record<string, unknown>> {
  const clean = validateLoginInput(input);
  return newCipher(ItemType.Login, clean, userKey, async (itemKey) => ({
    fields: await withNickname([], clean.nickname, itemKey),
    login: {
      ...(await encryptedLogin(clean, itemKey)),
      fido2Credentials: passkey ? [await encryptPasskey(passkey, itemKey)] : [],
    },
  }));
}

// `baseKey` is the account key, or the organization key for an organization login.
export async function updateEncryptedLogin(
  rawCipher: Record<string, unknown>,
  input: LoginWriteInput,
  baseKey: Uint8Array,
  passkey?: Passkey | null, // null removes the login's passkeys
): Promise<Record<string, unknown>> {
  const clean = validateLoginInput(input);
  return editedCipher(rawCipher, clean, input.folderId, baseKey, async (itemKey) => {
    const rawLogin = recordProp(rawCipher, "Login") ?? {};
    const edited = await encryptedLogin(clean, itemKey);
    const now = new Date().toISOString();

    // Only the first URI is editable; keep the rest, and keep the first one (with its match rule) if unchanged.
    const rawUris = arrayProp(rawLogin, "Uris");
    const firstRaw = rawUris[0];
    const oldUri = typeof firstRaw === "object" && firstRaw !== null
      ? await decryptOrUndefined(prop(firstRaw as Record<string, unknown>, "Uri"), itemKey)
      : undefined;
    const uris = sameUri(oldUri, clean.uri) ? rawUris : [...edited.uris, ...rawUris.slice(1)];

    // Keep the replaced password recoverable, like the official clients (newest first, five entries).
    const oldPasswordCipher = stringProp(rawLogin, "Password");
    const oldPassword = await decryptOrUndefined(oldPasswordCipher, itemKey);
    const history = arrayProp(rawCipher, "PasswordHistory");
    const passwordChanged = Boolean(oldPassword) && oldPassword !== clean.password;

    return {
      type: numberProp(rawCipher, "Type") ?? ItemType.Login,
      // Callers that do not edit notes, favorite or the nickname (the website save prompt) must not erase them.
      ...(input.notes === undefined ? { notes: prop(rawCipher, "Notes") ?? null } : {}),
      ...(input.favorite === undefined ? { favorite: prop(rawCipher, "Favorite") === true } : {}),
      ...(input.nickname === undefined ? {} : { fields: await withNickname(arrayProp(rawCipher, "Fields"), clean.nickname, itemKey) }),
      passwordHistory: passwordChanged
        ? [{ password: oldPasswordCipher, lastUsedDate: now }, ...history].slice(0, 5)
        : history,
      login: {
        ...rawLogin,
        ...edited,
        uris,
        totp: input.totp === undefined ? prop(rawLogin, "Totp") ?? null : edited.totp,
        fido2Credentials: passkey === null ? [] : [
          ...arrayProp(rawLogin, "Fido2Credentials"),
          ...(passkey ? [await encryptPasskey(passkey, itemKey)] : []),
        ],
        autofillOnPageLoad: prop(rawLogin, "AutofillOnPageLoad") ?? null,
        passwordRevisionDate: passwordChanged
          ? now
          : prop(rawLogin, "PasswordRevisionDate") ?? null,
      },
    };
  });
}

async function encryptedLogin(input: Required<LoginWriteInput>, key: Uint8Array) {
  if (input.totp) {
    // Saving a key that cannot produce codes would only fail later, on the login page.
    await generateTotp(input.totp).catch(() => {
      throw new Error("Enter a valid authenticator key: a Base32 secret or an otpauth://totp/ link.");
    });
  }
  const uris = input.uri
    ? [
        {
          uri: await encryptSymmetricString(input.uri, key),
          match: null,
          uriChecksum: await encryptSymmetricString(await sha256Base64(input.uri), key),
        },
      ]
    : [];
  return {
    username: input.username ? await encryptSymmetricString(input.username, key) : null,
    password: input.password ? await encryptSymmetricString(input.password, key) : null,
    passwordRevisionDate: null,
    totp: input.totp ? await encryptSymmetricString(input.totp, key) : null,
    uris,
    autofillOnPageLoad: null,
    fido2Credentials: [],
  };
}

function validateLoginInput(input: LoginWriteInput): Required<LoginWriteInput> {
  const name = input.name.trim();
  const username = input.username.trim();
  const password = input.password;
  const notes = (input.notes ?? "").trim();
  const totp = (input.totp ?? "").trim();
  const uri = normalizeUri(input.uri);
  if (!name || name.length > 1_000) throw new Error("Enter a login name up to 1,000 characters.");
  if (username.length > 1_000) throw new Error("Username is too long.");
  if (password.length > 10_000) throw new Error("Password is too long.");
  if (notes.length > 10_000) throw new Error("Notes are too long.");
  if (totp.length > 2_048) throw new Error("The authenticator key is too long.");
  const nickname = (input.nickname ?? "").trim();
  if (nickname.length > 200) throw new Error("The nickname is too long.");
  return { name, username, password, uri, notes, favorite: input.favorite === true, folderId: input.folderId ?? "", totp, nickname };
}

// Replaces the nickname field (matched by its decrypted name) and keeps every other field as stored.
async function withNickname(rawFields: unknown[], nickname: string, key: Uint8Array): Promise<unknown[]> {
  const kept: unknown[] = [];
  for (const field of rawFields) {
    const name = typeof field === "object" && field !== null
      ? await decryptOrUndefined(prop(field as Record<string, unknown>, "Name"), key)
      : undefined;
    if (name !== NICKNAME_FIELD) kept.push(field);
  }
  if (!nickname) return kept;
  return [...kept, {
    type: 0,
    name: await encryptSymmetricString(NICKNAME_FIELD, key),
    value: await encryptSymmetricString(nickname, key),
    linkedId: null,
  }];
}

function normalizeUri(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Website URLs must use HTTPS or HTTP.");
  }
  return parsed.href;
}

// Bitwarden's Fido2CredentialApi: every field is an EncString except creationDate.
async function encryptPasskey(passkey: Passkey, key: Uint8Array): Promise<Record<string, unknown>> {
  const encrypt = (value: string | undefined) => (value === undefined ? null : encryptSymmetricString(value, key));
  return {
    credentialId: await encrypt(passkey.credentialId),
    keyType: await encrypt("public-key"),
    keyAlgorithm: await encrypt("ECDSA"),
    keyCurve: await encrypt("P-256"),
    keyValue: await encrypt(passkey.keyValue),
    rpId: await encrypt(passkey.rpId),
    userHandle: await encrypt(passkey.userHandle),
    userName: await encrypt(passkey.userName),
    counter: await encrypt(String(passkey.counter)),
    rpName: await encrypt(passkey.rpName),
    userDisplayName: await encrypt(passkey.userDisplayName),
    discoverable: await encrypt(String(passkey.discoverable)),
    creationDate: passkey.creationDate,
  };
}

function chosenFolder(rawCipher: Record<string, unknown>, folderId: string | undefined): unknown {
  return folderId === undefined ? prop(rawCipher, "FolderId") ?? null : folderId || null;
}

function sameUri(saved: string | undefined, edited: string): boolean {
  if (saved === undefined) return edited === "";
  try {
    return normalizeUri(saved) === edited;
  } catch {
    return false;
  }
}

async function decryptOrUndefined(value: unknown, key: Uint8Array): Promise<string | undefined> {
  if (typeof value !== "string" || !value) return undefined;
  try {
    return await decryptSymmetricString(value, key);
  } catch {
    return undefined;
  }
}
