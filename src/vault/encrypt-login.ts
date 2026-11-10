import {
  decryptSymmetricBytes,
  decryptSymmetricString,
  encryptSymmetricBytes,
  encryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import { generateTotp } from "../crypto/totp";
import { arrayProp, asRecord, numberProp, prop, recordProp, stringProp } from "../shared/props";
import { CARD_FIELDS, IDENTITY_FIELDS, ItemType, NICKNAME_FIELD, SSH_KEY_FIELDS, type CardData, type CustomField, type IdentityData, type Passkey, type SshKeyData, type VaultItem } from "./models";
import { publicKeyFromPrivate, sshFingerprint } from "./ssh-key";

export interface LoginWriteInput {
  name: string;
  username: string;
  password: string;
  uri: string;
  // Bitwarden's match rule for `uri` (0 domain … 5 never). null = the default; omitted = keep it.
  // With 4 (regular expression), `uri` is a pattern, not a URL.
  uriMatch?: number | null;
  notes?: string;
  favorite?: boolean;
  // "" = no folder; omitted = keep the current folder.
  folderId?: string;
  // Authenticator key: a Base32 secret or otpauth://totp/ link. "" = remove; omitted = keep the current one.
  totp?: string;
  // Authenticator tab display name, kept as a custom field. "" = remove; omitted = keep.
  nickname?: string;
  // Fill on page load: true always, false never, null = the default from Settings; omitted = keep.
  autofillOnPageLoad?: boolean | null;
  // Every website with its match rule (null = default). Replaces all of them, and `uri`/`uriMatch`
  // are ignored; omitted = only the first website is edited (through `uri`).
  uris?: { uri: string; match: number | null }[];
  // Custom fields (text, hidden, checkbox). Replaces them; linked fields and the authenticator
  // nickname stay as stored. Omitted = keep.
  fields?: CustomField[];
}

export { NICKNAME_FIELD };

// A secure note, card, identity or SSH key. Logins use LoginWriteInput.
export interface ItemWriteInput {
  type: typeof ItemType.SecureNote | typeof ItemType.Card | typeof ItemType.Identity | typeof ItemType.SshKey;
  name: string;
  notes?: string;
  favorite?: boolean;
  folderId?: string;
  card?: CardData;
  identity?: IdentityData;
  // The fingerprint is always computed from the public key; a missing public key is read from the private key.
  sshKey?: SshKeyData;
  // As in LoginWriteInput.
  fields?: CustomField[];
}

type CleanItem = Required<Omit<ItemWriteInput, "fields">> & { fields?: CustomField[] };

export async function createEncryptedItem(input: ItemWriteInput, userKey: Uint8Array): Promise<Record<string, unknown>> {
  const clean = await validateItemInput(input);
  return newCipher(clean.type, clean, userKey, async (itemKey) => ({
    ...(await encryptedTypeData(clean, itemKey, {})),
    fields: await editedFields([], clean.fields ?? [], itemKey),
  }));
}

// `baseKey` is the account key, or the organization key for an organization item.
export async function updateEncryptedItem(
  rawCipher: Record<string, unknown>,
  input: ItemWriteInput,
  baseKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = await validateItemInput(input);
  if (numberProp(rawCipher, "Type") !== clean.type) throw new Error("The item type cannot be changed.");
  const rawData = recordProp(rawCipher, TYPE_PROPERTY[clean.type]) ?? {};
  return editedCipher(rawCipher, clean, input.folderId, baseKey, async (itemKey) => ({
    ...(await encryptedTypeData(clean, itemKey, rawData)),
    ...(clean.fields ? { fields: await editedFields(arrayProp(rawCipher, "Fields"), clean.fields, itemKey) } : {}),
  }));
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
      // The server un-archives an item saved without its archive date.
      archivedDate: prop(rawCipher, "ArchivedDate") ?? null,
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
  [ItemType.SshKey]: "SshKey",
} as const;

// The server rejects a cipher whose type has no matching data object, so a note sends `secureNote`.
async function encryptedTypeData(input: CleanItem, key: Uint8Array, raw: Record<string, unknown>) {
  if (input.type === ItemType.SecureNote) return { secureNote: { type: 0 } };
  const [names, values, property] = input.type === ItemType.Card
    ? [CARD_FIELDS, input.card as Record<string, string | undefined>, "card"] as const
    : input.type === ItemType.SshKey
    ? [SSH_KEY_FIELDS, input.sshKey as Record<string, string | undefined>, "sshKey"] as const
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

async function validateItemInput(input: ItemWriteInput): Promise<CleanItem> {
  const name = input.name.trim();
  const notes = (input.notes ?? "").trim();
  if (!name || name.length > 1_000) throw new Error("Enter a name up to 1,000 characters.");
  if (notes.length > 10_000) throw new Error("Notes are too long.");
  const trimmed = (values: Record<string, string | undefined> | undefined, names: readonly string[], maximum = 1_000) => {
    const result: Record<string, string> = {};
    for (const name of names) {
      const value = values?.[name]?.trim();
      if (value && value.length > maximum) throw new Error("A field is too long.");
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
  const sshKey: SshKeyData = {};
  if (input.type === ItemType.SshKey) {
    const { privateKey, publicKey } = trimmed(input.sshKey, SSH_KEY_FIELDS, 10_000) as SshKeyData;
    if (!privateKey) throw new Error("Enter the private key.");
    sshKey.privateKey = `${privateKey}\n`;
    const derived = publicKeyFromPrivate(privateKey) ?? publicKey;
    if (!derived) throw new Error("Enter the public key for this private key.");
    sshKey.publicKey = derived;
    sshKey.keyFingerprint = await sshFingerprint(derived);
  }
  return {
    type: input.type, name, notes, favorite: input.favorite === true, folderId: input.folderId ?? "", card, identity, sshKey,
    ...(input.fields ? { fields: validFields(input.fields) } : {}),
  };
}

// Everything an imported item can carry: several URIs, custom fields, password history, passkeys.
export type CipherContent = Pick<VaultItem, "type" | "name" | "username" | "password" | "favorite" | "reprompt" | "uris"> &
  Partial<Pick<VaultItem, "totp" | "notes" | "passkeys" | "card" | "identity" | "sshKey" | "fields" | "passwordHistory" | "folderId">>;

export async function createEncryptedCipher(content: CipherContent, userKey: Uint8Array): Promise<Record<string, unknown>> {
  const name = content.name.trim() || "Untitled";
  const common = { name, notes: content.notes ?? "", favorite: content.favorite, folderId: content.folderId ?? "" };
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
    fields: await withNickname(await editedFields([], clean.fields ?? [], itemKey), clean.nickname, itemKey),
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
    let uris = input.uris ? edited.uris : sameUri(oldUri, clean.uri) ? rawUris : [...edited.uris, ...rawUris.slice(1)];
    if (!input.uris && input.uriMatch !== undefined && uris[0] === firstRaw && typeof firstRaw === "object" && firstRaw !== null) {
      // Replace the rule under whichever key casing the server used.
      const entry = Object.fromEntries(Object.entries(firstRaw).filter(([name]) => name.toLowerCase() !== "match"));
      uris = [{ ...entry, match: input.uriMatch }, ...rawUris.slice(1)];
    }

    // Keep the replaced password recoverable, like the official clients (newest first, five entries).
    const oldPasswordCipher = stringProp(rawLogin, "Password");
    const oldPassword = await decryptOrUndefined(oldPasswordCipher, itemKey);
    const history = arrayProp(rawCipher, "PasswordHistory");
    const passwordChanged = Boolean(oldPassword) && oldPassword !== clean.password;
    const rawFields = arrayProp(rawCipher, "Fields");
    const fields = clean.fields ? await editedFields(rawFields, clean.fields, itemKey) : rawFields;

    return {
      type: numberProp(rawCipher, "Type") ?? ItemType.Login,
      // Callers that do not edit notes, favorite or the nickname (the website save prompt) must not erase them.
      ...(input.notes === undefined ? { notes: prop(rawCipher, "Notes") ?? null } : {}),
      ...(input.favorite === undefined ? { favorite: prop(rawCipher, "Favorite") === true } : {}),
      ...(input.nickname === undefined && !clean.fields ? {} : {
        fields: input.nickname === undefined ? fields : await withNickname(fields, clean.nickname, itemKey),
      }),
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
        autofillOnPageLoad: input.autofillOnPageLoad === undefined ? prop(rawLogin, "AutofillOnPageLoad") ?? null : clean.autofillOnPageLoad,
        passwordRevisionDate: passwordChanged
          ? now
          : prop(rawLogin, "PasswordRevisionDate") ?? null,
      },
    };
  });
}

async function encryptedLogin(input: CleanLogin, key: Uint8Array) {
  if (input.totp) {
    // Saving a key that cannot produce codes would only fail later, on the login page.
    await generateTotp(input.totp).catch(() => {
      throw new Error("Enter a valid authenticator key: a Base32 secret or an otpauth://totp/ link.");
    });
  }
  const uris = await Promise.all(input.uris.map(async ({ uri, match }) => ({
    uri: await encryptSymmetricString(uri, key),
    match,
    uriChecksum: await encryptSymmetricString(await sha256Base64(uri), key),
  })));
  return {
    username: input.username ? await encryptSymmetricString(input.username, key) : null,
    password: input.password ? await encryptSymmetricString(input.password, key) : null,
    passwordRevisionDate: null,
    totp: input.totp ? await encryptSymmetricString(input.totp, key) : null,
    uris,
    autofillOnPageLoad: input.autofillOnPageLoad,
    fido2Credentials: [],
  };
}

type CleanLogin = Required<Omit<LoginWriteInput, "uriMatch" | "autofillOnPageLoad" | "uris" | "fields">> & {
  uriMatch: number | null;
  autofillOnPageLoad: boolean | null;
  uris: { uri: string; match: number | null }[];
  fields?: CustomField[];
};

function validateLoginInput(input: LoginWriteInput): CleanLogin {
  const name = input.name.trim();
  const username = input.username.trim();
  const password = input.password;
  const notes = (input.notes ?? "").trim();
  const totp = (input.totp ?? "").trim();
  const uriMatch = validMatch(input.uriMatch ?? null);
  const uri = uriMatch === 4 ? validPattern(input.uri) : normalizeUri(input.uri);
  if ((input.uris?.length ?? 0) > 100) throw new Error("A login can have up to 100 websites.");
  const uris = input.uris
    ? input.uris.flatMap(({ uri: value, match }) => {
        const rule = validMatch(match);
        const clean = rule === 4 ? validPattern(value) : normalizeUri(value);
        return clean ? [{ uri: clean, match: rule }] : [];
      })
    : uri ? [{ uri, match: uriMatch }] : [];
  if (!name || name.length > 1_000) throw new Error("Enter a login name up to 1,000 characters.");
  if (username.length > 1_000) throw new Error("Username is too long.");
  if (password.length > 10_000) throw new Error("Password is too long.");
  if (notes.length > 10_000) throw new Error("Notes are too long.");
  if (totp.length > 2_048) throw new Error("The authenticator key is too long.");
  const nickname = (input.nickname ?? "").trim();
  if (nickname.length > 200) throw new Error("The nickname is too long.");
  const autofillOnPageLoad = typeof input.autofillOnPageLoad === "boolean" ? input.autofillOnPageLoad : null;
  return {
    name, username, password, uri, uriMatch, uris, notes, favorite: input.favorite === true, folderId: input.folderId ?? "", totp, nickname, autofillOnPageLoad,
    ...(input.fields ? { fields: validFields(input.fields) } : {}),
  };
}

function validMatch(match: number | null): number | null {
  if (match !== null && (!Number.isInteger(match) || match < 0 || match > 5)) throw new Error("Choose a valid match rule.");
  return match;
}

// Rows without a name and a value are dropped.
function validFields(fields: CustomField[]): CustomField[] {
  if (fields.length > 100) throw new Error("An item can have up to 100 custom fields.");
  return fields.flatMap((field) => {
    const name = field.name.trim();
    const value = field.boolean ? String(field.value === "true") : field.value;
    if (name.length > 1_000 || value.length > 5_000) throw new Error("A custom field is too long.");
    return name || (value && !field.boolean) ? [{ name, value, hidden: field.hidden && !field.boolean, ...(field.boolean ? { boolean: true } : {}) }] : [];
  });
}

// The stored linked fields and authenticator nickname, followed by the edited fields.
async function editedFields(rawFields: unknown[], fields: CustomField[], key: Uint8Array): Promise<unknown[]> {
  const kept: unknown[] = [];
  for (const field of rawFields) {
    const record = asRecord(field);
    if (!record) continue;
    if (numberProp(record, "Type") === 3 || (await decryptOrUndefined(prop(record, "Name"), key)) === NICKNAME_FIELD) kept.push(field);
  }
  return [...kept, ...(await Promise.all(fields.map(async (field) => ({
    type: field.boolean ? 2 : field.hidden ? 1 : 0,
    name: field.name ? await encryptSymmetricString(field.name, key) : null,
    value: field.value ? await encryptSymmetricString(field.value, key) : null,
    linkedId: null,
  }))))];
}

// A regular-expression website is matched against the page's full URL, so it must compile.
function validPattern(value: string): string {
  const pattern = value.trim();
  try {
    new RegExp(pattern);
  } catch {
    throw new Error("Enter a valid regular expression for the website.");
  }
  return pattern;
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
  if (saved === edited) return true;
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
