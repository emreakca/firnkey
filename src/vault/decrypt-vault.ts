import type { SyncResponse } from "../api/models";
import { arrayProp, asRecord, numberProp, prop, stringProp } from "../shared/props";
import {
  decryptRsaKey,
  decryptSymmetricBytes,
  isSymmetricKey,
  decryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ItemType,
  SSH_KEY_FIELDS,
  type CardData,
  type CustomField,
  type IdentityData,
  type Passkey,
  type Attachment,
  type PasswordHistoryEntry,
  type SshKeyData,
  type VaultCollection,
  type VaultFolder,
  type VaultItem,
  type VaultItemDetail,
  type VaultItemSummary,
  type VaultUri,
} from "./models";

const SUPPORTED_TYPES: readonly number[] = Object.values(ItemType);

export interface VaultDecryptionResult {
  items: VaultItem[];
  // Trashed items stay apart so autofill, passkeys and suggestions can never reach them.
  trash: VaultItem[];
  folders: VaultFolder[];
  collections: VaultCollection[];
  failures: number;
}

export async function decryptVault(
  sync: SyncResponse,
  userKey: Uint8Array,
  identityPrivateKey?: string,
): Promise<VaultDecryptionResult> {
  if (!isSymmetricKey(userKey)) {
    throw new Error("The decrypted account key has an invalid length.");
  }
  const profile = asRecord(sync.Profile ?? sync.profile);
  const orgKeys = await decryptOrganizationKeys(profile, userKey, identityPrivateKey);
  const ciphers = sync.Ciphers ?? sync.ciphers;
  const rawCiphers = Array.isArray(ciphers) ? ciphers : [];
  const items: VaultItem[] = [];
  const trash: VaultItem[] = [];
  let failures = 0;

  for (const raw of rawCiphers) {
    try {
      const cipher = asRecord(raw);
      if (!cipher || !SUPPORTED_TYPES.includes(numberProp(cipher, "Type") ?? 0)) {
        continue;
      }
      const organizationId = stringProp(cipher, "OrganizationId");
      const baseKey = organizationId ? orgKeys.get(organizationId) : userKey;
      if (!baseKey) {
        failures += 1;
        continue;
      }
      (prop(cipher, "DeletedDate") ? trash : items).push(await decryptCipher(cipher, baseKey, organizationId));
    } catch {
      failures += 1;
    }
  }

  const byName = (left: { name: string }, right: { name: string }) =>
    left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
  items.sort((left, right) => left.favorite !== right.favorite ? (left.favorite ? -1 : 1) : byName(left, right));
  trash.sort(byName);
  const collections = (await decryptCollections(sync, orgKeys, profile)).sort((left, right) =>
    left.organizationName.localeCompare(right.organizationName) || byName(left, right));
  for (const organizationKey of orgKeys.values()) {
    organizationKey.fill(0);
  }
  return { items, trash, folders: (await decryptFolders(sync, userKey)).sort(byName), collections, failures };
}

// Collection names are encrypted with their organization's key; organization names are plain text.
async function decryptCollections(
  sync: SyncResponse,
  orgKeys: Map<string, Uint8Array>,
  profile: Record<string, unknown> | undefined,
): Promise<VaultCollection[]> {
  const names = new Map(organizationList(profile).map((org) => [stringProp(org, "Id"), stringProp(org, "Name") ?? "Organization"]));
  const raw = sync.Collections ?? sync.collections;
  const collections: VaultCollection[] = [];
  for (const entry of Array.isArray(raw) ? raw : []) {
    try {
      const collection = asRecord(entry);
      const organizationId = collection && stringProp(collection, "OrganizationId");
      const key = organizationId && orgKeys.get(organizationId);
      if (!collection || !organizationId || !key) continue;
      collections.push({
        id: requiredString(collection, "Id"),
        organizationId,
        organizationName: names.get(organizationId) ?? "Organization",
        name: await decryptRequiredString(collection, key, "Name"),
        readOnly: prop(collection, "ReadOnly") === true,
      });
    } catch {
      // Skip it; its items still show under All items.
    }
  }
  return collections;
}

// Folder names are encrypted with the account key. A damaged folder is skipped; its items show under "No folder".
async function decryptFolders(sync: SyncResponse, userKey: Uint8Array): Promise<VaultFolder[]> {
  const raw = sync.Folders ?? sync.folders;
  const folders: VaultFolder[] = [];
  for (const entry of Array.isArray(raw) ? raw : []) {
    try {
      const folder = asRecord(entry);
      if (!folder) continue;
      folders.push({ id: requiredString(folder, "Id"), name: await decryptRequiredString(folder, userKey, "Name") });
    } catch {
      // Skip it.
    }
  }
  return folders;
}

export function listVaultItems(
  items: VaultItem[],
  queryInput: string,
  currentUrl?: string,
): VaultItemSummary[] {
  const query = queryInput.trim().toLocaleLowerCase();
  return items
    .map((item) => ({ item, matched: currentUrl ? matchesCurrentUrl(item, currentUrl) : false, subtitle: itemSubtitle(item) }))
    .filter(({ item, matched, subtitle }) => {
      if (!query) {
        return true;
      }
      return (
        matched ||
        item.name.toLocaleLowerCase().includes(query) ||
        item.username.toLocaleLowerCase().includes(query) ||
        subtitle.toLocaleLowerCase().includes(query) ||
        item.uris.some((uri) => uri.uri.toLocaleLowerCase().includes(query))
      );
    })
    .sort((left, right) => Number(right.matched) - Number(left.matched))
    .map(({ item, matched, subtitle }) => ({
      id: item.id,
      type: item.type,
      name: item.name,
      username: item.username,
      hasTotp: Boolean(item.totp),
      favorite: item.favorite,
      requiresReprompt: item.reprompt,
      editable: item.editable,
      matched,
      ...(subtitle ? { subtitle } : {}),
      ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
      ...(item.folderId ? { folderId: item.folderId } : {}),
    }));
}

// What the vault list shows under the name: "Visa *1234" or "Jane Doe". Never the full card number.
function itemSubtitle(item: VaultItem): string {
  if (item.card) {
    const last = item.card.number && item.card.number.length > 4 ? `*${item.card.number.slice(-4)}` : "";
    return [item.card.brand, last].filter(Boolean).join(" ");
  }
  if (item.identity) {
    return [item.identity.firstName, item.identity.lastName].filter(Boolean).join(" ");
  }
  return item.sshKey?.keyFingerprint ?? "";
}

export function getVaultItemDetail(
  item: VaultItem,
  currentUrl?: string,
  repromptSatisfied = false,
): VaultItemDetail {
  const protectedItem = item.reprompt && !repromptSatisfied;
  const subtitle = itemSubtitle(item);
  return {
    id: item.id,
    type: item.type,
    name: item.name,
    username: item.username,
    password: protectedItem ? "" : item.password,
    hasTotp: !protectedItem && Boolean(item.totp),
    protected: protectedItem,
    favorite: item.favorite,
    requiresReprompt: item.reprompt,
    matched: currentUrl ? matchesCurrentUrl(item, currentUrl) : false,
    uris: item.uris,
    editable: item.editable,
    ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
    ...(item.folderId ? { folderId: item.folderId } : {}),
    ...(subtitle ? { subtitle } : {}),
    ...(protectedItem || !item.totp ? {} : { totp: item.totp }),
    ...(protectedItem || item.notes === undefined ? {} : { notes: item.notes }),
    ...(protectedItem || !item.card ? {} : { card: item.card }),
    ...(protectedItem || !item.identity ? {} : { identity: item.identity }),
    ...(protectedItem || !item.sshKey ? {} : { sshKey: item.sshKey }),
    ...(protectedItem || !item.fields ? {} : { fields: item.fields }),
    ...(protectedItem || !item.passwordHistory ? {} : { passwordHistory: item.passwordHistory }),
    ...(item.organizationId ? { organizationId: item.organizationId } : {}),
    ...(item.collectionIds ? { collectionIds: item.collectionIds } : {}),
    ...(protectedItem || !item.attachments ? {} : { attachments: item.attachments }),
    ...(protectedItem || !item.passkeys?.length
      ? {}
      : { passkeys: item.passkeys.map(({ rpId, userName, creationDate }) => ({ rpId, creationDate, ...(userName ? { userName } : {}) })) }),
  };
}

export function matchesCurrentUrl(item: VaultItem, currentUrl: string): boolean {
  const page = safeUrl(currentUrl);
  if (!page || (page.protocol !== "http:" && page.protocol !== "https:")) {
    return false;
  }
  return item.uris.some(({ uri, match }) => {
    // Bitwarden URI match strategies: Domain (0/default), Host (1),
    // Starts With (2), Exact (3), Regular Expression (4), and Never (5).
    // Unknown strategies fail closed so a future server value cannot broaden access.
    if (match === 5) {
      return false;
    }
    if (match === 4) {
      try {
        return new RegExp(uri, "i").test(page.href);
      } catch {
        return false;
      }
    }
    const saved = safeUrl(uri);
    if (!saved) {
      return false;
    }
    if (match === 3) {
      return page.href === saved.href;
    }
    if (match === 2) {
      return page.href.startsWith(saved.href);
    }
    if (match === 1) {
      return page.hostname === saved.hostname && page.port === saved.port;
    }
    if (match !== undefined && match !== 0) {
      return false;
    }
    const pageHost = page.hostname.toLocaleLowerCase();
    const savedHost = saved.hostname.toLocaleLowerCase();
    return pageHost === savedHost || pageHost.endsWith(`.${savedHost}`);
  });
}

async function decryptCipher(
  cipher: Record<string, unknown>,
  baseKey: Uint8Array,
  organizationId?: string,
): Promise<VaultItem> {
  const encryptedItemKey = stringProp(cipher, "Key");
  const itemKey = encryptedItemKey
    ? await decryptSymmetricBytes(encryptedItemKey, baseKey)
    : baseKey;
  try {
    if (!isSymmetricKey(itemKey)) {
      throw new Error("A cipher key has an invalid length.");
    }
    const type = numberProp(cipher, "Type") as ItemType;
    const id = requiredString(cipher, "Id");
    const name = await decryptRequiredString(cipher, itemKey, "Name");
    const notes = await decryptOptionalString(cipher, itemKey, "Notes");
    const canViewPassword = prop(cipher, "ViewPassword") !== false;
    const folderId = stringProp(cipher, "FolderId");
    const fields = await decryptCustomFields(cipher, itemKey, canViewPassword);
    const passwordHistory = canViewPassword ? await decryptPasswordHistory(cipher, itemKey) : [];
    const attachments = await decryptAttachments(cipher, itemKey);
    const collectionIds = arrayProp(cipher, "CollectionIds").filter((value): value is string => typeof value === "string");
    const common = {
      id,
      type,
      name,
      username: "",
      password: "",
      favorite: booleanProp(cipher, "Favorite"),
      reprompt: numberProp(cipher, "Reprompt") === 1,
      // Editing an item whose password is hidden would erase it, so that needs view access too.
      editable: organizationId === undefined || (prop(cipher, "Edit") !== false && canViewPassword),
      uris: [],
      ...(organizationId === undefined ? {} : { organizationId }),
      ...(folderId ? { folderId } : {}),
      ...(notes === undefined ? {} : { notes }),
      ...(fields.length > 0 ? { fields } : {}),
      ...(passwordHistory.length > 0 ? { passwordHistory } : {}),
      ...(attachments.length > 0 ? { attachments } : {}),
      ...(collectionIds.length > 0 ? { collectionIds } : {}),
    };
    if (type === ItemType.SecureNote) return common;
    if (type === ItemType.Card) {
      const card: CardData = await decryptFields(asRecord(prop(cipher, "Card")), itemKey, CARD_FIELDS);
      // Like the login password, the organization can hide the card number and security code.
      if (!canViewPassword) {
        delete card.number;
        delete card.code;
      }
      return { ...common, card };
    }
    if (type === ItemType.Identity) {
      const identity: IdentityData = await decryptFields(asRecord(prop(cipher, "Identity")), itemKey, IDENTITY_FIELDS);
      return { ...common, identity };
    }
    if (type === ItemType.SshKey) {
      const sshKey: SshKeyData = await decryptFields(asRecord(prop(cipher, "SshKey")), itemKey, SSH_KEY_FIELDS);
      if (!canViewPassword) delete sshKey.privateKey;
      return { ...common, sshKey };
    }
    const login = asRecord(prop(cipher, "Login"));
    if (!login) {
      throw new Error("Login cipher is missing its login payload.");
    }
    const username = await decryptOptionalString(login, itemKey, "Username");
    const password = canViewPassword
      ? await decryptOptionalString(login, itemKey, "Password")
      : undefined;
    const totp = canViewPassword
      ? await decryptOptionalString(login, itemKey, "Totp")
      : undefined;
    const uris = await decryptUris(login, itemKey, Boolean(encryptedItemKey));
    // Passkeys are private keys: hide them where the organization hides the password.
    const passkeys = canViewPassword ? await decryptPasskeys(login, itemKey) : [];

    return {
      ...common,
      username: username ?? "",
      password: password ?? "",
      uris,
      ...(totp === undefined ? {} : { totp }),
      ...(passkeys.length > 0 ? { passkeys } : {}),
    };
  } finally {
    if (encryptedItemKey) {
      itemKey.fill(0);
    }
  }
}

async function decryptFields(
  source: Record<string, unknown> | undefined,
  key: Uint8Array,
  names: readonly string[],
): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  if (!source) return result;
  for (const name of names) {
    const decrypted = await decryptOptionalString(source, key, name[0]!.toUpperCase() + name.slice(1));
    if (decrypted) result[name] = decrypted;
  }
  return result;
}

async function decryptUris(
  login: Record<string, unknown>,
  key: Uint8Array,
  requiresChecksum: boolean,
): Promise<VaultUri[]> {
  const rawUris = prop(login, "Uris");
  if (!Array.isArray(rawUris)) {
    return [];
  }
  const uris: VaultUri[] = [];
  for (const raw of rawUris) {
    try {
      const entry = asRecord(raw);
      if (!entry) {
        continue;
      }
      const encryptedUri = stringProp(entry, "Uri");
      if (!encryptedUri) {
        continue;
      }
      const uri = await decryptSymmetricString(encryptedUri, key);
      if (requiresChecksum) {
        const encryptedChecksum = stringProp(entry, "UriChecksum");
        if (!encryptedChecksum) {
          continue;
        }
        const expected = await decryptSymmetricString(encryptedChecksum, key);
        const actual = await sha256Base64(uri);
        if (expected !== actual) {
          continue;
        }
      }
      const match = numberProp(entry, "Match");
      uris.push({ uri, ...(match === undefined ? {} : { match }) });
    } catch {
      // A damaged URI does not make the rest of a login unusable.
    }
  }
  return uris;
}

async function decryptPasskeys(login: Record<string, unknown>, key: Uint8Array): Promise<Passkey[]> {
  const raw = prop(login, "Fido2Credentials");
  if (!Array.isArray(raw)) return [];
  const passkeys: Passkey[] = [];
  for (const entry of raw) {
    try {
      const credential = asRecord(entry);
      if (!credential) continue;
      const field = (name: string) => decryptOptionalString(credential, key, name);
      // Only ES256 (ECDSA P-256) keys are supported; skip anything else.
      if ((await field("KeyAlgorithm")) !== "ECDSA" || (await field("KeyCurve")) !== "P-256") continue;
      const credentialId = await field("CredentialId");
      const keyValue = await field("KeyValue");
      const rpId = await field("RpId");
      if (!credentialId || !keyValue || !rpId) continue;
      const optional = async (name: string) => {
        const decrypted = await field(name);
        return decrypted ? { [name[0]!.toLowerCase() + name.slice(1)]: decrypted } : {};
      };
      passkeys.push({
        credentialId,
        keyValue,
        rpId,
        counter: Number(await field("Counter")) || 0,
        discoverable: (await field("Discoverable")) === "true",
        creationDate: stringProp(credential, "CreationDate") ?? "",
        ...(await optional("UserHandle")),
        ...(await optional("UserName")),
        ...(await optional("UserDisplayName")),
        ...(await optional("RpName")),
      });
    } catch {
      // A damaged passkey does not make the rest of a login unusable.
    }
  }
  return passkeys;
}

// Hidden fields count as secrets: the organization's "hide passwords" setting drops them too.
async function decryptCustomFields(cipher: Record<string, unknown>, key: Uint8Array, canViewHidden: boolean): Promise<CustomField[]> {
  const raw = prop(cipher, "Fields");
  if (!Array.isArray(raw)) return [];
  const fields: CustomField[] = [];
  for (const entry of raw) {
    try {
      const field = asRecord(entry);
      const type = field && numberProp(field, "Type");
      if (!field || (type !== 0 && type !== 1 && type !== 2) || (type === 1 && !canViewHidden)) continue;
      const name = (await decryptOptionalString(field, key, "Name")) ?? "";
      const text = (await decryptOptionalString(field, key, "Value")) ?? "";
      if (name || text) fields.push({ name, value: text, hidden: type === 1 });
    } catch {
      // A damaged field does not make the rest of the item unusable.
    }
  }
  return fields;
}

async function decryptAttachments(cipher: Record<string, unknown>, key: Uint8Array): Promise<Attachment[]> {
  const attachments: Attachment[] = [];
  for (const entry of arrayProp(cipher, "Attachments")) {
    try {
      const attachment = asRecord(entry);
      if (!attachment) continue;
      const size = Number(prop(attachment, "Size"));
      attachments.push({
        id: requiredString(attachment, "Id"),
        fileName: await decryptRequiredString(attachment, key, "FileName"),
        size: Number.isFinite(size) ? size : 0,
        sizeName: stringProp(attachment, "SizeName") ?? "",
      });
    } catch {
      // A damaged attachment does not make the rest of the item unusable.
    }
  }
  return attachments;
}

async function decryptPasswordHistory(cipher: Record<string, unknown>, key: Uint8Array): Promise<PasswordHistoryEntry[]> {
  const raw = prop(cipher, "PasswordHistory");
  if (!Array.isArray(raw)) return [];
  const history: PasswordHistoryEntry[] = [];
  for (const entry of raw) {
    try {
      const old = asRecord(entry);
      const password = old && (await decryptOptionalString(old, key, "Password"));
      if (password) history.push({ password, lastUsedDate: stringProp(old, "LastUsedDate") ?? "" });
    } catch {
      // Skip it.
    }
  }
  return history;
}

// The key an organization item is encrypted with, for writing it back.
export async function decryptOrganizationKey(
  sync: SyncResponse,
  userKey: Uint8Array,
  identityPrivateKey: string | undefined,
  organizationId: string,
): Promise<Uint8Array> {
  const keys = await decryptOrganizationKeys(asRecord(sync.Profile ?? sync.profile), userKey, identityPrivateKey);
  const key = keys.get(organizationId);
  for (const [id, other] of keys) if (id !== organizationId) other.fill(0);
  if (!key) throw new Error("This organization's key is not available. Sync and try again.");
  return key;
}

async function decryptOrganizationKeys(
  profile: Record<string, unknown> | undefined,
  userKey: Uint8Array,
  identityPrivateKey?: string,
): Promise<Map<string, Uint8Array>> {
  const result = new Map<string, Uint8Array>();
  if (!profile) {
    return result;
  }
  const encryptedPrivateKey = stringProp(profile, "PrivateKey") ?? identityPrivateKey;
  if (!encryptedPrivateKey) {
    return result;
  }
  let privateKey: Uint8Array;
  try {
    privateKey = await decryptSymmetricBytes(encryptedPrivateKey, userKey);
  } catch {
    return result;
  }
  for (const organization of organizationList(profile)) {
    try {
      const id = requiredString(organization, "Id");
      const encryptedKey = requiredString(organization, "Key");
      const key = await decryptRsaKey(encryptedKey, privateKey);
      if (isSymmetricKey(key)) {
        result.set(id, key);
      }
    } catch {
      // Unsupported organization keys are isolated to that organization.
    }
  }
  privateKey.fill(0);
  return result;
}

function organizationList(profile: Record<string, unknown> | undefined): Record<string, unknown>[] {
  if (!profile) return [];
  const current = arrayProp(profile, "OrganizationsNew");
  const list = current.length > 0 ? current : arrayProp(profile, "Organizations");
  return list.flatMap((entry) => {
    const organization = asRecord(entry);
    return organization ? [organization] : [];
  });
}

async function decryptRequiredString(source: Record<string, unknown>, key: Uint8Array, name: string): Promise<string> {
  return decryptSymmetricString(requiredString(source, name), key);
}

async function decryptOptionalString(source: Record<string, unknown>, key: Uint8Array, name: string): Promise<string | undefined> {
  const encrypted = stringProp(source, name);
  return encrypted ? decryptSymmetricString(encrypted, key) : undefined;
}

function safeUrl(input: string): URL | null {
  const trimmed = input.trim();
  if (!trimmed) {
    return null;
  }
  try {
    return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
}




function requiredString(source: Record<string, unknown>, name: string): string {
  const result = stringProp(source, name);
  if (!result) throw new Error(`Vault data is missing ${name}.`);
  return result;
}

function booleanProp(source: Record<string, unknown>, name: string): boolean {
  return prop(source, name) === true;
}


