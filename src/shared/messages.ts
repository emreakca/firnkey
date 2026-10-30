import type { ServerSnapshot } from "./storage";
import type { VaultCollection, VaultFolder, VaultItemDetail, VaultItemSummary } from "../vault/models";
import { MAX_FILE_BYTES, SEND_DELETION_DAYS, type SendSummary, type SendWriteInput } from "../vault/send";
import { VAULT_IMPORT_MAX_CHARACTERS, type ExportFormat } from "../vault/transfer";
import type { ItemWriteInput, LoginWriteInput } from "../vault/encrypt-login";
import { CARD_FIELDS, IDENTITY_FIELDS, ItemType } from "../vault/models";
import { isRecord } from "./props";
import type { AssertedCredential, CreatedCredential } from "../passkey/webauthn";
import { IMPORT_MAX_CHARACTERS, type AuthenticatorEntry, type AuthenticatorWriteInput, type ImportRow } from "../vault/authenticator";
import {
  isBrowserIntegrationOptions,
  isClipboardClearSeconds,
  type ClipboardClearSeconds,
  isVaultTimeoutMinutes,
  type BrowserIntegrationOptions,
  type StoredGeneratorOptions,
  type VaultTimeoutMinutes,
} from "./settings";

export type { ServerSnapshot } from "./storage";

// Accounts switched out of the active slot.
export interface SavedAccountSummary {
  id: string;
  email: string;
  baseUrl: string;
}

export type PublicAppState =
  | { phase: "setup" }
  | { phase: "signed-out"; snapshot: ServerSnapshot; accounts: SavedAccountSummary[]; email?: string }
  | {
      phase: "locked";
      snapshot: ServerSnapshot;
      accounts: SavedAccountSummary[];
      email: string;
      itemCount: number;
      lastSync?: string;
      biometricCredentialId?: string;
    }
  | {
      phase: "unlocked";
      snapshot: ServerSnapshot;
      accounts: SavedAccountSummary[];
      email: string;
      itemCount: number;
      decryptionFailures: number;
      lastSync?: string;
      biometricCredentialId?: string;
    };

export interface AuthLoginRequest {
  type: "auth.login";
  baseUrl: string;
  email: string;
  masterPassword: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: boolean;
  newDeviceOtp?: string;
}

export interface VaultListRequest {
  type: "vault.list";
  query: string;
  currentUrl?: string;
  // A folder id, "none" for items without a folder, or "trash". Omitted = every active item.
  folder?: string;
}

// WebAuthn options as serialized by the page bridge (binary values are base64url).
export interface PasskeyCreateOptions {
  challenge: string;
  rpId?: string;
  rpName?: string;
  userId: string;
  userName?: string;
  userDisplayName?: string;
  algorithms: number[];
  excludeCredentials: string[];
  userVerification?: string;
}

export interface PasskeyGetOptions {
  challenge: string;
  rpId?: string;
  allowCredentials: string[];
  userVerification?: string;
  // Autofill-style request: offered in Firnkey's field menu instead of opening a window.
  conditional?: boolean;
}

export type PasskeyPageResult =
  | { fallback: true }
  | { error: "NotAllowedError" | "InvalidStateError" }
  | { created: CreatedCredential }
  | { asserted: AssertedCredential };

export interface PasskeyPromptDetails {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  rpName?: string;
  userName?: string;
  locked: boolean;
  verificationRequired: boolean;
  biometricCredentialId?: string;
  alreadySaved?: boolean;
  targets?: { id: string; name: string; username: string }[];
  candidates?: { id: string; itemName: string; userName: string; reprompt: boolean }[];
}

export type LoginOutcome =
  | { status: "unlocked"; itemCount: number; failures: number }
  | { status: "two-factor"; providers: number[]; providerDetails: Record<string, Record<string, unknown>> }
  | { status: "device-verification"; message: string };

export type ExtensionRequest =
  | { type: "app.getState" }
  | { type: "server.check"; baseUrl: string }
  | AuthLoginRequest
  | { type: "auth.sendEmailCode"; baseUrl: string; email: string; masterPassword: string }
  | { type: "auth.unlock"; masterPassword: string }
  | { type: "auth.lock" }
  | { type: "auth.logout" }
  // `prfOutput` is the base64 WebAuthn PRF result from the biometric window.
  | { type: "biometric.enable"; credentialId: string; prfOutput: string }
  | { type: "biometric.unlock"; prfOutput: string }
  | { type: "biometric.disable" }
  | { type: "account.switch"; id: string }
  | { type: "account.add" }
  | { type: "account.remove"; id: string }
  | { type: "vault.sync" }
  | VaultListRequest
  | { type: "vault.get"; id: string; currentUrl?: string }
  | { type: "vault.authorize"; id: string; masterPassword: string }
  | { type: "vault.totp"; id: string }
  | { type: "vault.fill"; id: string }
  // collectionId: create the item in that organization collection instead of the personal vault.
  | { type: "vault.create"; login: LoginWriteInput; collectionId?: string }
  | { type: "vault.update"; id: string; login: LoginWriteInput }
  | { type: "vault.createItem"; item: ItemWriteInput; collectionId?: string }
  | { type: "vault.move"; id: string; collectionId: string }
  // File contents travel as base64.
  | { type: "attachment.download"; id: string; attachmentId: string }
  | { type: "attachment.add"; id: string; fileName: string; data: string }
  | { type: "attachment.delete"; id: string; attachmentId: string }
  | { type: "send.list" }
  | { type: "send.create"; send: SendWriteInput; file?: string }
  | { type: "send.delete"; id: string }
  | { type: "vault.export"; masterPassword: string; format: ExportFormat; filePassword?: string }
  | { type: "vault.import"; text: string; password?: string; confirm: boolean }
  | { type: "vault.updateItem"; id: string; item: ItemWriteInput }
  | { type: "vault.trash"; id: string }
  | { type: "vault.removePasskey"; id: string }
  | { type: "vault.restore"; id: string }
  | { type: "vault.deleteForever"; id: string }
  | { type: "authenticator.list"; currentUrl?: string }
  | { type: "authenticator.save"; id?: string; entry: AuthenticatorWriteInput }
  | { type: "authenticator.remove"; id: string }
  | { type: "authenticator.fill"; id: string }
  | { type: "authenticator.import"; text: string; confirm: boolean }
  | { type: "authenticator.export"; masterPassword: string }
  | { type: "folder.save"; id?: string; name: string }
  | { type: "folder.delete"; id: string }
  | { type: "settings.get" }
  // digest: SHA-256 of the copied value, sent only when Firnkey may read the clipboard.
  | { type: "clipboard.scheduleClear"; digest?: string }
  | { type: "settings.siteIntegration"; enabled: boolean }
  | { type: "settings.vaultTimeout"; minutes: VaultTimeoutMinutes }
  | { type: "settings.browserOptions"; options: BrowserIntegrationOptions }
  | { type: "settings.generator"; options: StoredGeneratorOptions }
  | { type: "settings.clipboard"; seconds: ClipboardClearSeconds }
  | { type: "site.suggestions"; url: string }
  | { type: "site.credential"; id: string; url: string }
  | { type: "site.totp"; id: string; url: string }
  | { type: "site.totpAuto"; url: string }
  | { type: "site.formItems"; url: string }
  | { type: "site.fillItem"; id: string; url: string }
  | { type: "site.inspect"; url: string; username: string; password: string }
  | { type: "site.pendingPrompt" }
  | { type: "site.generatePassword"; url: string }
  | { type: "site.save"; promptId: string; login?: LoginWriteInput }
  | { type: "site.dismiss"; promptId: string }
  | { type: "site.hold"; promptId: string }
  // id: the page script's request ID, so an abort from the page reaches the right request.
  | { type: "site.passkeyCreate"; id: string; options: PasskeyCreateOptions }
  | { type: "site.passkeyGet"; id: string; options: PasskeyGetOptions }
  | { type: "site.passkeyAbort"; id: string }
  | { type: "site.passkeyChoose" }
  | { type: "passkey.details"; id: string }
  | { type: "passkey.unlock"; id: string; masterPassword: string }
  // Touch ID in the passkey window: unlocks when locked, otherwise verifies the user.
  | { type: "passkey.biometric"; id: string; prfOutput: string }
  | {
      type: "passkey.respond";
      id: string;
      action: "save" | "use" | "fallback" | "cancel";
      itemId?: string;
      credentialId?: string;
      masterPassword?: string;
    };

export type ResponseData =
  | { type: "state"; state: PublicAppState }
  | { type: "server"; snapshot: ServerSnapshot }
  | { type: "login"; result: LoginOutcome }
  | { type: "unlock"; itemCount: number; failures: number }
  | { type: "done" }
  | { type: "sync"; itemCount: number; failures: number }
  | { type: "items"; items: VaultItemSummary[]; folders: VaultFolder[]; collections: VaultCollection[] }
  | { type: "file"; fileName: string; data: string }
  | { type: "sends"; sends: SendSummary[] }
  | { type: "sendCreated"; link: string | null }
  | { type: "export"; text: string }
  | { type: "import"; items: number; folders: number }
  | { type: "item"; item: VaultItemDetail }
  | { type: "totp"; code: string; period: number; remaining: number }
  | { type: "authenticatorEntries"; entries: AuthenticatorEntry[] }
  | { type: "authenticatorImport"; rows: ImportRow[]; imported: number }
  | { type: "authenticatorExport"; text: string }
  | { type: "fill"; username: boolean; password: boolean; fields?: number }
  | {
      type: "settings";
      siteIntegrationEnabled: boolean;
      vaultTimeoutMinutes: VaultTimeoutMinutes;
      browserOptions: BrowserIntegrationOptions;
      generatorOptions: StoredGeneratorOptions;
      clipboardClearSeconds: ClipboardClearSeconds;
    }
  | { type: "siteSuggestions"; items: VaultItemSummary[]; passkeyOffer: boolean }
  | { type: "siteFormItems"; cards: VaultItemSummary[]; identities: VaultItemSummary[] }
  | { type: "siteCredential"; username: string; password: string }
  | { type: "siteTotp"; result: { code: string; itemName: string } | null }
  | { type: "generatedPassword"; password: string }
  | { type: "passkeyResult"; result: PasskeyPageResult }
  | { type: "passkeyDetails"; details: PasskeyPromptDetails }
  | {
      type: "sitePrompt";
      prompt: ({ id: string; expiresAt: number; action: "save" | "update" } & LoginWriteInput) | null;
    };

export type ExtensionResponse = { ok: true; data: ResponseData } | { ok: false; error: string };

export function isExtensionRequest(request: unknown): request is ExtensionRequest {
  if (!isRecord(request)) return false;
  switch (request.type) {
    case "app.getState":
    case "auth.lock":
    case "auth.logout":
    case "vault.sync":
    case "biometric.disable":
    case "account.add":
      return true;
    case "account.switch":
    case "account.remove":
      return boundedString(request.id, 2_400);
    case "biometric.enable":
      return boundedString(request.credentialId, 1_400) && boundedString(request.prfOutput, 64);
    case "biometric.unlock":
      return boundedString(request.prfOutput, 64);
    case "server.check":
      return boundedString(request.baseUrl, 2_048);
    case "auth.login":
      return (
        boundedString(request.baseUrl, 2_048) &&
        boundedString(request.email, 320) &&
        boundedString(request.masterPassword, 1_024) &&
        optionalInteger(request.twoFactorProvider) &&
        optionalString(request.twoFactorToken, 4_096) &&
        (request.twoFactorRemember === undefined || typeof request.twoFactorRemember === "boolean") &&
        optionalString(request.newDeviceOtp, 4_096)
      );
    case "auth.unlock":
      return boundedString(request.masterPassword, 1_024);
    case "auth.sendEmailCode":
      return (
        boundedString(request.baseUrl, 2_048) &&
        boundedString(request.email, 320) &&
        boundedString(request.masterPassword, 1_024)
      );
    case "vault.list":
      return (
        typeof request.query === "string" &&
        request.query.length <= 200 &&
        optionalString(request.currentUrl, 8_192) &&
        optionalString(request.folder, 128)
      );
    case "vault.get":
      return boundedString(request.id, 128) && optionalString(request.currentUrl, 8_192);
    case "vault.authorize":
      return boundedString(request.id, 128) && boundedString(request.masterPassword, 1_024);
    case "vault.fill":
    case "vault.totp":
    case "vault.trash":
    case "vault.removePasskey":
    case "vault.restore":
    case "vault.deleteForever":
    case "folder.delete":
      return boundedString(request.id, 128);
    case "vault.create":
      return validLogin(request.login) && optionalString(request.collectionId, 128);
    case "vault.update":
      return boundedString(request.id, 128) && validLogin(request.login);
    case "vault.createItem":
      return validItem(request.item) && optionalString(request.collectionId, 128);
    case "vault.move":
      return boundedString(request.id, 128) && boundedString(request.collectionId, 128);
    case "attachment.download":
    case "attachment.delete":
      return boundedString(request.id, 128) && boundedString(request.attachmentId, 128);
    case "attachment.add":
      return boundedString(request.id, 128) && boundedString(request.fileName, 255) && base64Data(request.data);
    case "send.list":
      return true;
    case "send.create":
      return validSend(request.send) && (request.file === undefined || base64Data(request.file));
    case "send.delete":
      return boundedString(request.id, 128);
    case "vault.export":
      return boundedString(request.masterPassword, 1_024) &&
        (request.format === "json" || request.format === "encrypted_json") &&
        optionalString(request.filePassword, 1_024);
    case "vault.import":
      return boundedString(request.text, VAULT_IMPORT_MAX_CHARACTERS) &&
        optionalString(request.password, 1_024) &&
        typeof request.confirm === "boolean";
    case "vault.updateItem":
      return boundedString(request.id, 128) && validItem(request.item);
    case "folder.save":
      return optionalString(request.id, 128) && boundedString(request.name, 1_000);
    case "authenticator.list":
      return optionalString(request.currentUrl, 8_192);
    case "authenticator.save":
      return optionalString(request.id, 128) && validAuthenticator(request.entry);
    case "authenticator.remove":
    case "authenticator.fill":
      return boundedString(request.id, 128);
    case "authenticator.import":
      return boundedString(request.text, IMPORT_MAX_CHARACTERS) && typeof request.confirm === "boolean";
    case "authenticator.export":
      return boundedString(request.masterPassword, 1_024);
    case "settings.get":
    case "site.pendingPrompt":
    case "site.passkeyChoose":
      return true;
    case "clipboard.scheduleClear":
      return request.digest === undefined || base64(request.digest, 44);
    case "settings.siteIntegration":
      return typeof request.enabled === "boolean";
    case "settings.vaultTimeout":
      return isVaultTimeoutMinutes(request.minutes);
    case "settings.browserOptions":
      return isBrowserIntegrationOptions(request.options);
    case "settings.generator":
      return boundedRecord(request.options, 2_000);
    case "settings.clipboard":
      return isClipboardClearSeconds(request.seconds);
    case "site.suggestions":
      return boundedString(request.url, 8_192);
    case "site.credential":
    case "site.totp":
      return boundedString(request.id, 128) && boundedString(request.url, 8_192);
    case "site.totpAuto":
    case "site.formItems":
      return boundedString(request.url, 8_192);
    case "site.fillItem":
      return boundedString(request.id, 128) && boundedString(request.url, 8_192);
    case "site.inspect":
      return (
        boundedString(request.url, 8_192) &&
        optionalString(request.username, 1_000) &&
        boundedString(request.password, 10_000)
      );
    case "site.generatePassword":
      return boundedString(request.url, 8_192);
    case "site.save":
      return boundedString(request.promptId, 128) && (request.login === undefined || validLogin(request.login));
    case "site.dismiss":
    case "site.hold":
      return boundedString(request.promptId, 128);
    case "site.passkeyCreate":
      return boundedString(request.id, 64) && validPasskeyCreate(request.options);
    case "site.passkeyGet":
      return boundedString(request.id, 64) && validPasskeyGet(request.options);
    case "site.passkeyAbort":
      return boundedString(request.id, 64);
    case "passkey.details":
      return boundedString(request.id, 64);
    case "passkey.unlock":
      return boundedString(request.id, 64) && boundedString(request.masterPassword, 1_024);
    case "passkey.biometric":
      return boundedString(request.id, 64) && boundedString(request.prfOutput, 64);
    case "passkey.respond":
      return (
        boundedString(request.id, 64) &&
        ["save", "use", "fallback", "cancel"].includes(request.action as string) &&
        optionalString(request.itemId, 128) &&
        optionalString(request.credentialId, 1_400) &&
        optionalString(request.masterPassword, 1_024)
      );
    default:
      return false;
  }
}

function base64(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[A-Za-z0-9+/]+=*$/.test(value);
}

// A file of at most MAX_FILE_BYTES, base64-encoded.
function base64Data(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= Math.ceil(MAX_FILE_BYTES / 3) * 4 && /^[A-Za-z0-9+/]+=*$/.test(value);
}

function validSend(send: unknown): send is SendWriteInput {
  if (!isRecord(send)) return false;
  return (
    (send.type === 0 || send.type === 1) &&
    boundedString(send.name, 1_000) &&
    optionalString(send.text, 1_000) &&
    (send.hidden === undefined || typeof send.hidden === "boolean") &&
    optionalString(send.fileName, 255) &&
    optionalString(send.password, 1_024) &&
    (send.maxAccessCount === undefined || (Number.isSafeInteger(send.maxAccessCount) && (send.maxAccessCount as number) > 0)) &&
    SEND_DELETION_DAYS.some((days) => days === send.deletionDays)
  );
}

function base64Url(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && /^[A-Za-z0-9_-]+$/.test(value);
}

// Credential IDs are at most 1,023 bytes (1,364 base64url characters).
function credentialList(value: unknown): boolean {
  return Array.isArray(value) && value.length <= 64 && value.every((id) => base64Url(id, 1_400));
}

function validPasskeyCreate(options: unknown): options is PasskeyCreateOptions {
  if (!isRecord(options)) return false;
  return (
    base64Url(options.challenge, 1_400) &&
    optionalString(options.rpId, 253) &&
    optionalString(options.rpName, 256) &&
    base64Url(options.userId, 88) && // user.id is at most 64 bytes
    optionalString(options.userName, 256) &&
    optionalString(options.userDisplayName, 256) &&
    Array.isArray(options.algorithms) && options.algorithms.length <= 32 && options.algorithms.every(Number.isSafeInteger) &&
    credentialList(options.excludeCredentials) &&
    optionalString(options.userVerification, 32)
  );
}

function validPasskeyGet(options: unknown): options is PasskeyGetOptions {
  if (!isRecord(options)) return false;
  return (
    base64Url(options.challenge, 1_400) &&
    optionalString(options.rpId, 253) &&
    credentialList(options.allowCredentials) &&
    optionalString(options.userVerification, 32) &&
    (options.conditional === undefined || typeof options.conditional === "boolean")
  );
}

function validLogin(login: unknown): login is LoginWriteInput {
  if (!isRecord(login)) return false;
  return (
    boundedString(login.name, 1_000) &&
    optionalString(login.username, 1_000) &&
    optionalString(login.password, 10_000) &&
    optionalString(login.uri, 8_192) &&
    optionalString(login.notes, 10_000) &&
    optionalString(login.totp, 2_048) &&
    optionalString(login.nickname, 200) &&
    (login.favorite === undefined || typeof login.favorite === "boolean") &&
    optionalString(login.folderId, 128)
  );
}

function validAuthenticator(entry: unknown): entry is AuthenticatorWriteInput {
  if (!isRecord(entry)) return false;
  return (
    string(entry.name, 1_000) &&
    string(entry.nickname, 200) &&
    string(entry.account, 1_000) &&
    string(entry.website, 8_192) &&
    string(entry.issuer, 200) &&
    optionalString(entry.secret, 2_048) &&
    ["SHA1", "SHA256", "SHA512"].includes(entry.algorithm as string) &&
    Number.isSafeInteger(entry.digits) && Number.isSafeInteger(entry.period)
  );
}

function validItem(item: unknown): boolean {
  if (!isRecord(item)) return false;
  const fields = (data: unknown, names: readonly string[]) =>
    data === undefined || (isRecord(data) &&
      Object.entries(data).every(([name, field]) => names.includes(name) && optionalString(field, 1_000)));
  return (
    [ItemType.SecureNote, ItemType.Card, ItemType.Identity].some((type) => type === item.type) &&
    boundedString(item.name, 1_000) &&
    optionalString(item.notes, 10_000) &&
    (item.favorite === undefined || typeof item.favorite === "boolean") &&
    optionalString(item.folderId, 128) &&
    fields(item.card, CARD_FIELDS) &&
    fields(item.identity, IDENTITY_FIELDS)
  );
}

// Messages are checked loosely (a record of bounded size); storage always goes through normalize.
function boundedRecord(value: unknown, maximum: number): boolean {
  return isRecord(value) && JSON.stringify(value).length <= maximum;
}

// A string up to `maximum` characters, empty allowed.
function string(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length <= maximum;
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function optionalString(value: unknown, maximum: number): boolean {
  return value === undefined || string(value, maximum);
}

function optionalInteger(value: unknown): boolean {
  return value === undefined || Number.isSafeInteger(value);
}
