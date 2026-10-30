import { isRecord } from "./props";
// -2 = when the computer locks, -1 = until logout, 0 = when the browser closes, otherwise idle minutes.
// Every option also locks when the browser closes, except "until logout".
export const VAULT_TIMEOUT_OPTIONS = [-2, -1, 0, 1, 5, 15, 30, 60, 120, 240, 480, 1440] as const;
export const LOCK_ON_SYSTEM_LOCK = -2;

export type VaultTimeoutMinutes = (typeof VAULT_TIMEOUT_OPTIONS)[number];

export interface BrowserIntegrationOptions {
  askPasskeys: boolean;
  askAddLogin: boolean;
  askUpdateLogin: boolean;
  savePromptTimeoutSeconds: number;
  excludedDomains: string[];
  authenticatorTab: boolean;
  // Authenticator tab: show only the current site's codes when it has any (with "View all").
  authenticatorSmartFilter: boolean;
  // Answer a site's HTTP sign-in dialog (basic auth) with its one matching login. Opt-in.
  fillBasicAuth: boolean;
  // Keep a notifications socket open for instant sync; off falls back to the one-minute poll.
  liveSync: boolean;
  // After the user picks a login on a username-only step, fill its password on the next step.
  fillPasswordAfterUsername: boolean;
  // Offer to save a card or address typed into a website form.
  askSaveForms: boolean;
}

export interface StoredGeneratorOptions {
  type: "password" | "passphrase" | "username";
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
  usernameKind: "word" | "plus" | "catchall";
  usernameCapitalize: boolean;
  usernameIncludeNumber: boolean;
  usernameEmail: string;
  usernameDomain: string;
}

// 0 = never clear.
export const CLIPBOARD_CLEAR_OPTIONS = [0, 10, 20, 30, 60, 120, 300] as const;
export type ClipboardClearSeconds = (typeof CLIPBOARD_CLEAR_OPTIONS)[number];
const CLIPBOARD_CLEAR_KEY = "firnkey.clipboardClearSeconds";

const VAULT_TIMEOUT_KEY = "firnkey.vaultTimeoutMinutes";
const DEFAULT_VAULT_TIMEOUT: VaultTimeoutMinutes = 0;
const BROWSER_OPTIONS_KEY = "firnkey.browserIntegrationOptions";
const GENERATOR_OPTIONS_KEY = "firnkey.generatorOptions";

export const DEFAULT_BROWSER_INTEGRATION_OPTIONS: BrowserIntegrationOptions = {
  askPasskeys: true,
  askAddLogin: true,
  askUpdateLogin: true,
  savePromptTimeoutSeconds: 10,
  excludedDomains: [],
  authenticatorTab: false,
  authenticatorSmartFilter: true,
  fillBasicAuth: false,
  liveSync: true,
  fillPasswordAfterUsername: true,
  askSaveForms: true,
};

export const DEFAULT_GENERATOR_OPTIONS: StoredGeneratorOptions = {
  type: "password",
  length: 22,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  words: 6,
  separator: "-",
  capitalize: false,
  includeNumber: false,
  usernameKind: "word",
  usernameCapitalize: false,
  usernameIncludeNumber: true,
  usernameEmail: "",
  usernameDomain: "",
};

export async function readClipboardClearSeconds(): Promise<ClipboardClearSeconds> {
  const value = (await chrome.storage.local.get(CLIPBOARD_CLEAR_KEY))[CLIPBOARD_CLEAR_KEY];
  return isClipboardClearSeconds(value) ? value : 30;
}

export async function writeClipboardClearSeconds(seconds: ClipboardClearSeconds): Promise<void> {
  await chrome.storage.local.set({ [CLIPBOARD_CLEAR_KEY]: seconds });
}

export function isClipboardClearSeconds(value: unknown): value is ClipboardClearSeconds {
  return CLIPBOARD_CLEAR_OPTIONS.some((seconds) => seconds === value);
}

export async function readVaultTimeoutMinutes(): Promise<VaultTimeoutMinutes> {
  const value = await chrome.storage.local.get(VAULT_TIMEOUT_KEY);
  const minutes = value[VAULT_TIMEOUT_KEY];
  return isVaultTimeoutMinutes(minutes) ? minutes : DEFAULT_VAULT_TIMEOUT;
}

export async function writeVaultTimeoutMinutes(minutes: VaultTimeoutMinutes): Promise<void> {
  await chrome.storage.local.set({ [VAULT_TIMEOUT_KEY]: minutes });
}

export function isVaultTimeoutMinutes(value: unknown): value is VaultTimeoutMinutes {
  return VAULT_TIMEOUT_OPTIONS.some((minutes) => minutes === value);
}

export async function readBrowserIntegrationOptions(): Promise<BrowserIntegrationOptions> {
  const value = await chrome.storage.local.get(BROWSER_OPTIONS_KEY);
  return normalizeBrowserIntegrationOptions(value[BROWSER_OPTIONS_KEY]);
}

export async function writeBrowserIntegrationOptions(options: BrowserIntegrationOptions): Promise<void> {
  await chrome.storage.local.set({ [BROWSER_OPTIONS_KEY]: normalizeBrowserIntegrationOptions(options) });
}

export function normalizeBrowserIntegrationOptions(value: unknown): BrowserIntegrationOptions {
  if (!isRecord(value)) return { ...DEFAULT_BROWSER_INTEGRATION_OPTIONS };
  const excludedDomains = Array.isArray(value.excludedDomains)
    ? [...new Set(value.excludedDomains.filter((domain): domain is string => typeof domain === "string")
      .map(normalizeDomain).filter(Boolean))].slice(0, 200)
    : [];
  return {
    askPasskeys: typeof value.askPasskeys === "boolean" ? value.askPasskeys : true,
    askAddLogin: typeof value.askAddLogin === "boolean" ? value.askAddLogin : true,
    askUpdateLogin: typeof value.askUpdateLogin === "boolean" ? value.askUpdateLogin : true,
    savePromptTimeoutSeconds: isPromptTimeout(value.savePromptTimeoutSeconds) ? value.savePromptTimeoutSeconds : 10,
    excludedDomains,
    authenticatorTab: value.authenticatorTab === true,
    authenticatorSmartFilter: value.authenticatorSmartFilter !== false,
    fillBasicAuth: value.fillBasicAuth === true,
    liveSync: value.liveSync !== false,
    fillPasswordAfterUsername: value.fillPasswordAfterUsername !== false,
    askSaveForms: value.askSaveForms !== false,
  };
}


// Strict, so an out-of-range value from the popup is refused (and the field reverted) instead of reset to the default.
export function isBrowserIntegrationOptions(value: unknown): value is BrowserIntegrationOptions {
  if (!isRecord(value) || typeof value.askAddLogin !== "boolean" || typeof value.askUpdateLogin !== "boolean") return false;
  if (value.askPasskeys !== undefined && typeof value.askPasskeys !== "boolean") return false;
  if (value.authenticatorTab !== undefined && typeof value.authenticatorTab !== "boolean") return false;
  if (value.authenticatorSmartFilter !== undefined && typeof value.authenticatorSmartFilter !== "boolean") return false;
  if (value.fillBasicAuth !== undefined && typeof value.fillBasicAuth !== "boolean") return false;
  for (const flag of ["liveSync", "fillPasswordAfterUsername", "askSaveForms"]) {
    if (value[flag] !== undefined && typeof value[flag] !== "boolean") return false;
  }
  return isPromptTimeout(value.savePromptTimeoutSeconds) && Array.isArray(value.excludedDomains) && value.excludedDomains.length <= 200 &&
    value.excludedDomains.every((domain) => typeof domain === "string" && domain.length > 0 && domain.length <= 253);
}

export function isUrlExcluded(url: string, options: BrowserIntegrationOptions): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return true;
  }
  return options.excludedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

export async function readGeneratorOptions(): Promise<StoredGeneratorOptions> {
  const value = await chrome.storage.local.get(GENERATOR_OPTIONS_KEY);
  return normalizeGeneratorOptions(value[GENERATOR_OPTIONS_KEY]);
}

export async function writeGeneratorOptions(options: StoredGeneratorOptions): Promise<void> {
  await chrome.storage.local.set({ [GENERATOR_OPTIONS_KEY]: normalizeGeneratorOptions(options) });
}

export function normalizeGeneratorOptions(value: unknown): StoredGeneratorOptions {
  if (!isRecord(value)) return { ...DEFAULT_GENERATOR_OPTIONS };
  const defaults = DEFAULT_GENERATOR_OPTIONS;
  const integer = (name: "length" | "words", minimum: number, maximum: number): number => {
    const number = value[name];
    return Number.isSafeInteger(number) && Number(number) >= minimum && Number(number) <= maximum ? Number(number) : defaults[name];
  };
  const flag = (name: "uppercase" | "lowercase" | "numbers" | "symbols" | "capitalize" | "includeNumber" | "usernameCapitalize" | "usernameIncludeNumber"): boolean =>
    typeof value[name] === "boolean" ? value[name] as boolean : defaults[name];
  const text = (name: "separator" | "usernameEmail" | "usernameDomain", maximum: number): string =>
    typeof value[name] === "string" && (value[name] as string).length <= maximum ? value[name] as string : defaults[name];
  const choice = <T extends string>(name: "type" | "usernameKind", options: readonly T[]): T =>
    options.includes(value[name] as T) ? value[name] as T : defaults[name] as T;
  const result: StoredGeneratorOptions = {
    type: choice("type", ["password", "passphrase", "username"]),
    length: integer("length", 8, 64),
    uppercase: flag("uppercase"),
    lowercase: flag("lowercase"),
    numbers: flag("numbers"),
    symbols: flag("symbols"),
    words: integer("words", 3, 20),
    separator: text("separator", 4),
    capitalize: flag("capitalize"),
    includeNumber: flag("includeNumber"),
    usernameKind: choice("usernameKind", ["word", "plus", "catchall"]),
    usernameCapitalize: flag("usernameCapitalize"),
    usernameIncludeNumber: flag("usernameIncludeNumber"),
    usernameEmail: text("usernameEmail", 320),
    usernameDomain: text("usernameDomain", 253),
  };
  if (!(result.uppercase || result.lowercase || result.numbers || result.symbols)) {
    Object.assign(result, { uppercase: true, lowercase: true, numbers: true, symbols: true });
  }
  return result;
}


export function normalizeDomain(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}


function isPromptTimeout(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 300;
}
