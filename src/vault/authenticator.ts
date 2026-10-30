import { cleanLabel, otpauthUri, parseTotpKey, type TotpAlgorithm, type TotpParameters } from "../crypto/totp";
import { matchesCurrentUrl } from "./decrypt-vault";
import { NICKNAME_FIELD } from "./encrypt-login";
import { ItemType, type VaultItem } from "./models";

// One Authenticator tab entry: a login's TOTP settings without its secret.
export interface AuthenticatorEntry {
  id: string;
  name: string;
  nickname?: string;
  account: string;
  uri?: string;
  issuer: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  steam: boolean;
  matched: boolean;
  requiresReprompt: boolean;
  editable: boolean;
}

// What the popup sends to add or edit an entry. A blank secret keeps the saved one.
export interface AuthenticatorWriteInput {
  name: string;
  nickname: string;
  account: string;
  website: string;
  issuer: string;
  secret?: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

export interface ImportRow {
  line: number;
  label: string;
  status: "new" | "duplicate" | "invalid";
  reason?: string;
}

export const IMPORT_MAX_ENTRIES = 500;
export const IMPORT_MAX_CHARACTERS = 262_144;

export function authenticatorEntries(items: VaultItem[], currentUrl?: string): AuthenticatorEntry[] {
  return items.flatMap((item) => {
    if (item.type !== ItemType.Login || !item.totp) return [];
    let parameters: TotpParameters;
    try {
      parameters = parseTotpKey(item.totp);
    } catch {
      return []; // A key that cannot produce codes has nothing to show here.
    }
    const nickname = item.fields?.find((field) => field.name === NICKNAME_FIELD)?.value;
    return [{
      id: item.id,
      name: item.name,
      account: item.username || parameters.account,
      issuer: parameters.steam ? "Steam" : parameters.issuer,
      algorithm: parameters.algorithm,
      digits: parameters.digits,
      period: parameters.period,
      steam: parameters.steam,
      matched: currentUrl ? matchesCurrentUrl(item, currentUrl) : false,
      requiresReprompt: item.reprompt,
      editable: item.editable,
      ...(nickname ? { nickname } : {}),
      ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
    }];
  });
}

// Builds the key to store from the editor's fields. `saved` is the current key when editing.
export function authenticatorKey(input: AuthenticatorWriteInput, saved?: string): TotpParameters {
  const typed = input.secret?.trim();
  if (!typed && !saved) throw new Error("Enter the authenticator key: a Base32 secret or an otpauth://totp/ link.");
  // The popup copies a pasted link's settings into the fields first, so the fields always win.
  const base = parseTotpKey(typed || saved!);
  if (![6, 7, 8, 9, 10].includes(input.digits)) throw new Error("Choose 6 to 10 digits.");
  if (!Number.isSafeInteger(input.period) || input.period < 5 || input.period > 300) throw new Error("Choose a period from 5 to 300 seconds.");
  const issuer = cleanLabel(input.issuer);
  const steam = issuer.toLowerCase() === "steam" || base.steam;
  return { ...base, issuer, account: cleanLabel(input.account), algorithm: input.algorithm, digits: steam ? 5 : input.digits, period: input.period, steam };
}

// Checks newline-delimited otpauth links. `known` holds the secrets already in the vault.
export function previewImport(text: string, known: Set<string>): { rows: ImportRow[]; entries: TotpParameters[] } {
  if (text.length > IMPORT_MAX_CHARACTERS) throw new Error("The import is too large (256 KB at most).");
  const lines = text.split(/\r?\n/).map((value, index) => ({ value: value.trim(), line: index + 1 })).filter(({ value }) => value);
  if (lines.length > IMPORT_MAX_ENTRIES) throw new Error(`Import at most ${IMPORT_MAX_ENTRIES} entries at a time.`);
  const seen = new Set(known);
  const rows: ImportRow[] = [];
  const entries: TotpParameters[] = [];
  for (const { value, line } of lines) {
    if (!/^otpauth:\/\//i.test(value)) {
      rows.push({ line, label: `Line ${line}`, status: "invalid", reason: "Not an otpauth:// link." });
      continue;
    }
    let parameters: TotpParameters;
    try {
      parameters = parseTotpKey(value);
    } catch (error) {
      rows.push({ line, label: `Line ${line}`, status: "invalid", reason: error instanceof Error ? error.message : "Invalid link." });
      continue;
    }
    const label = [parameters.issuer, parameters.account].filter(Boolean).join(" · ") || `Line ${line}`;
    if (seen.has(parameters.secret)) {
      rows.push({ line, label, status: "duplicate", reason: "This key is already in your vault or earlier in the list." });
      continue;
    }
    seen.add(parameters.secret);
    rows.push({ line, label, status: "new" });
    entries.push(parameters);
  }
  return { rows, entries };
}

// The normalized secrets of every authenticator key in the vault, for duplicate detection.
export function knownSecrets(items: VaultItem[]): Set<string> {
  const secrets = new Set<string>();
  for (const item of items) {
    if (!item.totp) continue;
    try {
      secrets.add(parseTotpKey(item.totp).secret);
    } catch {
      // Unusable keys cannot be duplicates.
    }
  }
  return secrets;
}

// One otpauth:// link per line. Bare Base32 keys get the login's name and username as their label.
export function exportAuthenticator(items: VaultItem[]): string {
  return authenticatorEntries(items).map((entry) => {
    const item = items.find((candidate) => candidate.id === entry.id)!;
    const parameters = parseTotpKey(item.totp!);
    return otpauthUri({ ...parameters, issuer: parameters.issuer || item.name, account: parameters.account || item.username });
  }).join("\n");
}
