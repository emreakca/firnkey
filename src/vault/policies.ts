import type { SyncResponse } from "../api/models";
import { arrayProp, asRecord, isRecord, numberProp, prop, stringProp } from "../shared/props";
import type { StoredGeneratorOptions } from "../shared/settings";

// Bitwarden policy types that Firnkey enforces. Two-step login, master-password rules and the like
// are enforced by the server.
const PASSWORD_GENERATOR = 2;
const PERSONAL_OWNERSHIP = 5;
const DISABLE_SEND = 6;
const REMOVE_UNLOCK_WITH_PIN = 14;
const RESTRICTED_ITEM_TYPES = 15;
const URI_MATCH_DEFAULTS = 16;
const MAXIMUM_VAULT_TIMEOUT = 9;
// Owners and admins are exempt from these, like in Bitwarden's apps.
const ADMIN_EXEMPT = new Set([PERSONAL_OWNERSHIP, DISABLE_SEND, URI_MATCH_DEFAULTS]);
// Only owners are exempt from these.
const OWNER_EXEMPT = new Set([MAXIMUM_VAULT_TIMEOUT]);

export interface GeneratorPolicy {
  type?: "password" | "passphrase";
  minLength: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  minNumbers: number;
  minSymbols: number;
  minWords: number;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface VaultPolicies {
  generator?: GeneratorPolicy;
  // New items must belong to an organization.
  personalOwnership: boolean;
  disableSend: boolean;
  disablePin: boolean;
  // Item types that cannot be created and are hidden (Bitwarden's "Remove card item type").
  restrictedTypes: number[];
  // The match rule for websites without one.
  uriMatch?: number;
  // The longest idle time before the vault locks, in minutes, and whether it logs out instead.
  maxVaultTimeout?: number;
  vaultTimeoutAction?: "lock" | "logOut";
}

export const NO_POLICIES: VaultPolicies = { personalOwnership: false, disableSend: false, disablePin: false, restrictedTypes: [] };

// The policies that apply to this user, merged over all their organizations.
export function readPolicies(sync: SyncResponse | null): VaultPolicies {
  if (!sync) return { ...NO_POLICIES };
  const profile = asRecord(prop(sync as Record<string, unknown>, "Profile"));
  const memberships = new Map<string, Record<string, unknown>>();
  for (const entry of [...arrayProp(profile ?? {}, "Organizations"), ...arrayProp(profile ?? {}, "OrganizationsNew")]) {
    const organization = asRecord(entry);
    const id = organization && stringProp(organization, "Id");
    if (id) memberships.set(id, organization);
  }
  const result: VaultPolicies = { ...NO_POLICIES, restrictedTypes: [] };
  for (const entry of arrayProp(sync as Record<string, unknown>, "Policies")) {
    const policy = asRecord(entry);
    if (!policy || prop(policy, "Enabled") !== true) continue;
    const type = numberProp(policy, "Type");
    if (type === undefined || !applies(type, memberships.get(stringProp(policy, "OrganizationId") ?? ""))) continue;
    const data = prop(policy, "Data");
    if (type === PASSWORD_GENERATOR && isRecord(data)) result.generator = mergeGenerator(result.generator, data);
    if (type === PERSONAL_OWNERSHIP) result.personalOwnership = true;
    if (type === DISABLE_SEND) result.disableSend = true;
    if (type === REMOVE_UNLOCK_WITH_PIN) result.disablePin = true;
    if (type === RESTRICTED_ITEM_TYPES) result.restrictedTypes = [...new Set([...result.restrictedTypes, ...restrictedTypes(data)])];
    if (type === URI_MATCH_DEFAULTS && isRecord(data)) {
      const match = numberProp(data, "UriMatchDetection");
      if (match !== undefined && Number.isInteger(match) && match >= 0 && match <= 5) result.uriMatch = match;
    }
    if (type === MAXIMUM_VAULT_TIMEOUT && isRecord(data)) {
      // Several organizations: the shortest time wins, and logging out wins over locking.
      const minutes = numberProp(data, "Minutes");
      if (minutes !== undefined && minutes > 0) result.maxVaultTimeout = Math.min(result.maxVaultTimeout ?? minutes, minutes);
      if (prop(data, "Action") === "logOut") result.vaultTimeoutAction = "logOut";
      else result.vaultTimeoutAction ??= "lock";
    }
  }
  return result;
}

// Accepted or confirmed members of an enabled organization that uses policies. Without a membership
// record the policy applies, like in Bitwarden's apps.
function applies(type: number, membership: Record<string, unknown> | undefined): boolean {
  if (!membership) return true;
  const status = numberProp(membership, "Status");
  const role = numberProp(membership, "Type");
  if (prop(membership, "Enabled") === false || prop(membership, "UsePolicies") === false) return false;
  if (status !== undefined && status !== 1 && status !== 2) return false;
  return !(ADMIN_EXEMPT.has(type) && (role === 0 || role === 1)) && !(OWNER_EXEMPT.has(type) && role === 0);
}

// Bitwarden stores the restricted types as a list; without one the policy restricts cards.
function restrictedTypes(data: unknown): number[] {
  const list = Array.isArray(data) ? data : isRecord(data) ? arrayProp(data, "RestrictedTypes") : [];
  const types = list.filter((type): type is number => Number.isInteger(type));
  return types.length > 0 ? types : [3];
}

function mergeGenerator(current: GeneratorPolicy | undefined, data: Record<string, unknown>): GeneratorPolicy {
  const number = (name: string) => Math.max(0, Math.min(128, Math.trunc(numberProp(data, name) ?? 0)));
  const flag = (name: string) => prop(data, name) === true;
  const forced = stringProp(data, "OverridePasswordType") ?? stringProp(data, "DefaultType");
  const type = current?.type === "passphrase" || forced === "passphrase" ? "passphrase" : current?.type ?? (forced === "password" ? "password" : undefined);
  return {
    ...(type ? { type } : {}),
    minLength: Math.max(current?.minLength ?? 0, number("MinLength")),
    uppercase: (current?.uppercase ?? false) || flag("UseUpper"),
    lowercase: (current?.lowercase ?? false) || flag("UseLower"),
    numbers: (current?.numbers ?? false) || flag("UseNumbers"),
    symbols: (current?.symbols ?? false) || flag("UseSpecial"),
    minNumbers: Math.max(current?.minNumbers ?? 0, number("MinNumbers")),
    minSymbols: Math.max(current?.minSymbols ?? 0, number("MinSpecial")),
    minWords: Math.max(current?.minWords ?? 0, number("MinNumberWords")),
    capitalize: (current?.capitalize ?? false) || flag("Capitalize"),
    includeNumber: (current?.includeNumber ?? false) || flag("IncludeNumber"),
  };
}

// Generator settings raised to what the policy requires. The username generator is not affected.
export function applyGeneratorPolicy(
  options: StoredGeneratorOptions,
  policy: GeneratorPolicy | undefined,
): StoredGeneratorOptions & { minNumbers?: number; minSymbols?: number } {
  if (!policy) return options;
  const numbers = options.numbers || policy.numbers || policy.minNumbers > 0;
  const symbols = options.symbols || policy.symbols || policy.minSymbols > 0;
  const required = (numbers ? Math.max(1, policy.minNumbers) : 0) + (symbols ? Math.max(1, policy.minSymbols) : 0) + 2;
  return {
    ...options,
    type: options.type === "username" || !policy.type ? options.type : policy.type,
    length: Math.min(64, Math.max(options.length, policy.minLength, required)),
    uppercase: options.uppercase || policy.uppercase,
    lowercase: options.lowercase || policy.lowercase,
    numbers,
    symbols,
    words: Math.min(20, Math.max(options.words, policy.minWords)),
    capitalize: options.capitalize || policy.capitalize,
    includeNumber: options.includeNumber || policy.includeNumber,
    ...(policy.minNumbers > 1 ? { minNumbers: policy.minNumbers } : {}),
    ...(policy.minSymbols > 1 ? { minSymbols: policy.minSymbols } : {}),
  };
}
