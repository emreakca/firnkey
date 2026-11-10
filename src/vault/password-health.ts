import { ItemType, type VaultItem } from "./models";

export interface HealthEntry {
  id: string;
  name: string;
  username: string;
  uri?: string;
  // Exposed: how often the password appears in known breaches. Reused: how many logins share it.
  count?: number;
}

export interface HealthReport {
  weak: HealthEntry[];
  reused: HealthEntry[];
  exposed: HealthEntry[];
  // Logins whose password was checked against breaches (all of them once a check finished).
  breachChecked: number;
  logins: number;
}

// Logins with a password the user may see. Organization logins with hidden passwords have none here.
export function passwordLogins(items: VaultItem[]): VaultItem[] {
  return items.filter((item) => item.type === ItemType.Login && item.password);
}

// `breaches` maps a login's id to its breach count, for the logins checked so far.
export function healthReport(items: VaultItem[], breaches: Map<string, number>): HealthReport {
  const logins = passwordLogins(items);
  const entry = (item: VaultItem, count?: number): HealthEntry => ({
    id: item.id,
    name: item.name,
    username: item.username,
    ...(item.uris[0] ? { uri: item.uris[0].uri } : {}),
    ...(count === undefined ? {} : { count }),
  });
  const byPassword = new Map<string, VaultItem[]>();
  for (const item of logins) byPassword.set(item.password, [...(byPassword.get(item.password) ?? []), item]);
  return {
    weak: logins.filter((item) => isWeakPassword(item.password, [item.username, item.name, ...item.uris.map(({ uri }) => uri)])).map((item) => entry(item)),
    reused: [...byPassword.values()].filter((group) => group.length > 1).flatMap((group) => group.map((item) => entry(item, group.length))),
    exposed: logins.filter((item) => (breaches.get(item.id) ?? 0) > 0).map((item) => entry(item, breaches.get(item.id)))
      .sort((left, right) => (right.count ?? 0) - (left.count ?? 0)),
    breachChecked: logins.filter((item) => breaches.has(item.id)).length,
    logins: logins.length,
  };
}

// ponytail: a length-and-variety estimate, not zxcvbn (about 800 KB). It flags short, single-class,
// repetitive or name-based passwords; swap in a dictionary estimator if users need finer scores.
export function isWeakPassword(password: string, context: string[] = []): boolean {
  if (password.length < 8) return true;
  const lower = password.toLowerCase();
  // Built from the username, the item's name or its website ("anna1990", "github2024").
  for (const value of context) {
    for (const word of value.toLowerCase().split(/[^a-z0-9]+/)) {
      if (word.length >= 4 && !["http", "https", "www"].includes(word) && lower.includes(word)) return true;
    }
  }
  const used = ([[/[a-z]/, 26], [/[A-Z]/, 26], [/\d/, 10], [/[^a-zA-Z\d]/, 33]] as const).filter(([pattern]) => pattern.test(password));
  const pool = used.reduce((sum, [, size]) => sum + size, 0);
  // Repeats and runs ("aaaa", "1234", "abcd") add almost nothing, so count them once.
  let effective = 1;
  for (let index = 1; index < password.length; index += 1) {
    const step = password.charCodeAt(index) - password.charCodeAt(index - 1);
    const run = index >= 2 && step === password.charCodeAt(index - 1) - password.charCodeAt(index - 2) && Math.abs(step) <= 1;
    if (step !== 0 && !run) effective += 1;
  }
  const bits = effective * Math.log2(pool);
  // Few character types need more length ("password123" is weak, a long passphrase is not).
  return bits < 50 || (used.length === 1 && password.length < 16) || (used.length === 2 && password.length < 12);
}
