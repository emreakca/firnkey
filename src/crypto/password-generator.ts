export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const CHARACTER_SETS = {
  uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  lowercase: "abcdefghijkmnopqrstuvwxyz",
  numbers: "23456789",
  symbols: "!@#$%^&*_-+=",
} as const;

import { EFF_WORDS } from "./eff-wordlist";

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export type UsernameOptions =
  | { kind: "word"; capitalize: boolean; includeNumber: boolean }
  | { kind: "plus"; email: string }
  | { kind: "catchall"; domain: string };

export function generatePassword(options: PasswordGeneratorOptions): string {
  if (!Number.isSafeInteger(options.length) || options.length < 4 || options.length > 128) {
    throw new Error("Password length must be between 4 and 128 characters.");
  }

  const enabledSets = [
    options.uppercase ? CHARACTER_SETS.uppercase : "",
    options.lowercase ? CHARACTER_SETS.lowercase : "",
    options.numbers ? CHARACTER_SETS.numbers : "",
    options.symbols ? CHARACTER_SETS.symbols : "",
  ].filter(Boolean);
  if (enabledSets.length === 0) {
    throw new Error("Select at least one character type.");
  }
  if (options.length < enabledSets.length) {
    throw new Error("Password length is too short for the selected character types.");
  }

  const alphabet = enabledSets.join("");
  const output = enabledSets.map((set) => set[randomIndex(set.length)]!);
  while (output.length < options.length) {
    output.push(alphabet[randomIndex(alphabet.length)]!);
  }
  for (let index = output.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [output[index], output[swapIndex]] = [output[swapIndex]!, output[index]!];
  }
  return output.join("");
}

// Like Bitwarden: EFF words, optional capitals, and one digit appended to a random word.
export function generatePassphrase(options: PassphraseOptions): string {
  if (!Number.isSafeInteger(options.words) || options.words < 3 || options.words > 20) {
    throw new Error("Use between 3 and 20 words.");
  }
  const words = Array.from({ length: options.words }, () => randomWord(options.capitalize));
  if (options.includeNumber) words[randomIndex(words.length)] += String(randomIndex(10));
  return words.join(options.separator);
}

export function generateUsername(options: UsernameOptions): string {
  if (options.kind === "word") {
    const number = options.includeNumber ? String(randomIndex(10_000)).padStart(4, "0") : "";
    return randomWord(options.capitalize) + number;
  }
  const tag = Array.from({ length: 8 }, () => CHARACTER_SETS.lowercase[randomIndex(CHARACTER_SETS.lowercase.length)]).join("");
  if (options.kind === "catchall") {
    const domain = options.domain.trim().replace(/^@/, "");
    if (!/^[^\s@]+\.[^\s@]+$/.test(domain)) throw new Error("Enter your catch-all domain, such as example.com.");
    return `${tag}@${domain}`;
  }
  const match = /^([^\s@+]+)(?:\+[^\s@]*)?@([^\s@]+\.[^\s@]+)$/.exec(options.email.trim());
  if (!match) throw new Error("Enter the email address to add a +tag to.");
  return `${match[1]}+${tag}@${match[2]}`;
}

function randomWord(capitalize: boolean): string {
  const word = EFF_WORDS[randomIndex(EFF_WORDS.length)]!;
  return capitalize ? word[0]!.toUpperCase() + word.slice(1) : word;
}

// Uniform integer in [0, maximum) by rejection sampling, so no value is more likely than another.
function randomIndex(maximum: number): number {
  const limit = 2 ** 32 - (2 ** 32 % maximum);
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0]! >= limit);
  return value[0]! % maximum;
}
