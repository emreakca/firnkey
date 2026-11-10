import { isRecord, prop } from "./props";

export const enum KdfType {
  Pbkdf2Sha256 = 0,
  Argon2id = 1,
}

export interface Pbkdf2KdfConfig {
  type: KdfType.Pbkdf2Sha256;
  iterations: number;
}

export interface Argon2idKdfConfig {
  type: KdfType.Argon2id;
  iterations: number;
  memoryMiB: number;
  parallelism: number;
}

export type KdfConfig = Pbkdf2KdfConfig | Argon2idKdfConfig;

// Bitwarden's default since 2018 (600,000 since 2023). Lower values are offline-crackable.
const PBKDF2_MIN_ITERATIONS = 100_000;
const PBKDF2_MAX_ITERATIONS = 2_000_000;
const ARGON2_MIN_ITERATIONS = 2;
const ARGON2_MAX_ITERATIONS = 10;
const ARGON2_MIN_MEMORY_MIB = 16;
const ARGON2_MAX_MEMORY_MIB = 1_024;
const ARGON2_MIN_PARALLELISM = 1;
const ARGON2_MAX_PARALLELISM = 16;


function integer(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`Server returned an invalid ${name}.`);
  }
  return value as number;
}

function inRange(value: number, min: number, max: number, name: string): void {
  if (value < min) {
    throw new Error(
      `${name} is below the safe minimum (${value} < ${min}); possible prelogin downgrade attack.`,
    );
  }
  if (value > max) {
    throw new Error(`${name} exceeds the client safety limit (${value} > ${max}).`);
  }
}

export function parseKdfConfig(input: unknown): KdfConfig {
  if (!isRecord(input)) throw new Error("Server returned an invalid prelogin response.");
  const response = input;
  const type = integer(prop(response, "Kdf"), "KDF type");
  const iterations = integer(
    prop(response, "KdfIterations"),
    "KDF iteration count",
  );

  if (type === KdfType.Pbkdf2Sha256) {
    inRange(iterations, PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS, "PBKDF2 iterations");
    return { type, iterations };
  }

  if (type === KdfType.Argon2id) {
    const memoryMiB = integer(prop(response, "KdfMemory"), "Argon2 memory");
    const parallelism = integer(
      prop(response, "KdfParallelism"),
      "Argon2 parallelism",
    );
    inRange(iterations, ARGON2_MIN_ITERATIONS, ARGON2_MAX_ITERATIONS, "Argon2 iterations");
    inRange(memoryMiB, ARGON2_MIN_MEMORY_MIB, ARGON2_MAX_MEMORY_MIB, "Argon2 memory");
    inRange(
      parallelism,
      ARGON2_MIN_PARALLELISM,
      ARGON2_MAX_PARALLELISM,
      "Argon2 parallelism",
    );
    return { type, iterations, memoryMiB, parallelism };
  }

  throw new Error(`Server selected unsupported KDF type ${type}.`);
}

// True when `next` is cheaper to brute-force than a KDF this account already used.
export function isWeakerKdf(next: KdfConfig, pinned: KdfConfig): boolean {
  if (pinned.type === KdfType.Argon2id) {
    return next.type !== KdfType.Argon2id ||
      next.iterations < pinned.iterations ||
      next.memoryMiB < pinned.memoryMiB;
  }
  return next.type === KdfType.Pbkdf2Sha256 && next.iterations < pinned.iterations;
}
