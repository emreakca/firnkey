import { describe, expect, it } from "vitest";

import { isWeakerKdf, KdfType, parseKdfConfig } from "../src/shared/kdf";

describe("parseKdfConfig", () => {
  it("parses a PascalCase PBKDF2 response", () => {
    expect(parseKdfConfig({ Kdf: 0, KdfIterations: 600_000 })).toEqual({
      type: KdfType.Pbkdf2Sha256,
      iterations: 600_000,
    });
  });

  it("parses a camelCase Argon2id response", () => {
    expect(
      parseKdfConfig({
        kdf: 1,
        kdfIterations: 3,
        kdfMemory: 64,
        kdfParallelism: 4,
      }),
    ).toEqual({
      type: KdfType.Argon2id,
      iterations: 3,
      memoryMiB: 64,
      parallelism: 4,
    });
  });

  it("rejects downgrade parameters", () => {
    expect(() => parseKdfConfig({ Kdf: 0, KdfIterations: 1_000 })).toThrow(/downgrade/);
    expect(() =>
      parseKdfConfig({ Kdf: 1, KdfIterations: 1, KdfMemory: 8, KdfParallelism: 1 }),
    ).toThrow(/downgrade/);
  });

  it("rejects resource-exhaustion parameters", () => {
    expect(() => parseKdfConfig({ Kdf: 0, KdfIterations: 20_000_000 })).toThrow(
      /safety limit/,
    );
    expect(() =>
      parseKdfConfig({ Kdf: 1, KdfIterations: 3, KdfMemory: 2048, KdfParallelism: 4 }),
    ).toThrow(/safety limit/);
  });
});

describe("KDF downgrade protection", () => {
  it("rejects PBKDF2 below 100,000 iterations", () => {
    expect(() => parseKdfConfig({ Kdf: 0, KdfIterations: 99_999 })).toThrow(/downgrade/);
    expect(parseKdfConfig({ Kdf: 0, KdfIterations: 100_000 })).toMatchObject({ iterations: 100_000 });
  });

  it("detects weaker settings than an account used before", () => {
    const pbkdf2 = (iterations: number) => ({ type: KdfType.Pbkdf2Sha256 as const, iterations });
    const argon = (iterations: number, memoryMiB: number) =>
      ({ type: KdfType.Argon2id as const, iterations, memoryMiB, parallelism: 4 });
    expect(isWeakerKdf(pbkdf2(100_000), pbkdf2(600_000))).toBe(true);
    expect(isWeakerKdf(pbkdf2(600_000), pbkdf2(600_000))).toBe(false);
    expect(isWeakerKdf(argon(3, 64), pbkdf2(600_000))).toBe(false);
    expect(isWeakerKdf(pbkdf2(2_000_000), argon(3, 64))).toBe(true);
    expect(isWeakerKdf(argon(3, 32), argon(3, 64))).toBe(true);
    expect(isWeakerKdf(argon(2, 64), argon(3, 64))).toBe(true);
    expect(isWeakerKdf(argon(4, 128), argon(3, 64))).toBe(false);
  });
});
