import { describe, expect, it } from "vitest";

import { EFF_WORDS } from "../src/crypto/eff-wordlist";
import { generatePassphrase, generatePassword, generateUsername } from "../src/crypto/password-generator";

describe("password generator", () => {
  it("uses every selected character class", () => {
    const password = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });

    expect(password).toHaveLength(32);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*_.+=-]/);
  });

  it("rejects an empty character selection", () => {
    expect(() =>
      generatePassword({
        length: 20,
        uppercase: false,
        lowercase: false,
        numbers: false,
        symbols: false,
      }),
    ).toThrow("Select at least one character type");
  });
});

describe("passphrase and username generators", () => {
  it("builds passphrases from the EFF list", () => {
    const phrase = generatePassphrase({ words: 6, separator: "-", capitalize: true, includeNumber: true });
    const words = phrase.split("-").filter(Boolean);
    expect(words.length).toBeGreaterThanOrEqual(6); // A few EFF words contain a hyphen themselves.
    expect(phrase).toMatch(/\d/);
    expect(words.every((word) => /^[A-Z]/.test(word) || /^[a-z]/.test(word))).toBe(true);
    expect(EFF_WORDS).toHaveLength(7776);
    expect(() => generatePassphrase({ words: 2, separator: " ", capitalize: false, includeNumber: false })).toThrow();
  });

  it("generates the three username styles", () => {
    expect(generateUsername({ kind: "word", capitalize: false, includeNumber: true })).toMatch(/^[a-z-]+\d{4}$/);
    expect(generateUsername({ kind: "plus", email: "me+old@example.com" })).toMatch(/^me\+[a-z]{8}@example\.com$/);
    expect(generateUsername({ kind: "catchall", domain: "@example.com" })).toMatch(/^[a-z]{8}@example\.com$/);
    expect(() => generateUsername({ kind: "plus", email: "not-an-email" })).toThrow();
    expect(() => generateUsername({ kind: "catchall", domain: "nodot" })).toThrow();
  });
});
