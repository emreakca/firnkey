import { describe, expect, it } from "vitest";

import { isExtensionRequest } from "../src/shared/messages";
import {
  isUrlExcluded,
  isVaultTimeoutMinutes,
  normalizeBrowserIntegrationOptions,
  normalizeGeneratorOptions,
} from "../src/shared/settings";

describe("vault timeout settings", () => {
  it("accepts only supported timeout values", () => {
    expect([-2, -1, 0, 1, 5, 15, 30, 60, 120, 240, 480, 1440].every(isVaultTimeoutMinutes)).toBe(true);
    expect(isVaultTimeoutMinutes(2)).toBe(false);
    expect(isVaultTimeoutMinutes(-3)).toBe(false);
    expect(isVaultTimeoutMinutes("60")).toBe(false);
  });

  it("validates vault-timeout runtime messages", () => {
    expect(isExtensionRequest({ type: "settings.vaultTimeout", minutes: -1 })).toBe(true);
    expect(isExtensionRequest({ type: "settings.vaultTimeout", minutes: 30 })).toBe(true);
    expect(isExtensionRequest({ type: "settings.vaultTimeout", minutes: 2 })).toBe(false);
  });
});

describe("browser integration settings", () => {
  it("normalizes and matches excluded domains including subdomains", () => {
    const options = normalizeBrowserIntegrationOptions({
      askAddLogin: false,
      askUpdateLogin: true,
      excludedDomains: ["https://www.Example.com/path", "example.com", ""],
    });
    expect(options).toEqual({ askPasskeys: true, askAddLogin: false, askUpdateLogin: true, savePromptTimeoutSeconds: 10, excludedDomains: ["example.com"], authenticatorTab: false, authenticatorSmartFilter: true, fillBasicAuth: false, liveSync: true });
    expect(isUrlExcluded("https://accounts.example.com/login", options)).toBe(true);
    expect(isUrlExcluded("https://notexample.com/login", options)).toBe(false);
  });

  it("validates browser and generator preference messages", () => {
    expect(isExtensionRequest({
      type: "settings.browserOptions",
      options: { askAddLogin: true, askUpdateLogin: true, savePromptTimeoutSeconds: 10, excludedDomains: ["example.com"] },
    })).toBe(true);
    expect(isExtensionRequest({
      type: "settings.generator",
      options: { length: 22, uppercase: true, lowercase: true, numbers: true, symbols: true },
    })).toBe(true);
    expect(normalizeGeneratorOptions({ length: 2 })).toMatchObject({ length: 22 });
  });
});

it("defaults old settings to ten seconds and validates prompt timeouts", () => {
  expect(normalizeBrowserIntegrationOptions({}).savePromptTimeoutSeconds).toBe(10);
  expect(normalizeBrowserIntegrationOptions({ savePromptTimeoutSeconds: 45 }).savePromptTimeoutSeconds).toBe(45);
  for (const value of [0, -1, 301, 1.5, "10", NaN]) {
    expect(normalizeBrowserIntegrationOptions({ savePromptTimeoutSeconds: value }).savePromptTimeoutSeconds).toBe(10);
    expect(isExtensionRequest({ type: "settings.browserOptions", options: {
      askAddLogin: true, askUpdateLogin: true, excludedDomains: [], savePromptTimeoutSeconds: value,
    } })).toBe(false);
  }
});
