import { describe, expect, it } from "vitest";

import { normalizeServerEnvironment } from "../src/shared/environment";

describe("normalizeServerEnvironment", () => {
  it("normalizes a root HTTPS server", () => {
    expect(normalizeServerEnvironment(" https://vault.example.com/ ")).toEqual({
      baseUrl: "https://vault.example.com",
      apiUrl: "https://vault.example.com/api",
      identityUrl: "https://vault.example.com/identity",
      originPattern: "https://vault.example.com/*",
    });
  });

  it("preserves a reverse-proxy subpath", () => {
    expect(normalizeServerEnvironment("https://example.com/passwords/")).toMatchObject({
      baseUrl: "https://example.com/passwords",
      apiUrl: "https://example.com/passwords/api",
      identityUrl: "https://example.com/passwords/identity",
    });
  });

  it("allows HTTP for loopback development", () => {
    expect(normalizeServerEnvironment("http://localhost:8080").baseUrl).toBe(
      "http://localhost:8080",
    );
  });

  it("rejects insecure remote servers", () => {
    expect(() => normalizeServerEnvironment("http://vault.example.com")).toThrow(/HTTPS/);
  });

  it("rejects embedded credentials and fragments", () => {
    expect(() => normalizeServerEnvironment("https://user:pass@example.com")).toThrow(
      /credentials/,
    );
    expect(() => normalizeServerEnvironment("https://example.com/#setup")).toThrow(/fragment/);
  });
});
