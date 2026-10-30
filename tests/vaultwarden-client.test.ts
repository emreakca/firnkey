import { describe, expect, it, vi } from "vitest";

import { VaultwardenClient } from "../src/api/vaultwarden-client";
import { KdfType } from "../src/shared/kdf";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("VaultwardenClient", () => {
  it("binds the browser fetch implementation to its global context", async () => {
    const browserFetch = vi.fn(function (this: typeof globalThis) {
      if (this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return Promise.resolve(jsonResponse({ version: "2026.6.0" }));
    });
    vi.stubGlobal("fetch", browserFetch);
    try {
      const client = new VaultwardenClient();

      await expect(client.checkServer("https://vault.example.com")).resolves.toMatchObject({
        serverVersion: "2026.6.0",
      });
      expect(browserFetch.mock.contexts[0]).toBe(globalThis);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("checks the server config endpoint", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ version: "1.36.0" }));
    const client = new VaultwardenClient(fetchMock);

    await expect(client.checkServer("https://vault.example.com")).resolves.toEqual({
      baseUrl: "https://vault.example.com",
      serverVersion: "1.36.0",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://vault.example.com/api/config",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("uses the modern password-prelogin endpoint", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ Kdf: 0, KdfIterations: 600_000 }));
    const client = new VaultwardenClient(fetchMock);

    await expect(client.getPrelogin("https://vault.example.com", " USER@Example.com ")).resolves.toEqual({
      endpoint: "password",
      kdf: { type: KdfType.Pbkdf2Sha256, iterations: 600_000 },
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "https://vault.example.com/identity/accounts/prelogin/password",
    );
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe('{"email":"user@example.com"}');
  });

  it("falls back to the legacy prelogin endpoint on 404", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ message: "not found" }, 404))
      .mockResolvedValueOnce(jsonResponse({ Kdf: 1, KdfIterations: 3, KdfMemory: 64, KdfParallelism: 4 }));
    const client = new VaultwardenClient(fetchMock);

    await expect(client.getPrelogin("https://vault.example.com", "user@example.com")).resolves.toEqual({
      endpoint: "legacy",
      kdf: {
        type: KdfType.Argon2id,
        iterations: 3,
        memoryMiB: 64,
        parallelism: 4,
      },
    });
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      "https://vault.example.com/identity/accounts/prelogin",
    );
  });

  it("does not fall back for authentication or server failures", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ error: "bad" }, 500));
    const client = new VaultwardenClient(fetchMock);

    await expect(client.getPrelogin("https://vault.example.com", "user@example.com")).rejects.toThrow(
      /HTTP 500/,
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("posts a password grant and parses a legacy Vaultwarden token response", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({
        access_token: "access",
        refresh_token: "refresh",
        token_type: "Bearer",
        expires_in: 3600,
        Key: "2.a|b|c",
        PrivateKey: "2.d|e|f",
        Kdf: 0,
        KdfIterations: 600_000,
      }),
    );
    const client = new VaultwardenClient(fetchMock);

    await expect(
      client.loginWithPassword({
        baseUrl: "https://vault.example.com",
        email: "USER@example.com",
        masterPasswordHash: "hash",
        deviceIdentifier: "device-id",
      }),
    ).resolves.toEqual({
      kind: "success",
      accessToken: "access",
      refreshToken: "refresh",
      expiresIn: 3600,
      wrappedUserKey: "2.a|b|c",
      privateKey: "2.d|e|f",
      kdf: { type: KdfType.Pbkdf2Sha256, iterations: 600_000 },
    });
    const request = fetchMock.mock.calls[0]?.[1];
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://vault.example.com/identity/connect/token");
    expect(request?.body).toContain("grant_type=password");
    expect(request?.body).toContain("client_id=browser");
    expect(request?.body).not.toContain("USER%40example.com");
  });

  it("returns a two-factor challenge without treating it as a generic failure", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ TwoFactorProviders2: { 0: {}, 1: { Email: "u***@example.com" } } }, 400),
    );
    const client = new VaultwardenClient(fetchMock);

    await expect(
      client.loginWithPassword({
        baseUrl: "https://vault.example.com",
        email: "user@example.com",
        masterPasswordHash: "hash",
        deviceIdentifier: "device-id",
      }),
    ).resolves.toEqual({
      kind: "two-factor",
      providers: [0, 1],
      providerDetails: { 0: {}, 1: { Email: "u***@example.com" } },
    });
  });

  it("surfaces Vaultwarden's lower-camel-case identity error", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse(
        {
          errorModel: {
            message: "Username or password is incorrect. Try again",
            object: "error",
          },
          error: "",
          error_description: "",
        },
        400,
      ),
    );
    const client = new VaultwardenClient(fetchMock);

    await expect(
      client.loginWithPassword({
        baseUrl: "https://vault.example.com",
        email: "user@example.com",
        masterPasswordHash: "wrong-hash",
        deviceIdentifier: "device-id",
      }),
    ).rejects.toThrow("Username or password is incorrect. Try again");
  });

  it("falls back to the OAuth error description when no error model exists", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ error: "invalid_grant", error_description: "SSO sign-in is required" }, 400),
    );
    const client = new VaultwardenClient(fetchMock);

    await expect(
      client.loginWithPassword({
        baseUrl: "https://vault.example.com",
        email: "user@example.com",
        masterPasswordHash: "hash",
        deviceIdentifier: "device-id",
      }),
    ).rejects.toThrow("SSO sign-in is required");
  });
});
