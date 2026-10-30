import { describe, expect, it } from "vitest";

import {
  decryptVault,
  getVaultItemDetail,
  listVaultItems,
  matchesCurrentUrl,
} from "../src/vault/decrypt-vault";
import type { VaultItem } from "../src/vault/models";

const fixture = {
  Profile: { Email: "alice@example.com", Organizations: [] },
  Ciphers: [
    {
      Id: "cipher-1",
      Type: 1,
      Name: "2.AAAAAAAAAAAAAAAAAAAAAQ==|iXGU5ND43rhNlkktTPw2UA==|BKN5WUmd5OLWCUpsALk3lNi3V/ss1zNEQS6Moc2Z+r4=",
      Notes: "2.AAAAAAAAAAAAAAAAAAAABQ==|LWiX7ms1IQ2BYqsJDf3uhw==|lgRSJvyBO81NglgW1I2uMqI3/7C+gIuD4+ZBsYvyG2k=",
      Favorite: true,
      Login: {
        Username: "2.AAAAAAAAAAAAAAAAAAAAAg==|HYultroEonFpkWyEawcxsVFSKYchJLURpiv5Yv/4IZE=|WcRzjp23xjhqgWcVK39dOIk2Z07PZJeGnskdLBhQN48=",
        Password: "2.AAAAAAAAAAAAAAAAAAAAAw==|KjQUck/390FP9xglILlN7A==|S7BkH8p8e189edtLi6YrYQ+/34udtvOCkXb3ClyjnZ4=",
        Uris: [
          {
            Uri: "2.AAAAAAAAAAAAAAAAAAAABA==|c7yovhktS+B9c3iFAYE5F6EPp07S65Ye50z7fgiqKqk=|OMMRHp+tXXs+7bWa5lKNu7v4OlphCrJ/HVbB3N0UF3U=",
          },
        ],
      },
    },
  ],
};

describe("vault decryption and matching", () => {
  it("decrypts only the minimal login model and ranks page matches", async () => {
    const { items, failures } = await decryptVault(fixture, new Uint8Array([...Array(64).keys()]));

    expect(failures).toBe(0);
    expect(items).toEqual([
      {
        id: "cipher-1",
        type: 1,
        name: "Example",
        username: "alice@example.com",
        password: "hunter2",
        notes: "notes",
        favorite: true,
        reprompt: false,
        editable: true,
        uris: [{ uri: "https://login.example.com" }],
      },
    ]);
    expect(matchesCurrentUrl(items[0]!, "https://login.example.com/sign-in")).toBe(true);
    expect(matchesCurrentUrl(items[0]!, "https://evil-example.com/")).toBe(false);
    expect(listVaultItems(items, "", "https://login.example.com")[0]).toMatchObject({
      matched: true,
      editable: true,
    });
  });

  it("accepts 2026 lower-camel-case sync responses", async () => {
    const camelFixture = lowerCamelKeys(structuredClone(fixture));
    const { items, failures } = await decryptVault(
      camelFixture,
      new Uint8Array([...Array(64).keys()]),
    );

    expect(failures).toBe(0);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: "cipher-1", name: "Example", password: "hunter2" });
  });

  it("redacts reprompt-protected fields until the background authorizes access", async () => {
    const protectedFixture = structuredClone(fixture);
    Object.assign(protectedFixture.Ciphers[0]!, { Reprompt: 1 });
    const { items } = await decryptVault(
      protectedFixture,
      new Uint8Array([...Array(64).keys()]),
    );

    expect(getVaultItemDetail(items[0]!)).toMatchObject({
      password: "",
      hasTotp: false,
      protected: true,
      requiresReprompt: true,
    });
    expect(getVaultItemDetail(items[0]!, undefined, true)).toMatchObject({
      password: "hunter2",
      protected: false,
    });
    const withKey = { ...items[0]!, totp: "JBSWY3DPEHPK3PXP" };
    expect(getVaultItemDetail(withKey).totp).toBeUndefined();
    expect(getVaultItemDetail(withKey, undefined, true).totp).toBe("JBSWY3DPEHPK3PXP");
  });

  it("shows passkeys to the popup without their private keys", () => {
    const passkey = { credentialId: "id", keyValue: "secret-key", rpId: "example.com", userName: "alice", counter: 0, discoverable: true, creationDate: "2026-01-02T00:00:00Z" };
    const item: VaultItem = { ...loginForUri("https://example.com"), passkeys: [passkey] };
    const detail = getVaultItemDetail(item);
    expect(detail.passkeys).toEqual([{ rpId: "example.com", userName: "alice", creationDate: "2026-01-02T00:00:00Z" }]);
    expect(JSON.stringify(detail)).not.toContain("secret-key");
    expect(getVaultItemDetail({ ...item, reprompt: true }).passkeys).toBeUndefined();
  });

  it("isolates damaged ciphers instead of exposing partial data", async () => {
    const damaged = structuredClone(fixture);
    damaged.Ciphers[0]!.Name = damaged.Ciphers[0]!.Name.replace("BKN5", "AKN5");

    const result = await decryptVault(damaged, new Uint8Array([...Array(64).keys()]));
    expect(result.items).toEqual([]);
    expect(result.failures).toBe(1);
  });

  it("never lets a child-domain credential match its parent domain", () => {
    expect(
      matchesCurrentUrl(loginForUri("https://attacker.targetbank.com"), "https://targetbank.com/login"),
    ).toBe(false);
    expect(
      matchesCurrentUrl(loginForUri("https://targetbank.com"), "https://login.targetbank.com/login"),
    ).toBe(true);
  });

  it("implements Host matching without broadening to subdomains or other ports", () => {
    const item = loginForUri("https://login.example.com:8443/account", 1);

    expect(matchesCurrentUrl(item, "https://login.example.com:8443/sign-in")).toBe(true);
    expect(matchesCurrentUrl(item, "https://sub.login.example.com:8443/sign-in")).toBe(false);
    expect(matchesCurrentUrl(item, "https://login.example.com/sign-in")).toBe(false);
  });

  it("implements Starts With and Exact matching independently", () => {
    const startsWith = loginForUri("https://example.com/account", 2);
    const exact = loginForUri("https://example.com/account", 3);

    expect(matchesCurrentUrl(startsWith, "https://example.com/account/login")).toBe(true);
    expect(matchesCurrentUrl(startsWith, "https://example.com/other")).toBe(false);
    expect(matchesCurrentUrl(exact, "https://example.com/account")).toBe(true);
    expect(matchesCurrentUrl(exact, "https://example.com/account/login")).toBe(false);
  });

  it("supports case-insensitive regular-expression matching and rejects invalid patterns", () => {
    expect(
      matchesCurrentUrl(
        loginForUri("^https://[a-z]+\\.example\\.com/login", 4),
        "https://ACCOUNTS.example.com/login",
      ),
    ).toBe(true);
    expect(matchesCurrentUrl(loginForUri("[", 4), "https://example.com/")).toBe(false);
  });

  it("fails closed for Never and unknown URI match strategies", () => {
    expect(matchesCurrentUrl(loginForUri("https://example.com", 5), "https://example.com/")).toBe(false);
    expect(matchesCurrentUrl(loginForUri("https://example.com", 99), "https://example.com/")).toBe(false);
  });
});

function loginForUri(uri: string, match?: number): VaultItem {
  return {
    id: "uri-match-test",
    type: 1,
    name: "URI match test",
    username: "alice@example.com",
    password: "secret",
    favorite: false,
    reprompt: false,
    editable: true,
    uris: [{ uri, ...(match === undefined ? {} : { match }) }],
  };
}

function lowerCamelKeys(value: unknown): any {
  if (Array.isArray(value)) return value.map(lowerCamelKeys);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key[0]!.toLowerCase() + key.slice(1),
      lowerCamelKeys(child),
    ]),
  );
}
