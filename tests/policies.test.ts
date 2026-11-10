import { expect, it } from "vitest";
import { applyGeneratorPolicy, readPolicies } from "../src/vault/policies";
import { capVaultTimeout, DEFAULT_GENERATOR_OPTIONS } from "../src/shared/settings";
import { generatePassword } from "../src/crypto/password-generator";

const sync = (role: number, policies: unknown[]) => ({
  Profile: { Organizations: [{ Id: "o1", Type: role, Status: 2, Enabled: true, UsePolicies: true }] },
  Policies: policies,
});
const policy = (type: number, data: unknown = null, enabled = true) => ({ OrganizationId: "o1", Type: type, Data: data, Enabled: enabled });

it("applies organization policies, with owners and admins exempt where Bitwarden exempts them", () => {
  const all = [
    policy(2, { minLength: 30, useSpecial: true, minNumbers: 3, overridePasswordType: "password" }),
    policy(5), policy(6), policy(14), policy(15), policy(16, { uriMatchDetection: 1 }), policy(1, { minLength: 20 }),
  ];
  expect(readPolicies(sync(2, all) as never)).toMatchObject({
    personalOwnership: true, disableSend: true, disablePin: true, restrictedTypes: [3], uriMatch: 1,
    generator: { type: "password", minLength: 30, symbols: true, minNumbers: 3 },
  });
  const owner = readPolicies(sync(0, all) as never);
  expect(owner).toMatchObject({ personalOwnership: false, disableSend: false, disablePin: true, restrictedTypes: [3] });
  expect(owner.uriMatch).toBeUndefined();
  expect(readPolicies(sync(2, [policy(5, null, false)]) as never).personalOwnership).toBe(false);
  expect(readPolicies({ ...sync(2, [policy(5)]), Profile: { Organizations: [{ Id: "o1", Type: 2, Status: 0 }] } } as never).personalOwnership).toBe(false);
});

it("raises generator settings to the policy and keeps its digit minimum", () => {
  const policies = readPolicies(sync(2, [policy(2, { minLength: 30, minNumbers: 4, useUpper: true, overridePasswordType: "passphrase", minNumberWords: 7 })]) as never);
  const options = applyGeneratorPolicy({ ...DEFAULT_GENERATOR_OPTIONS, length: 12, uppercase: false, numbers: false, words: 4 }, policies.generator);
  expect(options).toMatchObject({ type: "passphrase", length: 30, uppercase: true, numbers: true, words: 7, minNumbers: 4 });
  expect(applyGeneratorPolicy({ ...DEFAULT_GENERATOR_OPTIONS, type: "username" }, policies.generator).type).toBe("username");
  for (let attempt = 0; attempt < 20; attempt += 1) {
    expect(generatePassword({ ...options, type: "password" } as never).replace(/\D/g, "").length).toBeGreaterThanOrEqual(4);
  }
});

it("reads the vault-timeout policy (owners exempt) and caps the chosen timeout to it", () => {
  const timeout = [policy(9, { minutes: 45, action: "logOut" })];
  expect(readPolicies(sync(1, timeout) as never)).toMatchObject({ maxVaultTimeout: 45, vaultTimeoutAction: "logOut" });
  expect(readPolicies(sync(0, timeout) as never).maxVaultTimeout).toBeUndefined();
  expect(capVaultTimeout(-1, 45)).toBe(30);
  expect(capVaultTimeout(60, 45)).toBe(30);
  expect(capVaultTimeout(15, 45)).toBe(15);
  expect(capVaultTimeout(-2, 45)).toBe(-2);
  expect(capVaultTimeout(-1)).toBe(-1);
});

