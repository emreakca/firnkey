import { describe, expect, it } from "vitest";

import { generateTotp } from "../src/crypto/totp";

describe("TOTP", () => {
  it("matches RFC 6238 SHA-1 vectors", async () => {
    const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    await expect(
      generateTotp(`otpauth://totp/Test?secret=${seed}&digits=8&period=30`, 59_000),
    ).resolves.toMatchObject({ code: "94287082", period: 30, remaining: 1 });
    await expect(
      generateTotp(`otpauth://totp/Test?secret=${seed}&digits=8&period=30`, 1_111_111_109_000),
    ).resolves.toMatchObject({ code: "07081804" });
  });

  it("rejects malformed and undersized seeds", async () => {
    await expect(generateTotp("NOT*BASE32")).rejects.toThrow(/Base32/);
    await expect(generateTotp("JBSWY3DP")).rejects.toThrow(/length/);
  });
});
