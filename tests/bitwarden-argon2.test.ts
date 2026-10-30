import { describe, expect, it } from "vitest";

import { deriveBitwardenArgon2idKey } from "../src/crypto/bitwarden-argon2";
import { KdfType } from "../src/shared/kdf";

describe("Bitwarden Argon2id derivation", () => {
  it(
    "matches Bitwarden's official Argon2id master-key vector",
    async () => {
      const key = await deriveBitwardenArgon2idKey("67t9b5g67$%Dh89n", "test_key", {
        type: KdfType.Argon2id,
        iterations: 4,
        memoryMiB: 32,
        parallelism: 2,
      });

      expect([...key]).toEqual([
        207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240,
        20, 147, 237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242,
      ]);
    },
    30_000,
  );
});
