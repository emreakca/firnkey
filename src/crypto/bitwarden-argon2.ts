import { argon2id } from "hash-wasm";

import type { Argon2idKdfConfig } from "../shared/kdf";
import { utf8 } from "./bytes";

/**
 * Derive Bitwarden's 32-byte Argon2id master-key material.
 *
 * Bitwarden does not pass the account email directly to Argon2. It first
 * hashes the normalized email salt with SHA-256, then uses those 32 bytes as
 * the Argon2 salt (version 0x13, which is hash-wasm's Argon2 default).
 */
export async function deriveBitwardenArgon2idKey(
  password: string,
  salt: string,
  kdf: Argon2idKdfConfig,
): Promise<Uint8Array> {
  const saltHash = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(salt)));
  try {
    const result = await argon2id({
      password: utf8(password),
      salt: saltHash,
      iterations: kdf.iterations,
      memorySize: kdf.memoryMiB * 1024,
      parallelism: kdf.parallelism,
      hashLength: 32,
      outputType: "binary",
    });
    return new Uint8Array(result);
  } finally {
    saltHash.fill(0);
  }
}
