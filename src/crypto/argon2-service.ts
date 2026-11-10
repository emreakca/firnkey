import type { Argon2idKdfConfig } from "../shared/kdf";
import { offscreenRequest } from "../shared/offscreen";

interface ArgonResponse {
  requestId: string;
  ok: boolean;
  key?: number[];
  error?: string;
}

export async function deriveArgon2idMasterKey(
  password: string,
  salt: string,
  kdf: Argon2idKdfConfig,
): Promise<Uint8Array> {
  const requestId = crypto.randomUUID();
  const response = (await offscreenRequest({
    type: "crypto.argon2id",
    requestId,
    password,
    salt,
    iterations: kdf.iterations,
    memoryMiB: kdf.memoryMiB,
    parallelism: kdf.parallelism,
  })) as ArgonResponse | undefined;

  if (!response?.ok || response.requestId !== requestId || !Array.isArray(response.key)) {
    throw new Error(response?.error ?? "Argon2id key derivation returned an invalid result.");
  }
  const key = new Uint8Array(response.key);
  if (key.length !== 32) {
    throw new Error("Argon2id key derivation returned an invalid key length.");
  }
  return key;
}
