import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { generateEd25519Key, publicKeyFromPrivate, sshFingerprint } from "../src/vault/ssh-key";

// From `ssh-keygen -t ed25519 -N fixture-pass`: the public part is readable without the passphrase.
const ENCRYPTED = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC0/v2kHQ
FPZ4u18SL9YPnPAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIKRDCpkOagmE76S1
jeNBb/xdjByOvjGDZvMHftKhOyMgAAAAkA12uxFR9Wf8c1d1dorXl+GXgWwxWcmQhyWFY2
EjAldE2uNJkG89FI6XDBgIpU0VdML7kV7/buNV5EYA7k0Z35cfSJFeHwp+nqGE9OhLscd2
FcliRMLgrluj1uRwnQDLxeNq/br6U8sKkxYCWekIoxOuKSaoFsbXUBs6YsY7Zn/UB/TBE2
thX7aTuuoNn0BRqQ==
-----END OPENSSH PRIVATE KEY-----`;
const PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKRDCpkOagmE76S1jeNBb/xdjByOvjGDZvMHftKhOyMg";

it("reads the public key and fingerprint of an OpenSSH private key, even a protected one", async () => {
  expect(publicKeyFromPrivate(ENCRYPTED)).toBe(PUBLIC);
  expect(await sshFingerprint(`${PUBLIC} fixture`)).toBe("SHA256:Mh18weVL/0d1n5d8pLBW46tnDoGk2yTUYZfSeLGxukA");
  expect(publicKeyFromPrivate("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----")).toBeUndefined();
  expect(publicKeyFromPrivate(ENCRYPTED.replace("b3BlbnNzaC1rZXktdjE", "AAAA"))).toBeUndefined();
  await expect(sshFingerprint("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIKRDCpkOagmE76S1jeNBb/xdjByOvjGDZvMHftKhOyMg")).rejects.toThrow(/OpenSSH public key/);
  await expect(sshFingerprint("not a key")).rejects.toThrow(/OpenSSH public key/);
});

it("generates Ed25519 keys that ssh-keygen accepts", async () => {
  const key = await generateEd25519Key();
  expect(publicKeyFromPrivate(key.privateKey)).toBe(key.publicKey);
  expect(key.keyFingerprint).toBe(await sshFingerprint(key.publicKey));
  let derived: string;
  try {
    const file = join(mkdtempSync(join(tmpdir(), "firnkey-ssh-")), "id");
    writeFileSync(file, key.privateKey, { mode: 0o600 });
    derived = execFileSync("ssh-keygen", ["-y", "-f", file], { encoding: "utf8" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return; // no OpenSSH on this machine
    throw error;
  }
  expect(derived.trim().split(" ").slice(0, 2).join(" ")).toBe(key.publicKey);
});

it("saves an SSH key item with the public key and fingerprint taken from the private key", async () => {
  const { createEncryptedItem, updateEncryptedItem } = await import("../src/vault/encrypt-login");
  const { decryptSymmetricBytes, decryptSymmetricString } = await import("../src/crypto/bitwarden-crypto");
  const userKey = crypto.getRandomValues(new Uint8Array(64));
  const created = await createEncryptedItem({ type: 5, name: "Server", sshKey: { privateKey: ENCRYPTED, publicKey: "ignored" } }, userKey);
  const read = async (cipher: Record<string, unknown>) => {
    const itemKey = await decryptSymmetricBytes(cipher.key as string, userKey);
    const data = cipher.sshKey as Record<string, string>;
    return Object.fromEntries(await Promise.all(["privateKey", "publicKey", "keyFingerprint"]
      .map(async (name) => [name, await decryptSymmetricString(data[name]!, itemKey)])));
  };
  expect(created.type).toBe(5);
  expect(await read(created)).toEqual({ privateKey: `${ENCRYPTED.trim()}\n`, publicKey: PUBLIC, keyFingerprint: await sshFingerprint(PUBLIC) });

  // A PEM key keeps the pasted public key; an edit stays an SSH key.
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----";
  const raw = { ...created, Type: 5, SshKey: created.sshKey, Key: created.key };
  const updated = await updateEncryptedItem(raw, { type: 5, name: "Server", sshKey: { privateKey: pem, publicKey: PUBLIC } }, userKey);
  expect((await read(updated)).publicKey).toBe(PUBLIC);
  await expect(createEncryptedItem({ type: 5, name: "Server", sshKey: { privateKey: pem } }, userKey)).rejects.toThrow(/public key/);
  await expect(createEncryptedItem({ type: 5, name: "Server", sshKey: {} }, userKey)).rejects.toThrow(/private key/);
});
