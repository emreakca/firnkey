import { concatenate, decodeUtf8, fromBase64, utf8 } from "../crypto/bytes";

// OpenSSH key helpers for SSH key items: the public key and fingerprint that go with a private key,
// and new Ed25519 keys. Formats: PROTOCOL.key and RFC 4253 in the OpenSSH sources.

const PEM = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/;
const MAGIC = utf8("openssh-key-v1\0");

// "ssh-ed25519 AAAA…" from an OpenSSH private key. Its public part is never encrypted, so this works
// for passphrase-protected keys too. Undefined for other formats (PEM RSA keys keep a pasted public key).
export function publicKeyFromPrivate(privateKey: string): string | undefined {
  const body = PEM.exec(privateKey)?.[1];
  if (!body) return undefined;
  try {
    const bytes = fromBase64(body.replace(/\s+/g, ""));
    if (!MAGIC.every((byte, index) => bytes[index] === byte)) return undefined;
    const reader = new Reader(bytes, MAGIC.length);
    reader.string(); // cipher
    reader.string(); // kdf
    reader.string(); // kdf options
    if (reader.uint32() < 1) return undefined;
    const blob = reader.string();
    return `${decodeUtf8(new Reader(blob).string())} ${blob.toBase64()}`;
  } catch {
    return undefined;
  }
}

// "SHA256:…" like `ssh-keygen -l`. Throws for text that is not an OpenSSH public key.
export async function sshFingerprint(publicKey: string): Promise<string> {
  const [type, data] = publicKey.trim().split(/\s+/);
  let blob: Uint8Array<ArrayBuffer> | undefined;
  try {
    blob = fromBase64(data ?? "");
    if (decodeUtf8(new Reader(blob).string()) !== type) blob = undefined;
  } catch {
    blob = undefined;
  }
  if (!blob) throw new Error("Enter an OpenSSH public key, like ssh-ed25519 AAAA…");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return `SHA256:${digest.toBase64({ omitPadding: true })}`;
}

export async function generateEd25519Key(): Promise<{ privateKey: string; publicKey: string; keyFingerprint: string }> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const seed = pkcs8.slice(-32); // An Ed25519 PKCS#8 key ends with the 32-byte seed.
  const type = utf8("ssh-ed25519");
  const blob = concatenate(sshString(type), sshString(publicBytes));
  const check = crypto.getRandomValues(new Uint8Array(4));
  let secret = concatenate(check, check, sshString(type), sshString(publicBytes),
    sshString(concatenate(seed, publicBytes)), sshString(new Uint8Array()));
  const padding = Array.from({ length: (8 - (secret.length % 8)) % 8 }, (_, index) => index + 1);
  secret = concatenate(secret, Uint8Array.from(padding));
  const none = sshString(utf8("none"));
  const file = concatenate(MAGIC, none, none, sshString(new Uint8Array()), uint32(1), sshString(blob), sshString(secret));
  const lines = file.toBase64().match(/.{1,70}/g)!.join("\n");
  seed.fill(0);
  secret.fill(0);
  const publicKey = `ssh-ed25519 ${blob.toBase64()}`;
  return {
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines}\n-----END OPENSSH PRIVATE KEY-----\n`,
    publicKey,
    keyFingerprint: await sshFingerprint(publicKey),
  };
}

function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

function sshString(value: Uint8Array): Uint8Array {
  return concatenate(uint32(value.length), value);
}

class Reader {
  constructor(private readonly bytes: Uint8Array, private offset = 0) {}

  uint32(): number {
    if (this.offset + 4 > this.bytes.length) throw new Error("Truncated SSH key.");
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    return value;
  }

  string(): Uint8Array {
    const length = this.uint32();
    if (this.offset + length > this.bytes.length) throw new Error("Truncated SSH key.");
    this.offset += length;
    return this.bytes.subarray(this.offset - length, this.offset);
  }
}
