import { deriveBitwardenArgon2idKey } from "../crypto/bitwarden-argon2";

// Work that needs a DOM page: the offscreen document on Chrome, the background page itself on Firefox.
interface ArgonRequest {
  target: "firnkey-offscreen";
  type: "crypto.argon2id";
  requestId: string;
  password: string;
  salt: string;
  iterations: number;
  memoryMiB: number;
  parallelism: number;
}

interface ArgonResponse {
  requestId: string;
  ok: boolean;
  key?: number[];
  error?: string;
}

// The answer for an offscreen message, or undefined when the message is not for this page.
export function handleOffscreenMessage(message: unknown): Promise<unknown> | undefined {
  if (isClipboardClear(message)) return clearClipboard((message as { digest?: unknown }).digest).catch(() => false);
  if (!isArgonRequest(message)) return undefined;
  return derive(message).then(
    (key) => ({ requestId: message.requestId, ok: true, key }) satisfies ArgonResponse,
    () => ({ requestId: message.requestId, ok: false, error: "Argon2id key derivation failed." }) satisfies ArgonResponse,
  );
}

async function derive(request: ArgonRequest): Promise<number[]> {
  const key = await deriveBitwardenArgon2idKey(request.password, request.salt, {
    type: 1,
    iterations: request.iterations,
    memoryMiB: request.memoryMiB,
    parallelism: request.parallelism,
  });
  try {
    return [...key];
  } finally {
    key.fill(0);
  }
}

function isArgonRequest(value: unknown): value is ArgonRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const request = value as Record<string, unknown>;
  return (
    request.target === "firnkey-offscreen" &&
    request.type === "crypto.argon2id" &&
    typeof request.requestId === "string" &&
    typeof request.password === "string" &&
    typeof request.salt === "string" &&
    typeof request.iterations === "number" &&
    typeof request.memoryMiB === "number" &&
    typeof request.parallelism === "number"
  );
}

function isClipboardClear(value: unknown): boolean {
  const request = value as Record<string, unknown> | null;
  return request?.target === "firnkey-offscreen" && request.type === "clipboard.clear";
}

// Offscreen documents and background pages cannot take focus, so the async Clipboard API is unavailable; use copy/paste commands.
// With a digest and the optional clipboardRead permission, text the user copied since is left alone.
async function clearClipboard(digest: unknown): Promise<boolean> {
  const field = document.createElement("textarea");
  document.body.append(field);
  try {
    if (typeof digest === "string") {
      field.focus();
      // Paste fails without the clipboardRead permission; then clear as before.
      if (document.execCommand("paste") && (await sha256Base64(field.value)) !== digest) return false;
    }
    field.value = " "; // Chrome ignores copying an empty selection.
    field.select();
    return document.execCommand("copy");
  } finally {
    field.value = "";
    field.remove();
  }
}

async function sha256Base64(value: string): Promise<string> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))).toBase64();
}
