const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

export interface TotpResult {
  code: string;
  period: number;
  remaining: number;
}

interface TotpConfig {
  secret: Uint8Array;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  digits: number;
  period: number;
  steam: boolean;
}

export async function generateTotp(seed: string, now = Date.now()): Promise<TotpResult> {
  const config = parseSeed(seed);
  const counter = Math.floor(now / 1000 / config.period);
  const message = new Uint8Array(8);
  let remainingCounter = counter;
  for (let index = 7; index >= 0; index -= 1) {
    message[index] = remainingCounter & 0xff;
    remainingCounter = Math.floor(remainingCounter / 256);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    config.secret.slice(),
    { name: "HMAC", hash: config.algorithm },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  const code = config.steam
    ? steamCode(binary)
    : String(binary % 10 ** config.digits).padStart(config.digits, "0");
  const elapsed = Math.floor(now / 1000) % config.period;
  return { code, period: config.period, remaining: config.period - elapsed };
}

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

// Everything an authenticator key describes. `secret` is normalized Base32 (no spaces or padding).
export interface TotpParameters {
  secret: string;
  issuer: string;
  account: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  steam: boolean;
}

// Accepts a Base32 secret, an otpauth://totp/ link, Bitwarden's steam://<secret>, or otpauth://steam/.
// HOTP and every other scheme are refused. Error messages never repeat the input: it may be a secret.
export function parseTotpKey(input: string): TotpParameters {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2_048) throw new Error("The authenticator key is empty or too long.");
  const result: TotpParameters = { secret: trimmed, issuer: "", account: "", algorithm: "SHA1", digits: 6, period: 30, steam: false };
  if (/^steam:\/\//i.test(trimmed)) {
    result.secret = trimmed.slice(8);
    result.steam = true;
  } else if (/^otpauth:/i.test(trimmed)) {
    let uri: URL;
    try {
      uri = new URL(trimmed);
    } catch {
      throw new Error("The otpauth link is malformed.");
    }
    const kind = uri.hostname.toLowerCase();
    if (kind !== "totp" && kind !== "steam") throw new Error("Only time-based (TOTP) authenticator keys are supported.");
    let label = "";
    try {
      label = decodeURIComponent(uri.pathname.replace(/^\/+/, ""));
    } catch {
      throw new Error("The otpauth link has a malformed label.");
    }
    const colon = label.indexOf(":");
    result.account = cleanLabel(colon >= 0 ? label.slice(colon + 1) : label);
    result.issuer = cleanLabel(uri.searchParams.get("issuer") ?? (colon >= 0 ? label.slice(0, colon) : ""));
    result.secret = uri.searchParams.get("secret") ?? "";
    const algorithm = (uri.searchParams.get("algorithm") ?? "SHA1").toUpperCase().replace("-", "");
    if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") {
      throw new Error("The TOTP seed uses an unsupported hash algorithm.");
    }
    result.algorithm = algorithm;
    result.digits = positiveInteger(uri.searchParams.get("digits"), 6, kind === "steam" ? 5 : 6, 10, "TOTP digit count");
    result.period = positiveInteger(uri.searchParams.get("period"), 30, 5, 300, "TOTP period");
    result.steam = kind === "steam" || result.issuer.toLowerCase() === "steam";
  }
  result.secret = result.secret.toUpperCase().replace(/[\s=-]/g, "");
  const decoded = decodeBase32(result.secret);
  if (decoded.length < 10 || decoded.length > 128) throw new Error("The TOTP seed has an invalid length.");
  decoded.fill(0);
  if (result.steam) result.digits = 5;
  return result;
}

// A portable otpauth://totp/ link, as authenticator apps export and import them.
export function otpauthUri(parameters: TotpParameters): string {
  const issuer = parameters.steam ? "Steam" : cleanLabel(parameters.issuer);
  const account = cleanLabel(parameters.account);
  const label = issuer ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` : encodeURIComponent(account);
  const query = new URLSearchParams({ secret: parameters.secret });
  if (issuer) query.set("issuer", issuer);
  if (!parameters.steam) {
    if (parameters.algorithm !== "SHA1") query.set("algorithm", parameters.algorithm);
    if (parameters.digits !== 6) query.set("digits", String(parameters.digits));
  } else query.set("digits", "5");
  if (parameters.period !== 30) query.set("period", String(parameters.period));
  return `otpauth://totp/${label}?${query.toString()}`;
}

// What a login stores: Bitwarden reads Steam keys only as steam://<secret>.
export function storedTotpKey(parameters: TotpParameters): string {
  return parameters.steam ? `steam://${parameters.secret}` : otpauthUri(parameters);
}

// Labels come from QR codes and imported files: drop control and bidirectional-override characters.
export function cleanLabel(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "").trim().slice(0, 200);
}

function parseSeed(input: string): TotpConfig {
  const parameters = parseTotpKey(input);
  const algorithm = `SHA-${parameters.algorithm.slice(3)}` as TotpConfig["algorithm"];
  return { secret: decodeBase32(parameters.secret), algorithm, digits: parameters.digits, period: parameters.period, steam: parameters.steam };
}

function decodeBase32(value: string): Uint8Array {
  const normalized = value.toUpperCase().replace(/[\s=-]/g, "");
  if (!normalized || /[^A-Z2-7]/.test(normalized)) {
    throw new Error("The TOTP seed is not valid Base32.");
  }
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of normalized) {
    const code = character.charCodeAt(0);
    const next = code >= 65 && code <= 90 ? code - 65 : code - 24;
    buffer = (buffer << 5) | next;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(output);
}

function steamCode(input: number): string {
  let value = input;
  let output = "";
  for (let index = 0; index < 5; index += 1) {
    output += STEAM_ALPHABET[value % STEAM_ALPHABET.length];
    value = Math.floor(value / STEAM_ALPHABET.length);
  }
  return output;
}

function positiveInteger(
  value: string | null,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (value === null || value === "") {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || String(parsed) !== value || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} is invalid.`);
  }
  return parsed;
}
