export interface UsernameFieldSignals {
  type: string;
  autocomplete: string;
  inputHint: string;
  contextHint: string;
  eligibleFieldCount: number;
}

const supportedTypes = new Set(["", "text", "email", "tel", "search"]);
const explicitUsername = /user[\s_-]*(?:name|id)|login[\s_-]*(?:name|id)|e[\s_-]*mail|email|identifier|account[\s_-]*name/;
const nonCredential = /search|query|one[\s_-]*time|otp|verification|security[\s_-]*code|captcha|coupon|promo/;
const loginContext = /sign[\s_-]*in|log[\s_-]*in|login|authenticate|authentication|session|continue|next/;

export function looksLikeUsernameField(signals: UsernameFieldSignals): boolean {
  const type = signals.type.toLowerCase();
  if (!supportedTypes.has(type)) return false;

  const autocomplete = signals.autocomplete.toLowerCase();
  const inputHint = signals.inputHint.toLowerCase();
  // "webauthn" marks the field where a site offers passkey autofill, e.g. "username webauthn".
  if (["username", "email"].includes(autocomplete) || autocomplete.split(/\s+/).includes("webauthn")) return true;
  if (nonCredential.test(inputHint)) return false;
  if (type === "email" || explicitUsername.test(inputHint)) return true;
  if (type === "tel" && /phone|mobile/.test(inputHint)) return true;

  // Multi-step sign-in pages often use a generic text/identifier control before
  // rendering the password step. Treat it as a username only when it is the
  // sole plausible field in an explicitly login-shaped context.
  return type !== "search" && signals.eligibleFieldCount === 1 && loginContext.test(signals.contextHint.toLowerCase());
}

export function canBeUsernameField(typeInput: string, hintInput: string): boolean {
  const type = typeInput.toLowerCase();
  return supportedTypes.has(type) && type !== "search" && !nonCredential.test(hintInput.toLowerCase());
}

export interface OtpFieldSignals {
  type: string;
  autocomplete: string;
  inputHint: string;
  maxLength: number; // -1 when unset
}

const otpTypes = new Set(["", "text", "tel", "number", "password"]);
const otpHint = /one[\s_-]*time|\botp\b|totp|2fa|mfa|two[\s_-]*(?:factor|step)|verification[\s_-]*code|security[\s_-]*code|auth(?:entication|enticator)?[\s_-]*code|passcode|\bcode\b/;
// Codes sent by SMS or email, recovery codes and other "codes" are not authenticator codes.
// Payment card security codes (CVV/CVC) are not either.
const notOtp = /sms|text[\s_-]*message|e[\s_-]*mail|phone|recovery|backup|captcha|coupon|promo|voucher|gift|postal|zip|country|area[\s_-]*code|discount|cc-|card|cvv|cvc|csc/;

// For code injected with chrome.scripting, which cannot import: [hint, not-a-code hint].
export const OTP_HINT_SOURCES: [string, string] = [otpHint.source, notOtp.source];

// Authenticator (TOTP) code fields, including one box of a split "one digit per box" control.
export function looksLikeOtpField(signals: OtpFieldSignals): boolean {
  if (!otpTypes.has(signals.type.toLowerCase())) return false;
  const hint = signals.inputHint.toLowerCase();
  if (notOtp.test(hint)) return false;
  if (signals.autocomplete.toLowerCase() === "one-time-code") return true;
  // A code field holds the whole code (6-8 digits) or exactly one digit of it.
  const fits = signals.maxLength <= 0 || signals.maxLength === 1 || signals.maxLength >= 6;
  return fits && otpHint.test(hint);
}
