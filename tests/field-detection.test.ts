import { describe, expect, it } from "vitest";

import { looksLikeOtpField, looksLikeUsernameField } from "../src/site/field-detection";

const base = {
  type: "text",
  autocomplete: "",
  inputHint: "",
  contextHint: "",
  eligibleFieldCount: 1,
};

describe("username field detection", () => {
  it("recognizes the AWS-style username control", () => {
    expect(looksLikeUsernameField({
      ...base,
      autocomplete: "on",
      inputHint: "on username username username",
      contextHint: "Sign in Next",
    })).toBe(true);
  });

  it("recognizes fields marked for passkey autofill", () => {
    expect(looksLikeUsernameField({ ...base, autocomplete: "username webauthn", eligibleFieldCount: 2 })).toBe(true);
    expect(looksLikeUsernameField({ ...base, autocomplete: "webauthn", eligibleFieldCount: 2 })).toBe(true);
  });

  it("recognizes generic single-field multi-step sign-in forms", () => {
    expect(looksLikeUsernameField({
      ...base,
      inputHint: "principal",
      contextHint: "/platform/tenant/login Continue",
    })).toBe(true);
  });

  it("recognizes identifier and associated-label signals", () => {
    expect(looksLikeUsernameField({ ...base, inputHint: "account identifier" })).toBe(true);
    expect(looksLikeUsernameField({ ...base, inputHint: "Corporate user ID" })).toBe(true);
  });

  it("does not treat search, OTP, or ambiguous multi-field controls as usernames", () => {
    expect(looksLikeUsernameField({ ...base, type: "search", inputHint: "search", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "verification code", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "customer", contextHint: "Sign in", eligibleFieldCount: 2 })).toBe(false);
  });
});

describe("one-time code field detection", () => {
  const otp = (inputHint: string, extra: Partial<Parameters<typeof looksLikeOtpField>[0]> = {}) =>
    looksLikeOtpField({ type: "text", autocomplete: "", inputHint, maxLength: -1, ...extra });

  it("recognizes authenticator code fields", () => {
    expect(otp("", { autocomplete: "one-time-code" })).toBe(true);
    expect(otp("totp")).toBe(true);
    expect(otp("authenticator code")).toBe(true);
    expect(otp("enter the 6-digit code from your app", { maxLength: 6 })).toBe(true);
    expect(otp("verification code", { type: "tel" })).toBe(true);
    expect(otp("mfa-code digit 1", { maxLength: 1 })).toBe(true);
  });

  it("leaves other code fields alone", () => {
    expect(otp("sms code")).toBe(false);
    expect(otp("code we emailed you", { autocomplete: "one-time-code" })).toBe(false);
    expect(otp("recovery code")).toBe(false);
    expect(otp("promo code")).toBe(false);
    expect(otp("zip code")).toBe(false);
    expect(otp("cc-csc security code")).toBe(false);
    expect(otp("card security code")).toBe(false);
    expect(otp("username")).toBe(false);
    expect(otp("code", { maxLength: 4 })).toBe(false);
    expect(otp("code", { type: "email" })).toBe(false);
  });
});
