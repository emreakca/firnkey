import { expect, it } from "vitest";
import { CARD_KINDS, classifyFormField, IDENTITY_MENU_KINDS } from "../src/shared/form-fields";
import { isExtensionRequest } from "../src/shared/messages";

it("classifies card and address fields by autocomplete token first, then by hints", () => {
  expect(classifyFormField("section-pay billing cc-number", "")).toBe("cc-number");
  expect(classifyFormField("shipping postal-code", "zip")).toBe("postal-code");
  // Junk autocomplete values (used to block browser autofill) fall back to hints.
  expect(classifyFormField("chrome-off", "cardnumber Card number")).toBe("cc-number");
  expect(classifyFormField("", "cvv   Security code")).toBe("cc-csc");
  expect(classifyFormField("", "exp-date MM / YY")).toBe("cc-exp");
  expect(classifyFormField("", "expiry_month")).toBe("cc-exp-month");
  expect(classifyFormField("", "first_name First name")).toBe("given-name");
  expect(classifyFormField("", "name name")).toBe("name");
  expect(classifyFormField("", "address2 Apartment, suite")).toBe("address-line2");
  // Login fields are not card or address fields.
  expect(classifyFormField("username", "user")).toBe("username");
  expect(classifyFormField("", "username Username")).toBeUndefined();
  expect(classifyFormField("current-password", "password")).toBeUndefined();
  expect(classifyFormField("", "q Search")).toBeUndefined();
});

it("keeps email and phone fields out of the identity menu", () => {
  for (const kind of ["email", "tel", "username"]) expect(IDENTITY_MENU_KINDS.has(kind)).toBe(false);
  expect(CARD_KINDS.has("cc-csc")).toBe(true);
});

it("validates the in-page card and identity messages", () => {
  expect(isExtensionRequest({ type: "site.formItems", url: "https://shop.example/checkout" })).toBe(true);
  expect(isExtensionRequest({ type: "site.fillItem", id: "card-1", url: "https://shop.example/checkout" })).toBe(true);
  expect(isExtensionRequest({ type: "site.fillItem", url: "https://shop.example/checkout" })).toBe(false);
});
