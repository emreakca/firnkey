import { describe, expect, it } from "vitest";
import { CARD_KINDS, classifyFormField, IDENTITY_MENU_KINDS, cardBrand, formData, validCardNumber } from "../src/shared/form-fields";
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

describe("form data for saving", () => {
  it("reads a card, splitting a combined expiry and naming the brand", () => {
    expect(formData([["cc-number", "4242 4242 4242 4242"], ["cc-exp", "03 / 27"], ["cc-csc", "123"], ["cc-name", "Max Muster"]]).card)
      .toEqual({ number: "4242424242424242", expMonth: "3", expYear: "2027", code: "123", cardholderName: "Max Muster", brand: "Visa" });
    expect(formData([["cc-exp-month", "12"], ["cc-exp-year", "2030"]]).card).toEqual({ expMonth: "12", expYear: "2030" });
    expect(formData([["cc-exp-month", "Dezember"], ["cc-exp", "13/27"]]).card).toEqual({});
  });

  it("reads an address, splitting a single name field", () => {
    expect(formData([["name", "Anna Maria Huber"], ["street-address", "Hauptstraße 1\nTop 4"], ["postal-code", "1010"], ["address-level2", "Wien"]]).identity)
      .toEqual({ firstName: "Anna Maria", lastName: "Huber", address1: "Hauptstraße 1", address2: "Top 4", postalCode: "1010", city: "Wien" });
  });

  it("only accepts card numbers that pass the Luhn check", () => {
    expect(validCardNumber("4242424242424242")).toBe(true);
    expect(validCardNumber("4242424242424241")).toBe(false);
    expect(validCardNumber("06641234567")).toBe(false);
    expect([cardBrand("5555555555554444"), cardBrand("378282246310005"), cardBrand("9999")]).toEqual(["Mastercard", "Amex", undefined]);
  });

  it("recognizes German field names", () => {
    expect(["Kartennummer", "Karteninhaber", "Prüfnummer", "Ablaufdatum", "Vorname", "Nachname", "Straße und Hausnummer", "PLZ", "Ort", "Land"]
      .map((label) => classifyFormField("", label)))
      .toEqual(["cc-number", "cc-name", "cc-csc", "cc-exp", "given-name", "family-name", "address-line1", "postal-code", "address-level2", "country"]);
    expect(classifyFormField("", "Passwort")).toBeUndefined();
    expect(classifyFormField("", "exp mm / yy")).toBe("cc-exp");
  });
});
