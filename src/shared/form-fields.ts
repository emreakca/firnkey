import type { CardData, IdentityData } from "../vault/models";

// Card and identity form fields, named by their HTML autocomplete tokens. Used by the in-page menu
// (which fields offer cards or identities) and by the fill script (what goes where).

export const CARD_KINDS = new Set(["cc-name", "cc-number", "cc-exp-month", "cc-exp-year", "cc-exp", "cc-csc", "cc-type"]);

// Fields that open the identity menu. Email, phone and username fields are left to the login menu.
export const IDENTITY_MENU_KINDS = new Set([
  "honorific-prefix", "given-name", "additional-name", "family-name", "name", "organization",
  "address-line1", "address-line2", "address-line3", "street-address", "address-level2",
  "address-level1", "postal-code", "country",
]);

const FILLABLE_KINDS = new Set([...CARD_KINDS, ...IDENTITY_MENU_KINDS, "email", "tel", "username"]);

// Fallback for fields without autocomplete tokens, matched against name, id, placeholder, label and
// aria-label. Checked in order; the first match wins. Sources (not RegExps) so the list can be passed
// to a script injected with chrome.scripting.
export const FIELD_HINTS: [kind: string, pattern: string][] = [
  ["cc-csc", /cvc|cvv|csc|cvn|security.?code|card.?code|card.?verification|pr(ü|ue)f(nummer|ziffer|code)|sicherheitscode/.source],
  // A combined "MM / YY" box, even when its name says "exp month".
  ["cc-exp", /mm.?\/.?yy/.source],
  ["cc-name", /(card|cc).?holder|name.?on.?card|cc.?name|card.?name|karteninhaber|name.?auf.?der.?karte/.source],
  ["cc-number", /card.?(number|no\b|num)|cc.?(number|num|no\b)|credit.?card|\bpan\b|kartennummer|kreditkarte/.source],
  ["cc-exp-month", /(exp|expiry|expiration|cc|card|ablauf).?(month|mm\b|monat)/.source],
  ["cc-exp-year", /(exp|expiry|expiration|cc|card|ablauf).?(year|yy|jahr)/.source],
  ["cc-exp", /exp(iry|iration)?.?(date)?\b|mm.?\/.?yy|ablaufdatum|g(ü|ue)ltig.?bis/.source],
  ["cc-type", /card.?(type|brand)|kartentyp/.source],
  ["email", /e.?mail/.source],
  ["tel", /phone|mobile|\btel\b|telefon|handy/.source],
  ["given-name", /first.?name|given.?name|fname|forename|vorname/.source],
  ["additional-name", /middle.?name|mname/.source],
  ["family-name", /last.?name|family.?name|surname|lname|nachname|familienname/.source],
  ["name", /full.?name|your.?name|^(name )*name$|vollst(ä|ae)ndiger.?name/.source],
  ["organization", /company|organi[sz]ation|business.?name|firma|unternehmen/.source],
  ["address-line2", /address.?(line)?.?2|addr2|apartment|suite|\bapt\b|adresszusatz/.source],
  ["address-line3", /address.?(line)?.?3|addr3/.source],
  ["address-line1", /address.?(line)?.?1|addr1|street|^address$|stra(ß|ss)e|anschrift|^adresse$/.source],
  ["address-level2", /city|town|locality|suburb|stadt|\bort\b|wohnort/.source],
  ["address-level1", /state|province|county|region|bundesland/.source],
  ["postal-code", /zip|postal|post.?code|\bplz\b|postleitzahl/.source],
  ["country", /country|\bland\b/.source],
];

const HINT_PATTERNS = FIELD_HINTS.map(([kind, source]) => [kind, new RegExp(source)] as const);

// The fill kind of a field: its autocomplete token when it names one, otherwise the first hint match.
export function classifyFormField(autocomplete: string, hint: string): string | undefined {
  const token = autocomplete.toLowerCase().split(/\s+/).find((candidate) => FILLABLE_KINDS.has(candidate));
  if (token) return token;
  const text = hint.toLowerCase().replace(/\s+/g, " ").trim();
  return HINT_PATTERNS.find(([, pattern]) => pattern.test(text))?.[0];
}

export type FormData = { card: CardData; identity: IdentityData };

// Card and identity data from filled form fields, as [fill kind, value] pairs. Values the item cannot
// hold (a month name, a malformed date) are left out rather than guessed.
export function formData(fields: [kind: string, value: string][]): FormData {
  const card: CardData = {};
  const identity: IdentityData = {};
  const month = (value: string) => /^\d{1,2}$/.test(value) && Number(value) >= 1 && Number(value) <= 12 ? String(Number(value)) : undefined;
  const year = (value: string) => /^\d{4}$/.test(value) ? value : /^\d{2}$/.test(value) ? `20${value}` : undefined;
  const set = <T extends Record<string, string>>(target: T, name: keyof T, value: string | undefined) => {
    if (value && !target[name]) target[name] = value as T[keyof T];
  };
  for (const [kind, raw] of fields) {
    const value = raw.trim();
    if (!value) continue;
    switch (kind) {
      case "cc-name": set(card, "cardholderName", value); break;
      case "cc-number": set(card, "number", value.replace(/[\s-]/g, "")); break;
      case "cc-csc": set(card, "code", value); break;
      case "cc-type": set(card, "brand", value); break;
      case "cc-exp-month": set(card, "expMonth", month(value)); break;
      case "cc-exp-year": set(card, "expYear", year(value)); break;
      case "cc-exp": {
        const [, mm, yy] = /^(\d{1,2})\s*[/.-]?\s*(\d{2}|\d{4})$/.exec(value.replace(/\s+/g, "")) ?? [];
        if (!mm || !yy || !month(mm)) break;
        set(card, "expMonth", month(mm));
        set(card, "expYear", year(yy));
        break;
      }
      case "honorific-prefix": set(identity, "title", value); break;
      case "given-name": set(identity, "firstName", value); break;
      case "additional-name": set(identity, "middleName", value); break;
      case "family-name": set(identity, "lastName", value); break;
      case "name": {
        // A single name field: everything but the last word is the first name.
        const words = value.split(/\s+/);
        if (!identity.lastName && words.length > 1) set(identity, "lastName", words.pop());
        set(identity, "firstName", words.join(" "));
        break;
      }
      case "organization": set(identity, "company", value); break;
      case "email": set(identity, "email", value); break;
      case "tel": set(identity, "phone", value); break;
      case "username": set(identity, "username", value); break;
      case "street-address": {
        const [line1, line2, ...rest] = value.split(/\n+/);
        set(identity, "address1", line1);
        set(identity, "address2", line2);
        set(identity, "address3", rest.join(", "));
        break;
      }
      case "address-line1": set(identity, "address1", value); break;
      case "address-line2": set(identity, "address2", value); break;
      case "address-line3": set(identity, "address3", value); break;
      case "address-level2": set(identity, "city", value); break;
      case "address-level1": set(identity, "state", value); break;
      case "postal-code": set(identity, "postalCode", value); break;
      case "country": set(identity, "country", value); break;
    }
  }
  if (card.number && !card.brand) set(card, "brand", cardBrand(card.number));
  return { card, identity };
}

// Luhn check, so a phone or order number is never offered as a card.
export function validCardNumber(number: string): boolean {
  if (!/^\d{12,19}$/.test(number)) return false;
  let sum = 0;
  for (let index = 0; index < number.length; index += 1) {
    let digit = Number(number[number.length - 1 - index]);
    if (index % 2 === 1) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
  }
  return sum % 10 === 0;
}

// Bitwarden's brand names, for the common prefixes.
export function cardBrand(number: string): string | undefined {
  if (/^4/.test(number)) return "Visa";
  if (/^(5[1-5]|222[1-9]|22[3-9]|2[3-6]|27[01]|2720)/.test(number)) return "Mastercard";
  if (/^3[47]/.test(number)) return "Amex";
  if (/^(6011|65|64[4-9])/.test(number)) return "Discover";
  if (/^3(0[0-5]|[68])/.test(number)) return "Diners Club";
  if (/^35(2[89]|[3-8])/.test(number)) return "JCB";
  return undefined;
}
