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
  ["cc-csc", /cvc|cvv|csc|cvn|security.?code|card.?code|card.?verification/.source],
  ["cc-name", /(card|cc).?holder|name.?on.?card|cc.?name|card.?name/.source],
  ["cc-number", /card.?(number|no\b|num)|cc.?(number|num|no\b)|credit.?card|\bpan\b/.source],
  ["cc-exp-month", /(exp|expiry|expiration|cc|card).?(month|mm\b)/.source],
  ["cc-exp-year", /(exp|expiry|expiration|cc|card).?(year|yy)/.source],
  ["cc-exp", /exp(iry|iration)?.?(date)?\b|mm.?\/.?yy/.source],
  ["cc-type", /card.?(type|brand)/.source],
  ["email", /e.?mail/.source],
  ["tel", /phone|mobile|\btel\b/.source],
  ["given-name", /first.?name|given.?name|fname|forename/.source],
  ["additional-name", /middle.?name|mname/.source],
  ["family-name", /last.?name|family.?name|surname|lname/.source],
  ["name", /full.?name|your.?name|^(name )*name$/.source],
  ["organization", /company|organi[sz]ation|business.?name/.source],
  ["address-line2", /address.?(line)?.?2|addr2|apartment|suite|\bapt\b/.source],
  ["address-line3", /address.?(line)?.?3|addr3/.source],
  ["address-line1", /address.?(line)?.?1|addr1|street|^address$/.source],
  ["address-level2", /city|town|locality|suburb/.source],
  ["address-level1", /state|province|county|region/.source],
  ["postal-code", /zip|postal|post.?code/.source],
  ["country", /country/.source],
];

const HINT_PATTERNS = FIELD_HINTS.map(([kind, source]) => [kind, new RegExp(source)] as const);

// The fill kind of a field: its autocomplete token when it names one, otherwise the first hint match.
export function classifyFormField(autocomplete: string, hint: string): string | undefined {
  const token = autocomplete.toLowerCase().split(/\s+/).find((candidate) => FILLABLE_KINDS.has(candidate));
  if (token) return token;
  const text = hint.toLowerCase().replace(/\s+/g, " ").trim();
  return HINT_PATTERNS.find(([, pattern]) => pattern.test(text))?.[0];
}
