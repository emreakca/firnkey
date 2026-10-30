import type { CardData, IdentityData, VaultItem } from "../vault/models";
import { FIELD_HINTS } from "../shared/form-fields";
import { OTP_HINT_SOURCES } from "../site/field-detection";

export async function fillActiveTab(item: VaultItem): Promise<{ username: boolean; password: boolean; tabId: number }> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined || !tab.url || !/^https?:\/\//i.test(tab.url)) {
    throw new Error("Open an HTTP or HTTPS login page before filling.");
  }
  if (new URL(tab.url).protocol === "http:" && item.uris.some(({ uri }) => /^https:\/\//i.test(uri))) {
    throw new Error("Refusing to fill an HTTPS login into an insecure HTTP page.");
  }
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    world: "ISOLATED",
    func: fillDocument,
    args: [
      item.username,
      item.password,
      [...new Set([new URL(tab.url).origin, ...item.uris.flatMap(({ uri }) => {
        try { return [new URL(uri).origin]; } catch { return []; }
      })])],
    ],
  });
  const result = results.reduce(
    (filled, frame) => ({
      username: filled.username || Boolean(frame.result?.username),
      password: filled.password || Boolean(frame.result?.password),
    }),
    { username: false, password: false },
  );
  if (!result.username && !result.password) {
    throw new Error("No visible login fields were found on this page.");
  }
  return { ...result, tabId: tab.id };
}

function fillDocument(username: string, password: string, allowedOrigins: string[]): { username: boolean; password: boolean } {
  if (!allowedOrigins.includes(location.origin)) return { username: false, password: false };
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  const visible = (element: HTMLInputElement): boolean => {
    if (element.disabled || element.readOnly || element.type.toLowerCase() === "hidden") return false;
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity || "1") > 0 &&
      bounds.width > 1 && bounds.height > 1 && element.getClientRects().length > 0;
  };
  const inputs = roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(visible);
  const passwords = inputs.filter((input) => input.type.toLowerCase() === "password");
  const passwordField = passwords.find((input) => input.autocomplete.toLowerCase() === "current-password") ??
    passwords.find((input) => input.autocomplete.toLowerCase() !== "new-password") ?? passwords[0];
  const usernameCandidates = inputs.filter((input) => {
    const type = input.type.toLowerCase();
    return input !== passwordField && ["", "text", "email", "tel", "search"].includes(type);
  });
  const score = (input: HTMLInputElement): number => {
    const hint = `${input.autocomplete} ${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`.toLowerCase();
    let value = 0;
    if (/username|user-name|login|email|e-mail/.test(hint)) value += 12;
    if (input.autocomplete === "username" || input.autocomplete === "email") value += 15;
    if (input.type === "email") value += 10;
    if (/search|otp|code|phone|mobile|captcha/.test(hint)) value -= 15;
    if (passwordField && input.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING) value += 3;
    return value;
  };
  const usernameField = usernameCandidates.sort((left, right) => score(right) - score(left))[0];
  const setValue = (input: HTMLInputElement | undefined, value: string): boolean => {
    if (!input || !value) return false;
    input.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(input, value);
    try {
      input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    } catch {
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new Event("blur", { bubbles: true }));
    return input.value === value;
  };
  const usernameFilled = setValue(usernameField, username);
  const passwordFilled = setValue(passwordField, password);
  (passwordField ?? usernameField)?.focus();
  return { username: usernameFilled, password: passwordFilled };
}

// Card and identity fill, keyed by HTML autocomplete tokens. Each value lists the forms a field may
// expect, preferred first, e.g. ["2027", "27"] for a year or ["3", "03", "march", "mar"] for a month.
export type FormValues = Record<string, string[]>;

export function cardFormValues(card: CardData): FormValues {
  const values: FormValues = {};
  const add = (kind: string, ...candidates: (string | undefined)[]) => {
    const list = candidates.filter((value): value is string => Boolean(value));
    if (list.length > 0) values[kind] = [...new Set(list)];
  };
  const month = card.expMonth ? Number(card.expMonth) : undefined;
  const monthDate = month ? new Date(2000, month - 1, 1) : undefined;
  const year = card.expYear;
  const shortYear = year?.slice(-2);
  add("cc-name", card.cardholderName);
  add("cc-number", card.number);
  add("cc-csc", card.code);
  add("cc-type", card.brand);
  if (month) {
    add("cc-exp-month", String(month).padStart(2, "0"), String(month),
      monthDate!.toLocaleString("en", { month: "long" }), monthDate!.toLocaleString("en", { month: "short" }));
  }
  add("cc-exp-year", year, shortYear);
  // MM/YY first; a 4-character field gets MMYY.
  if (month && year) {
    const mm = String(month).padStart(2, "0");
    add("cc-exp", `${mm}/${shortYear}`, `${mm}/${year}`, `${mm}${shortYear}`);
  }
  return values;
}

export function identityFormValues(identity: IdentityData): FormValues {
  const values: FormValues = {};
  const add = (kind: string, ...candidates: (string | undefined)[]) => {
    const list = candidates.filter((value): value is string => Boolean(value));
    if (list.length > 0) values[kind] = [...new Set(list)];
  };
  add("honorific-prefix", identity.title);
  add("given-name", identity.firstName);
  add("additional-name", identity.middleName);
  add("family-name", identity.lastName);
  add("name", [identity.firstName, identity.middleName, identity.lastName].filter(Boolean).join(" "));
  add("organization", identity.company);
  add("email", identity.email);
  add("tel", identity.phone);
  add("username", identity.username);
  add("address-line1", identity.address1);
  add("address-line2", identity.address2);
  add("address-line3", identity.address3);
  add("street-address", [identity.address1, identity.address2, identity.address3].filter(Boolean).join("\n"));
  add("address-level2", identity.city);
  add("address-level1", identity.state);
  add("postal-code", identity.postalCode);
  // Country selects use either the ISO code or the English name.
  let countryName: string | undefined;
  try {
    countryName = identity.country && /^[a-z]{2}$/i.test(identity.country)
      ? new Intl.DisplayNames(["en"], { type: "region" }).of(identity.country.toUpperCase())
      : undefined;
  } catch {
    countryName = undefined;
  }
  add("country", identity.country, countryName);
  return values;
}

// Fills the active tab only after the user picks the item, like a login fill. Cards are refused on
// non-secure pages, as Chrome's own payment autofill does. Payment forms often sit in an iframe from
// the payment provider, so every frame is filled, but only visible, editable fields.
export async function fillFormActiveTab(values: FormValues, secureOnly: boolean): Promise<number> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined || !tab.url || !/^https?:\/\//i.test(tab.url)) {
    throw new Error("Open an HTTP or HTTPS page before filling.");
  }
  return fillFormInTab(tab.id, tab.url, values, secureOnly);
}

// `url` is the page Chrome reports for the tab (or the frame that asked), never a page-supplied value.
export async function fillFormInTab(tabId: number, url: string, values: FormValues, secureOnly: boolean): Promise<number> {
  if (secureOnly && new URL(url).protocol !== "https:") throw new Error("Cards are only filled on HTTPS pages.");
  const results = await chrome.scripting.executeScript({
    target: { tabId, allFrames: true },
    world: "ISOLATED",
    func: fillFormDocument,
    args: [values, secureOnly, FIELD_HINTS],
  });
  return results.reduce((total, frame) => total + (frame.result ?? 0), 0);
}

// Injected with chrome.scripting, so it must be self-contained: the shared hints arrive as an argument.
function fillFormDocument(values: Record<string, string[]>, secureOnly: boolean, hintSources: [string, string][]): number {
  if (secureOnly && !isSecureContext) return 0;
  const hints = hintSources.map(([kind, source]) => [kind, new RegExp(source)] as const);
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  const visible = (element: HTMLInputElement | HTMLSelectElement): boolean => {
    if (element.disabled || (element instanceof HTMLInputElement && (element.readOnly || element.type === "hidden"))) return false;
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity || "1") > 0 &&
      bounds.width > 1 && bounds.height > 1;
  };
  const kindOf = (element: HTMLInputElement | HTMLSelectElement): string | undefined => {
    const tokens = element.autocomplete.toLowerCase().split(/\s+/);
    const token = tokens.find((candidate) => Object.hasOwn(values, candidate));
    if (token) return token;
    if (element instanceof HTMLInputElement) {
      const type = element.type.toLowerCase();
      if (["password", "checkbox", "radio", "submit", "button", "file", "search"].includes(type)) return undefined;
      if (type === "email" && Object.hasOwn(values, "email")) return "email";
      if (type === "tel" && Object.hasOwn(values, "tel")) return "tel";
    }
    const label = [...(element.labels ?? [])].map((item) => item.textContent ?? "").join(" ");
    const hint = `${element.name} ${element.id} ${element.getAttribute("placeholder") ?? ""} ${element.getAttribute("aria-label") ?? ""} ${label}`
      .toLowerCase().replace(/\s+/g, " ").trim();
    return hints.find(([kind, pattern]) => Object.hasOwn(values, kind) && pattern.test(hint))?.[0];
  };
  const pick = (input: HTMLInputElement, list: string[]): string => {
    const hint = `${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`.toLowerCase();
    if (/yyyy/.test(hint)) return list.find((value) => /\d{4}/.test(value)) ?? list[0]!;
    if (/\byy\b|mm.?\/.?yy/.test(hint)) return list.find((value) => !/\d{4}/.test(value)) ?? list[0]!;
    return list.find((value) => input.maxLength <= 0 || value.length <= input.maxLength) ?? list[0]!;
  };
  const fire = (element: HTMLElement) => {
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    element.dispatchEvent(new Event("blur", { bubbles: true }));
  };
  let filled = 0;
  const fields = roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select")]).filter(visible);
  for (const field of fields) {
    const kind = kindOf(field);
    const list = kind && Object.hasOwn(values, kind) ? values[kind] : undefined;
    if (!list) continue;
    if (field instanceof HTMLSelectElement) {
      const wanted = list.map((value) => value.toLowerCase());
      const option = [...field.options].find((item) =>
        wanted.includes(item.value.toLowerCase()) || wanted.includes(item.text.trim().toLowerCase()) ||
        (/^\d+$/.test(item.value) && wanted.some((value) => /^\d+$/.test(value) && Number(value) === Number(item.value))));
      if (!option) continue;
      field.value = option.value;
      fire(field);
      filled += 1;
      continue;
    }
    const value = pick(field, list);
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(field, value);
    fire(field);
    if (field.value === value) filled += 1;
  }
  return filled;
}

// Puts a verification code into the code field(s) of the frames whose origin is in `allowedOrigins`.
// The caller has already checked that the entry is mapped to the tab's site.
export async function fillOtpInTab(tabId: number, code: string, allowedOrigins: string[]): Promise<number> {
  const results = await chrome.scripting.executeScript({
    target: { tabId, allFrames: true },
    world: "ISOLATED",
    func: fillOtpDocument,
    args: [code, allowedOrigins, OTP_HINT_SOURCES],
  });
  return results.reduce((total, frame) => total + (frame.result ?? 0), 0);
}

// Injected with chrome.scripting, so it must be self-contained. Mirrors looksLikeOtpField.
function fillOtpDocument(code: string, allowedOrigins: string[], [hintSource, notSource]: [string, string]): number {
  if (!allowedOrigins.includes(location.origin)) return 0;
  const hint = new RegExp(hintSource);
  const notCode = new RegExp(notSource);
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  const isCodeField = (input: HTMLInputElement): boolean => {
    if (input.disabled || input.readOnly || !["", "text", "tel", "number", "password"].includes(input.type.toLowerCase())) return false;
    const style = getComputedStyle(input);
    const bounds = input.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden" || bounds.width <= 1 || bounds.height <= 1) return false;
    const labels = [...(input.labels ?? [])].map((label) => label.textContent ?? "").join(" ");
    const text = `${input.autocomplete} ${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""} ${labels}`.toLowerCase();
    if (notCode.test(text)) return false;
    if (input.autocomplete.toLowerCase() === "one-time-code") return true;
    const fits = input.maxLength <= 0 || input.maxLength === 1 || input.maxLength >= 6;
    return fits && hint.test(text);
  };
  const set = (input: HTMLInputElement, value: string) => {
    input.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const fields = roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(isCodeField);
  // Split "one digit per box" controls get one character each.
  const boxes = fields.filter((input) => input.maxLength === 1);
  if (boxes.length >= code.length) {
    [...code].forEach((digit, index) => set(boxes[index]!, digit));
    return code.length;
  }
  const field = fields.find((input) => input.maxLength <= 0 || input.maxLength >= code.length);
  if (!field) return 0;
  set(field, code);
  return 1;
}
