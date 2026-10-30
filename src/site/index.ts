import type { ExtensionRequest, ExtensionResponse, ResponseData } from "../shared/messages";
import type { LoginWriteInput } from "../vault/encrypt-login";
import { canBeUsernameField, looksLikeOtpField, looksLikeUsernameField } from "./field-detection";
import { CARD_KINDS, classifyFormField, formData, IDENTITY_MENU_KINDS } from "../shared/form-fields";
import { icon as svgIcon } from "../shared/icons";
import { t } from "../shared/i18n";

// A message for an HTML template.
const h = (key: string) => t(key).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);

type Suggestion = Extract<ResponseData, { type: "siteSuggestions" }>["items"][number];
type FormItems = Omit<Extract<ResponseData, { type: "siteFormItems" }>, "type">;
type MenuFieldKind = "username" | "password" | "otp" | "card" | "identity";
interface MenuEntry {
  name: string;
  detail: string;
  favicon?: string;
  select: () => void;
}
type SitePrompt = NonNullable<Extract<ResponseData, { type: "sitePrompt" }>["prompt"]>;
type FormPrompt = NonNullable<Extract<ResponseData, { type: "sitePrompt" }>["formPrompt"]>;
type FormField = HTMLInputElement | HTMLSelectElement;

const marker = "data-firnkey-loaded";
let suggestions: Suggestion[] = [];
let suggestionsUrl = "";
let suggestionsLoad: Promise<void> | null = null;
// This page has an autofill passkey request that Firnkey can answer (top frame only).
let passkeyOffered = false;
let lastUsername = "";
let lastCapture = "";
let activeField: HTMLInputElement | null = null;
let activeFieldKind: MenuFieldKind | null = null;
// Cards and identities, loaded the first time a card or address field is focused on this page.
let formItems: FormItems | null = null;
let formItemsUrl = "";
let autoTotpUrl = "";
// Firnkey filled only a username in this tab (a multi-step sign-in); the next password field may get its password.
let passwordPending = false;
const askedPasswordFields = new WeakSet<HTMLInputElement>();
let activeSavePromptId: string | null = null;
let dismissActiveSavePrompt: (() => void) | null = null;
// Closed shadow roots keep page scripts from reading or clicking Firnkey's UI; keep our own handles here.
const overlayRoots = new WeakMap<HTMLElement, ShadowRoot>();
// Passwords the user typed (or Firnkey generated). Save prompts are only offered for these, so a page
// script cannot plant a password in a field and fake an "Update login" prompt.
const enteredPasswords = new WeakMap<HTMLInputElement, string>();
// Card and address fields the user typed into or picked from. Only these are offered for saving.
const typedFormFields = new WeakSet<FormField>();
let dismissFormPrompt: (() => void) | null = null;

if (!document.documentElement.hasAttribute(marker)) {
  document.documentElement.setAttribute(marker, "true");
  void initialize();
}

async function initialize(): Promise<void> {
  chrome.runtime.onMessage.addListener((message: { type?: string; offered?: unknown }, sender) => {
    if (sender.id !== chrome.runtime.id || message?.type !== "firnkey.passkeyOffer") return;
    passkeyOffered = message.offered === true;
    if (activeField?.isConnected && deepActiveInput() === activeField) activateField(activeField);
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.accountMetadata) {
      suggestionsUrl = "";
      formItems = null;
    }
  });
  document.addEventListener("focusin", handleFocus, true);
  document.addEventListener("input", rememberInput, true);
  document.addEventListener("submit", captureLogin, true);
  document.addEventListener("pointerdown", captureSubmitPointer, true);
  document.addEventListener("pointerdown", dismissFieldMenuOnOutsideClick, true);
  document.addEventListener("keydown", captureEnter, true);
  document.addEventListener("keydown", dismissOverlaysOnEscape, true);
  document.addEventListener("keydown", moveThroughFieldMenu, true);
  window.addEventListener("scroll", repositionOpenOverlay, true);
  window.addEventListener("resize", repositionOpenOverlay);
  observeDynamicCredentialFields();
  const [, pending] = await Promise.allSettled([
    loadSuggestions(),
    request({ type: "site.pendingPrompt" }),
  ]);
  if (pending.status === "fulfilled" && pending.value.type === "sitePrompt") {
    if (pending.value.prompt) renderSavePrompt(pending.value.prompt);
    if (pending.value.formPrompt) renderFormPrompt(pending.value.formPrompt);
  }
  const focused = deepActiveInput();
  if (focused && menuFieldKind(focused)) activateField(focused);
  maybeAutoFillPassword();
  maybeAutoFillTotp();
}

function handleFocus(event: FocusEvent): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  // Focus coming back from Firnkey's own menu (arrow keys, Escape) must not reopen it.
  if (event.relatedTarget instanceof Element && isExtensionElement(event.relatedTarget)) return;
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (!(input instanceof HTMLInputElement) || !menuFieldKind(input)) return;
  activateField(input);
}

function activateField(input: HTMLInputElement): void {
  activeField = input;
  activeFieldKind = menuFieldKind(input);
  if (activeFieldKind === "card" || activeFieldKind === "identity") {
    const kind = activeFieldKind;
    document.getElementById("firnkey-field-toggle")?.remove();
    void loadFormItems().then(() => {
      if (activeField === input && input.isConnected && menuFieldKind(input) === kind) showFormMenu(input, kind);
    });
    return;
  }
  if (isUsernameField(input) && input.value) lastUsername = input.value;
  void loadSuggestions().then(() => {
    if (activeField !== input || !input.isConnected || !isCredentialField(input)) return;
    if (isUsernameField(input)) showFieldToggle(input);
    else document.getElementById("firnkey-field-toggle")?.remove();
    showFieldMenu(input);
  });
}

async function loadSuggestions(): Promise<void> {
  const url = location.href;
  if (suggestionsUrl === url) return;
  if (suggestionsLoad) return suggestionsLoad.then(loadSuggestions);
  suggestionsLoad = request({ type: "site.suggestions", url }).then((matches) => {
    if (location.href !== url) return;
    suggestions = matches.type === "siteSuggestions" ? matches.items : [];
    passkeyOffered = matches.type === "siteSuggestions" && matches.passkeyOffer;
    passwordPending ||= matches.type === "siteSuggestions" && matches.passwordPending;
    suggestionsUrl = url;
  }).catch(() => {
    if (location.href === url) {
      suggestions = [];
      suggestionsUrl = url;
    }
  }).finally(() => { suggestionsLoad = null; });
  return suggestionsLoad;
}

function observeDynamicCredentialFields(): void {
  let scheduled = false;
  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const focused = deepActiveInput();
      const focusedKind = focused ? menuFieldKind(focused) : null;
      if (focused && focusedKind && (focused !== activeField || focusedKind !== activeFieldKind)) {
        activateField(focused);
      } else if (activeField && (!activeField.isConnected || !menuFieldKind(activeField))) {
        activeField = null;
        activeFieldKind = null;
        document.getElementById("firnkey-field-toggle")?.remove();
        closeFieldMenu();
      }
      maybeAutoFillPassword();
      maybeAutoFillTotp();
    });
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["type", "name", "id", "autocomplete", "placeholder", "aria-label", "aria-labelledby"],
  });
}

function rememberInput(event: Event): void {
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  const field = event.composedPath().find((target) => target instanceof HTMLInputElement || target instanceof HTMLSelectElement);
  if (event.isTrusted && field) typedFormFields.add(field as FormField);
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (!(input instanceof HTMLInputElement)) return;
  if (event.isTrusted && isPasswordField(input)) enteredPasswords.set(input, input.value);
  if (isUsernameField(input) && input.value) lastUsername = input.value;
}

function showFieldMenu(input: HTMLInputElement): void {
  closeFieldMenu();
  // Code fields offer the authenticator codes of this site's logins instead of the logins.
  const otp = isOtpField(input);
  const items = otp ? suggestions.filter((item) => item.hasTotp) : suggestions;
  const entries: MenuEntry[] = items.map((item) => ({
    name: item.name,
    detail: otp ? [t("verificationCode"), item.username].filter(Boolean).join(" · ") : item.username || t("login"),
    favicon: faviconUrl(item.uri),
    select: () => void (otp ? fillTotp(item.id, input) : fill(item.id, input)),
  }));
  if (passkeyOffered && !otp && isUsernameField(input)) {
    entries.unshift({ name: t("passkey"), detail: t("passkeySuggestion"), select: () => void choosePasskey() });
  }
  if (entries.length === 0 && (otp || input.type.toLowerCase() !== "password")) return;
  const { host, choices } = openFieldMenu(input, entries);
  if (!otp && input.type.toLowerCase() === "password") {
    const generate = document.createElement("button");
    generate.type = "button";
    generate.className = "generate-choice";
    generate.innerHTML = `${svgIcon("generate")}<span>${h("generateAndFill")}</span>`;
    generate.addEventListener("pointerdown", (event) => event.preventDefault());
    generate.addEventListener("click", userClick(host, () => void generateAndFill(input, host)));
    choices.append(generate);
  }
  setFieldToggleExpanded(true);
  positionHost(host, input);
}

function showFormMenu(input: HTMLInputElement, kind: "card" | "identity"): void {
  closeFieldMenu();
  const items = (kind === "card" ? formItems?.cards : formItems?.identities) ?? [];
  // With nothing saved yet, offer "Add" only in a real address form, not on every lone name field.
  if (items.length === 0 && kind === "identity" && formFields(input).filter((field) => fieldFormKind(field) === "identity").length < 3) return;
  const { host, choices } = openFieldMenu(input, items.map((item) => ({
    name: item.name,
    detail: item.subtitle || t(kind === "card" ? "card" : "identity"),
    select: () => void fillItem(item.id),
  })));
  const add = document.createElement("button");
  add.type = "button";
  add.className = "generate-choice add-choice";
  add.innerHTML = `${svgIcon("add")}<span>${h(kind === "card" ? "addCard" : "addIdentity")}</span>`;
  add.addEventListener("pointerdown", (event) => event.preventDefault());
  add.addEventListener("click", userClick(host, () => void addFormItem(input, kind, host)));
  choices.append(add);
  setFieldToggleExpanded(true);
  positionHost(host, input);
}

// Opens Firnkey's editor with what this form holds so far; the user reviews it there before saving.
async function addFormItem(input: HTMLInputElement, kind: "card" | "identity", host: HTMLElement): Promise<void> {
  try {
    const data = formData(formFields(input).map((field) => [classifyField(field) ?? "", field.value]));
    await request({ type: "site.addItem", url: location.href, kind, ...(kind === "card" ? { card: data.card } : { identity: data.identity }) });
    closeFieldMenu(host);
  } catch (error) {
    showTransient(error instanceof Error ? error.message : t("openFirnkeyToAdd"));
  }
}

// The visible card and address fields around `anchor`: its form, or the whole frame.
function formFields(anchor: HTMLInputElement | ParentNode): FormField[] {
  const scope = anchor instanceof HTMLInputElement ? anchor.form ?? document : anchor;
  const roots = scope === document ? allRoots() : [scope];
  return roots.flatMap((root) => [...root.querySelectorAll<FormField>("input, select")])
    .filter((field) => (field instanceof HTMLSelectElement ? !field.disabled && field.getClientRects().length > 0 : visible(field)) && fieldFormKind(field));
}

function classifyField(field: FormField): string | undefined {
  if (isExtensionElement(field)) return undefined;
  if (field instanceof HTMLInputElement && !["", "text", "tel", "number", "email", "password"].includes(field.type.toLowerCase())) return undefined;
  if (field instanceof HTMLInputElement && field.type.toLowerCase() === "password" && !/cvc|cvv|csc|cc-csc|pr(ü|ue)f/.test(inputHint(field))) return undefined;
  return classifyFormField(field.autocomplete, inputHint(field));
}

function fieldFormKind(field: FormField): "card" | "identity" | null {
  const kind = classifyField(field);
  if (!kind) return null;
  if (CARD_KINDS.has(kind)) return "card";
  return IDENTITY_MENU_KINDS.has(kind) || ["email", "tel"].includes(kind) ? "identity" : null;
}

// After a submit: a card or an address the user typed here, for the "Save to Firnkey" offer.
function inspectForm(scope: ParentNode): void {
  const typed = formFields(scope).filter((field) => typedFormFields.has(field));
  if (!typed.some((field) => fieldFormKind(field))) return;
  const data = formData(typed.map((field) => [classifyField(field) ?? "", field.value]));
  const card = location.protocol === "https:" && data.card.number ? data.card : undefined;
  const identity = Object.keys(data.identity).length > 0 ? data.identity : undefined;
  if (!card && !identity) return;
  void request({ type: "site.inspectForm", url: location.href, ...(card ? { card } : {}), ...(identity ? { identity } : {}) })
    .then((response) => {
      if (response.type === "sitePrompt" && response.formPrompt) renderFormPrompt(response.formPrompt);
    }).catch(() => undefined);
}

function openFieldMenu(input: HTMLInputElement, entries: MenuEntry[]): { host: HTMLDivElement; choices: HTMLDivElement } {
  const host = overlayHost("firnkey-field-menu", input);
  host.dataset.entries = String(entries.length);
  const root = overlayRoots.get(host)!;
  root.innerHTML = `<style>${styles}</style><div class="field-menu" role="group" aria-label="${h("suggestionsLabel")}"><div class="menu-title"><span>Firnkey</span><button class="menu-close" type="button" aria-label="${h("dismissSuggestions")}" title="${h("dismiss")}">${svgIcon("close")}</button></div><div class="choices"></div></div>`;
  const choices = root.querySelector<HTMLDivElement>(".choices")!;
  const close = root.querySelector<HTMLButtonElement>(".menu-close")!;
  close.addEventListener("pointerdown", (event) => event.preventDefault());
  close.addEventListener("click", userClick(host, () => closeFieldMenu(host)));
  for (const entry of entries) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "choice";
    const icon = document.createElement("span");
    icon.className = "site-icon";
    icon.textContent = entry.name.charAt(0).toUpperCase() || "L";
    if (entry.favicon) {
      const image = document.createElement("img");
      image.src = entry.favicon;
      image.alt = "";
      image.addEventListener("load", () => { icon.textContent = ""; icon.append(image); });
    }
    const copy = document.createElement("span");
    copy.className = "choice-copy";
    const name = document.createElement("strong");
    name.textContent = entry.name;
    const detail = document.createElement("span");
    detail.textContent = entry.detail;
    copy.append(name, detail);
    const glyph = document.createElement("span");
    glyph.className = "fill-glyph";
    glyph.innerHTML = svgIcon("fill");
    button.append(icon, copy, glyph);
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", userClick(host, entry.select));
    choices.append(button);
  }
  return { host, choices };
}

function showFieldToggle(input: HTMLInputElement): void {
  document.getElementById("firnkey-field-toggle")?.remove();
  if (!isUsernameField(input) || (suggestions.length === 0 && !passkeyOffered)) return;
  const host = overlayHost("firnkey-field-toggle", input);
  const root = overlayRoots.get(host)!;
  root.innerHTML = `<style>${styles}</style><button class="field-toggle" type="button" aria-label="${h("toggleSuggestions")}" aria-expanded="true" title="${h("toggleSuggestionsTitle")}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z"/><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z" transform="rotate(60 12 12)"/><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z" transform="rotate(120 12 12)"/><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z" transform="rotate(180 12 12)"/><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z" transform="rotate(240 12 12)"/><path d="M12 8.3C9.9 6.5 10.2 3.5 12 1.3C13.8 3.5 14.1 6.5 12 8.3Z" transform="rotate(300 12 12)"/><circle cx="12" cy="12" r="3.7"/><g fill="currentColor" stroke="none"><circle cx="12" cy="11.3" r="1.05"/><path d="M11.4 11.8 11 13.7h2l-.4-1.9Z"/></g></svg></button>`;
  const button = root.querySelector<HTMLButtonElement>(".field-toggle")!;
  button.addEventListener("pointerdown", (event) => event.preventDefault());
  button.addEventListener("click", userClick(host, () => {
    const menu = document.getElementById("firnkey-field-menu");
    if (menu) closeFieldMenu(menu);
    else showFieldMenu(input);
  }));
  positionFieldToggle(host, input);
}

// Arrow keys move from the field into the suggestions and back, so the menu works without a mouse.
function moveThroughFieldMenu(event: KeyboardEvent): void {
  if (!event.isTrusted || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
  const host = document.getElementById("firnkey-field-menu");
  const root = host && overlayRoots.get(host);
  if (!root) return;
  const buttons = [...root.querySelectorAll<HTMLButtonElement>(".choice, .generate-choice")];
  const current = buttons.indexOf(root.activeElement as HTMLButtonElement);
  if (current < 0 && (event.key === "ArrowUp" || event.target !== activeField)) return;
  event.preventDefault();
  event.stopPropagation();
  if (event.key === "ArrowUp" && current === 0) return activeField?.focus();
  buttons[Math.min(current + (event.key === "ArrowDown" ? 1 : -1), buttons.length - 1)]?.focus();
}

function closeFieldMenu(host = document.getElementById("firnkey-field-menu")): void {
  if (host) removeOverlay(host);
  setFieldToggleExpanded(false);
}

function setFieldToggleExpanded(expanded: boolean): void {
  const toggle = document.getElementById("firnkey-field-toggle");
  const button = toggle && overlayRoots.get(toggle)?.querySelector<HTMLButtonElement>(".field-toggle");
  button?.setAttribute("aria-expanded", String(expanded));
  button?.classList.toggle("expanded", expanded);
}

function dismissFieldMenuOnOutsideClick(event: PointerEvent): void {
  const host = document.getElementById("firnkey-field-menu");
  if (!host) return;
  const path = event.composedPath();
  const toggle = document.getElementById("firnkey-field-toggle");
  if (path.includes(host) || (toggle && path.includes(toggle)) || (activeField && path.includes(activeField))) return;
  closeFieldMenu(host);
}

function dismissOverlaysOnEscape(event: KeyboardEvent): void {
  if (event.key !== "Escape") return;
  const menu = document.getElementById("firnkey-field-menu");
  if (menu) {
    if (document.activeElement === menu) activeField?.focus();
    closeFieldMenu(menu);
    event.stopPropagation();
  }
  if (dismissActiveSavePrompt) {
    dismissActiveSavePrompt();
    event.stopPropagation();
  }
  if (dismissFormPrompt) {
    dismissFormPrompt();
    event.stopPropagation();
  }
}

async function fill(id: string, preferred: HTMLInputElement): Promise<void> {
  try {
    const password = preferred.type.toLowerCase() === "password" ? preferred : findPasswordField(preferred);
    const data = await request({ type: "site.credential", id, url: location.href, usernameOnly: !password });
    if (data.type !== "siteCredential") return;
    const username = findUsernameField(password, preferred);
    setInputValue(username, data.username);
    setInputValue(password, data.password);
    // Several accounts on one site: keep the chosen one first if this page asks again.
    const chosen = suggestions.findIndex((item) => item.id === id);
    if (chosen > 0) suggestions.unshift(...suggestions.splice(chosen, 1));
    if (!password) passwordPending = true;
    closeFieldMenu();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "Firnkey could not fill this login.");
  }
}

// Opens Firnkey's passkey window for the page's waiting request; the answer goes straight to the page.
async function choosePasskey(): Promise<void> {
  try {
    await request({ type: "site.passkeyChoose" });
    closeFieldMenu();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "Firnkey could not open the passkey window.");
  }
}

async function loadFormItems(): Promise<void> {
  if (formItems && formItemsUrl === location.href) return;
  try {
    const data = await request({ type: "site.formItems", url: location.href });
    if (data.type !== "siteFormItems") return;
    formItems = { cards: data.cards, identities: data.identities };
    formItemsUrl = location.href;
  } catch {
    formItems = null; // Locked or disabled: ask again on the next focus.
  }
}

// The background fills every frame of the tab, so card fields split across payment iframes all fill.
async function fillItem(id: string): Promise<void> {
  try {
    await request({ type: "site.fillItem", id, url: location.href });
    closeFieldMenu();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "Firnkey could not fill this item.");
  }
}

async function fillTotp(id: string, input: HTMLInputElement): Promise<void> {
  try {
    const data = await request({ type: "site.totp", id, url: location.href });
    if (data.type !== "totp") return;
    fillCode(input, data.code);
    closeFieldMenu();
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "Firnkey could not fill the verification code.");
  }
}

// After Firnkey filled only the username of a login, fill that login's password into the next step's
// password field (same tab, a few minutes, once). The background decides; it may say no.
function maybeAutoFillPassword(): void {
  if (!passwordPending) return;
  const field = credentialInputs().find((input) =>
    isPasswordField(input) && !input.value && input.autocomplete.toLowerCase() !== "new-password" && !askedPasswordFields.has(input));
  if (!field) return;
  askedPasswordFields.add(field);
  passwordPending = false;
  void request({ type: "site.passwordAuto", url: location.href }).then((data) => {
    if (data.type !== "sitePassword" || !data.result || !field.isConnected || field.value) return;
    setInputValue(field, data.result.password);
    field.focus();
    showTransient(t("passwordFilledFor", data.result.itemName));
  }).catch(() => undefined);
}

// After Firnkey filled this site's login in this tab, fill the next code field without a click.
// The background only answers for that login, for a few minutes; otherwise focusing suggests it.
function maybeAutoFillTotp(): void {
  if (autoTotpUrl === location.href) return;
  const field = credentialInputs().find((input) => isOtpField(input) && !input.value);
  if (!field) return;
  autoTotpUrl = location.href; // Ask once per page.
  void request({ type: "site.totpAuto", url: location.href }).then((data) => {
    if (data.type !== "siteTotp" || !data.result || !field.isConnected || field.value) return;
    fillCode(field, data.result.code);
    showTransient(`Firnkey filled the verification code for ${data.result.itemName}.`);
  }).catch(() => undefined);
}

// Fills a code field, or spreads the digits over a split "one box per digit" control.
function fillCode(input: HTMLInputElement, code: string): void {
  if (input.maxLength === 1) {
    let scope: Element | null = input.parentElement;
    for (let depth = 0; scope && depth < 4; depth += 1, scope = scope.parentElement) {
      const boxes = [...scope.querySelectorAll<HTMLInputElement>("input")].filter((box) => box.maxLength === 1 && visible(box));
      if (boxes.length >= code.length) {
        boxes.slice(0, code.length).forEach((box, index) => setInputValue(box, code[index]!));
        boxes[Math.min(code.length, boxes.length) - 1]?.focus();
        return;
      }
    }
  }
  setInputValue(input, code);
}

async function generateAndFill(input: HTMLInputElement, host: HTMLElement): Promise<void> {
  try {
    const data = await request({ type: "site.generatePassword", url: location.href });
    if (data.type !== "generatedPassword") return;
    setInputValue(input, data.password);
    enteredPasswords.set(input, data.password);
    input.focus();
    input.select();
    closeFieldMenu(host);
    showTransient("A generated password was filled. Save it after submitting this form.");
  } catch (error) {
    showTransient(error instanceof Error ? error.message : "Firnkey could not generate a password.");
  }
}

function captureLogin(event: Event): void {
  if (!event.isTrusted) return;
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  inspectCredentials(event.target instanceof HTMLFormElement ? event.target : document);
  inspectForm(event.target instanceof HTMLFormElement ? event.target : document);
}

function captureSubmitPointer(event: PointerEvent): void {
  if (!event.isTrusted) return;
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  const target = event.composedPath().find((value) => value instanceof Element);
  if (!(target instanceof Element)) return;
  const control = target.closest<HTMLElement>('button,input[type="submit"],[role="button"]');
  if (!control || !looksLikeSubmit(control)) return;
  const scope = control instanceof HTMLButtonElement || control instanceof HTMLInputElement ? control.form ?? document : document;
  inspectCredentials(scope);
  inspectForm(scope);
}

function captureEnter(event: KeyboardEvent): void {
  if (!event.isTrusted) return;
  if (event.composedPath().some((target) => target instanceof Element && isExtensionElement(target))) return;
  if (event.key !== "Enter") return;
  const input = event.composedPath().find((target) => target instanceof HTMLInputElement);
  if (input instanceof HTMLInputElement) {
    inspectCredentials(input.form ?? document);
    inspectForm(input.form ?? document);
  }
}

function looksLikeSubmit(control: HTMLElement): boolean {
  if (control instanceof HTMLInputElement) return control.type.toLowerCase() === "submit";
  if (control instanceof HTMLButtonElement && (control.type === "submit" || Boolean(control.form))) return true;
  const label = `${control.textContent ?? ""} ${control.getAttribute("aria-label") ?? ""}`.toLowerCase();
  return /sign\s*in|log\s*in|login|continue|submit|next|verify|\bpay\b|bezahl|kaufen|\bbuy\b|\border\b|bestell|checkout|kasse|\bsave\b|speichern|weiter/.test(label);
}

function inspectCredentials(scope: ParentNode): void {
  const passwordField = credentialInputs(scope).filter((input) => isPasswordField(input) && input.value).at(-1) ??
    findPasswordField();
  if (!passwordField?.value || enteredPasswords.get(passwordField) !== passwordField.value) return;
  const username = findUsernameField(passwordField)?.value || lastUsername;
  const fingerprint = `${location.origin}\0${username}\0${passwordField.value}`;
  if (fingerprint === lastCapture) return;
  lastCapture = fingerprint;
  setTimeout(() => { lastCapture = ""; }, 3_000);
  void request({
    type: "site.inspect",
    url: location.href,
    username,
    password: passwordField.value,
  }).then((data) => {
    if (data.type === "sitePrompt" && data.prompt) renderSavePrompt(data.prompt);
  }).catch(() => undefined);
}

function renderSavePrompt(prompt: SitePrompt): void {
  if (activeSavePromptId === prompt.id || prompt.expiresAt <= Date.now()) return;
  dismissActiveSavePrompt?.();
  activeSavePromptId = prompt.id;
  const host = overlayHost("firnkey-save-prompt");
  host.style.top = "18px";
  host.style.right = "18px";
  host.style.bottom = "auto";
  const root = overlayRoots.get(host)!;
  const update = prompt.action === "update";
  const heading = h(update ? "updateExistingLogin" : "saveLoginToFirnkey");
  root.innerHTML = `<style>${styles}</style><form class="prompt" aria-label="${heading}">
    <div class="prompt-heading"><strong>${heading}</strong><button class="close" type="button" aria-label="${h("notNow")}">${svgIcon("close")}</button></div>
    <label>${h("name")}<input class="prompt-name" maxlength="1000" required></label>
    <label>${h("username")}<input class="prompt-username" maxlength="1000"></label>
    <label>${h("password")}<div class="password-edit"><input class="prompt-password" type="password" maxlength="10000"><button class="show" type="button">${h("show")}</button></div></label>
    <label>${h("website")}<input class="prompt-uri" type="url" maxlength="8192"></label>
    <div class="prompt-actions"><button class="dismiss" type="button">${h("notNow")}</button><button class="save" type="submit">${h(update ? "update" : "save")}</button></div>
  </form>`;
  const form = root.querySelector<HTMLFormElement>("form")!;
  const name = root.querySelector<HTMLInputElement>(".prompt-name")!;
  const username = root.querySelector<HTMLInputElement>(".prompt-username")!;
  const password = root.querySelector<HTMLInputElement>(".prompt-password")!;
  const uri = root.querySelector<HTMLInputElement>(".prompt-uri")!;
  name.value = prompt.name;
  username.value = prompt.username ?? "";
  password.value = prompt.password ?? "";
  uri.value = prompt.uri ?? location.href;
  root.querySelector<HTMLButtonElement>(".show")!.addEventListener("click", trusted((event) => {
    const button = event.currentTarget as HTMLButtonElement;
    password.type = password.type === "password" ? "text" : "password";
    button.textContent = t(password.type === "password" ? "show" : "hide");
  }));
  let dismissed = false;
  const dismiss = () => {
    if (dismissed) return;
    dismissed = true;
    clearTimeout(dismissTimer);
    activeSavePromptId = null;
    dismissActiveSavePrompt = null;
    void request({ type: "site.dismiss", promptId: prompt.id }).catch(() => undefined);
    removeOverlay(host);
  };
  let dismissTimer = setTimeout(dismiss, Math.max(0, prompt.expiresAt - Date.now()));
  dismissActiveSavePrompt = dismiss;
  // Never vanish under the user: focus pauses the countdown, and asks the background to keep the
  // prompt saveable. Leaving untouched resumes a short countdown; after an edit it stays until it expires.
  let heldUntil = prompt.expiresAt;
  let edited = false;
  form.addEventListener("input", trusted(() => { edited = true; }));
  form.addEventListener("focusin", trusted(() => {
    clearTimeout(dismissTimer);
    if (heldUntil !== prompt.expiresAt) return;
    heldUntil = 0;
    void request({ type: "site.hold", promptId: prompt.id }).then((data) => {
      if (data.type === "sitePrompt" && data.prompt?.id === prompt.id) heldUntil = data.prompt.expiresAt;
    }).catch(() => undefined);
  }));
  form.addEventListener("focusout", trusted((event) => {
    if (form.contains((event as FocusEvent).relatedTarget as Node | null)) return;
    const until = Math.max(heldUntil, prompt.expiresAt) - Date.now();
    const untouched = Math.max(prompt.expiresAt - Date.now(), 3_000);
    dismissTimer = setTimeout(dismiss, Math.max(0, edited ? until : Math.min(until, untouched)));
  }));
  for (const button of root.querySelectorAll<HTMLButtonElement>(".dismiss,.close")) {
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", trusted(dismiss));
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!isUserAction(host, event)) return;
    const save = root.querySelector<HTMLButtonElement>(".save")!;
    save.disabled = true;
    clearTimeout(dismissTimer);
    save.textContent = t("saving");
    const login: LoginWriteInput = { name: name.value, username: username.value, password: password.value, uri: uri.value };
    void request({ type: "site.save", promptId: prompt.id, login }).then(() => {
      dismissed = true;
      activeSavePromptId = null;
      dismissActiveSavePrompt = null;
      removeOverlay(host);
      showTransient(t(update ? "loginUpdated" : "loginSaved"));
    }).catch((error: unknown) => {
      dismissTimer = setTimeout(dismiss, Math.max(0, Math.max(heldUntil, prompt.expiresAt) - Date.now()));
      save.disabled = false;
      save.textContent = t(update ? "update" : "save");
      showTransient(error instanceof Error ? error.message : t("saveFailed"));
    });
  });
}

// "Save this card / address to Firnkey?" A summary only: the page's own fields hold the details.
function renderFormPrompt(prompt: FormPrompt): void {
  if (prompt.expiresAt <= Date.now()) return;
  dismissFormPrompt?.();
  const host = overlayHost("firnkey-form-prompt");
  host.style.top = "18px";
  host.style.right = "18px";
  host.style.bottom = "auto";
  const root = overlayRoots.get(host)!;
  const heading = h(prompt.kind === "card" ? "saveCardToFirnkey" : "saveIdentityToFirnkey");
  root.innerHTML = `<style>${styles}</style><form class="prompt" aria-label="${heading}">
    <div class="prompt-heading"><strong>${heading}</strong><button class="close" type="button" aria-label="${h("notNow")}">${svgIcon("close")}</button></div>
    <p class="summary"></p>
    <label>${h("name")}<input class="prompt-name" maxlength="1000" required></label>
    <div class="prompt-actions"><button class="dismiss" type="button">${h("notNow")}</button><button class="save" type="submit">${h("save")}</button></div>
  </form>`;
  const form = root.querySelector<HTMLFormElement>("form")!;
  const name = root.querySelector<HTMLInputElement>(".prompt-name")!;
  root.querySelector<HTMLParagraphElement>(".summary")!.textContent = prompt.summary;
  name.value = prompt.name;
  let done = false;
  const close = (tellBackground: boolean) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (dismissFormPrompt === dismiss) dismissFormPrompt = null;
    if (tellBackground) void request({ type: "site.dismiss", promptId: prompt.id }).catch(() => undefined);
    removeOverlay(host);
  };
  const dismiss = () => close(true);
  dismissFormPrompt = dismiss;
  // Like the login prompt: it waits while the user is in it.
  let timer = setTimeout(dismiss, Math.max(0, prompt.expiresAt - Date.now()));
  form.addEventListener("focusin", trusted(() => clearTimeout(timer)));
  form.addEventListener("focusout", trusted((event) => {
    if (form.contains((event as FocusEvent).relatedTarget as Node | null)) return;
    timer = setTimeout(dismiss, 10_000);
  }));
  for (const button of root.querySelectorAll<HTMLButtonElement>(".dismiss,.close")) {
    button.addEventListener("pointerdown", (event) => event.preventDefault());
    button.addEventListener("click", trusted(dismiss));
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!isUserAction(host, event)) return;
    const save = root.querySelector<HTMLButtonElement>(".save")!;
    save.disabled = true;
    clearTimeout(timer);
    save.textContent = t("saving");
    void request({ type: "site.saveForm", promptId: prompt.id, name: name.value }).then(() => {
      close(false);
      showTransient(t("itemAdded", t(prompt.kind === "card" ? "card" : "identity")));
    }).catch((error: unknown) => {
      save.disabled = false;
      save.textContent = t("save");
      showTransient(error instanceof Error ? error.message : t("saveFailed"));
    });
  });
}

function overlayHost(id: string, anchor?: HTMLInputElement): HTMLDivElement {
  document.getElementById(id)?.remove();
  const host = document.createElement("div");
  host.id = id;
  host.style.cssText = "all:initial;display:block;position:fixed;inset:auto 18px 18px auto;margin:0;padding:0;border:0;background:transparent;overflow:visible;pointer-events:auto;z-index:2147483647;width:min(390px,calc(100vw - 24px))";
  if (anchor) host.dataset.anchor = "true";
  host.setAttribute("popover", "manual");
  overlayRoots.set(host, host.attachShadow({ mode: "closed" }));
  document.documentElement.append(host);
  showInTopLayer(host);
  trackVisibility(host);
  return host;
}

// Plays the panel's entrance backwards, from wherever it is now, then removes it. It stops taking
// clicks and loses its id at once, so a new overlay of the same kind can open meanwhile.
function removeOverlay(host: HTMLElement): void {
  host.removeAttribute("id");
  host.style.pointerEvents = "none";
  const panel = overlayRoots.get(host)?.querySelector<HTMLElement>(".field-menu,.prompt,.toast");
  if (!panel || !host.isConnected) return host.remove();
  const from = getComputedStyle(panel).getPropertyValue("--from").trim() || "none";
  panel.animate([{ opacity: 0, transform: from }], { duration: 150, easing: "ease-in" }).finished.then(
    () => host.remove(),
    () => host.remove(),
  );
}

function showInTopLayer(host: HTMLElement): void {
  try {
    host.showPopover();
  } catch {
    // Chrome versions without Popover API keep the maximum-z-index fallback.
  }
  requestAnimationFrame(() => {
    if (!host.isConnected) return;
    try {
      if (host.matches(":popover-open")) host.hidePopover();
      host.showPopover();
    } catch {
      document.documentElement.append(host);
    }
  });
}

function positionHost(host: HTMLElement, anchor: HTMLInputElement): void {
  if (!anchor.isConnected) return;
  const rect = anchor.getBoundingClientRect();
  const width = Math.max(280, Math.min(390, rect.width));
  const left = Math.max(8, Math.min(innerWidth - width - 8, rect.left));
  const entries = Number(host.dataset.entries ?? suggestions.length);
  const estimatedHeight = host.id === "firnkey-save-prompt" ? 390 : Math.min(360, 54 + entries * 66 + 44);
  const below = innerHeight - rect.bottom >= Math.min(estimatedHeight, 240);
  host.style.width = `${width}px`;
  host.style.right = "auto";
  host.style.bottom = "auto";
  host.dataset.side = below ? "below" : "above"; // The menu grows out of the field, from this side.
  host.style.left = `${left}px`;
  host.style.top = `${Math.max(8, below ? rect.bottom + 4 : rect.top - Math.min(estimatedHeight, rect.top - 8) - 4)}px`;
  restartVisibilityTimer(host);
}

function positionFieldToggle(host: HTMLElement, input: HTMLInputElement): void {
  if (!input.isConnected || !visible(input)) {
    host.remove();
    closeFieldMenu();
    return;
  }
  const rect = input.getBoundingClientRect();
  const size = Math.max(24, Math.min(34, rect.height - 8));
  host.style.width = `${size}px`;
  host.style.height = `${size}px`;
  host.style.right = "auto";
  host.style.bottom = "auto";
  host.style.left = `${Math.max(2, rect.right - size - 7)}px`;
  host.style.top = `${rect.top + Math.max(4, (rect.height - size) / 2)}px`;
  restartVisibilityTimer(host);
}

function repositionOpenOverlay(): void {
  if (!activeField) return;
  const menu = document.getElementById("firnkey-field-menu");
  if (menu) positionHost(menu, activeField);
  const toggle = document.getElementById("firnkey-field-toggle");
  if (toggle) positionFieldToggle(toggle, activeField);
}

function showTransient(message: string): void {
  const host = overlayHost("firnkey-toast");
  const root = overlayRoots.get(host)!;
  root.innerHTML = `<style>${styles}</style><div class="toast"></div>`;
  root.querySelector<HTMLDivElement>(".toast")!.textContent = message;
  setTimeout(() => removeOverlay(host), 3_500);
}

// Clickjacking guard. A click only counts once the overlay has been fully visible and in place for a
// moment: not covered by page content, and not made transparent, filtered, transformed or moved by
// page CSS. Chrome's IntersectionObserver v2 (trackVisibility) computes visibility from what is painted.
const MIN_VISIBLE_MS = 500;
const overlayVisibility = new WeakMap<HTMLElement, { visible: boolean; since: number; rect: string }>();

function trackVisibility(host: HTMLElement): void {
  const state = { visible: false, since: 0, rect: "" };
  overlayVisibility.set(host, state);
  const observer = new IntersectionObserver(([entry]) => {
    if (!host.isConnected) return observer.disconnect();
    state.visible = Boolean((entry as IntersectionObserverEntry & { isVisible?: boolean } | undefined)?.isVisible);
    restartVisibilityTimer(host);
  }, { trackVisibility: true, delay: 100 } as IntersectionObserverInit);
  observer.observe(host);
}

function restartVisibilityTimer(host: HTMLElement): void {
  const state = overlayVisibility.get(host);
  if (!state) return;
  state.since = performance.now();
  state.rect = rectKey(host);
}

function rectKey(element: Element): string {
  const { left, top, width, height } = element.getBoundingClientRect();
  return `${left},${top},${width},${height}`;
}

function isUserAction(host: HTMLElement, event: Event): boolean {
  const state = overlayVisibility.get(host);
  if (!event.isTrusted || !state?.visible) return false;
  if (rectKey(host) !== state.rect) {
    // Something other than Firnkey moved the overlay; make it sit still before accepting a click.
    restartVisibilityTimer(host);
    return false;
  }
  const style = getComputedStyle(host); // Visibility notifications lag by up to 100 ms.
  return style.opacity === "1" && style.visibility === "visible" &&
    performance.now() - state.since >= MIN_VISIBLE_MS;
}

function userClick<E extends Event>(host: HTMLElement, handler: (event: E) => void): (event: E) => void {
  return (event) => {
    if (isUserAction(host, event)) handler(event);
  };
}

// Page scripts can dispatch synthetic clicks; only act on real user input.
function trusted<E extends Event>(handler: (event: E) => void): (event: E) => void {
  return (event) => {
    if (event.isTrusted) handler(event);
  };
}

function isExtensionElement(element: Element): boolean {
  if (element.id.startsWith("firnkey-")) return true;
  const root = element.getRootNode();
  return root instanceof ShadowRoot && isExtensionElement(root.host);
}

function allRoots(): ParentNode[] {
  const roots: ParentNode[] = [document];
  for (let index = 0; index < roots.length; index += 1) {
    for (const element of roots[index]!.querySelectorAll<HTMLElement>("*")) {
      if (element.shadowRoot && !isExtensionElement(element)) roots.push(element.shadowRoot);
    }
  }
  return roots;
}

function credentialInputs(scope?: ParentNode): HTMLInputElement[] {
  const roots = scope && scope !== document ? [scope] : allRoots();
  return roots.flatMap((root) => [...root.querySelectorAll<HTMLInputElement>("input")]).filter(visible);
}

function findPasswordField(preferred?: HTMLInputElement): HTMLInputElement | undefined {
  if (preferred && isPasswordField(preferred) && visible(preferred)) return preferred;
  const passwords = credentialInputs().filter(isPasswordField);
  return passwords.find((input) => input.autocomplete.toLowerCase() === "current-password") ??
    passwords.find((input) => input.autocomplete.toLowerCase() !== "new-password") ?? passwords[0];
}

function findUsernameField(password?: HTMLInputElement, preferred?: HTMLInputElement): HTMLInputElement | undefined {
  if (preferred && preferred !== password && isUsernameField(preferred) && visible(preferred)) return preferred;
  const candidates = credentialInputs().filter((input) => input !== password && isUsernameField(input));
  const score = (input: HTMLInputElement): number => {
    const hint = inputHint(input);
    let value = 0;
    if (/username|user-name|login|email|e-mail/.test(hint)) value += 12;
    if (["username", "email"].includes(input.autocomplete.toLowerCase())) value += 15;
    if (input.type.toLowerCase() === "email") value += 10;
    if (/search|otp|code|phone|mobile|captcha/.test(hint)) value -= 20;
    if (password && input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) value += 3;
    return value;
  };
  return candidates.sort((left, right) => score(right) - score(left))[0];
}

function isPasswordField(input: HTMLInputElement): boolean {
  // Card security codes are often password-type fields; they are neither passwords nor worth saving.
  return input.type.toLowerCase() === "password" && !isOtpField(input) &&
    !/one-time-code|\botp\b|verification.?code|security.?code|authenticator.?code|\bcvv|\bcvc|\bcsc\b|cc-csc/.test(inputHint(input));
}

function isCredentialField(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  return isOtpField(input) || isPasswordField(input) || isUsernameField(input);
}

function isOtpField(input: HTMLInputElement): boolean {
  return !isExtensionElement(input) && looksLikeOtpField({
    type: input.type,
    autocomplete: input.autocomplete,
    inputHint: inputHint(input),
    maxLength: input.maxLength,
  });
}

// Which menu a field opens. Card fields win over login fields: a CVV box is often type="password".
function menuFieldKind(input: HTMLInputElement): MenuFieldKind | null {
  if (isExtensionElement(input)) return null;
  const type = input.type.toLowerCase();
  const kind = ["", "text", "tel", "number", "password"].includes(type)
    ? classifyFormField(input.autocomplete, inputHint(input))
    : undefined;
  if (kind && CARD_KINDS.has(kind)) return location.protocol === "https:" ? "card" : null;
  if (isCredentialField(input)) return fieldKind(input);
  return kind && type !== "password" && IDENTITY_MENU_KINDS.has(kind) ? "identity" : null;
}

function fieldKind(input: HTMLInputElement): "username" | "password" | "otp" {
  if (isOtpField(input)) return "otp";
  return input.type.toLowerCase() === "password" ? "password" : "username";
}

function isUsernameField(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  const type = input.type.toLowerCase();
  const hint = inputHint(input);
  const root = input.getRootNode();
  const scope = input.form ?? (root instanceof Document || root instanceof ShadowRoot ? root : document);
  const eligibleFieldCount = credentialInputs(scope).filter((candidate) =>
    canBeUsernameField(candidate.type, inputHint(candidate)),
  ).length;
  return looksLikeUsernameField({
    type,
    autocomplete: input.autocomplete,
    inputHint: hint,
    contextHint: credentialContextHint(input),
    eligibleFieldCount,
  });
}

function inputHint(input: FormField): string {
  const root = input.getRootNode();
  const labelledBy = (input.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter(Boolean)
    .map((id) => root instanceof Document || root instanceof ShadowRoot ? root.getElementById(id)?.textContent ?? "" : "")
    .join(" ");
  const labels = [...(input.labels ?? [])].map((label) => label.textContent ?? "").join(" ");
  return `${input.autocomplete} ${input.name} ${input.id} ${input.getAttribute("placeholder") ?? ""} ${input.getAttribute("aria-label") ?? ""} ${labelledBy} ${labels}`.toLowerCase();
}

function credentialContextHint(input: HTMLInputElement): string {
  const form = input.form;
  const controls = form ? [...form.querySelectorAll<HTMLElement>('button,input[type="submit"],[role="button"]')]
    .map((control) => `${control.textContent ?? ""} ${control.getAttribute("aria-label") ?? ""}`)
    .join(" ") : "";
  return `${document.title} ${location.pathname} ${form?.id ?? ""} ${form?.getAttribute("name") ?? ""} ${form?.getAttribute("action") ?? ""} ${form?.getAttribute("aria-label") ?? ""} ${controls}`;
}

function visible(input: HTMLInputElement): boolean {
  if (isExtensionElement(input)) return false;
  if (input.disabled || input.readOnly || input.type.toLowerCase() === "hidden") return false;
  const bounds = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return bounds.width > 1 && bounds.height > 1 && input.getClientRects().length > 0 &&
    style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity || "1") > 0;
}

function setInputValue(input: HTMLInputElement | undefined, value: string): boolean {
  if (!input || !value) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
  try {
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
  } catch {
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

function deepActiveInput(): HTMLInputElement | null {
  let active: Element | null = document.activeElement;
  while (active instanceof HTMLElement && active.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active instanceof HTMLInputElement ? active : null;
}

function faviconUrl(uri?: string): string {
  try {
    return `${new URL(uri ?? location.href).origin}/favicon.ico`;
  } catch {
    return `${location.origin}/favicon.ico`;
  }
}

async function request(value: ExtensionRequest): Promise<ResponseData> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) throw new Error("Firnkey is unavailable.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

const styles = `
  *{box-sizing:border-box;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
  button,input{font:inherit}button{cursor:pointer}.field-menu,.prompt{overflow:hidden;border:1px solid #2f5274;border-radius:16px;background:#12293f;color:#f0f6f8;box-shadow:0 12px 32px #020a1499}
  .menu-title{display:flex;min-height:38px;align-items:center;justify-content:space-between;gap:8px;padding:5px 7px 5px 12px;border-bottom:1px solid #23405e;color:#9db2c6;font-size:11px;font-weight:700}.menu-close{display:grid;width:28px;height:28px;padding:0;place-items:center;border:0;border-radius:7px;background:transparent;color:#c9d7e4;font-size:20px;line-height:1}.menu-close:hover,.menu-close:focus-visible{background:#1f3d5c;color:#fff;outline:none}
  .field-toggle{display:grid;width:100%;height:100%;padding:4px;place-items:center;border:1px solid #f0f8f838;border-radius:8px;background:linear-gradient(160deg,#2a5b85,#163453);color:#f0f8f8;box-shadow:0 2px 8px #020a1466}.field-toggle:hover,.field-toggle:focus-visible,.field-toggle.expanded{background:linear-gradient(160deg,#336a98,#1c3f63);outline:none}.field-toggle svg>path{fill:#f0f8f8}.field-toggle svg>circle{fill:#f0c050;stroke:#d8a838}.field-toggle svg>g{fill:#13263b}.field-toggle svg{width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
  .choices{max-height:310px;overflow:auto}.choice,.generate-choice{display:flex;width:100%;align-items:center;gap:11px;padding:10px 12px;border:0;border-bottom:1px solid #1f3a56;background:#12293f;color:#f0f6f8;text-align:left}
  .choice:hover,.generate-choice:hover{background:#1a3550}.site-icon{display:grid;width:34px;height:34px;flex:none;overflow:hidden;place-items:center;border-radius:7px;background:#0a1a2b;color:#d5e1ec;font-weight:800}.site-icon img{width:24px;height:24px;object-fit:contain}
  .choice-copy{display:grid;min-width:0;flex:1;gap:2px}.choice-copy strong,.choice-copy span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.choice-copy strong{font-size:13px}.choice-copy span{color:#a9bdd0;font-size:11px}.fill-glyph{color:#f0c050}.generate-choice{justify-content:center;border-bottom:0;color:#f0c050;font-size:12px;font-weight:700}
  .prompt{max-height:calc(100vh - 16px);overflow:auto;padding:14px}.summary{margin:0 0 4px;color:#c9d7e4;font-size:12px;line-height:1.4;overflow-wrap:anywhere}.prompt-heading{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}.prompt-heading strong{font-size:14px}.close{display:grid;width:28px;height:28px;padding:0;place-items:center;border:0;border-radius:7px;background:transparent;color:#c9d7e4;font-size:20px}.close:hover{background:#1f3d5c}
  .prompt label{display:grid;gap:4px;margin-top:8px;color:#b4c6d6;font-size:11px;font-weight:700}.prompt input{width:100%;height:34px;padding:6px 9px;border:1px solid #2f5274;border-radius:7px;background:#0a1a2b;color:#f0f6f8;outline:none}.prompt input:focus{border-color:#f0c050;box-shadow:0 0 0 3px #f0c05038}.password-edit{display:flex;gap:6px}.password-edit input{flex:1}.show{min-width:54px;border:1px solid #2f5274;border-radius:7px;background:#18324d;color:#fff;font-size:11px;font-weight:700}
  .prompt-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:13px}.prompt-actions button{height:34px;padding:0 13px;border:1px solid #2f5274;border-radius:10px;font-size:11px;font-weight:700}.save{border-color:#f0c050;background:#f0c050;color:#13263b}.save:hover{background:#f6d27c}.dismiss{background:#18324d;color:#f0f6f8}
  .icon{display:block;width:18px;height:18px;flex:none}.generate-choice{gap:8px}
  .choice:active,.generate-choice:active{background:#21405f}.prompt-actions button:active,.show:active{transform:scale(.97)}
  @keyframes lv-in{from{opacity:0;transform:var(--from)}}
  .field-menu,.prompt,.toast{animation:lv-in 180ms cubic-bezier(.32,.72,0,1)}
  .field-menu{--from:scale(.96);transform-origin:top center}:host([data-side=above]) .field-menu{transform-origin:bottom center}
  .prompt{--from:translateY(-8px)}.toast{--from:translateY(8px)}
  @media (prefers-reduced-motion:reduce){.field-menu,.prompt,.toast{--from:none}}
  .toast{max-width:390px;padding:11px 14px;border:1px solid #2f5274;border-radius:14px;background:#12293f;color:#f0f6f8;box-shadow:0 8px 26px #020a1499;font:12px Inter,system-ui,sans-serif}
`;
