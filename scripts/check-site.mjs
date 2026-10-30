// Browser checks for the in-page script and popup, driven by Playwright in the installed Chrome.
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
const bundle = await build({ entryPoints: ["src/site/index.ts"], bundle: true, write: false, format: "iife" });
// The pages stub chrome.*; chrome.i18n answers from the real English messages.
const messages = JSON.parse(await readFile("src/_locales/en/messages.json", "utf8"));
const withI18n = (page) => page.evaluate((messages) => {
  window.chrome.i18n = { getMessage: (key, values = []) => (messages[key]?.message ?? "").replace(/\$(\d)/g, (_, n) => values[n - 1] ?? "") };
}, messages);
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  for (const dismissSelector of [".dismiss", ".close"]) {
    const page = await browser.newPage();
    await page.route("https://example.com/**", (route) => route.fulfill({ contentType: "text/html", body: '<form><input name="username" autocomplete="username" value="alice"><input type="password" value="secret"><button>Sign in</button></form>' }));
    await page.goto("https://example.com/login");
    await page.clock.install({ time: new Date("2030-01-01T00:00:00Z") });
    await page.clock.pauseAt(new Date("2030-01-01T00:00:00Z"));
    await page.evaluate(() => {
      // Firnkey's overlays use closed shadow roots; open them here so the checks can click inside.
      const attachShadow = Element.prototype.attachShadow;
      Element.prototype.attachShadow = function (init) { return attachShadow.call(this, { ...init, mode: "open" }); };
      window.messages = [];
      window.promptSeconds = 10;
      window.chrome = { storage: { onChanged: { addListener: (listener) => { window.siteStorageListener = listener; } } }, runtime: { onMessage: { addListener: () => undefined }, sendMessage: async (message) => {
        window.messages.push(message);
        if (message.type === "site.save" && window.failSave) return { ok: false, error: "offline" };
        let data = { type: "done" };
        if (message.type === "site.suggestions") data = { type: "siteSuggestions", items: [] };
        if (message.type === "site.pendingPrompt") data = { type: "sitePrompt", prompt: null };
        if (message.type === "site.inspect") data = { type: "sitePrompt", prompt: {
          id: "prompt", action: "save", name: "Example", username: message.username,
          password: message.password, uri: message.url, expiresAt: Date.now() + window.promptSeconds * 1000,
        } };
        return { ok: true, data };
      } } };
      document.querySelector("form").addEventListener("submit", (event) => event.preventDefault());
    });
    await withI18n(page);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    // Save prompts are only offered for passwords the user typed, not ones the page pre-filled.
    await page.locator('input[type="password"]').fill("secret");
    await page.locator("form > button").click();
    await page.locator("#firnkey-save-prompt").waitFor();
    await page.clock.runFor(3_100);
    await page.locator(`#firnkey-save-prompt ${dismissSelector}`).click();
    await page.waitForTimeout(50);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 0, `${dismissSelector} must dismiss on the first click`);
    assert.equal(await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length), 1, "prompt controls must not capture credentials");
    await page.locator("form > button").click();
    await page.locator("#firnkey-save-prompt").waitFor();
    await page.clock.runFor(9_999);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 1);
    await page.clock.runFor(1);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 0, "default timeout must dismiss after ten seconds");
    await page.evaluate(() => { window.promptSeconds = 30; });
    await page.locator("form > button").click();
    await page.locator("#firnkey-save-prompt").waitFor();
    await page.clock.runFor(29_999);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 1);
    await page.clock.runFor(1);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 0, "configured timeout must be honored");
    await page.locator("form > button").click();
    await page.locator("#firnkey-save-prompt").waitFor();
    await page.locator("#firnkey-save-prompt .prompt-username").fill("edited");
    assert.equal(await page.locator("#firnkey-field-menu").count(), 0, "prompt fields must not open autofill menus");
    await page.clock.runFor(60_000);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 1, "the prompt must not vanish while the user is editing it");
    await page.locator('form > input[name="username"]').focus();
    await page.clock.runFor(1);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 0, "an expired prompt must close once focus leaves it");
    await page.evaluate(() => { window.promptSeconds = 10; window.failSave = true; });
    await page.locator("form > button").click();
    await page.locator("#firnkey-save-prompt").waitFor();
    await page.clock.runFor(3_100); // clicks only count once the prompt has been visible for a moment
    await page.locator("#firnkey-save-prompt .save").click();
    await page.clock.runFor(10_000);
    assert.equal(await page.locator("#firnkey-save-prompt").count(), 0, "failed saves must restore auto-dismissal");
    const capturesBeforeMfa = await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length);
    await page.evaluate(() => {
      const form = document.querySelector("form");
      form.innerHTML = '<input type="password" autocomplete="one-time-code" value="123456"><button>Verify</button>';
    });
    await page.locator("form > button").click();
    assert.equal(await page.evaluate(() => window.messages.filter((m) => m.type === "site.inspect").length), capturesBeforeMfa, "MFA codes must not be captured as new passwords");
    await page.close();
  }
  for (const origin of ["https://shop.example", "http://shop.example"]) {
    const page = await browser.newPage();
    await page.route(`${origin}/**`, (route) => route.fulfill({ contentType: "text/html", body: '<form><input id="full-name" autocomplete="name"><input id="cc" name="cardnumber" placeholder="Card number"><input id="cvv" type="password" name="cvv"><button>Pay</button></form>' }));
    await page.goto(`${origin}/checkout`);
    await page.clock.install({ time: new Date("2030-01-01T00:00:00Z") });
    await page.clock.pauseAt(new Date("2030-01-01T00:00:00Z"));
    await page.evaluate(() => {
      const attachShadow = Element.prototype.attachShadow;
      Element.prototype.attachShadow = function (init) { return attachShadow.call(this, { ...init, mode: "open" }); };
      window.messages = [];
      window.chrome = { storage: { onChanged: { addListener: () => undefined } }, runtime: { onMessage: { addListener: () => undefined }, sendMessage: async (message) => {
        window.messages.push(message);
        let data = { type: "done" };
        if (message.type === "site.suggestions") data = { type: "siteSuggestions", items: [] };
        if (message.type === "site.pendingPrompt") data = { type: "sitePrompt", prompt: null };
        if (message.type === "site.inspect") data = { type: "sitePrompt", prompt: null };
        if (message.type === "site.fillItem") data = { type: "fill", username: false, password: false, fields: 3 };
        if (message.type === "site.formItems") data = { type: "siteFormItems",
          cards: location.protocol === "https:" ? [{ id: "card-1", type: 3, name: "Visa", username: "", subtitle: "Visa *1111" }] : [],
          identities: [{ id: "identity-1", type: 4, name: "Me", username: "", subtitle: "Jane Doe" }] };
        return { ok: true, data };
      } } };
      document.querySelector("form").addEventListener("submit", (event) => event.preventDefault());
    });
    await withI18n(page);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const menu = page.locator("#firnkey-field-menu");
    const sent = (type) => page.evaluate((name) => window.messages.filter((m) => m.type === name), type);
    if (origin.startsWith("https")) {
      await page.locator("#cc").focus();
      await menu.getByText("Visa *1111").waitFor();
      await page.waitForTimeout(300); // Chrome reports the menu visible ~100 ms later, in real time
      await page.clock.runFor(3_100);
      await menu.locator(".choice").click();
      assert.deepEqual((await sent("site.fillItem")).map((m) => m.id), ["card-1"], "choosing a card must ask the background to fill it");
      assert.equal(await menu.count(), 0, "the menu must close after filling");
      await page.locator("#cvv").focus();
      await menu.getByText("Visa *1111").waitFor();
      assert.equal(await menu.locator(".generate-choice:not(.add-choice)").count(), 0, "a CVV box must offer cards, not a generated password");
    } else {
      await page.locator("#cc").focus();
      await page.clock.runFor(500);
      assert.equal(await menu.count(), 0, "cards must not be offered on HTTP pages");
    }
    await page.locator("#full-name").focus();
    await menu.getByText("Jane Doe").waitFor();
    const choiceFocused = () => menu.locator(".choice").evaluate((el) => el.getRootNode().activeElement === el);
    await page.keyboard.press("ArrowDown");
    assert.equal(await choiceFocused(), true, "ArrowDown must move from the field into the suggestions");
    await page.keyboard.press("ArrowUp");
    assert.equal(await page.evaluate(() => document.activeElement.id), "full-name", "ArrowUp from the first suggestion must return to the field");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Escape");
    assert.equal(await menu.count(), 0, "Escape must close the suggestions");
    assert.equal(await page.evaluate(() => document.activeElement.id), "full-name", "Escape must return focus to the field");
    await page.locator("#cvv").focus();
    await page.locator("#full-name").focus();
    await menu.getByText("Jane Doe").waitFor();
    await page.locator("#cvv").fill("123");
    await page.locator("form > button").click();
    assert.equal((await sent("site.inspect")).length, 0, "a typed CVV must not be offered as a login password");
    await page.close();
  }
  {
    // Multi-step sign-in: the account picked on the username step is filled again on the password step.
    const page = await browser.newPage();
    await page.route("https://accounts.example/**", (route) => route.fulfill({ contentType: "text/html", body: '<form><input id="user" name="username" autocomplete="username"><button>Next</button></form>' }));
    await page.goto("https://accounts.example/signin");
    await page.clock.install({ time: new Date("2030-01-01T00:00:00Z") });
    await page.clock.pauseAt(new Date("2030-01-01T00:00:00Z"));
    await page.evaluate(() => {
      const attachShadow = Element.prototype.attachShadow;
      Element.prototype.attachShadow = function (init) { return attachShadow.call(this, { ...init, mode: "open" }); };
      window.messages = [];
      window.chrome = { storage: { onChanged: { addListener: () => undefined } }, runtime: { onMessage: { addListener: () => undefined }, sendMessage: async (message) => {
        window.messages.push(message);
        let data = { type: "done" };
        if (message.type === "site.suggestions") data = { type: "siteSuggestions", passkeyOffer: false, passwordPending: false, items: [
          { id: "a", type: 1, name: "Work", username: "alice@work.example" }, { id: "b", type: 1, name: "Home", username: "alice@home.example" }] };
        if (message.type === "site.pendingPrompt") data = { type: "sitePrompt", prompt: null };
        if (message.type === "site.credential") data = { type: "siteCredential", username: "alice@home.example", password: "home secret" };
        if (message.type === "site.passwordAuto") data = { type: "sitePassword", result: { password: "home secret", itemName: "Home" } };
        return { ok: true, data };
      } } };
      document.querySelector("form").addEventListener("submit", (event) => event.preventDefault());
    });
    await withI18n(page);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const menu = page.locator("#firnkey-field-menu");
    await page.locator("#user").focus();
    await menu.getByText("alice@home.example").waitFor();
    await page.waitForTimeout(300);
    await page.clock.runFor(3_100);
    await menu.locator(".choice", { hasText: "Home" }).click();
    assert.equal(await page.locator("#user").inputValue(), "alice@home.example");
    const credential = await page.evaluate(() => window.messages.find((m) => m.type === "site.credential"));
    assert.equal(credential.usernameOnly, true, "a username-only step must say so");
    assert.equal(await page.evaluate(() => window.messages.some((m) => m.type === "site.passwordAuto")), false, "no password is asked for without a password field");
    await page.evaluate(() => { document.querySelector("form").innerHTML = '<input id="pass" type="password" autocomplete="current-password"><button>Sign in</button>'; });
    await page.clock.runFor(100); // the field watcher runs on the next animation frame
    await page.waitForFunction(() => document.querySelector("#pass")?.value === "home secret", null, { polling: 50, timeout: 5_000 });
    await page.locator("#pass").focus();
    await menu.locator(".choice").first().waitFor();
    assert.equal(await menu.locator(".choice strong").first().textContent(), "Home", "the chosen account must come first on the password step");
    await page.close();
  }
  {
    // Cards: "Add card" hands the form's values to Firnkey's editor, and a typed card is offered for saving.
    const page = await browser.newPage();
    await page.route("https://shop.example/**", (route) => route.fulfill({ contentType: "text/html", body: '<form><input id="cc" name="cardnumber" placeholder="Kartennummer"><input id="exp" placeholder="MM / YY"><input id="cvc" name="cvc"><input id="holder" placeholder="Karteninhaber"><button>Jetzt bezahlen</button></form>' }));
    await page.goto("https://shop.example/pay");
    await page.clock.install({ time: new Date("2030-01-01T00:00:00Z") });
    await page.clock.pauseAt(new Date("2030-01-01T00:00:00Z"));
    await page.evaluate(() => {
      const attachShadow = Element.prototype.attachShadow;
      Element.prototype.attachShadow = function (init) { return attachShadow.call(this, { ...init, mode: "open" }); };
      window.messages = [];
      window.chrome = { storage: { onChanged: { addListener: () => undefined } }, runtime: { onMessage: { addListener: () => undefined }, sendMessage: async (message) => {
        window.messages.push(message);
        let data = { type: "done" };
        if (message.type === "site.suggestions") data = { type: "siteSuggestions", items: [], passkeyOffer: false, passwordPending: false };
        if (message.type === "site.pendingPrompt") data = { type: "sitePrompt", prompt: null, formPrompt: null };
        if (message.type === "site.formItems") data = { type: "siteFormItems", cards: [], identities: [] };
        if (message.type === "site.inspectForm") data = { type: "sitePrompt", prompt: null, formPrompt: {
          id: "form", kind: "card", name: "Visa *4242", summary: "•••• 4242 · 03/2027", expiresAt: Date.now() + 10_000 } };
        return { ok: true, data };
      } } };
      document.querySelector("form").addEventListener("submit", (event) => event.preventDefault());
    });
    await withI18n(page);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const sent = (type) => page.evaluate((name) => window.messages.filter((m) => m.type === name), type);
    const menu = page.locator("#firnkey-field-menu");
    await page.locator("#cc").fill("4242 4242 4242 4242");
    await page.locator("#exp").fill("03/27");
    await page.locator("#holder").fill("Max Muster");
    await page.locator("#cc").focus();
    await menu.locator(".add-choice").waitFor();
    await page.waitForTimeout(300);
    await page.clock.runFor(3_100);
    await menu.locator(".add-choice").click();
    assert.deepEqual((await sent("site.addItem"))[0]?.card, { number: "4242424242424242", expMonth: "3", expYear: "2027", cardholderName: "Max Muster", brand: "Visa" },
      "Add card must hand over the form's card");
    await page.locator("form > button").click();
    const inspected = (await sent("site.inspectForm"))[0];
    assert.equal(inspected?.card?.number, "4242424242424242", "submitting a typed card must offer to save it");
    const prompt = page.locator("#firnkey-form-prompt");
    await prompt.getByText("•••• 4242 · 03/2027").waitFor();
    await page.waitForTimeout(300);
    await page.clock.runFor(3_100);
    await prompt.locator(".save").click();
    assert.deepEqual((await sent("site.saveForm")).map((m) => [m.promptId, m.name]), [["form", "Visa *4242"]]);
    await page.close();
  }
  const popup = await browser.newPage();
  const html = (await readFile("src/popup/index.html", "utf8")).replace(/<script[^>]*>[\s\S]*?<\/script>/g, "");
  await popup.route("https://extension.test/**", (route) => route.fulfill({ contentType: "text/html", body: html }));
  await popup.goto("https://extension.test/");
  await popup.evaluate(() => {
    window.itemName = "Before sync";
    window.syncListener = () => {};
    window.chrome = {
      tabs: { query: async () => [] },
      permissions: { contains: async () => false },
      storage: {
        onChanged: { addListener: (listener) => { window.syncListener = listener; } },
        session: { get: async () => ({}), remove: async () => undefined },
      },
      runtime: {
        getManifest: () => ({ version: "1.0.2" }),
        getURL: (path) => `https://extension.test${path}`,
        sendMessage: async (message) => {
          let data;
          if (message.type === "settings.get") data = {
            type: "settings", siteIntegrationEnabled: true, vaultTimeoutMinutes: 0,
            browserOptions: { askAddLogin: true, askUpdateLogin: true, savePromptTimeoutSeconds: 10, excludedDomains: [] },
            generatorOptions: { length: 22, uppercase: true, lowercase: true, numbers: true, symbols: true },
          };
          if (message.type === "app.getState") data = { type: "state", state: {
            phase: "unlocked", snapshot: { baseUrl: "https://vault.example.com" }, email: "alice@example.com", itemCount: 1, decryptionFailures: 0, accounts: [],
          } };
          if (message.type === "vault.list") data = { type: "items", folders: [], collections: [], items: [{ id: "login", type: 1, name: window.itemName, username: "alice", favorite: false, requiresReprompt: false, editable: true, matched: false }] };
          return { ok: true, data };
        },
      },
    };
  });
  const popupBundle = await build({ entryPoints: ["src/popup/index.ts"], bundle: true, write: false, format: "iife" });
  await withI18n(popup);
  await popup.addScriptTag({ content: popupBundle.outputFiles[0].text });
  await popup.getByText("Before sync", { exact: true }).waitFor();
  assert.equal(await popup.locator("#nav-vault").getAttribute("aria-current"), "page", "the active tab must be announced");
  assert.equal(await popup.locator('.item-main[role="button"]').count(), 1, "vault rows must be exposed as buttons");
  await popup.evaluate(() => { window.itemName = "After sync"; window.syncListener({ accountMetadata: { newValue: { lastSync: "new" } } }, "local"); });
  await popup.getByText("After sync", { exact: true }).waitFor({ timeout: 2_000 });
  await popup.locator("#add-login").click();
  await popup.locator("#login-name").fill("Unsaved draft");
  await popup.evaluate(() => window.syncListener({ accountMetadata: { newValue: { lastSync: "newer" } } }, "local"));
  assert.equal(await popup.locator("#login-name").inputValue(), "Unsaved draft");
  assert.equal(await popup.locator("#editor-view").isVisible(), true, "background sync must preserve the editor");
  await popup.close();
  console.log("Browser checks passed: popup refresh preserves drafts; first-click dismissal, isolated prompt controls, default and configured timeouts; card and identity menus, keyboard menu navigation, CVV handling, no cards on HTTP; chosen account first and its password filled on the next sign-in step; Add card hand-off and the card save offer.");
} finally {
  await browser.close();
}
