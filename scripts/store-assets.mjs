// Renders the Chrome Web Store screenshots and promo tiles into docs/store/ from the built extension
// with demo data (no server, no real secrets). Run `pnpm build` first, then `node scripts/store-assets.mjs`
// for English, or `node scripts/store-assets.mjs de` for German (written to docs/store/de/).
import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const LANG = process.argv[2] ?? "en";
const out = path.join(root, "docs/store", LANG === "en" ? "" : LANG);
const LOCALE = { en: "en-US", de: "de-AT" }[LANG];
const TEXT = {
  en: {
    page: { title: "Sign in to online banking", username: "Username", password: "Password", submit: "Sign in" },
    tagline: "Password manager for your own server",
    shots: [
      ["Your passwords,<br>light as firn.", "A small, fast password manager for your own self-hosted server. No tracking, no telemetry."],
      ["Fill logins where<br>you type.", "Matching logins appear right in the field. New and changed passwords are offered for saving."],
      ["Earlier passwords<br>stay at hand.", "Each login keeps its previous passwords, so a change never locks you out."],
      ["Every generated<br>password, and where.", "The generator remembers what you copied or used and on which website. Encrypted, only in your browser."],
    ],
  },
  de: {
    page: { title: "Beim Online-Banking anmelden", username: "Benutzername", password: "Passwort", submit: "Anmelden" },
    tagline: "Passwortmanager für deinen Server",
    shots: [
      ["Deine Passwörter,<br>leicht wie Firn.", "Ein kleiner, schneller Passwortmanager für deinen eigenen, selbst gehosteten Server. Kein Tracking, keine Telemetrie."],
      ["Ausfüllen, wo<br>du tippst.", "Passende Zugangsdaten erscheinen direkt im Feld. Neue und geänderte Passwörter werden zum Speichern angeboten."],
      ["Frühere Passwörter<br>bleiben griffbereit.", "Jeder Eintrag behält seine bisherigen Passwörter, damit dich eine Änderung nie aussperrt."],
      ["Jedes generierte<br>Passwort – und wo.", "Der Generator merkt sich, was du kopiert oder verwendet hast und auf welcher Website. Verschlüsselt, nur in deinem Browser."],
    ],
  },
}[LANG];
if (!TEXT) throw new Error(`No store texts for language ${LANG}.`);
const SITE = "https://konto.alpenbank.at/login";

const messages = JSON.parse(await readFile(path.join(dist, `_locales/${LANG}/messages.json`), "utf8"));
const icon = (await readFile(path.join(root, "src/assets/firnkey-icon.svg"), "utf8")).replace(/<title[^>]*>.*?<\/title>/, "");

const day = (offset) => new Date(Date.UTC(2026, 9, 30 - offset, 9 + offset, 41)).toISOString();
const login = (id, name, username, uri, extra = {}) => ({
  id, type: 1, name, username, uri, hasTotp: false, favorite: false, requiresReprompt: false, editable: true, matched: false, ...extra,
});
// A demo person per language, so no real name appears in the store images.
const [FIRST, LAST] = { en: ["john", "doe"], de: ["max", "mustermann"] }[LANG];
const EMAIL = `${FIRST}.${LAST}@bergpost.at`;
const items = [
  login("bank", "Alpenbank", `${FIRST}.${LAST}`, SITE, { matched: true, hasTotp: true, favorite: true }),
  login("bank-biz", "Alpenbank Business", `${LAST}-consulting`, "https://konto.alpenbank.at", { matched: true }),
  login("mail", "Bergpost Mail", EMAIL, "https://mail.bergpost.at", { favorite: true }),
  login("shop", "Gipfelshop", `${FIRST}@bergpost.at`, "https://www.gipfelshop.at"),
  login("cloud", "Firnstack Cloud", "admin", "https://console.firnstack.io", { hasTotp: true }),
  login("tickets", "Tauernbahn Tickets", `${FIRST}.${LAST}`, "https://tickets.tauernbahn.at"),
  login("forum", "Hüttenforum", "edelweiss_88", "https://huettenforum.at"),
  login("nas", "Home NAS", FIRST, "https://nas.home.arpa"),
];
const detail = {
  ...items[0], password: "Zirbe-Gams-Firn-7-Lärche", protected: false, uris: [{ uri: SITE, match: null }], totp: `otpauth://totp/Alpenbank:${FIRST}?secret=JBSWY3DPEHPK3PXP`,
  passwordHistory: [
    { password: "Alpen#2025-winter", lastUsedDate: day(30) },
    { password: "kT8$wq2!vLmz9Rx", lastUsedDate: day(190) },
  ],
};
const generatorHistory = [
  { password: "Zirbe-Gams-Firn-7-Lärche", date: day(0), site: "konto.alpenbank.at" },
  { password: "u7#Qe!xR2m@pV9zLk4sT", date: day(1), site: "www.gipfelshop.at" },
  { password: "Firn-Joch-Enzian-Murmel-3", date: day(3), site: "console.firnstack.io" },
  { password: "pK9!vT2#mQ7xL4@wZ8r", date: day(6) },
];
const settings = {
  type: "settings", siteIntegrationEnabled: true, vaultTimeoutMinutes: 15, clipboardClearSeconds: 30,
  browserOptions: { savePrompts: true, inlineMenu: true, liveSync: true, passkeys: true, basicAuth: false, excludedDomains: [] },
  generatorOptions: { type: "passphrase", length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true, words: 5, separator: "-", capitalize: true, includeNumber: true, username: { kind: "word", capitalize: false, includeNumber: false, email: "", domain: "" } },
};
const responses = {
  "app.getState": { type: "state", state: { phase: "unlocked", snapshot: { baseUrl: "https://vault.example.com", serverVersion: "1.34.3" }, accounts: [], email: EMAIL, itemCount: items.length, decryptionFailures: 0, lastSync: day(0) } },
  "settings.get": settings,
  "vault.list": { type: "items", items, folders: [], collections: [] },
  "vault.get": { type: "item", item: detail },
  "vault.totp": { type: "totp", code: "482913", period: 30, remaining: 21 },
  "send.list": { type: "sends", sends: [] },
  "authenticator.list": { type: "authenticatorEntries", entries: [] },
  "generator.history": { type: "generatorHistory", entries: generatorHistory },
  "site.suggestions": { type: "siteSuggestions", items: items.filter((item) => item.matched), passkeyOffer: false },
  "site.pendingPrompt": { type: "sitePrompt", prompt: null },
};

// Stands in for the chrome.* APIs the popup and site script use.
function chromeStub({ messages, responses, site, lang }) {
  const listeners = { addListener() {}, removeListener() {} };
  const store = { get: async () => ({}), set: async () => {}, remove: async () => {}, onChanged: listeners };
  globalThis.chrome = {
    i18n: {
      getMessage: (key, values = []) => (messages[key]?.message ?? "").replace(/\$(\d)/g, (_, n) => values[n - 1] ?? ""),
      getUILanguage: () => lang,
    },
    runtime: {
      id: "firnkey", getManifest: () => ({ version: "1.0.0", name: "Firnkey" }), getURL: (p) => `/${p}`,
      sendMessage: async (request) => {
        const data = responses[request.type] ?? { type: "done" };
        return { ok: true, data };
      },
      onMessage: listeners,
    },
    storage: { local: store, session: store, onChanged: listeners },
    tabs: { query: async () => [{ id: 1, url: site }], create: async () => {} },
    permissions: { contains: async () => true, request: async () => true, remove: async () => true },
  };
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, "http://x");
  if (url.pathname === "/demo-login") {
    response.setHeader("content-type", "text/html");
    response.end(DEMO_LOGIN);
    return;
  }
  try {
    const file = path.join(dist, decodeURIComponent(url.pathname));
    if (!file.startsWith(dist)) throw new Error("outside dist");
    const type = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" }[path.extname(file)] ?? "application/octet-stream";
    response.setHeader("content-type", type);
    response.end(await readFile(file));
  } catch {
    response.statusCode = 404;
    response.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const DEMO_LOGIN = `<!doctype html><meta charset="utf-8"><title>Alpenbank Login</title>
<style>
  body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#eef2f6;color:#1d2733}
  header{display:flex;align-items:center;gap:10px;padding:16px 32px;background:#14365a;color:#fff;font-weight:700;font-size:18px}
  header span{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:8px;background:#f2c654;color:#14365a}
  .card{width:360px;margin:56px auto;padding:28px 32px;border-radius:14px;background:#fff;box-shadow:0 10px 30px rgb(20 54 90 / 12%)}
  h1{margin:0 0 18px;font-size:22px} label{display:block;margin:12px 0 4px;font-size:13px;font-weight:600}
  input{box-sizing:border-box;width:100%;padding:10px 12px;border:1px solid #c5ced8;border-radius:8px;font:inherit}
  button{width:100%;margin-top:20px;padding:11px;border:0;border-radius:8px;background:#14365a;color:#fff;font:inherit;font-weight:700}
</style>
<header><span>A</span>Alpenbank</header>
<form class="card"><h1>${TEXT.page.title}</h1>
<label for="u">${TEXT.page.username}</label><input id="u" name="username" autocomplete="username">
<label for="p">${TEXT.page.password}</label><input id="p" name="password" type="password" autocomplete="current-password">
<button type="submit">${TEXT.page.submit}</button></form>`;

const browser = await chromium.launch();
await mkdir(out, { recursive: true });
const shots = {};

async function popupShot(name, prepare) {
  const page = await browser.newPage({ viewport: { width: 420, height: 600 }, deviceScaleFactor: 2, colorScheme: "dark", locale: LOCALE });
  await page.addInitScript(chromeStub, { messages, responses, site: SITE, lang: LANG });
  await page.goto(`${base}/popup/index.html`);
  await page.waitForTimeout(500);
  try {
    await prepare?.(page);
  } catch (error) {
    await page.screenshot({ path: path.join(out, `failed-${name}.png`) }); // What the step saw.
    throw error;
  }
  await page.waitForTimeout(300);
  shots[name] = (await page.screenshot({ clip: { x: 0, y: 0, width: 420, height: 600 } })).toString("base64");
  await page.close();
}

await popupShot("vault");
await popupShot("item", async (page) => {
  await page.locator(".item-name", { hasText: "Alpenbank" }).first().click();
  await page.waitForTimeout(400);
  await page.locator("details.password-history:not(#generator-history) summary").click();
  await page.evaluate(() => document.querySelector("details.password-history:not(#generator-history)")?.scrollIntoView({ block: "end" }));
});
await popupShot("generator", async (page) => {
  await page.locator("#nav-generator").click();
  await page.waitForTimeout(300);
  await page.locator("#generator-history summary").click();
  await page.waitForTimeout(300);
  await page.addStyleTag({ content: "#generator-refresh{scroll-margin-top:84px}" });
  await page.evaluate(() => document.querySelector("#generator-refresh")?.scrollIntoView({ block: "start" }));
});

// The in-page field menu on a demo login page.
{
  const page = await browser.newPage({ viewport: { width: 760, height: 560 }, deviceScaleFactor: 2, locale: LOCALE });
  await page.addInitScript(chromeStub, { messages, responses, site: SITE, lang: LANG });
  await page.goto(`${base}/demo-login`);
  await page.addScriptTag({ url: "/site.js" });
  await page.waitForTimeout(300);
  await page.locator("#u").click();
  await page.waitForTimeout(800);
  shots.site = (await page.screenshot()).toString("base64");
  await page.close();
}

const RIDGE = `<svg class="ridge" viewBox="0 0 1280 240" preserveAspectRatio="none"><path d="M0 200L180 110L290 170L470 40L650 160L760 110L930 190L1080 90L1280 170V240H0Z" fill="#fff" opacity=".06"/><path d="M0 230L220 160L400 210L600 120L820 220L1010 150L1280 220V240H0Z" fill="#fff" opacity=".05"/></svg>`;
const STYLE = `<style>
  *{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#f4f7fa;-webkit-font-smoothing:antialiased}
  .frame{position:relative;overflow:hidden;background:linear-gradient(160deg,#2f6894 0%,#163a5c 45%,#0b1d30 100%)}
  .ridge{position:absolute;left:0;right:0;bottom:0;width:100%;height:30%}
  .brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:-.01em}
  .brand svg{flex:none;filter:drop-shadow(0 4px 10px rgb(0 0 0 / 25%))}
  h1{margin:0;font-weight:750;letter-spacing:-.025em;line-height:1.08}
  p{margin:0;color:#c6d5e3;line-height:1.45}
  .shot{position:absolute;border-radius:18px;box-shadow:0 30px 70px rgb(3 12 24 / 55%),0 0 0 1px rgb(255 255 255 / 8%)}
  .window{position:absolute;overflow:hidden;border-radius:14px;background:#fff;box-shadow:0 30px 70px rgb(3 12 24 / 55%)}
  .bar{display:flex;align-items:center;gap:8px;height:40px;padding:0 14px;background:#e8edf2}
  .bar i{width:11px;height:11px;border-radius:50%;background:#c2cbd4}
  .bar span{flex:1;margin-left:14px;padding:5px 12px;border-radius:7px;background:#fff;color:#4a5866;font-size:13px}
  .window img{display:block}
</style>`;

const screenshots = ["vault", "site", "item", "generator"].map((shot, index) => ({
  shot, title: TEXT.shots[index][0], text: TEXT.shots[index][1], browser: shot === "site",
}));

const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
for (const [index, { shot, title, text, browser: framed }] of screenshots.entries()) {
  const image = `data:image/png;base64,${shots[shot]}`;
  const visual = framed
    ? `<div class="window" style="right:64px;top:118px;width:680px"><div class="bar"><i></i><i></i><i></i><span>konto.alpenbank.at/login</span></div><img src="${image}" width="680" height="501"></div>`
    : `<img class="shot" src="${image}" style="right:120px;top:60px;width:476px;height:680px">`;
  await page.setContent(`${STYLE}<div class="frame" style="width:1280px;height:800px">${RIDGE}
    <div style="position:absolute;left:96px;top:0;bottom:0;width:${framed ? 400 : 560}px;display:flex;flex-direction:column;justify-content:center;gap:26px">
      <div class="brand" style="font-size:24px">${icon.replace("<svg ", '<svg width="44" height="44" ')}Firnkey</div>
      <h1 style="font-size:${framed ? 46 : 54}px">${title}</h1>
      <p style="font-size:21px">${text}</p>
    </div>${visual}</div>`);
  await page.screenshot({ path: path.join(out, `screenshot-${index + 1}-${shot}.png`) });
}

const tiles = [
  { name: "promo-small-440x280", width: 440, height: 280, iconSize: 92, nameSize: 40, tagSize: 15 },
  { name: "promo-marquee-1400x560", width: 1400, height: 560, iconSize: 200, nameSize: 92, tagSize: 30 },
];
for (const tile of tiles) {
  await page.setViewportSize({ width: tile.width, height: tile.height });
  await page.setContent(`${STYLE}<div class="frame" style="width:${tile.width}px;height:${tile.height}px;display:flex;align-items:center;justify-content:center;gap:${tile.iconSize * 0.3}px">${RIDGE}
    ${icon.replace("<svg ", `<svg width="${tile.iconSize}" height="${tile.iconSize}" style="position:relative;filter:drop-shadow(0 ${tile.iconSize / 12}px ${tile.iconSize / 6}px rgb(0 0 0 / 30%))" `)}
    <div style="position:relative;display:grid;gap:${tile.tagSize * 0.4}px">
      <h1 style="font-size:${tile.nameSize}px">Firnkey</h1>
      <p style="font-size:${tile.tagSize}px;color:#d6e2ec">${TEXT.tagline}</p>
    </div></div>`);
  await page.screenshot({ path: path.join(out, `${tile.name}.png`) });
}

await browser.close();
server.close();
console.log("wrote", path.relative(root, out));
