import { readBrowserIntegrationOptions } from "../shared/settings";

const SCRIPT_ID = "firnkey-site-integration";
const PASSKEY_SCRIPT_IDS = ["firnkey-passkey-page", "firnkey-passkey-bridge"];
// WebAuthn needs a secure context; localhost is allowed for development.
const PASSKEY_MATCHES = ["https://*/*", "http://localhost/*"];
const STORAGE_KEY = "firnkey.siteIntegrationEnabled";

export async function siteIntegrationEnabled(): Promise<boolean> {
  const value = await chrome.storage.local.get(STORAGE_KEY);
  return value[STORAGE_KEY] === true;
}

export async function configureSiteIntegration(enabled: boolean): Promise<void> {
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID, ...PASSKEY_SCRIPT_IDS] });
  if (existing.length > 0) await chrome.scripting.unregisterContentScripts({ ids: existing.map((script) => script.id) });
  if (enabled) {
    const granted = await chrome.permissions.contains({ origins: ["https://*/*", "http://*/*"] });
    if (!granted) throw new Error("Website access was not granted.");
    await chrome.scripting.registerContentScripts([
      {
        id: SCRIPT_ID,
        js: ["site.js"],
        matches: ["https://*/*", "http://*/*"],
        allFrames: true,
        runAt: "document_idle",
        persistAcrossSessions: true,
      },
    ]);
    if ((await readBrowserIntegrationOptions()).askPasskeys) {
      // Both run at document_start so pages that ask for passkeys while loading are covered.
      // Top frame only: the background also refuses passkey requests from frames.
      await chrome.scripting.registerContentScripts([
        {
          id: PASSKEY_SCRIPT_IDS[0]!,
          js: ["passkey-page.js"],
          matches: PASSKEY_MATCHES,
          runAt: "document_start",
          world: "MAIN",
          persistAcrossSessions: true,
        },
        {
          id: PASSKEY_SCRIPT_IDS[1]!,
          js: ["passkey-bridge.js"],
          matches: PASSKEY_MATCHES,
          runAt: "document_start",
          persistAcrossSessions: true,
        },
      ]);
    }
  }
  await chrome.storage.local.set({ [STORAGE_KEY]: enabled });
}

export async function restoreSiteIntegration(): Promise<void> {
  if (await siteIntegrationEnabled()) await configureSiteIntegration(true);
}
