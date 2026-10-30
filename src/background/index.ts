import { VaultwardenClient } from "../api/vaultwarden-client";
import { normalizeServerEnvironment } from "../shared/environment";
import {
  isExtensionRequest,
  type ExtensionRequest,
  type ExtensionResponse,
  type ResponseData,
} from "../shared/messages";
import { readAuthSession, writeAuthSession, writeServerSnapshot, type ServerSnapshot } from "../shared/storage";
import {
  LOCK_ON_SYSTEM_LOCK,
  isUrlExcluded,
  readBrowserIntegrationOptions,
  readClipboardClearSeconds,
  readGeneratorOptions,
  readVaultTimeoutMinutes,
  writeBrowserIntegrationOptions,
  writeClipboardClearSeconds,
  writeGeneratorOptions,
  writeVaultTimeoutMinutes,
} from "../shared/settings";
import { generatePassphrase, generatePassword } from "../crypto/password-generator";
import { VaultController } from "./vault-controller";
import { PasskeyPrompts } from "./passkeys";
import { configureSiteIntegration, restoreSiteIntegration, siteIntegrationEnabled } from "./site-integration";
import { AUTO_LOCK_ALARM, installToolbar, refreshBadges, touchAutoLock } from "./toolbar";
import { clearClipboard } from "../shared/offscreen";
import { clearBiometricUnlock } from "../shared/biometric";
import { fromBase64 } from "../crypto/bytes";
import { PushSync } from "./push-sync";
import { installBasicAuth } from "./basic-auth";

const client = new VaultwardenClient();
const controller = new VaultController();
const passkeys = new PasskeyPrompts(controller);
const SYNC_ALARM = "firnkey-sync";
const CLIPBOARD_ALARM = "firnkey-clear-clipboard";
const CLIPBOARD_DIGEST_KEY = "firnkey.clipboardDigest";
// Requests sent automatically (popup refreshes, page loads, form submits) are not user activity,
// so they must not keep an otherwise idle vault unlocked.
const PASSIVE_REQUESTS = new Set<ExtensionRequest["type"]>([
  "app.getState", "vault.list", "send.list", "authenticator.list", "site.suggestions", "site.pendingPrompt", "site.formItems", "site.totpAuto", "site.inspect",
  // Pages ask for passkeys on load; only the user's answer in Firnkey's window counts as activity.
  "site.passkeyCreate", "site.passkeyGet", "site.passkeyAbort",
]);

// Check on each worker start: Chrome can clear alarms when the browser restarts.
void chrome.alarms.get(SYNC_ALARM).then((alarm) => {
  if (alarm?.periodInMinutes !== 1) return chrome.alarms.create(SYNC_ALARM, { periodInMinutes: 1 });
}).catch(() => undefined);
chrome.tabs.onRemoved.addListener((tabId) => {
  void controller.clearPendingSiteLogins(tabId);
  controller.forgetTab(tabId);
});

installToolbar(controller);
installBasicAuth((url) => controller.basicAuthCredential(url));
// Saving settings is a non-passive request, so turning Live sync off closes the socket right away.
const push = new PushSync(
  async () => ((await readBrowserIntegrationOptions()).liveSync ? controller.pushTarget() : null),
  () => void backgroundSync().catch(() => undefined),
);
void push.update();
globalThis.addEventListener("online", () => void push.update());

void restoreSiteIntegration().catch(() => configureSiteIntegration(false));

void chrome.storage.session
  .setAccessLevel({ accessLevel: chrome.storage.AccessLevel.TRUSTED_CONTEXTS })
  .catch(() => undefined);

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !isExtensionRequest(message)) {
    return false;
  }
  // Content scripts share the extension ID; only Firnkey's own pages may use non-website actions.
  if (!message.type.startsWith("site.") && !sender.url?.startsWith(chrome.runtime.getURL(""))) {
    sendResponse({ ok: false, error: "This request is not allowed from a website." } satisfies ExtensionResponse);
    return false;
  }
  void dispatch(message, sender)
    .then(async (data) => {
      const state = await controller.getState();
      if (!PASSIVE_REQUESTS.has(message.type)) {
        await touchAutoLock(state.phase === "unlocked");
        void refreshBadges(controller);
      }
      sendResponse({ ok: true, data } satisfies ExtensionResponse);
      // Sign-in, logout and account switches change which account the socket should follow.
      if (!PASSIVE_REQUESTS.has(message.type)) void push.update();
    })
    .catch((error: unknown) => {
      sendResponse({ ok: false, error: publicError(error) } satisfies ExtensionResponse);
    });
  return true;
});

chrome.idle.onStateChanged.addListener((state) => {
  if (state !== "locked") return;
  void readVaultTimeoutMinutes().then((minutes) => {
    if (minutes === LOCK_ON_SYSTEM_LOCK) return controller.lock().then(() => refreshBadges(controller));
  }).catch(() => undefined);
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) void controller.lock().then(() => refreshBadges(controller)).catch(() => undefined);
  if (alarm.name === CLIPBOARD_ALARM) {
    void chrome.storage.session.get(CLIPBOARD_DIGEST_KEY)
      .then((stored) => clearClipboard(stored[CLIPBOARD_DIGEST_KEY] as string | null | undefined))
      .then(() => chrome.storage.session.remove(CLIPBOARD_DIGEST_KEY))
      .catch(() => undefined);
  }
  // Offline, polling would only log failed requests; it resumes on the next alarm after reconnecting.
  if (alarm.name === SYNC_ALARM && navigator.onLine !== false) {
    // With a live socket the server pushes changes, so polling only runs while it is down.
    void push.update()
      .then(() => (push.connected ? undefined : backgroundSync()))
      .catch(() => undefined); // Offline/expired sessions retry on the next alarm; manual sync reports errors.
  }
});

async function backgroundSync(): Promise<void> {
  const state = await controller.getState();
  if (state.phase === "locked" || state.phase === "unlocked") await controller.sync();
  if (state.phase === "unlocked") await refreshBadges(controller);
}

async function dispatch(request: ExtensionRequest, sender: chrome.runtime.MessageSender): Promise<ResponseData> {
  switch (request.type) {
    case "app.getState":
      return { type: "state", state: await controller.getState() };
    case "server.check": {
      const environment = normalizeServerEnvironment(request.baseUrl);
      const server = await client.checkServer(environment.baseUrl);
      const snapshot: ServerSnapshot = {
        baseUrl: server.baseUrl,
        ...(server.serverVersion === undefined ? {} : { serverVersion: server.serverVersion }),
      };
      await writeServerSnapshot(snapshot);
      return { type: "server", snapshot };
    }
    case "auth.login":
      return { type: "login", result: await controller.login(request) };
    case "auth.sendEmailCode":
      await controller.sendTwoFactorEmail(request.baseUrl, request.email, request.masterPassword);
      return { type: "done" };
    case "auth.unlock": {
      const result = await controller.unlock(request.masterPassword);
      return { type: "unlock", ...result };
    }
    case "auth.lock":
      await controller.lock();
      return { type: "done" };
    case "auth.logout":
      await controller.logout();
      return { type: "done" };
    case "biometric.enable":
      await controller.enableBiometricUnlock(request.credentialId, fromBase64(request.prfOutput));
      return { type: "done" };
    case "biometric.unlock":
      return { type: "unlock", ...(await controller.unlockWithBiometric(fromBase64(request.prfOutput))) };
    case "biometric.disable":
      await clearBiometricUnlock();
      return { type: "done" };
    case "account.switch":
      await controller.switchAccount(request.id);
      return { type: "done" };
    case "account.add":
      await controller.addAccount();
      return { type: "done" };
    case "account.remove":
      await controller.removeAccount(request.id);
      return { type: "done" };
    case "vault.sync":
      return { type: "sync", ...(await controller.sync()) };
    case "vault.list":
      return { type: "items", ...(await controller.list(request)) };
    case "vault.get":
      return { type: "item", item: await controller.detail(request.id, request.currentUrl) };
    case "vault.authorize":
      await controller.authorizeReprompt(request.id, request.masterPassword);
      return { type: "done" };
    case "vault.totp":
      return { type: "totp", ...(await controller.totp(request.id)) };
    case "vault.fill":
      return { type: "fill", ...(await controller.fill(request.id)) };
    case "vault.create":
      await controller.createLogin(request.login, undefined, request.collectionId);
      return { type: "done" };
    case "vault.update":
      await controller.updateLogin(request.id, request.login);
      return { type: "done" };
    case "vault.createItem":
      await controller.createItem(request.item, request.collectionId);
      return { type: "done" };
    case "vault.move":
      await controller.moveToCollection(request.id, request.collectionId);
      return { type: "done" };
    case "attachment.download":
      return { type: "file", ...(await controller.downloadAttachment(request.id, request.attachmentId)) };
    case "attachment.add":
      await controller.addAttachment(request.id, request.fileName, fromBase64(request.data));
      return { type: "done" };
    case "attachment.delete":
      await controller.deleteAttachment(request.id, request.attachmentId);
      return { type: "done" };
    case "send.list":
      return { type: "sends", sends: await controller.listSends() };
    case "send.create":
      return { type: "sendCreated", link: await controller.createSend(request.send, request.file === undefined ? undefined : fromBase64(request.file)) };
    case "send.delete":
      await controller.deleteSend(request.id);
      return { type: "done" };
    case "vault.export":
      return { type: "export", text: await controller.exportVault(request.masterPassword, request.format, request.filePassword) };
    case "vault.import":
      return { type: "import", ...(await controller.importVault(request.text, request.password, request.confirm)) };
    case "vault.updateItem":
      await controller.updateItem(request.id, request.item);
      return { type: "done" };
    case "vault.trash":
      await controller.trashItem(request.id);
      return { type: "done" };
    case "vault.removePasskey":
      await controller.removePasskey(request.id);
      return { type: "done" };
    case "vault.restore":
      await controller.restoreItem(request.id);
      return { type: "done" };
    case "vault.deleteForever":
      await controller.deleteForever(request.id);
      return { type: "done" };
    case "authenticator.list":
      return { type: "authenticatorEntries", entries: await controller.authenticatorList(request.currentUrl) };
    case "authenticator.save":
      await controller.saveAuthenticator(request.id, request.entry);
      return { type: "done" };
    case "authenticator.remove":
      await controller.removeAuthenticator(request.id);
      return { type: "done" };
    case "authenticator.fill":
      return { type: "fill", username: false, password: false, fields: await controller.fillAuthenticator(request.id) };
    case "authenticator.import":
      return { type: "authenticatorImport", ...(await controller.importAuthenticator(request.text, request.confirm)) };
    case "authenticator.export":
      return { type: "authenticatorExport", text: await controller.exportAuthenticator(request.masterPassword) };
    case "folder.save":
      await controller.saveFolder(request.id, request.name);
      return { type: "done" };
    case "folder.delete":
      await controller.deleteFolder(request.id);
      return { type: "done" };
    case "clipboard.scheduleClear": {
      // Re-creating the alarm restarts the countdown after each copy.
      const seconds = await readClipboardClearSeconds();
      // Session storage stays in memory and is closed to content scripts.
      await chrome.storage.session.set({ [CLIPBOARD_DIGEST_KEY]: request.digest ?? null });
      if (seconds === 0) await chrome.alarms.clear(CLIPBOARD_ALARM);
      else await chrome.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + seconds * 1000 });
      return { type: "done" };
    }
    case "settings.get":
      return currentSettings();
    case "settings.siteIntegration":
      await configureSiteIntegration(request.enabled);
      if (!request.enabled) await controller.clearPendingSiteLogins();
      return currentSettings();
    case "settings.vaultTimeout":
      {
      const session = await readAuthSession();
      await writeVaultTimeoutMinutes(request.minutes);
      if (session) await writeAuthSession(session);
      return currentSettings();
      }
    case "settings.browserOptions":
      await writeBrowserIntegrationOptions(request.options);
      // The passkey bridge is registered only while "Ask to save and use passkeys" is on.
      if (await siteIntegrationEnabled()) await configureSiteIntegration(true);
      return currentSettings();
    case "settings.generator":
      await writeGeneratorOptions(request.options);
      return currentSettings();
    case "settings.clipboard":
      await writeClipboardClearSeconds(request.seconds);
      if (request.seconds === 0) await chrome.alarms.clear(CLIPBOARD_ALARM);
      return currentSettings();
    case "site.suggestions": {
      await siteSender(sender, request.url);
      return {
        type: "siteSuggestions",
        // A locked vault has no suggestions, but a waiting passkey request must still be offered.
        items: await controller.siteSuggestions(request.url).catch(() => []),
        passkeyOffer: passkeys.offered(sender.documentId),
      };
    }
    case "site.credential": {
      const { tabId } = await siteSender(sender, request.url);
      return { type: "siteCredential", ...(await controller.siteCredential(request.id, request.url, tabId)) };
    }
    case "site.totp": {
      await siteSender(sender, request.url);
      return { type: "totp", ...(await controller.siteTotp(request.id, request.url)) };
    }
    case "site.formItems": {
      await siteSender(sender, request.url);
      return { type: "siteFormItems", ...(await controller.siteFormItems(request.url)) };
    }
    case "site.fillItem": {
      // Every frame of the tab is filled, so the top page must not be an excluded domain either.
      const { tabId } = await siteSender(sender, request.url);
      if (sender.tab?.url) await requireSiteAllowed(sender.tab.url);
      return { type: "fill", username: false, password: false, fields: await controller.siteFillItem(request.id, sender.url!, tabId) };
    }
    case "site.totpAuto": {
      const { tabId } = await siteSender(sender, request.url);
      return { type: "siteTotp", result: await controller.autoTotp(tabId, request.url) };
    }
    case "site.inspect": {
      const { tabId, options } = await siteSender(sender, request.url);
      return {
        type: "sitePrompt",
        prompt: await controller.inspectSiteLogin(tabId, request.url, request.username, request.password, options, sender.frameId ?? 0),
      };
    }
    case "site.pendingPrompt": {
      const { tabId } = await siteSender(sender);
      return { type: "sitePrompt", prompt: await controller.pendingSitePrompt(tabId, sender.url!, sender.frameId ?? 0) };
    }
    case "site.generatePassword": {
      await siteSender(sender, request.url);
      // A username generator makes no sense for a password field, so that choice falls back to a password.
      const options = await readGeneratorOptions();
      return { type: "generatedPassword", password: options.type === "passphrase" ? generatePassphrase(options) : generatePassword(options) };
    }
    case "site.save": {
      const { tabId } = await siteSender(sender);
      const pending = await controller.pendingSitePrompt(tabId, sender.url!, sender.frameId ?? 0);
      if (pending?.id !== request.promptId) throw new Error("The save prompt expired. Submit the login form again.");
      await controller.savePendingSiteLogin(tabId, request.promptId, request.login);
      return { type: "done" };
    }
    case "site.passkeyCreate":
    case "site.passkeyGet": {
      const { tabId, options } = await siteSender(sender);
      // Only top-level pages: framed WebAuthn has extra permission rules that the browser enforces.
      if (!options.askPasskeys || sender.frameId !== 0 || !sender.documentId) return { type: "passkeyResult", result: { fallback: true } };
      const origin = new URL(sender.url!).origin;
      const source = { tabId, documentId: sender.documentId, requestId: request.id };
      return {
        type: "passkeyResult",
        result: request.type === "site.passkeyCreate"
          ? await passkeys.create(source, origin, request.options)
          : await passkeys.get(source, origin, request.options),
      };
    }
    case "site.passkeyAbort":
      requireSiteSender(sender);
      if (sender.documentId) passkeys.abort(sender.documentId, request.id);
      return { type: "done" };
    case "site.passkeyChoose":
      await siteSender(sender);
      await passkeys.choose(sender.documentId);
      return { type: "done" };
    case "passkey.details":
      return { type: "passkeyDetails", details: await passkeys.details(request.id) };
    case "passkey.unlock":
      await passkeys.unlock(request.id, request.masterPassword);
      return { type: "done" };
    case "passkey.biometric":
      await passkeys.biometric(request.id, fromBase64(request.prfOutput));
      return { type: "done" };
    case "passkey.respond":
      await passkeys.respond(request.id, request);
      return { type: "done" };
    case "site.dismiss": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender);
      const pending = await controller.pendingSitePrompt(tabId, sender.url!, sender.frameId ?? 0);
      if (pending?.id === request.promptId) await controller.dismissPendingSiteLogin(tabId, request.promptId);
      return { type: "done" };
    }
    case "site.hold": {
      await requireSiteIntegrationEnabled();
      const tabId = requireSiteSender(sender);
      const pending = await controller.pendingSitePrompt(tabId, sender.url!, sender.frameId ?? 0);
      if (pending?.id === request.promptId) await controller.holdPendingSiteLogin(tabId, request.promptId);
      return { type: "sitePrompt", prompt: await controller.pendingSitePrompt(tabId, sender.url!, sender.frameId ?? 0) };
    }
  }
}

async function currentSettings(): Promise<Extract<ResponseData, { type: "settings" }>> {
  const [integration, vaultTimeoutMinutes, browserOptions, generatorOptions, clipboardClearSeconds] = await Promise.all([
    siteIntegrationEnabled(),
    readVaultTimeoutMinutes(),
    readBrowserIntegrationOptions(),
    readGeneratorOptions(),
    readClipboardClearSeconds(),
  ]);
  return { type: "settings", siteIntegrationEnabled: integration, vaultTimeoutMinutes, browserOptions, generatorOptions, clipboardClearSeconds };
}

// A website request: integration on, sent from a website tab (at `url`'s origin), not an excluded domain.
async function siteSender(sender: chrome.runtime.MessageSender, url?: string) {
  await requireSiteIntegrationEnabled();
  const tabId = requireSiteSender(sender, url);
  return { tabId, options: await requireSiteAllowed(url ?? sender.url!) };
}

async function requireSiteIntegrationEnabled(): Promise<void> {
  if (!(await siteIntegrationEnabled())) throw new Error("Website integration is disabled.");
}

async function requireSiteAllowed(url: string) {
  const options = await readBrowserIntegrationOptions();
  if (isUrlExcluded(url, options)) throw new Error("Firnkey is disabled for this domain.");
  return options;
}

function requireSiteSender(sender: chrome.runtime.MessageSender, requestedUrl?: string): number {
  if (sender.tab?.id === undefined || !sender.url || !/^https?:\/\//i.test(sender.url)) {
    throw new Error("This request must come from a website tab.");
  }
  if (requestedUrl) {
    let senderOrigin: string;
    let requestedOrigin: string;
    try {
      senderOrigin = new URL(sender.url).origin;
      requestedOrigin = new URL(requestedUrl).origin;
    } catch {
      throw new Error("The website URL is invalid.");
    }
    if (senderOrigin !== requestedOrigin) throw new Error("The website origin changed.");
  }
  return sender.tab.id;
}

function publicError(error: unknown): string {
  if (!(error instanceof Error)) {
    return "Unexpected extension error.";
  }
  if (/integrity|decrypt|master password/i.test(error.message)) {
    return "The vault could not be unlocked. Check the master password and account encryption settings.";
  }
  return error.message;
}
