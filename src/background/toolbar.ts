import type { VaultController } from "./vault-controller";
import { readVaultTimeoutMinutes } from "../shared/settings";
import { t } from "../shared/i18n";

const FILL_MENU_ID = "firnkey-fill";
const FILL_COMMAND = "fill-login";
export const AUTO_LOCK_ALARM = "firnkey-auto-lock";

export async function touchAutoLock(unlocked: boolean): Promise<void> {
  const minutes = unlocked ? await readVaultTimeoutMinutes() : 0;
  if (minutes <= 0) await chrome.alarms.clear(AUTO_LOCK_ALARM);
  else chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: minutes });
}

// Keyboard shortcut, right-click menu and the toolbar count of logins for the current page.
export function installToolbar(controller: VaultController): void {
  void chrome.action.setBadgeBackgroundColor({ color: "#5b6472" }).catch(() => undefined);
  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({ id: FILL_MENU_ID, title: t("fillLogin"), contexts: ["editable"] });
    });
  });
  chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === FILL_MENU_ID) void fillMatchingLogin(controller);
  });
  chrome.commands.onCommand.addListener((command) => {
    if (command === FILL_COMMAND) void fillMatchingLogin(controller);
  });
  chrome.tabs.onActivated.addListener(({ tabId }) => {
    void chrome.tabs.get(tabId).then((tab) => updateBadge(controller, tab)).catch(() => undefined);
  });
  chrome.tabs.onUpdated.addListener((_tabId, change, tab) => {
    if (change.url || change.status === "complete") void updateBadge(controller, tab);
  });
}

// After lock, unlock, sync or edits. Background tabs refresh when they are activated.
export async function refreshBadges(controller: VaultController): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({ active: true });
    await Promise.all(tabs.map((tab) => updateBadge(controller, tab)));
  } catch {
    // The badge is a hint; a closed tab or window must not fail the action that triggered it.
  }
}

async function updateBadge(controller: VaultController, tab: chrome.tabs.Tab): Promise<void> {
  if (tab.id === undefined) return;
  let text = "";
  // The URL is only visible with website access; locked or signed out vaults throw and show nothing.
  if (tab.url && /^https?:\/\//i.test(tab.url)) {
    const count = await controller.matchingLogins(tab.url).then((items) => items.length, () => 0);
    if (count > 0) text = count > 99 ? "99+" : String(count);
  }
  await chrome.action.setBadgeText({ tabId: tab.id, text }).catch(() => undefined);
}

// Fills the first matching login. Locked vault, no match, a protected login or a page without login
// fields opens the popup instead, where the user can unlock or pick.
async function fillMatchingLogin(controller: VaultController): Promise<void> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const item = tab?.url ? (await controller.matchingLogins(tab.url)).find((login) => !login.requiresReprompt) : undefined;
    if (!item) throw new Error("No login to fill.");
    await controller.fill(item.id);
    await touchAutoLock(true);
  } catch {
    await chrome.action.openPopup().catch(() => undefined);
  }
}
