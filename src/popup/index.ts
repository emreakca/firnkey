import { normalizeServerEnvironment } from "../shared/environment";
import { icon, type IconName } from "../shared/icons";
import { generatePassphrase, generatePassword, generateUsername } from "../crypto/password-generator";
import type {
  ExtensionRequest,
  ExtensionResponse,
  PublicAppState,
  ResponseData,
  SavedAccountSummary,
} from "../shared/messages";
import {
  DEFAULT_BROWSER_INTEGRATION_OPTIONS,
  DEFAULT_GENERATOR_OPTIONS,
  isClipboardClearSeconds,
  isVaultTimeoutMinutes,
  type BrowserIntegrationOptions,
  type ClipboardClearSeconds,
  type StoredGeneratorOptions,
  type VaultTimeoutMinutes,
  normalizeDomain,
} from "../shared/settings";
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ItemType,
  type Attachment,
  type PasskeySummary,
  type VaultCollection,
  type VaultFolder,
  type VaultItemDetail,
  type VaultItemSummary,
} from "../vault/models";
import { MAX_FILE_BYTES, type SendSummary, type SendWriteInput } from "../vault/send";
import type { ItemWriteInput } from "../vault/encrypt-login";
import type { AuthenticatorEntry, AuthenticatorWriteInput, ImportRow } from "../vault/authenticator";
import { parseTotpKey, type TotpAlgorithm } from "../crypto/totp";
import { assertBiometricPrf, PRF_SALT, prfOutput, random } from "../shared/biometric";
import { fromBase64 } from "../crypto/bytes";
import { generateEd25519Key, publicKeyFromPrivate } from "../vault/ssh-key";
import { localizePage, plural, t } from "../shared/i18n";

localizePage();

const TYPE_NAMES: Record<ItemType, string> = { 1: t("login"), 2: t("secureNote"), 3: t("card"), 4: t("identity"), 5: t("sshKey") };
// [add, edit] page titles.
const EDITOR_TITLES: Record<ItemType, [string, string]> = {
  1: [t("addLogin"), t("editLogin")], 2: [t("addSecureNote"), t("editSecureNote")], 3: [t("addCard"), t("editCard")],
  4: [t("addIdentity"), t("editIdentity")], 5: [t("addSshKey"), t("editSshKey")],
};
const FIELD_LABELS: Record<string, string> = {
  cardholderName: t("cardholderName"), brand: t("brand"), number: t("number"), expMonth: t("expirationMonth"),
  expYear: t("expirationYear"), code: t("securityCode"), title: t("title"), firstName: t("firstName"),
  middleName: t("middleName"), lastName: t("lastName"), username: t("username"), company: t("company"), email: t("email"),
  phone: t("phone"), address1: t("address1"), address2: t("address2"), address3: t("address3"), city: t("city"),
  state: t("stateProvince"), postalCode: t("postalCode"), country: t("country"), ssn: t("ssn"),
  passportNumber: t("passportNumber"), licenseNumber: t("licenseNumber"),
};
const GENERATOR_TEXT = {
  password: { heading: t("passwordGenerator"), copied: t("generatedPasswordCopied") },
  passphrase: { heading: t("passphraseGenerator"), copied: t("generatedPassphraseCopied") },
  username: { heading: t("usernameGenerator"), copied: t("generatedUsernameCopied") },
};
const SENSITIVE_FIELDS = new Set(["number", "code", "ssn", "passportNumber", "licenseNumber"]);

const views = {
  setup: element<HTMLElement>("setup-view"),
  login: element<HTMLElement>("login-view"),
  locked: element<HTMLElement>("locked-view"),
  vault: element<HTMLElement>("vault-view"),
  authenticator: element<HTMLElement>("authenticator-view"),
  send: element<HTMLElement>("send-view"),
  sendEditor: element<HTMLElement>("send-editor-view"),
  generator: element<HTMLElement>("generator-view"),
  settings: element<HTMLElement>("settings-view"),
  detail: element<HTMLElement>("detail-view"),
  editor: element<HTMLElement>("editor-view"),
  authenticatorEditor: element<HTMLElement>("authenticator-editor-view"),
  authenticatorTransfer: element<HTMLElement>("authenticator-transfer-view"),
};
const appTitle = element<HTMLHeadingElement>("app-title");
const headerBack = element<HTMLButtonElement>("header-back");
const brandMark = element<HTMLSpanElement>("brand-mark");
const statePill = element<HTMLSpanElement>("state-pill");
const subtitle = element<HTMLParagraphElement>("subtitle");
const addLogin = element<HTMLButtonElement>("add-login");
const accountAvatar = element<HTMLButtonElement>("account-avatar");
const bottomNav = element<HTMLElement>("bottom-nav");
const navVault = element<HTMLButtonElement>("nav-vault");
const navGenerator = element<HTMLButtonElement>("nav-generator");
const navAuthenticator = element<HTMLButtonElement>("nav-authenticator");
const navSend = element<HTMLButtonElement>("nav-send");
const sendList = element<HTMLDivElement>("send-list");
const sendEmpty = element<HTMLParagraphElement>("send-empty");
const sendForm = element<HTMLFormElement>("send-form");
const sendName = element<HTMLInputElement>("send-name");
const sendText = element<HTMLTextAreaElement>("send-text");
const sendHidden = element<HTMLInputElement>("send-hidden");
const sendFile = element<HTMLInputElement>("send-file");
const sendFileName = element<HTMLParagraphElement>("send-file-name");
const sendDeletion = element<HTMLSelectElement>("send-deletion");
const sendPassword = element<HTMLInputElement>("send-password");
const sendMaxAccess = element<HTMLInputElement>("send-max-access");
const sendSubmit = element<HTMLButtonElement>("send-submit");
const detailOwner = element<HTMLParagraphElement>("detail-owner");
const detailAttachments = element<HTMLDivElement>("detail-attachments");
const addAttachment = element<HTMLLabelElement>("add-attachment");
const attachmentFile = element<HTMLInputElement>("attachment-file");
const collectionField = element<HTMLDivElement>("collection-field");
const itemCollection = element<HTMLSelectElement>("item-collection");
const collectionHint = element<HTMLParagraphElement>("collection-hint");
const transferGroup = element<HTMLElement>("settings-group-transfer");
const vaultImportForm = element<HTMLFormElement>("vault-import-form");
const vaultImportFile = element<HTMLInputElement>("vault-import-file");
const vaultImportName = element<HTMLParagraphElement>("vault-import-name");
const vaultImportPasswordField = element<HTMLDivElement>("vault-import-password-field");
const vaultImportPassword = element<HTMLInputElement>("vault-import-password");
const vaultImportSummary = element<HTMLParagraphElement>("vault-import-summary");
const vaultImportSubmit = element<HTMLButtonElement>("vault-import-submit");
const vaultExportForm = element<HTMLFormElement>("vault-export-form");
const vaultExportFormat = element<HTMLSelectElement>("vault-export-format");
const vaultExportFilePassword = element<HTMLInputElement>("vault-export-file-password");
const vaultExportPassword = element<HTMLInputElement>("vault-export-password");
const vaultExportSubmit = element<HTMLButtonElement>("vault-export-submit");
// The chosen import file's text, kept only while the Import & export page is open.
let importFileText = "";
let importChecked = false;
let importLabel = t("checkFile");
const navSettings = element<HTMLButtonElement>("nav-settings");
const settingsMenu = element<HTMLElement>("settings-menu");
const settingsGroups = [...document.querySelectorAll<HTMLElement>(".settings-group")];
let settingsPage: HTMLElement = settingsMenu;
const authenticatorTab = element<HTMLInputElement>("authenticator-tab");
const authenticatorList = element<HTMLDivElement>("authenticator-list");
const authenticatorContext = element<HTMLParagraphElement>("authenticator-context");
const authenticatorAll = element<HTMLButtonElement>("authenticator-all");
const authenticatorEmpty = element<HTMLParagraphElement>("authenticator-empty");
// Live cards on the Authenticator tab. Codes come from the background; seeds never reach the popup.
const codeCards = new Map<string, { card: HTMLElement; code: HTMLElement; bar: HTMLElement; seconds: HTMLElement; expiresAt: number }>();
let showAllCodes = false;
const authenticatorSmartFilter = element<HTMLInputElement>("authenticator-smart-filter");
const authenticatorForm = element<HTMLFormElement>("authenticator-form");
const authenticatorTargetField = element<HTMLDivElement>("authenticator-target-field");
const authenticatorTarget = element<HTMLSelectElement>("authenticator-target");
const authenticatorSecret = element<HTMLInputElement>("authenticator-secret");
const authenticatorName = element<HTMLInputElement>("authenticator-name");
const authenticatorNickname = element<HTMLInputElement>("authenticator-nickname");
const authenticatorAccount = element<HTMLInputElement>("authenticator-account");
const authenticatorWebsite = element<HTMLInputElement>("authenticator-website");
const authenticatorIssuer = element<HTMLInputElement>("authenticator-issuer");
const authenticatorAlgorithm = element<HTMLSelectElement>("authenticator-algorithm");
const authenticatorDigits = element<HTMLSelectElement>("authenticator-digits");
const authenticatorPeriod = element<HTMLInputElement>("authenticator-period");
const authenticatorSave = element<HTMLButtonElement>("authenticator-save");
const authenticatorRemove = confirmButton(t("removeKey"), () => void removeAuthenticatorKey());
authenticatorRemove.className = "danger-button";
authenticatorForm.append(authenticatorRemove);
const importText = element<HTMLTextAreaElement>("import-text");
const importRows = element<HTMLDivElement>("import-rows");
const importConfirm = element<HTMLButtonElement>("import-confirm");
const exportForm = element<HTMLFormElement>("export-form");
const exportPassword = element<HTMLInputElement>("export-password");
const exportSubmit = element<HTMLButtonElement>("export-submit");
// The entry being edited on the Authenticator editor page; null while adding one.
let editingEntry: AuthenticatorEntry | null = null;
// Logins (id -> summary) a new key can be added to.
let keyTargets = new Map<string, VaultItemSummary>();
const status = element<HTMLParagraphElement>("status");
let statusTimer: number | undefined;
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const EASE = "cubic-bezier(0.32, 0.72, 0, 1)";
const REST: Keyframe = { transform: "none", opacity: 1 };
const serverForm = element<HTMLFormElement>("server-form");
const serverUrl = element<HTMLInputElement>("server-url");
const serverSubmit = element<HTMLButtonElement>("server-submit");
const serverDetail = element<HTMLParagraphElement>("server-detail");
const changeServer = element<HTMLButtonElement>("change-server");
const loginForm = element<HTMLFormElement>("login-form");
const email = element<HTMLInputElement>("email");
const masterPassword = element<HTMLInputElement>("master-password");
const loginSubmit = element<HTMLButtonElement>("login-submit");
const twoFactorFields = element<HTMLFieldSetElement>("two-factor-fields");
const twoFactorProvider = element<HTMLSelectElement>("two-factor-provider");
const sendEmailCode = element<HTMLButtonElement>("send-email-code");
const twoFactorToken = element<HTMLInputElement>("two-factor-token");
const twoFactorTokenLabel = element<HTMLLabelElement>("two-factor-token-label");
const twoFactorRemember = element<HTMLInputElement>("two-factor-remember");
const deviceFields = element<HTMLFieldSetElement>("device-fields");
const deviceOtp = element<HTMLInputElement>("device-otp");
const unlockForm = element<HTMLFormElement>("unlock-form");
const unlockPassword = element<HTMLInputElement>("unlock-password");
const unlockSubmit = element<HTMLButtonElement>("unlock-submit");
const lockedAccount = element<HTMLParagraphElement>("locked-account");
const search = element<HTMLInputElement>("search");
const itemList = element<HTMLDivElement>("item-list");
const emptyState = element<HTMLParagraphElement>("empty-state");
const vaultContext = element<HTMLParagraphElement>("vault-context");
const detailName = element<HTMLHeadingElement>("detail-name");
const detailUri = element<HTMLParagraphElement>("detail-uri");
const usernameRow = element<HTMLButtonElement>("username-row");
const detailFields = element<HTMLDivElement>("detail-fields");
const detailUsername = element<HTMLSpanElement>("detail-username");
const detailPassword = element<HTMLSpanElement>("detail-password");
const detailTotp = element<HTMLSpanElement>("detail-totp");
const totpRow = element<HTMLButtonElement>("totp-row");
const totpTimer = element<HTMLSpanElement>("totp-timer");
let totpExpiresAt = 0; // NaN once fetching the code failed: the countdown stops.
// One ticker drives both the detail code and the authenticator list; it stops when neither is shown.
let ticker: number | undefined;
const passwordRow = element<HTMLDivElement>("password-row");
const fillDetail = element<HTMLButtonElement>("fill-detail");
const repromptForm = element<HTMLFormElement>("reprompt-form");
const repromptPassword = element<HTMLInputElement>("reprompt-password");
const repromptSubmit = element<HTMLButtonElement>("reprompt-submit");
const editorForm = element<HTMLFormElement>("editor-form");
const editorTitle = element<HTMLHeadingElement>("editor-title");
const itemType = element<HTMLSelectElement>("item-type");
const loginFields = element<HTMLDivElement>("login-fields");
const typeFields = element<HTMLDivElement>("type-fields");
const loginName = element<HTMLInputElement>("login-name");
const loginUsername = element<HTMLInputElement>("login-username");
const loginPassword = element<HTMLInputElement>("login-password");
const toggleLoginPassword = element<HTMLButtonElement>("toggle-login-password");
const loginUri = element<HTMLInputElement>("login-uri");
const loginTotp = element<HTMLInputElement>("login-totp");
const loginNotes = element<HTMLTextAreaElement>("login-notes");
const loginFavorite = element<HTMLInputElement>("login-favorite");
const editorSubmit = element<HTMLButtonElement>("editor-submit");
const editLogin = element<HTMLButtonElement>("edit-login");
const siteAccess = element<HTMLButtonElement>("site-access");
const fillBasicAuth = element<HTMLInputElement>("fill-basic-auth");
const fillPasswordAfterUsername = element<HTMLInputElement>("fill-password-after-username");
const askSaveForms = element<HTMLInputElement>("ask-save-forms");
const liveSync = element<HTMLInputElement>("live-sync");
const vaultTimeout = element<HTMLSelectElement>("vault-timeout");
const biometricToggle = element<HTMLInputElement>("biometric-toggle");
const biometricUnlock = element<HTMLButtonElement>("biometric-unlock");
const settingsAccount = element<HTMLParagraphElement>("settings-account");
const settingsServer = element<HTMLParagraphElement>("settings-server");
const appVersion = element<HTMLParagraphElement>("app-version");
const generatorOutput = element<HTMLInputElement>("generator-output");
const generatorLength = element<HTMLInputElement>("generator-length");
const generatorLengthValue = element<HTMLOutputElement>("generator-length-value");
const generatorUppercase = element<HTMLInputElement>("generator-uppercase");
const generatorLowercase = element<HTMLInputElement>("generator-lowercase");
const generatorNumbers = element<HTMLInputElement>("generator-numbers");
const generatorSymbols = element<HTMLInputElement>("generator-symbols");
const generatorHeading = element<HTMLHeadingElement>("generator-heading");
const generatorWords = element<HTMLInputElement>("generator-words");
const generatorWordsValue = element<HTMLOutputElement>("generator-words-value");
const generatorSeparator = element<HTMLInputElement>("generator-separator");
const generatorCapitalize = element<HTMLInputElement>("generator-capitalize");
const generatorIncludeNumber = element<HTMLInputElement>("generator-include-number");
const generatorHistory = element<HTMLDetailsElement>("generator-history");
const generatorHistoryList = element<HTMLDivElement>("generator-history-list");
generatorHistory.addEventListener("toggle", () => {
  if (generatorHistory.open) void loadGeneratorHistory();
});
const usernameKind = element<HTMLSelectElement>("username-kind");
const usernameCapitalize = element<HTMLInputElement>("username-capitalize");
const usernameIncludeNumber = element<HTMLInputElement>("username-include-number");
const usernameEmail = element<HTMLInputElement>("username-email");
const usernameDomain = element<HTMLInputElement>("username-domain");
const clipboardClear = element<HTMLSelectElement>("clipboard-clear");
const clipboardOwnOnly = element<HTMLInputElement>("clipboard-own-only");
const askPasskeys = element<HTMLInputElement>("ask-passkeys");
const askAddLogin = element<HTMLInputElement>("ask-add-login");
const savePromptTimeout = element<HTMLInputElement>("save-prompt-timeout");
const askUpdateLogin = element<HTMLInputElement>("ask-update-login");
const excludedDomainForm = element<HTMLFormElement>("excluded-domain-form");
const excludedDomain = element<HTMLInputElement>("excluded-domain");
const excludedDomainList = element<HTMLDivElement>("excluded-domain-list");
const folderFilter = element<HTMLSelectElement>("folder-filter");
const itemFolder = element<HTMLSelectElement>("item-folder");
const folderForm = element<HTMLFormElement>("folder-form");
const folderName = element<HTMLInputElement>("folder-name");
const folderList = element<HTMLDivElement>("folder-list");

let currentUrl: string | undefined;
let selectedItem: VaultItemDetail | null = null;
let editingId: string | null = null;
// Editing a login that has a key: the saved key never reaches the popup, so a blank field keeps it.
let savedTotp = false;
let siteIntegrationEnabled = false;
let vaultTimeoutMinutes: VaultTimeoutMinutes = 0;
let browserOptions: BrowserIntegrationOptions = { ...DEFAULT_BROWSER_INTEGRATION_OPTIONS };
let generatorOptions: StoredGeneratorOptions = { ...DEFAULT_GENERATOR_OPTIONS };
let clipboardClearSeconds: ClipboardClearSeconds = 30;
let totalItems = 0;
let vaultContextText = "";
let folders: VaultFolder[] = [];
let collections: VaultCollection[] = [];
let currentView: keyof typeof views = "setup";

void initialize().catch(showError);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.accountMetadata) return;
  if (currentView === "vault") void refreshState();
});

serverForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void verifyServer();
});
loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void login();
});
unlockForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void unlock();
});
repromptForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void authorizeReprompt();
});
editorForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveEditor();
});
changeServer.addEventListener("click", () => showView("setup"));
element("locked-logout").addEventListener("click", () => void logout());
element("logout").addEventListener("click", () => void logout());
element("lock").addEventListener("click", () => void lock());
element("sync").addEventListener("click", () => void syncVault());
addLogin.addEventListener("click", () => {
  if (currentView === "authenticator") void openAuthenticatorEditor();
  else if (currentView === "send") openSendEditor();
  else openEditor();
});
navSend.addEventListener("click", () => {
  showView("send");
  void loadSends();
});
sendForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void createSend();
});
for (const radio of document.querySelectorAll<HTMLInputElement>('input[name="send-type"]')) radio.addEventListener("change", updateSendType);
sendFile.addEventListener("change", () => {
  const file = sendFile.files?.[0];
  sendFileName.textContent = file ? `${file.name} · ${formatSize(file.size)}` : t("noFileChosenSendLimit");
  if (file && !sendName.value) sendName.value = file.name;
});
attachmentFile.addEventListener("change", () => void uploadAttachment());
itemCollection.addEventListener("change", () => {
  collectionHint.hidden = !editingId || !itemCollection.value;
});
vaultImportFile.addEventListener("change", () => void chooseImportFile());
vaultImportPassword.addEventListener("input", () => resetImportCheck());
vaultImportForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void importVault();
});
vaultExportFormat.addEventListener("change", updateExportFormat);
vaultExportForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void exportVault();
});
accountAvatar.addEventListener("click", () => showView("settings"));
navSettings.addEventListener("click", () => showView("settings"));
settingsMenu.addEventListener("click", (event) => {
  const link = (event.target as HTMLElement).closest<HTMLElement>("[data-group]");
  if (!link) return;
  showSettingsGroup(element(`settings-group-${link.dataset.group}`), "push");
});
// Tapping the active tab again: settings pops back to its menu, other tabs scroll to the top.
bottomNav.addEventListener(
  "click",
  (event) => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>(".nav-button");
    if (!button?.classList.contains("active")) return;
    button.querySelector("svg")?.animate([{ transform: "scale(1)" }, { transform: "scale(0.82)" }, { transform: "scale(1)" }], {
      duration: 280,
      easing: EASE,
    });
    if (currentView === "settings" && settingsPage !== settingsMenu) {
      showSettingsGroup(undefined, "pop");
      return;
    }
    const behavior = reducedMotion.matches ? "auto" : "smooth";
    for (const scroller of [views[currentView], itemList]) scroller.scrollTo({ top: 0, behavior });
  },
  { capture: true }, // Runs before the tab's own handler marks it active.
);
navVault.addEventListener("click", () => {
  showView("vault");
  void loadItems();
});
navAuthenticator.addEventListener("click", () => {
  showAllCodes = false;
  showView("authenticator");
  void loadAuthenticator();
});
authenticatorAll.addEventListener("click", () => {
  showAllCodes = !showAllCodes;
  void loadAuthenticator();
});
authenticatorTab.addEventListener("change", () => void updateBrowserOptions());
authenticatorSmartFilter.addEventListener("change", () => void updateBrowserOptions());
element("authenticator-transfer").addEventListener("click", () => {
  importRows.replaceChildren();
  importConfirm.hidden = true;
  showView("authenticatorTransfer");
});
authenticatorForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveAuthenticatorEntry();
});
element("authenticator-scan").addEventListener("click", () => void scanQrCode());
element("scan-login-totp").addEventListener("click", () => void scanLoginTotp());
authenticatorSecret.addEventListener("change", () => applyKeyDetails(true));
authenticatorTarget.addEventListener("change", () => {
  const target = keyTargets.get(authenticatorTarget.value);
  authenticatorName.value = target?.name ?? "";
  authenticatorAccount.value = target?.username ?? authenticatorAccount.value;
  authenticatorWebsite.value = target?.uri ?? editableCurrentUrl();
});
importText.addEventListener("input", () => {
  importRows.replaceChildren();
  importConfirm.hidden = true;
});
element("import-check").addEventListener("click", () => void checkImport(false));
importConfirm.addEventListener("click", () => void checkImport(true));
element<HTMLInputElement>("import-file").addEventListener("change", (event) => void readImportFile(event.target as HTMLInputElement));
exportForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void exportKeys();
});
navGenerator.addEventListener("click", () => {
  showView("generator");
  refreshGeneratedPassword();
});
siteAccess.addEventListener("click", () => void toggleSiteIntegration());
fillBasicAuth.addEventListener("change", () => void toggleBasicAuth());
liveSync.addEventListener("change", () => void updateBrowserOptions());
fillPasswordAfterUsername.addEventListener("change", () => void updateBrowserOptions());
askSaveForms.addEventListener("change", () => void updateBrowserOptions());
vaultTimeout.addEventListener("change", () => void updateVaultTimeout());
biometricUnlock.addEventListener("click", () => void runBiometric("unlock"));
biometricToggle.addEventListener("change", () => {
  if (biometricToggle.checked) {
    void runBiometric("enable");
    return;
  }
  void request({ type: "biometric.disable" })
    .then(() => showStatus(t("biometricOff"), "success"))
    .catch((error: unknown) => {
      biometricToggle.checked = true;
      showError(error);
    });
});
editLogin.addEventListener("click", () => selectedItem && openEditor(selectedItem));
itemType.addEventListener("change", () => {
  const type = Number(itemType.value) as ItemType;
  // The site-name suggestion only makes sense for a login.
  if (loginName.value === suggestedSiteName()) loginName.value = type === ItemType.Login ? suggestedSiteName() : "";
  renderEditorFields(type);
});
headerBack.addEventListener("click", () => {
  if (currentView === "authenticatorEditor" || currentView === "authenticatorTransfer") {
    showView("authenticator");
    void loadAuthenticator();
    return;
  }
  if (currentView === "sendEditor") {
    showView("send");
    return;
  }
  if (currentView === "settings") {
    showSettingsGroup(undefined, "pop");
    return;
  }
  if (currentView === "editor" && editingId) {
    const id = editingId;
    editingId = null;
    void showDetail(id);
    return;
  }
  editingId = null;
  selectedItem = null;
  showView("vault");
});
element("generate-password").addEventListener("click", () => {
  loginPassword.value = defaultGeneratedPassword();
  recordGenerated(loginPassword.value, false);
  loginPassword.focus();
  loginPassword.select();
});
element("generator-refresh").addEventListener("click", refreshGeneratedPassword);
toggleLoginPassword.addEventListener("click", () => showLoginPassword(loginPassword.type === "password"));
element("generator-copy").addEventListener("click", () => {
  recordGenerated(generatorOutput.value, generatorOptions.type === "username");
  void copySecret(generatorOutput.value, GENERATOR_TEXT[generatorOptions.type].copied);
});
element("generator-use").addEventListener("click", () => {
  const value = generatorOutput.value;
  const username = generatorOptions.type === "username";
  recordGenerated(value, username);
  openEditor();
  (username ? loginUsername : loginPassword).value = value;
});
for (const input of [
  generatorLength,
  generatorUppercase,
  generatorLowercase,
  generatorNumbers,
  generatorSymbols,
  generatorWords,
  generatorSeparator,
  generatorCapitalize,
  generatorIncludeNumber,
  usernameKind,
  usernameCapitalize,
  usernameIncludeNumber,
  usernameEmail,
  usernameDomain,
  ...document.querySelectorAll<HTMLInputElement>('input[name="generator-type"]'),
]) {
  input.addEventListener("input", refreshGeneratedPassword);
  input.addEventListener("change", () => void persistGeneratorOptions());
}
clipboardClear.addEventListener("change", () => void updateClipboardClear());
clipboardOwnOnly.addEventListener("change", () => void toggleClipboardOwnOnly());
element("add-account").addEventListener("click", () => void addAccount());
askPasskeys.addEventListener("change", () => void updateBrowserOptions());
askAddLogin.addEventListener("change", () => void updateBrowserOptions());
askUpdateLogin.addEventListener("change", () => void updateBrowserOptions());
savePromptTimeout.addEventListener("change", () => {
  if (savePromptTimeout.reportValidity()) void updateBrowserOptions();
});
excludedDomainForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void addExcludedDomain();
});
fillDetail.addEventListener("click", () => selectedItem && void fill(selectedItem.id));
usernameRow.addEventListener("click", () =>
  selectedItem && void copySecret(selectedItem.username, t("usernameCopied"), usernameRow),
);
element("copy-password").addEventListener("click", () =>
  selectedItem && void copySecret(selectedItem.password, t("passwordCopied"), element("copy-password")),
);
totpRow.addEventListener("click", () => void copyTotp());
twoFactorProvider.addEventListener("change", updateTwoFactorControls);
sendEmailCode.addEventListener("click", () => void requestEmailCode());
element("reveal-password").addEventListener("click", () => {
  const hidden = detailPassword.classList.toggle("password-mask");
  element<HTMLButtonElement>("reveal-password").textContent = hidden ? t("show") : t("hide");
});
search.addEventListener("input", () => void loadItems());
folderFilter.addEventListener("change", () => void loadItems());
folderForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveFolder(undefined, folderName.value).then((saved) => { if (saved) folderName.value = ""; });
});
element("trash-item").addEventListener("click", () => selectedItem && void changeItem("vault.trash", selectedItem.id, t("movedToTrash")));

async function initialize(): Promise<void> {
  appVersion.textContent = `Firnkey ${chrome.runtime.getManifest().version}`;
  currentUrl = await activeTabUrl();
  await refreshSettings();
  refreshGeneratedPassword();
  await refreshState();
  // Start Touch ID as soon as the popup opens locked. If the last attempt never finished
  // (cancelled or popup closed), show the password form once instead so nobody gets stuck.
  if (currentView === "locked" && !biometricUnlock.hidden) {
    const { biometricAttempt } = await chrome.storage.session.get("biometricAttempt");
    if (biometricAttempt) await chrome.storage.session.remove("biometricAttempt");
    else void runBiometric("unlock");
  }
  // A security key or Duo sign-in finishes after this popup closed; show why it failed.
  const { loginNotice } = await chrome.storage.session.get("loginNotice");
  if (typeof loginNotice === "string") {
    await chrome.storage.session.remove("loginNotice");
    showError(new Error(loginNotice));
  }
}

async function refreshSettings(): Promise<void> {
  const data = await request({ type: "settings.get" }, "settings");
  siteIntegrationEnabled = data.siteIntegrationEnabled;
  vaultTimeoutMinutes = data.vaultTimeoutMinutes;
  browserOptions = data.browserOptions;
  generatorOptions = data.generatorOptions;
  clipboardClearSeconds = data.clipboardClearSeconds;
  clipboardClear.value = String(clipboardClearSeconds);
  clipboardOwnOnly.checked = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
  vaultTimeout.value = String(vaultTimeoutMinutes);
  askPasskeys.checked = browserOptions.askPasskeys;
  askAddLogin.checked = browserOptions.askAddLogin;
  askUpdateLogin.checked = browserOptions.askUpdateLogin;
  savePromptTimeout.value = String(browserOptions.savePromptTimeoutSeconds);
  authenticatorTab.checked = browserOptions.authenticatorTab;
  authenticatorSmartFilter.checked = browserOptions.authenticatorSmartFilter;
  navAuthenticator.hidden = !browserOptions.authenticatorTab;
  fillBasicAuth.checked = browserOptions.fillBasicAuth;
  liveSync.checked = browserOptions.liveSync;
  fillPasswordAfterUsername.checked = browserOptions.fillPasswordAfterUsername;
  askSaveForms.checked = browserOptions.askSaveForms;
  writeGeneratorForm(generatorOptions);
  renderExcludedDomains();
  updateSiteAccessButton();
}

async function toggleSiteIntegration(): Promise<void> {
  try {
    const enabled = !siteIntegrationEnabled;
    if (enabled) {
      const granted = await chrome.permissions.request({ origins: ["https://*/*", "http://*/*"] });
      if (!granted) throw new Error(t("websiteAccessDenied"));
    }
    const data = await request({ type: "settings.siteIntegration", enabled }, "settings");
    siteIntegrationEnabled = data.siteIntegrationEnabled;
    vaultTimeoutMinutes = data.vaultTimeoutMinutes;
    browserOptions = data.browserOptions;
    generatorOptions = data.generatorOptions;
    updateSiteAccessButton();
    showStatus(t(siteIntegrationEnabled ? "websiteIntegrationOn" : "websiteIntegrationOff"), "success");
  } catch (error) {
    showError(error);
  }
}

// Chrome only lets an extension answer sign-in dialogs with these permissions, so ask on opt-in.
async function toggleBasicAuth(): Promise<void> {
  if (fillBasicAuth.checked) {
    const granted = await chrome.permissions.request({
      permissions: ["webRequest", "webRequestAuthProvider"],
      origins: ["https://*/*", "http://*/*"],
    }).catch(() => false);
    if (!granted) {
      fillBasicAuth.checked = false;
      showError(new Error(t("basicAuthPermissionDenied")));
      return;
    }
  }
  await updateBrowserOptions();
}

async function updateBrowserOptions(next?: BrowserIntegrationOptions): Promise<void> {
  const previous = browserOptions;
  const options = next ?? {
    ...browserOptions,
    askPasskeys: askPasskeys.checked,
    askAddLogin: askAddLogin.checked,
    askUpdateLogin: askUpdateLogin.checked,
    savePromptTimeoutSeconds: Number(savePromptTimeout.value),
    authenticatorTab: authenticatorTab.checked,
    authenticatorSmartFilter: authenticatorSmartFilter.checked,
    fillBasicAuth: fillBasicAuth.checked,
    liveSync: liveSync.checked,
    fillPasswordAfterUsername: fillPasswordAfterUsername.checked,
    askSaveForms: askSaveForms.checked,
  };
  try {
    const data = await request({ type: "settings.browserOptions", options }, "settings");
    browserOptions = data.browserOptions;
    askPasskeys.checked = browserOptions.askPasskeys;
    askAddLogin.checked = browserOptions.askAddLogin;
    askUpdateLogin.checked = browserOptions.askUpdateLogin;
    savePromptTimeout.value = String(browserOptions.savePromptTimeoutSeconds);
    authenticatorTab.checked = browserOptions.authenticatorTab;
    authenticatorSmartFilter.checked = browserOptions.authenticatorSmartFilter;
    navAuthenticator.hidden = !browserOptions.authenticatorTab;
    fillBasicAuth.checked = browserOptions.fillBasicAuth;
    liveSync.checked = browserOptions.liveSync;
    fillPasswordAfterUsername.checked = browserOptions.fillPasswordAfterUsername;
    askSaveForms.checked = browserOptions.askSaveForms;
    renderExcludedDomains();
    showStatus(t("preferencesUpdated"), "success");
  } catch (error) {
    browserOptions = previous;
    askPasskeys.checked = previous.askPasskeys;
    askAddLogin.checked = previous.askAddLogin;
    askUpdateLogin.checked = previous.askUpdateLogin;
    savePromptTimeout.value = String(previous.savePromptTimeoutSeconds);
    authenticatorTab.checked = previous.authenticatorTab;
    authenticatorSmartFilter.checked = previous.authenticatorSmartFilter;
    fillBasicAuth.checked = previous.fillBasicAuth;
    liveSync.checked = previous.liveSync;
    fillPasswordAfterUsername.checked = previous.fillPasswordAfterUsername;
    askSaveForms.checked = previous.askSaveForms;
    showError(error);
  }
}

async function addExcludedDomain(): Promise<void> {
  const value = normalizeDomain(excludedDomain.value);
  if (!value) {
    showError(new Error(t("invalidDomain")));
    return;
  }
  const options = { ...browserOptions, excludedDomains: [...new Set([...browserOptions.excludedDomains, value])] };
  excludedDomain.value = "";
  await updateBrowserOptions(options);
}

function renderExcludedDomains(): void {
  excludedDomainList.replaceChildren();
  for (const domain of browserOptions.excludedDomains) {
    const row = document.createElement("div");
    row.className = "excluded-domain-row";
    const label = document.createElement("span");
    label.className = "truncate";
    label.textContent = domain;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "small-button";
    remove.textContent = t("remove");
    remove.addEventListener("click", () => {
      void updateBrowserOptions({
        ...browserOptions,
        excludedDomains: browserOptions.excludedDomains.filter((item) => item !== domain),
      });
    });
    row.append(label, remove);
    excludedDomainList.append(row);
  }
}

function updateSiteAccessButton(): void {
  siteAccess.textContent = t(siteIntegrationEnabled ? "enabled" : "enable");
  siteAccess.title = t(siteIntegrationEnabled ? "disableWebsiteIntegration" : "enableWebsiteIntegration");
}

async function updateVaultTimeout(): Promise<void> {
  try {
    const minutes = Number(vaultTimeout.value);
    if (!isVaultTimeoutMinutes(minutes)) throw new Error(t("unsupportedVaultTimeout"));
    const data = await request({ type: "settings.vaultTimeout", minutes }, "settings");
    vaultTimeoutMinutes = data.vaultTimeoutMinutes;
    vaultTimeout.value = String(vaultTimeoutMinutes);
    showStatus(timeoutConfirmation(vaultTimeoutMinutes), "success");
  } catch (error) {
    vaultTimeout.value = String(vaultTimeoutMinutes);
    showError(error);
  }
}

async function updateClipboardClear(): Promise<void> {
  try {
    const seconds = Number(clipboardClear.value);
    if (!isClipboardClearSeconds(seconds)) throw new Error(t("unsupportedClipboardTimeout"));
    const data = await request({ type: "settings.clipboard", seconds }, "settings");
    clipboardClearSeconds = data.clipboardClearSeconds;
    showStatus(seconds ? t("clipboardClearsAfter", clipboardLabel(seconds)) : t("clipboardKeeps"), "success");
  } catch (error) {
    clipboardClear.value = String(clipboardClearSeconds);
    showError(error);
  }
}

// Checking the clipboard before clearing it needs Chrome's clipboard-read permission, so it is opt-in.
async function toggleClipboardOwnOnly(): Promise<void> {
  const permission: chrome.permissions.Permissions = { permissions: ["clipboardRead"] };
  const granted = clipboardOwnOnly.checked
    ? await chrome.permissions.request(permission).catch(() => false)
    : !(await chrome.permissions.remove(permission).catch(() => false));
  clipboardOwnOnly.checked = granted;
  if (granted) showStatus(t("clipboardOwnOnlyOn"), "success");
}

function clipboardLabel(seconds: number): string {
  return seconds < 60 ? plural("seconds", seconds) : plural("minutes", seconds / 60);
}

function timeoutConfirmation(minutes: VaultTimeoutMinutes): string {
  if (minutes === -2) return t("lockOnComputerLock");
  if (minutes === -1) return t("lockOnLogout");
  if (minutes === 0) return t("lockOnBrowserClose");
  return t("lockAfterInactivity", minutes < 60 ? plural("minutes", minutes) : plural("hours", minutes / 60));
}

// Chrome keeps the toolbar popup open during the Touch ID / Windows Hello prompt, so the ceremony
// runs right here. The passkey belongs to Firnkey's own origin, so no website can use it.
async function runBiometric(mode: "enable" | "unlock"): Promise<void> {
  const button = mode === "unlock" ? biometricUnlock : undefined;
  const label = biometricUnlock.textContent ?? "";
  if (button) setBusy(button, true, t("waitingForVerification"));
  try {
    const data = await request({ type: "app.getState" }, "state");
    const state = data.state;
    if (mode === "enable") {
      if (state.phase !== "unlocked") throw new Error(t("unlockBeforeBiometric"));
      const credential = (await navigator.credentials.create({
        publicKey: {
          rp: { name: "Firnkey" },
          user: { id: random(16), name: state.email, displayName: `Firnkey (${state.email})` },
          challenge: random(32),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
          extensions: { prf: { eval: { first: PRF_SALT } } },
        },
      })) as PublicKeyCredential | null;
      if (!credential) throw new Error(t("noPasskeyCreated"));
      const credentialId = new Uint8Array(credential.rawId);
      // Some authenticators only return PRF results on sign-in, not on creation.
      const output = prfOutput(credential) ?? (await assertBiometricPrf(credentialId));
      await request({ type: "biometric.enable", credentialId: credentialId.toBase64(), prfOutput: output.toBase64() });
      await refreshState();
      showStatus(t("biometricOn"), "success");
    } else {
      if (state.phase !== "locked" || !state.biometricCredentialId) throw new Error(t("biometricUnavailable"));
      // Cleared only on success, so a cancelled attempt offers the password next time instead.
      await chrome.storage.session.set({ biometricAttempt: true });
      const output = await assertBiometricPrf(fromBase64(state.biometricCredentialId));
      const result = await request({ type: "biometric.unlock", prfOutput: output.toBase64() });
      await chrome.storage.session.remove("biometricAttempt");
      await refreshState();
      if (result.type === "unlock") showStatus(plural("vaultUnlocked", result.itemCount), "success");
    }
  } catch (error) {
    if (mode === "enable") biometricToggle.checked = false;
    showError(error instanceof DOMException && error.name === "NotAllowedError" ? new Error(t("verificationCancelled")) : error);
  } finally {
    if (button) setBusy(button, false, label);
  }
}

async function refreshState(): Promise<void> {
  const data = await request({ type: "app.getState" }, "state");
  renderState(data.state);
}

function renderState(state: PublicAppState): void {
  clearStatus();
  renderAccounts(state.phase === "setup" ? [] : state.accounts);
  switch (state.phase) {
    case "setup":
      markState(t("notConnected"), "neutral");
      subtitle.textContent = t("connectAServer");
      showView("setup");
      break;
    case "signed-out":
      serverUrl.value = state.snapshot.baseUrl;
      email.value = state.email ?? "";
      serverDetail.textContent = serverLabel(state.snapshot.baseUrl, state.snapshot.serverVersion);
      markState(t("signedOut"), "neutral");
      subtitle.textContent = state.snapshot.baseUrl;
      showView("login");
      break;
    case "locked":
      totalItems = state.itemCount;
      serverUrl.value = state.snapshot.baseUrl;
      lockedAccount.textContent = `${state.email} · ${plural("itemCount", state.itemCount)}`;
      biometricUnlock.hidden = !state.biometricCredentialId;
      markState(t("locked"), "neutral");
      subtitle.textContent = state.email;
      showView("locked");
      unlockPassword.focus();
      break;
    case "unlocked":
      totalItems = state.itemCount;
      serverUrl.value = state.snapshot.baseUrl;
      markState(t("unlocked"), "success");
      subtitle.textContent = state.email;
      accountAvatar.textContent = accountInitials(state.email);
      accountAvatar.title = t("settingsFor", state.email);
      settingsAccount.textContent = state.email;
      if (!usernameEmail.value) usernameEmail.value = state.email; // Default plus-address base.
      settingsServer.textContent = state.snapshot.baseUrl;
      biometricToggle.checked = Boolean(state.biometricCredentialId);
      vaultContextText = currentUrl
        ? t("itemsWithSuggestions", plural("itemCount", state.itemCount))
        : plural("itemCount", state.itemCount);
      vaultContext.textContent = vaultContextText;
      if (state.decryptionFailures > 0) {
        showStatus(plural("skippedItems", state.decryptionFailures), "error");
      }
      showView("vault");
      void loadItems().then(openEditorDraft);
      break;
  }
}

// The other accounts on this browser, in Settings and on the sign-in and unlock screens.
function renderAccounts(accounts: SavedAccountSummary[]): void {
  for (const list of document.querySelectorAll<HTMLElement>(".account-list")) {
    list.hidden = accounts.length === 0;
    const heading = document.createElement("h3");
    heading.textContent = t("otherAccounts");
    list.replaceChildren(heading, ...accounts.map((account) => {
      const row = document.createElement("div");
      row.className = "excluded-domain-row account-row";
      const text = document.createElement("div");
      const name = document.createElement("span");
      name.className = "truncate";
      name.textContent = account.email;
      const server = document.createElement("small");
      server.className = "truncate";
      server.textContent = account.baseUrl;
      text.append(name, server);
      const button = itemAction(t("switch"), () => void switchAccount(account));
      const remove = confirmButton(t("remove"), () => void removeAccount(account));
      button.className = remove.className = "small-button";
      remove.title = t("removeAccountTitle", account.email);
      row.append(text, button, remove);
      return row;
    }));
  }
}

async function switchAccount(account: SavedAccountSummary): Promise<void> {
  try {
    await request({ type: "account.switch", id: account.id });
    selectedItem = null;
    unlockPassword.value = "";
    await refreshState();
    showStatus(t("switchedTo", account.email), "success");
  } catch (error) {
    showError(error);
  }
}

async function removeAccount(account: SavedAccountSummary): Promise<void> {
  try {
    await request({ type: "account.remove", id: account.id });
    await refreshState();
    showStatus(t("accountRemoved", account.email), "success");
  } catch (error) {
    showError(error);
  }
}

async function addAccount(): Promise<void> {
  try {
    await request({ type: "account.add" });
    selectedItem = null;
    await refreshState();
    showStatus(t("addAccountHint"), "neutral");
    email.focus();
  } catch (error) {
    showError(error);
  }
}

async function verifyServer(): Promise<void> {
  setBusy(serverSubmit, true, t("verifying"));
  clearStatus();
  try {
    const environment = normalizeServerEnvironment(serverUrl.value);
    const granted = await chrome.permissions.request({ origins: [environment.originPattern] });
    if (!granted) {
      throw new Error(t("serverPermissionDenied"));
    }
    const data = await request({ type: "server.check", baseUrl: environment.baseUrl }, "server");
    serverDetail.textContent = serverLabel(data.snapshot.baseUrl, data.snapshot.serverVersion);
    subtitle.textContent = data.snapshot.baseUrl;
    markState(t("signedOut"), "neutral");
    showView("login");
    email.focus();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(serverSubmit, false, t("verifyServer"));
  }
}

async function login(): Promise<void> {
  setBusy(loginSubmit, true, t("signingIn"));
  clearStatus();
  try {
    const data = await request({
      type: "auth.login",
      baseUrl: normalizeServerEnvironment(serverUrl.value).baseUrl,
      email: email.value,
      masterPassword: masterPassword.value,
      ...(twoFactorFields.hidden ? {} : { twoFactorProvider: Number(twoFactorProvider.value) }),
      ...(twoFactorToken.value ? { twoFactorToken: twoFactorToken.value } : {}),
      ...(twoFactorFields.hidden ? {} : { twoFactorRemember: twoFactorRemember.checked }),
      ...(deviceOtp.value ? { newDeviceOtp: deviceOtp.value } : {}),
    }, "login");
    if (data.result.status === "two-factor") {
      twoFactorFields.hidden = false;
      populateTwoFactor(data.result.providers);
      if (twoFactorToken.hidden) {
        showStatus(t("continueInNewWindow"), "neutral");
        loginSubmit.focus();
      } else {
        showStatus(t("enterTwoStepCode"), "neutral");
        twoFactorToken.focus();
      }
      return;
    }
    if (data.result.status === "device-verification") {
      deviceFields.hidden = false;
      deviceOtp.required = true;
      showStatus(data.result.message, "neutral");
      deviceOtp.focus();
      return;
    }
    masterPassword.value = "";
    twoFactorToken.value = "";
    deviceOtp.value = "";
    await refreshState();
    showStatus(plural("vaultUnlocked", data.result.itemCount), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(loginSubmit, false, t("signInAndSync"));
  }
}

async function unlock(): Promise<void> {
  setBusy(unlockSubmit, true, t("unlocking"));
  try {
    const data = await request({ type: "auth.unlock", masterPassword: unlockPassword.value }, "unlock");
    unlockPassword.value = "";
    await refreshState();
    showStatus(plural("vaultUnlocked", data.itemCount), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(unlockSubmit, false, t("unlock"));
  }
}

async function loadItems(): Promise<void> {
  try {
    const data = await request({
      type: "vault.list",
      query: search.value,
      ...(currentUrl ? { currentUrl } : {}),
      ...(folderFilter.value ? { folder: folderFilter.value } : {}),
    }, "items");
    renderFolders(data.folders, data.collections);
    renderItems(data.items);
  } catch (error) {
    showError(error);
  }
}

function renderItems(items: VaultItemSummary[]): void {
  itemList.replaceChildren();
  emptyState.hidden = items.length > 0;
  const trash = folderFilter.value === "trash";
  vaultContext.textContent = trash ? t("trashHint") : vaultContextText;
  emptyState.textContent = t(trash && !search.value ? "trashEmpty" : "noMatchingItems");
  const matches = items.filter((item) => item.matched);
  const remaining = items.filter((item) => !item.matched);
  if (matches.length > 0) appendItemSection(t("autofillSuggestions"), matches, matches.length);
  if (remaining.length > 0) {
    const title = search.value ? t("otherResults") : folderFilter.selectedOptions[0]?.text ?? t("allItems");
    appendItemSection(title, remaining, search.value ? remaining.length : folderFilter.value ? items.length : totalItems);
  }
}

// Fills the vault filter, the editor's folder and owner pickers and the Settings folder list.
function renderFolders(list: VaultFolder[], collectionList: VaultCollection[]): void {
  folders = list;
  collections = collectionList;
  const filter = folderFilter.value;
  folderFilter.replaceChildren(
    new Option(t("allItems"), ""),
    ...list.map((folder) => new Option(folder.name, folder.id)),
    new Option(t("noFolder"), "none"),
    ...collectionGroups(collectionList, (collection) => `collection:${collection.id}`),
    new Option(t("trash"), "trash"),
  );
  folderFilter.value = filter;
  if (folderFilter.selectedIndex < 0) folderFilter.value = "";
  const editing = itemFolder.value;
  itemFolder.replaceChildren(new Option(t("noFolder"), ""), ...list.map((folder) => new Option(folder.name, folder.id)));
  itemFolder.value = editing;
  folderList.replaceChildren(...list.map(folderRow));
}

// One option group per organization, listing its collections.
function collectionGroups(list: VaultCollection[], value: (collection: VaultCollection) => string): HTMLOptGroupElement[] {
  const groups = new Map<string, HTMLOptGroupElement>();
  for (const collection of list) {
    let group = groups.get(collection.organizationId);
    if (!group) {
      group = document.createElement("optgroup");
      group.label = collection.organizationName;
      groups.set(collection.organizationId, group);
    }
    group.append(new Option(collection.name, value(collection)));
  }
  return [...groups.values()];
}

function folderRow(folder: VaultFolder): HTMLElement {
  const row = document.createElement("form");
  row.className = "excluded-domain-row folder-row";
  const name = document.createElement("input");
  name.value = folder.name;
  name.maxLength = 1_000;
  name.required = true;
  name.setAttribute("aria-label", t("folderName"));
  const rename = itemAction(t("rename"), () => undefined);
  rename.type = "submit";
  rename.className = "small-button";
  const remove = confirmButton(t("delete"), () => void deleteFolder(folder.id));
  remove.className = "small-button";
  row.addEventListener("submit", (event) => {
    event.preventDefault();
    if (name.value.trim() !== folder.name) void saveFolder(folder.id, name.value);
  });
  row.append(name, rename, remove);
  return row;
}

async function saveFolder(id: string | undefined, name: string): Promise<boolean> {
  try {
    await request({ type: "folder.save", ...(id ? { id } : {}), name }, "done");
    await loadItems();
    showStatus(t(id ? "folderRenamed" : "folderAdded"), "success");
    return true;
  } catch (error) {
    showError(error);
    return false;
  }
}

async function deleteFolder(id: string): Promise<void> {
  try {
    await request({ type: "folder.delete", id }, "done");
    if (folderFilter.value === id) folderFilter.value = "";
    await loadItems();
    showStatus(t("folderDeleted"), "success");
  } catch (error) {
    showError(error);
  }
}

async function changeItem(type: "vault.trash" | "vault.restore" | "vault.deleteForever", id: string, message: string): Promise<void> {
  try {
    await request({ type, id }, "done");
    selectedItem = null;
    showView("vault");
    await loadItems();
    showStatus(message, "success");
  } catch (error) {
    showError(error);
  }
}

// Asks for a second click before an action that cannot be undone.
function confirmButton(label: string, action: () => void): HTMLButtonElement {
  let timer: number | undefined;
  const button = itemAction(label, () => {
    if (timer === undefined) {
      button.textContent = t("confirm");
      timer = window.setTimeout(() => {
        button.textContent = label;
        timer = undefined;
      }, 3_000);
      return;
    }
    window.clearTimeout(timer);
    timer = undefined;
    button.textContent = label;
    action();
  });
  return button;
}

function appendItemSection(title: string, items: VaultItemSummary[], count: number): void {
  const section = document.createElement("section");
  section.className = "item-section";
  const heading = document.createElement("div");
  heading.className = "item-section-heading";
  const label = document.createElement("h2");
  label.textContent = title;
  const itemCount = document.createElement("span");
  itemCount.className = "item-count";
  itemCount.textContent = String(count);
  heading.append(label, itemCount);
  const group = document.createElement("div");
  group.className = "item-group";
  section.append(heading, group);
  let rendered = 0;
  const appendBatch = () => {
    const next = items.slice(rendered, rendered + 100);
    group.append(...next.map(createItemRow));
    rendered += next.length;
  };
  appendBatch();
  if (rendered < items.length) {
    const sentinel = document.createElement("span");
    sentinel.className = "item-sentinel";
    sentinel.setAttribute("aria-hidden", "true");
    section.append(sentinel);
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      appendBatch();
      if (rendered >= items.length) {
        observer.disconnect();
        sentinel.remove();
      }
    });
    observer.observe(sentinel);
  }
  itemList.append(section);
}

function createItemRow(item: VaultItemSummary): HTMLElement {
  const row = document.createElement("article");
  row.className = "item";
  row.setAttribute("role", "listitem");

  const icon = document.createElement("span");
  icon.className = "item-icon";
  icon.textContent = item.name.trim().charAt(0).toLocaleUpperCase() || "•";
  const favicon = siteFavicon(item.uri);
  if (favicon) icon.append(favicon);

  const main = document.createElement("div");
  main.className = "item-main";
  main.tabIndex = 0;
  main.setAttribute("role", "button");
  const name = document.createElement("div");
  name.className = "item-name truncate";
  name.textContent = `${item.favorite ? "★ " : ""}${item.name}`;
  if (item.matched) {
    const dot = document.createElement("span");
    dot.className = "match-dot";
    dot.title = t("matchesThisPage");
    dot.setAttribute("role", "img");
    dot.setAttribute("aria-label", t("matchesThisPage"));
    name.append(dot);
  }
  const meta = document.createElement("div");
  meta.className = "item-meta truncate";
  meta.textContent = item.subtitle || item.username || item.uri || TYPE_NAMES[item.type];
  main.append(name, meta);
  // Trashed items can only be restored or deleted; they are never filled or copied.
  if (folderFilter.value === "trash") {
    main.removeAttribute("tabindex");
    main.removeAttribute("role");
    main.style.cursor = "default";
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const restore = itemAction(t("restore"), () => void changeItem("vault.restore", item.id, t("itemRestored")));
    const purge = confirmButton(t("deleteForever"), () => void changeItem("vault.deleteForever", item.id, t("itemDeletedForever")));
    restore.className = purge.className = "small-button";
    actions.append(restore, purge);
    row.append(icon, main, actions);
    return row;
  }
  const open = () => void showDetail(item.id);
  main.addEventListener("click", open);
  main.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open();
    }
  });

  const actions = document.createElement("div");
  actions.className = "row-actions";
  if (item.matched) {
    const fillButton = document.createElement("button");
    fillButton.className = "fill-button";
    fillButton.type = "button";
    fillButton.textContent = t(item.requiresReprompt ? "open" : "fill");
    fillButton.addEventListener("click", () =>
      item.requiresReprompt ? void showDetail(item.id) : void fill(item.id),
    );
    actions.append(fillButton);
  }
  if (item.uri) actions.append(rowIconButton("external", t("openWebsite"), () => void openWebsite(item.uri!)));
  const copyPassword = () => void copyItemField(item.id, t("password"), (detail) => detail.password);
  const copyNumber = () => void copyItemField(item.id, t("cardNumber"), (detail) => detail.card?.number);
  const copyNote = () => void copyItemField(item.id, t("note"), (detail) => detail.notes);
  const copyPublicKey = () => void copyItemField(item.id, t("publicKey"), (detail) => detail.sshKey?.publicKey);
  if (item.type === ItemType.SshKey) actions.append(rowIconButton("copy", t("copyPublicKey"), copyPublicKey));
  if (item.type === ItemType.Login) actions.append(rowIconButton("copy", t("copyPassword"), copyPassword));
  if (item.type === ItemType.Card) actions.append(rowIconButton("copy", t("copyCardNumber"), copyNumber));
  if (item.type === ItemType.SecureNote) actions.append(rowIconButton("copy", t("copyNote"), copyNote));

  const menu = document.createElement("div");
  menu.className = "item-menu";
  menu.hidden = true;
  if (item.type === ItemType.Login) {
    menu.append(
      itemAction(t("copyUsername"), () => void copySecret(item.username, t("usernameCopied"))),
      itemAction(t("copyPassword"), copyPassword),
    );
  }
  if (item.type === ItemType.Card) {
    menu.append(
      itemAction(t("copyCardNumber"), copyNumber),
      itemAction(t("copySecurityCode"), () => void copyItemField(item.id, t("securityCode"), (detail) => detail.card?.code)),
    );
  }
  if (item.type === ItemType.SecureNote) menu.append(itemAction(t("copyNote"), copyNote));
  if (item.type === ItemType.SshKey) {
    menu.append(
      itemAction(t("copyPublicKey"), copyPublicKey),
      itemAction(t("copyPrivateKey"), () => void copyItemField(item.id, t("privateKey"), (detail) => detail.sshKey?.privateKey)),
    );
  }
  if (item.type === ItemType.Card || item.type === ItemType.Identity) {
    menu.append(itemAction(t("fillOnThisPage"), () => item.requiresReprompt ? void showDetail(item.id) : void fill(item.id)));
  }
  if (item.hasTotp) menu.append(itemAction(t("copyVerificationCode"), () => void copyItemTotp(item)));
  if (item.editable) {
    menu.append(
      itemAction(t("edit"), () => void editItem(item.id)),
      itemAction(t("moveToTrash"), () => {
        if (!item.requiresReprompt) return void changeItem("vault.trash", item.id, t("movedToTrash"));
        void showDetail(item.id).then(() => showStatus(t("confirmBeforeDeleting"), "neutral"));
      }),
    );
  }
  const more = rowIconButton("more", t("moreActions"), () => {
    closeItemMenus(menu);
    menu.hidden = !menu.hidden;
    more.setAttribute("aria-expanded", String(!menu.hidden));
  });
  more.setAttribute("aria-expanded", "false");
  actions.append(more);
  row.append(icon, main, actions, menu);
  return row;
}

async function openWebsite(uri: string): Promise<void> {
  try {
    const url = new URL(uri);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(t("noWebAddress"));
    await chrome.tabs.create({ url: url.href });
    window.close();
  } catch (error) {
    showError(error);
  }
}

function siteFavicon(uri?: string): HTMLImageElement | null {
  if (!uri) return null;
  try {
    const pageUrl = new URL(uri);
    if (pageUrl.protocol !== "http:" && pageUrl.protocol !== "https:") return null;
    const faviconUrl = new URL(chrome.runtime.getURL("/_favicon/"));
    faviconUrl.searchParams.set("pageUrl", pageUrl.href);
    faviconUrl.searchParams.set("size", "32");
    const image = document.createElement("img");
    image.src = faviconUrl.href;
    image.alt = "";
    image.loading = "lazy";
    image.addEventListener("error", () => image.remove());
    return image;
  } catch {
    return null;
  }
}

function closeItemMenus(except?: HTMLElement): void {
  for (const menu of itemList.querySelectorAll<HTMLElement>(".item-menu")) {
    if (menu === except) continue;
    menu.hidden = true;
    menu.parentElement?.querySelector('[aria-expanded="true"]')?.setAttribute("aria-expanded", "false");
  }
}

async function showDetail(id: string): Promise<void> {
  try {
    renderDetail(await getItemDetail(id));
  } catch (error) {
    showError(error);
  }
}

async function getItemDetail(id: string): Promise<VaultItemDetail> {
  const data = await request({ type: "vault.get", id, ...(currentUrl ? { currentUrl } : {}) }, "item");
  return data.item;
}

function renderDetail(item: VaultItemDetail): void {
  selectedItem = item;
  const login = item.type === ItemType.Login;
  detailName.textContent = item.name;
  detailUri.textContent = login ? item.uri ?? t("noWebsiteSaved") : item.subtitle || TYPE_NAMES[item.type];
  detailUsername.textContent = item.username || "—";
  detailPassword.textContent = item.password || "—";
  detailPassword.classList.add("password-mask");
  repromptForm.hidden = !item.protected;
  usernameRow.hidden = !login;
  passwordRow.hidden = !login || item.protected;
  fillDetail.hidden = item.protected || item.type === ItemType.SecureNote || item.type === ItemType.SshKey;
  detailFields.replaceChildren(...detailRows(item));
  const owner = ownerText(item);
  detailOwner.textContent = owner;
  detailOwner.hidden = !owner;
  detailAttachments.replaceChildren(...attachmentRows(item));
  addAttachment.hidden = !item.editable || item.protected;
  totpRow.hidden = !item.hasTotp;
  element("trash-item").hidden = !item.editable || item.protected;
  editLogin.hidden = element("trash-item").hidden;
  detailTotp.textContent = item.hasTotp ? t("loading") : "";
  totpTimer.textContent = "";
  element<HTMLButtonElement>("reveal-password").textContent = t("show");
  showView("detail");
  if (item.protected) {
    repromptPassword.focus();
  }
  if (item.hasTotp) {
    void refreshTotp();
  }
}

// Rows for card, identity, SSH key, note and custom-field content, shown the way Bitwarden groups them.
function detailRows(item: VaultItemDetail): HTMLElement[] {
  const rows: HTMLElement[] = [];
  const add = (label: string, value: string | undefined, sensitive = false, multiline = false) => {
    if (value) rows.push(detailRow(label, value, sensitive, multiline));
  };
  const card = item.card;
  if (card) {
    add(t("cardholderName"), card.cardholderName);
    add(t("brand"), card.brand);
    add(t("number"), card.number, true);
    add(t("expiration"), [card.expMonth?.padStart(2, "0"), card.expYear].filter(Boolean).join(" / "));
    add(t("securityCode"), card.code, true);
  }
  const identity = item.identity;
  if (identity) {
    add(t("name"), [identity.title, identity.firstName, identity.middleName, identity.lastName].filter(Boolean).join(" "));
    add(t("username"), identity.username);
    add(t("company"), identity.company);
    add(t("email"), identity.email);
    add(t("phone"), identity.phone);
    const cityLine = [identity.city, identity.state, identity.postalCode].filter(Boolean).join(", ");
    add(t("address"), [identity.address1, identity.address2, identity.address3, cityLine, identity.country].filter(Boolean).join("\n"), false, true);
    add(t("ssn"), identity.ssn, true);
    add(t("passportNumber"), identity.passportNumber, true);
    add(t("licenseNumber"), identity.licenseNumber, true);
  }
  const sshKey = item.sshKey;
  if (sshKey) {
    add(t("privateKey"), sshKey.privateKey, true);
    add(t("publicKey"), sshKey.publicKey);
    add(t("fingerprint"), sshKey.keyFingerprint);
  }
  for (const passkey of item.passkeys ?? []) rows.push(passkeyRow(passkey, item));
  add(t("notes"), item.notes, false, true);
  for (const field of item.fields ?? []) add(field.name || t("customField"), field.value, field.hidden);
  if (item.passwordHistory?.length) {
    const history = document.createElement("details");
    history.className = "password-history";
    const summary = document.createElement("summary");
    summary.textContent = t("passwordHistory", item.passwordHistory.length);
    history.append(summary, ...item.passwordHistory.map((entry) => detailRow(historyDate(entry.lastUsedDate), entry.password, true, false, t("oldPassword"))));
    rows.push(history);
  }
  return rows;
}

// "Acme · Ops, Audit" for an organization item.
function ownerText(item: VaultItemDetail): string {
  if (!item.organizationId) return "";
  const own = collections.filter((collection) => item.collectionIds?.includes(collection.id));
  const organization = collections.find((collection) => collection.organizationId === item.organizationId)?.organizationName ?? t("organization");
  return own.length ? `${organization} · ${own.map((collection) => collection.name).join(", ")}` : organization;
}

function attachmentRows(item: VaultItemDetail): HTMLElement[] {
  if (!item.attachments?.length) return [];
  const heading = document.createElement("span");
  heading.className = "label";
  heading.textContent = t("attachmentsCount", item.attachments.length);
  return [heading, ...item.attachments.map((attachment) => {
    const row = document.createElement("div");
    row.className = "secret-row";
    const open = itemAction("", () => void downloadAttachment(item.id, attachment, open));
    open.className = "copy-field";
    open.title = t("downloadFile", attachment.fileName);
    const name = document.createElement("span");
    name.className = "secret truncate";
    name.textContent = attachment.fileName;
    const size = document.createElement("span");
    size.className = "label";
    size.textContent = attachment.sizeName || formatSize(attachment.size);
    open.append(name, size);
    row.append(open);
    if (item.editable) {
      const remove = confirmButton(t("delete"), () => void deleteAttachment(item.id, attachment));
      remove.className = "small-button";
      remove.title = t("deleteFile", attachment.fileName);
      row.append(remove);
    }
    return row;
  })];
}

async function downloadAttachment(id: string, attachment: Attachment, field: HTMLElement): Promise<void> {
  field.setAttribute("aria-busy", "true");
  try {
    const data = await request({ type: "attachment.download", id, attachmentId: attachment.id }, "file");
    saveFile(data.fileName, new Blob([fromBase64(data.data)]));
    showStatus(t("fileDownloaded", data.fileName), "success");
  } catch (error) {
    showError(error);
  } finally {
    field.removeAttribute("aria-busy");
  }
}

async function uploadAttachment(): Promise<void> {
  const file = attachmentFile.files?.[0];
  attachmentFile.value = "";
  if (!file || !selectedItem) return;
  const id = selectedItem.id;
  try {
    if (file.size > MAX_FILE_BYTES) throw new Error(t("fileTooLarge25"));
    if (file.size === 0) throw new Error(t("fileEmpty"));
    showStatus(t("uploadingFile", file.name), "neutral");
    const data = new Uint8Array(await file.arrayBuffer()).toBase64();
    await request({ type: "attachment.add", id, fileName: file.name, data }, "done");
    renderDetail(await getItemDetail(id));
    showStatus(t("fileAttached", file.name), "success");
  } catch (error) {
    showError(error);
  }
}

async function deleteAttachment(id: string, attachment: Attachment): Promise<void> {
  try {
    await request({ type: "attachment.delete", id, attachmentId: attachment.id }, "done");
    renderDetail(await getItemDetail(id));
    showStatus(t("fileDeleted", attachment.fileName), "success");
  } catch (error) {
    showError(error);
  }
}

// Saves a file through the browser's download flow.
function saveFile(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const [value, unit] = bytes < 1024 * 1024 ? [bytes / 1024, "KB"] : [bytes / 1024 / 1024, "MB"];
  return `${value.toFixed(value < 10 ? 1 : 0)} ${unit}`;
}

async function loadSends(): Promise<void> {
  try {
    const data = await request({ type: "send.list" }, "sends");
    sendEmpty.hidden = data.sends.length > 0;
    sendList.hidden = data.sends.length === 0;
    sendList.replaceChildren(...data.sends.map(sendRow));
  } catch (error) {
    showError(error);
  }
}

function sendRow(send: SendSummary): HTMLElement {
  const row = document.createElement("article");
  row.className = "item";
  row.setAttribute("role", "listitem");
  const badge = document.createElement("span");
  badge.className = "item-icon";
  badge.textContent = send.name.trim().charAt(0).toLocaleUpperCase() || "•";
  const main = document.createElement("div");
  main.className = "item-main";
  main.tabIndex = 0;
  main.setAttribute("role", "button");
  main.title = t("copyLink");
  const name = document.createElement("div");
  name.className = "item-name truncate";
  name.textContent = send.name;
  const meta = document.createElement("div");
  meta.className = "item-meta truncate";
  const deletes = new Date(send.deletionDate);
  const views = send.maxAccessCount ? t("viewsOf", send.accessCount, send.maxAccessCount) : plural("views", send.accessCount);
  meta.textContent = [
    send.type === 1 ? send.fileName ?? t("file") : t("text"),
    Number.isNaN(deletes.getTime()) ? "" : t("deletesOn", deletes.toLocaleDateString(undefined, { dateStyle: "medium" })),
    views,
    send.hasPassword ? t("password") : "",
    send.disabled ? t("disabled") : "",
  ].filter(Boolean).join(" · ");
  main.append(name, meta);
  const copy = () => void copySecret(send.link, t("sendLinkCopied"));
  main.addEventListener("click", copy);
  main.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      copy();
    }
  });
  const actions = document.createElement("div");
  actions.className = "row-actions";
  const remove = confirmButton(t("delete"), () => void deleteSend(send));
  remove.className = "small-button";
  remove.title = t("deleteSendTitle", send.name);
  actions.append(rowIconButton("copy", t("copyLink"), copy), remove);
  row.append(badge, main, actions);
  return row;
}

async function deleteSend(send: SendSummary): Promise<void> {
  try {
    await request({ type: "send.delete", id: send.id }, "done");
    await loadSends();
    showStatus(t("sendDeleted", send.name), "success");
  } catch (error) {
    showError(error);
  }
}

function openSendEditor(): void {
  sendForm.reset();
  sendFileName.textContent = t("noFileChosenSendLimit");
  updateSendType();
  showView("sendEditor");
  sendName.focus();
}

function sendType(): 0 | 1 {
  return document.querySelector<HTMLInputElement>('input[name="send-type"]:checked')?.value === "1" ? 1 : 0;
}

function updateSendType(): void {
  const file = sendType() === 1;
  element("send-text-fields").hidden = file;
  element("send-file-fields").hidden = !file;
  sendText.required = !file;
}

async function createSend(): Promise<void> {
  setBusy(sendSubmit, true, t("encrypting"));
  try {
    const type = sendType();
    const file = type === 1 ? sendFile.files?.[0] : undefined;
    if (type === 1 && !file) throw new Error(t("chooseFileToSend"));
    if (file && file.size > MAX_FILE_BYTES) throw new Error(t("fileTooLarge25"));
    const maxAccessCount = sendMaxAccess.value ? Number(sendMaxAccess.value) : undefined;
    const send: SendWriteInput = {
      type,
      name: sendName.value,
      deletionDays: Number(sendDeletion.value),
      ...(file ? { fileName: file.name } : { text: sendText.value, hidden: sendHidden.checked }),
      ...(sendPassword.value ? { password: sendPassword.value } : {}),
      ...(maxAccessCount ? { maxAccessCount } : {}),
    };
    const data = await request({
      type: "send.create",
      send,
      ...(file ? { file: new Uint8Array(await file.arrayBuffer()).toBase64() } : {}),
    }, "sendCreated");
    sendForm.reset();
    showView("send");
    await loadSends();
    if (data.link) await copySecret(data.link, t("sendCreatedCopied"));
    else showStatus(t("sendCreatedSync"), "neutral");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(sendSubmit, false, t("createAndCopyLink"));
  }
}

async function chooseImportFile(): Promise<void> {
  const file = vaultImportFile.files?.[0];
  vaultImportFile.value = "";
  resetImportCheck();
  importFileText = "";
  vaultImportName.textContent = t("noFileChosen");
  vaultImportSubmit.disabled = true;
  if (!file) return;
  if (file.size > 10_000_000) {
    showError(new Error(t("fileTooLarge10")));
    return;
  }
  importFileText = await file.text();
  vaultImportName.textContent = `${file.name} · ${formatSize(file.size)}`;
  // A password-protected Bitwarden export says so in plain text.
  vaultImportPasswordField.hidden = !/"passwordProtected"\s*:\s*true/.test(importFileText);
  vaultImportPassword.required = !vaultImportPasswordField.hidden;
  vaultImportSubmit.disabled = false;
}

function resetImportCheck(): void {
  importChecked = false;
  importLabel = t("checkFile");
  vaultImportSummary.hidden = true;
  vaultImportSubmit.textContent = importLabel;
}

// First a check that reads the file (nothing saved), then the import itself.
async function importVault(): Promise<void> {
  if (!importFileText) return;
  const confirm = importChecked;
  setBusy(vaultImportSubmit, true, t(confirm ? "importing" : "checking"));
  try {
    const data = await request({
      type: "vault.import",
      text: importFileText,
      ...(vaultImportPassword.value ? { password: vaultImportPassword.value } : {}),
      confirm,
    }, "import");
    const items = plural("itemCount", data.items);
    if (confirm) {
      resetTransfer();
      showStatus(t("importedItems", items), "success");
    } else {
      importChecked = true;
      importLabel = t("importItems", items);
      vaultImportSummary.textContent = data.folders ? t("foundItemsInFolders", items, plural("folderCount", data.folders)) : t("foundItems", items);
      vaultImportSummary.hidden = false;
    }
  } catch (error) {
    showError(error);
  }
  setBusy(vaultImportSubmit, false, importLabel);
  vaultImportSubmit.disabled = !importFileText;
}

function updateExportFormat(): void {
  const encrypted = vaultExportFormat.value === "encrypted_json";
  element("vault-export-file-password-field").hidden = !encrypted;
  vaultExportFilePassword.required = encrypted;
  element("vault-export-warning").hidden = encrypted;
}

async function exportVault(): Promise<void> {
  setBusy(vaultExportSubmit, true, t("exporting"));
  try {
    const format = vaultExportFormat.value === "json" ? "json" : "encrypted_json";
    const data = await request({
      type: "vault.export",
      masterPassword: vaultExportPassword.value,
      format,
      ...(format === "encrypted_json" ? { filePassword: vaultExportFilePassword.value } : {}),
    }, "export");
    vaultExportPassword.value = "";
    vaultExportFilePassword.value = "";
    saveFile(`firnkey-export-${new Date().toISOString().slice(0, 10)}.json`, new Blob([data.text], { type: "application/json" }));
    showStatus(t(format === "json" ? "vaultExportedPlain" : "vaultExportedProtected"), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(vaultExportSubmit, false, t("exportVault"));
  }
}

// Typed passwords and the chosen file never outlive the Import & export page.
function resetTransfer(): void {
  vaultImportForm.reset();
  vaultExportForm.reset();
  importFileText = "";
  vaultImportName.textContent = t("noFileChosen");
  vaultImportPasswordField.hidden = true;
  vaultImportSubmit.disabled = true;
  resetImportCheck();
  updateExportFormat();
}

// Read-only: there is nothing useful to copy, and the private key never leaves the background.
function passkeyRow(passkey: PasskeySummary, item: VaultItemDetail): HTMLElement {
  const row = document.createElement("div");
  row.className = "secret-row";
  const name = document.createElement("span");
  name.className = "label";
  name.textContent = t("passkey");
  const content = document.createElement("span");
  content.className = "secret truncate";
  const date = new Date(passkey.creationDate);
  const created = Number.isNaN(date.getTime()) ? "" : ` · ${t("createdOn", date.toLocaleDateString(undefined, { dateStyle: "medium" }))}`;
  content.textContent = `${passkey.userName || passkey.rpId}${created}`;
  content.title = passkey.rpId;
  const text = document.createElement("span");
  text.append(name, content);
  row.append(text);
  if (item.editable) {
    const remove = confirmButton(t("remove"), () => void removePasskey(item.id));
    remove.className = "small-button";
    remove.title = t("removePasskeyTitle");
    row.append(remove);
  }
  return row;
}

async function removePasskey(id: string): Promise<void> {
  try {
    await request({ type: "vault.removePasskey", id }, "done");
    renderDetail(await getItemDetail(id));
    showStatus(t("passkeyRemoved"), "success");
  } catch (error) {
    showError(error);
  }
}

function historyDate(value: string): string {
  const date = new Date(value);
  return value && !Number.isNaN(date.getTime())
    ? t("usedUntil", date.toLocaleDateString(undefined, { dateStyle: "medium" }))
    : t("earlierPassword");
}

function detailRow(label: string, value: string, sensitive: boolean, multiline: boolean, copyName = label): HTMLElement {
  // Clicking the field copies it. A sensitive field keeps a Show button beside it, so only its text is the copy button.
  const field = itemAction("", () => void copySecret(value, t("fieldCopied", copyName), field));
  field.title = t("copyField", label);
  const name = document.createElement("span");
  name.className = "label";
  name.textContent = label;
  const content = document.createElement("span");
  content.className = multiline ? "secret notes-value" : "secret truncate";
  content.classList.toggle("password-mask", sensitive);
  content.textContent = value;
  field.append(name, content);
  if (!sensitive) {
    field.className = "secret-row";
    return field;
  }
  field.className = "copy-field";
  const reveal = itemAction(t("show"), () => {
    reveal.textContent = t(content.classList.toggle("password-mask") ? "show" : "hide");
  });
  reveal.className = "small-button";
  const row = document.createElement("div");
  row.className = "secret-row";
  row.append(field, reveal);
  return row;
}

function itemAction(label: string, action: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

function rowIconButton(name: IconName, label: string, action: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.className = "row-icon-button";
  button.type = "button";
  button.innerHTML = icon(name);
  button.title = label;
  button.setAttribute("aria-label", label);
  button.addEventListener("click", action);
  return button;
}

async function copyItemField(id: string, label: string, pick: (item: VaultItemDetail) => string | undefined): Promise<void> {
  try {
    const item = await getItemDetail(id);
    if (item.protected) {
      renderDetail(item);
      showStatus(t("confirmBeforeCopying"), "neutral");
      return;
    }
    await copySecret(pick(item) ?? "", t("fieldCopied", label));
  } catch (error) {
    showError(error);
  }
}

async function copyItemTotp(item: { id: string; requiresReprompt: boolean }): Promise<void> {
  if (item.requiresReprompt) {
    await showDetail(item.id); // Protected logins need the master password first.
    return;
  }
  try {
    const data = await request({ type: "vault.totp", id: item.id }, "totp");
    await copySecret(data.code, t("codeCopied"));
  } catch (error) {
    showError(error);
  }
}

async function editItem(id: string): Promise<void> {
  try {
    const item = await getItemDetail(id);
    if (!item.editable) {
      throw new Error(t("viewOnlyItem"));
    }
    if (item.protected) {
      renderDetail(item);
      showStatus(t("confirmBeforeEditing"), "neutral");
      return;
    }
    selectedItem = item;
    openEditor(item);
  } catch (error) {
    showError(error);
  }
}

function openEditor(item?: VaultItemDetail): void {
  editingId = item?.id ?? null;
  const type = item?.type ?? ItemType.Login;
  itemType.value = String(type);
  itemType.disabled = Boolean(item); // Bitwarden items keep their type.
  renderEditorFields(type, item);
  loginName.value = item?.name ?? suggestedSiteName();
  loginUsername.value = item?.username ?? "";
  loginPassword.value = item?.password ?? "";
  showLoginPassword(false);
  loginUri.value = item?.uri ?? editableCurrentUrl();
  loginTotp.value = item?.totp ?? "";
  savedTotp = Boolean(item?.totp);
  loginNotes.value = item?.notes ?? "";
  loginFavorite.checked = item?.favorite ?? false;
  // New items go to the folder being viewed. An item whose folder could not be read keeps it (blank picker).
  const viewing = folders.some((folder) => folder.id === folderFilter.value) ? folderFilter.value : "";
  itemFolder.value = item ? item.folderId ?? "" : viewing;
  // Owner: new items and personal items can go to a collection; organization items stay where they are.
  const writable = collections.filter((collection) => !collection.readOnly);
  itemCollection.replaceChildren(new Option(t("myVault"), ""), ...collectionGroups(writable, (collection) => collection.id));
  const viewingCollection = folderFilter.value.startsWith("collection:") ? folderFilter.value.slice(11) : "";
  itemCollection.value = !item && writable.some((collection) => collection.id === viewingCollection) ? viewingCollection : "";
  collectionField.hidden = writable.length === 0 || Boolean(item?.organizationId);
  collectionHint.hidden = true;
  showView("editor");
  loginName.focus();
}

// "Add card" / "Add identity" in a website's field menu leaves the form's values here for the editor.
async function openEditorDraft(): Promise<void> {
  const { editorDraft } = await chrome.storage.session.get("editorDraft");
  if (!editorDraft) return;
  await chrome.storage.session.remove("editorDraft");
  const draft = editorDraft as { type: ItemType; fields: Record<string, string>; expires: number };
  if (draft.expires < Date.now() || (draft.type !== ItemType.Card && draft.type !== ItemType.Identity)) return;
  openEditor();
  itemType.value = String(draft.type);
  renderEditorFields(draft.type);
  for (const input of typeFields.querySelectorAll<HTMLInputElement>("input")) input.value = draft.fields[input.dataset.field!] ?? "";
  const { firstName, lastName, cardholderName, brand, number } = draft.fields;
  loginName.value = draft.type === ItemType.Card
    ? [brand || t("card"), number ? `*${number.slice(-4)}` : ""].filter(Boolean).join(" ")
    : [firstName, lastName].filter(Boolean).join(" ") || cardholderName || "";
  loginUri.value = "";
}

function showLoginPassword(visible: boolean): void {
  loginPassword.type = visible ? "text" : "password";
  toggleLoginPassword.textContent = t(visible ? "hide" : "show");
  toggleLoginPassword.setAttribute("aria-pressed", String(visible));
}

// Clearing a shown key removes it. A key the popup never got (password hidden by the collection) stays untouched.
function chosenTotp(): { totp?: string } {
  const value = loginTotp.value.trim();
  return value || savedTotp ? { totp: value } : {};
}

function renderEditorFields(type: ItemType, item?: VaultItemDetail): void {
  editorTitle.textContent = EDITOR_TITLES[type][item ? 1 : 0];
  loginFields.hidden = type !== ItemType.Login;
  if (type === ItemType.SshKey) {
    renderSshKeyFields(item);
    return;
  }
  const names = type === ItemType.Card ? CARD_FIELDS : type === ItemType.Identity ? IDENTITY_FIELDS : [];
  const values: Record<string, string | undefined> = (type === ItemType.Card ? item?.card : item?.identity) ?? {};
  typeFields.replaceChildren(...names.flatMap((name) => {
    const label = document.createElement("label");
    label.htmlFor = `field-${name}`;
    label.textContent = FIELD_LABELS[name] ?? name;
    const input = document.createElement("input");
    input.id = `field-${name}`;
    input.dataset.field = name;
    input.maxLength = 1_000;
    input.autocomplete = "off";
    input.value = values[name] ?? "";
    if (SENSITIVE_FIELDS.has(name) || name === "expMonth" || name === "expYear") input.inputMode = "numeric";
    if (name === "expMonth") input.placeholder = t("monthPlaceholder");
    if (name === "expYear") input.placeholder = t("yearPlaceholder");
    return [label, input];
  }));
}

// Private and public key; the fingerprint is computed when saving. An OpenSSH private key brings its
// public key along, so pasting one fills the public key.
function renderSshKeyFields(item?: VaultItemDetail): void {
  const area = (name: "privateKey" | "publicKey", rows: number) => {
    const label = document.createElement("label");
    label.htmlFor = `field-${name}`;
    label.textContent = t(name);
    const input = document.createElement("textarea");
    input.id = `field-${name}`;
    input.dataset.field = name;
    input.rows = rows;
    input.maxLength = 10_000;
    input.spellcheck = false;
    input.autocomplete = "off";
    input.className = "mono";
    input.value = item?.sshKey?.[name] ?? "";
    return [label, input] as const;
  };
  const [privateLabel, privateKey] = area("privateKey", 6);
  const [publicLabel, publicKey] = area("publicKey", 3);
  privateKey.addEventListener("input", () => {
    const derived = publicKeyFromPrivate(privateKey.value);
    if (derived) publicKey.value = derived;
  });
  const generate = document.createElement("button");
  generate.type = "button";
  generate.className = "secondary";
  generate.textContent = t("generateSshKey");
  generate.hidden = Boolean(item);
  generate.addEventListener("click", () => {
    void generateEd25519Key().then((key) => {
      privateKey.value = key.privateKey;
      publicKey.value = key.publicKey;
      showStatus(t("sshKeyGenerated"), "success");
    }, showError);
  });
  typeFields.replaceChildren(privateLabel, privateKey, publicLabel, publicKey, generate);
}

async function saveEditor(): Promise<void> {
  const type = Number(itemType.value) as ItemType;
  if (type !== ItemType.Login) {
    await saveItemEditor(type as ItemWriteInput["type"]);
    return;
  }
  setBusy(editorSubmit, true, t("saving"));
  clearStatus();
  try {
    const login = {
      name: loginName.value,
      username: loginUsername.value,
      password: loginPassword.value,
      uri: loginUri.value,
      notes: loginNotes.value,
      favorite: loginFavorite.checked,
      ...chosenFolder(),
      ...chosenTotp(),
    };
    const id = editingId;
    const collectionId = collectionField.hidden ? "" : itemCollection.value;
    await request(id ? { type: "vault.update", id, login } : { type: "vault.create", login, ...(collectionId ? { collectionId } : {}) }, "done");
    if (id && collectionId) await request({ type: "vault.move", id, collectionId }, "done");
    editorForm.reset();
    editingId = null;
    selectedItem = null;
    showView("vault");
    await loadItems();
    showStatus(t(id ? "loginUpdated" : "loginAdded"), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(editorSubmit, false, t("save"));
  }
}

async function saveItemEditor(type: ItemWriteInput["type"]): Promise<void> {
  setBusy(editorSubmit, true, t("saving"));
  clearStatus();
  try {
    const fields = Object.fromEntries(
      [...typeFields.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")].map((input) => [input.dataset.field!, input.value]),
    );
    const item: ItemWriteInput = {
      type,
      name: loginName.value,
      notes: loginNotes.value,
      favorite: loginFavorite.checked,
      ...chosenFolder(),
      ...(type === ItemType.Card ? { card: fields } : type === ItemType.Identity ? { identity: fields } : {}),
      ...(type === ItemType.SshKey ? { sshKey: fields } : {}),
    };
    const id = editingId;
    const collectionId = collectionField.hidden ? "" : itemCollection.value;
    await request(id ? { type: "vault.updateItem", id, item } : { type: "vault.createItem", item, ...(collectionId ? { collectionId } : {}) }, "done");
    if (id && collectionId) await request({ type: "vault.move", id, collectionId }, "done");
    editorForm.reset();
    editingId = null;
    selectedItem = null;
    showView("vault");
    await loadItems();
    showStatus(t(id ? "itemUpdated" : "itemAdded", TYPE_NAMES[type]), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(editorSubmit, false, t("save"));
  }
}

function chosenFolder(): { folderId?: string } {
  return itemFolder.selectedIndex < 0 ? {} : { folderId: itemFolder.value };
}

function editableCurrentUrl(): string {
  if (!currentUrl) return "";
  try {
    const url = new URL(currentUrl);
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : "";
  } catch {
    return "";
  }
}

function suggestedSiteName(): string {
  const value = editableCurrentUrl();
  return value ? new URL(value).hostname.replace(/^www\./, "") : "";
}

// The editor's Generate button: a passphrase when that is the chosen style, otherwise a password.
function defaultGeneratedPassword(): string {
  const options = readGeneratorForm();
  return options.type === "passphrase" ? generatePassphrase(options) : generatePassword(options);
}

// Copied or used passwords go to the encrypted generator history, with the page the user was on.
function recordGenerated(password: string, username: boolean): void {
  if (username || !password) return;
  void request({ type: "generator.record", password, ...(currentUrl ? { url: currentUrl } : {}) }, "done")
    .then(() => (generatorHistory.open ? loadGeneratorHistory() : undefined))
    .catch(() => undefined); // A locked vault simply keeps no history.
}

async function loadGeneratorHistory(): Promise<void> {
  try {
    const { entries } = await request({ type: "generator.history" }, "generatorHistory");
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "detail";
      empty.textContent = t("generatorHistoryEmpty");
      generatorHistoryList.replaceChildren(empty);
      return;
    }
    const clear = confirmButton(t("clearGeneratorHistory"), () => void clearGeneratorHistoryList());
    clear.className = "danger-button";
    generatorHistoryList.replaceChildren(
      ...entries.map((entry) => detailRow(generatedLabel(entry.date, entry.site), entry.password, true, false, t("generatedPasswordLabel"))),
      clear,
    );
  } catch (error) {
    generatorHistoryList.replaceChildren();
    showError(error);
  }
}

async function clearGeneratorHistoryList(): Promise<void> {
  try {
    await request({ type: "generator.clearHistory" }, "done");
    showStatus(t("generatorHistoryCleared"), "success");
    await loadGeneratorHistory();
  } catch (error) {
    showError(error);
  }
}

function generatedLabel(value: string, site: string | undefined): string {
  const date = new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  return site ? t("generatedOnSite", site, date) : t("generatedWithoutSite", date);
}

function readGeneratorForm(): StoredGeneratorOptions {
  const type = document.querySelector<HTMLInputElement>('input[name="generator-type"]:checked')?.value;
  return {
    type: type === "passphrase" || type === "username" ? type : "password",
    length: Number(generatorLength.value),
    uppercase: generatorUppercase.checked,
    lowercase: generatorLowercase.checked,
    numbers: generatorNumbers.checked,
    symbols: generatorSymbols.checked,
    words: Number(generatorWords.value),
    separator: generatorSeparator.value,
    capitalize: generatorCapitalize.checked,
    includeNumber: generatorIncludeNumber.checked,
    usernameKind: usernameKind.value === "plus" || usernameKind.value === "catchall" ? usernameKind.value : "word",
    usernameCapitalize: usernameCapitalize.checked,
    usernameIncludeNumber: usernameIncludeNumber.checked,
    usernameEmail: usernameEmail.value.trim(),
    usernameDomain: usernameDomain.value.trim(),
  };
}

function writeGeneratorForm(options: StoredGeneratorOptions): void {
  const type = document.querySelector<HTMLInputElement>(`input[name="generator-type"][value="${options.type}"]`);
  if (type) type.checked = true;
  generatorLength.value = String(options.length);
  generatorUppercase.checked = options.uppercase;
  generatorLowercase.checked = options.lowercase;
  generatorNumbers.checked = options.numbers;
  generatorSymbols.checked = options.symbols;
  generatorWords.value = String(options.words);
  generatorSeparator.value = options.separator;
  generatorCapitalize.checked = options.capitalize;
  generatorIncludeNumber.checked = options.includeNumber;
  usernameKind.value = options.usernameKind;
  usernameCapitalize.checked = options.usernameCapitalize;
  usernameIncludeNumber.checked = options.usernameIncludeNumber;
  usernameEmail.value = options.usernameEmail;
  usernameDomain.value = options.usernameDomain;
}

async function persistGeneratorOptions(): Promise<void> {
  const options = readGeneratorForm();
  try {
    const data = await request({ type: "settings.generator", options }, "settings");
    generatorOptions = data.generatorOptions;
  } catch (error) {
    showError(error);
  }
}

function refreshGeneratedPassword(): void {
  const options = readGeneratorForm();
  generatorOptions = { ...generatorOptions, type: options.type };
  generatorLengthValue.value = generatorLength.value;
  generatorWordsValue.value = generatorWords.value;
  generatorHeading.textContent = GENERATOR_TEXT[options.type].heading;
  element("password-options").hidden = options.type !== "password";
  element("passphrase-options").hidden = options.type !== "passphrase";
  element("username-options").hidden = options.type !== "username";
  element("username-word-options").hidden = options.usernameKind !== "word";
  element("username-email-field").hidden = options.usernameKind !== "plus";
  element("username-domain-field").hidden = options.usernameKind !== "catchall";
  try {
    generatorOutput.value = options.type === "passphrase"
      ? generatePassphrase(options)
      : options.type === "username"
        ? generateUsername(options.usernameKind === "word"
          ? { kind: "word", capitalize: options.usernameCapitalize, includeNumber: options.usernameIncludeNumber }
          : options.usernameKind === "plus"
            ? { kind: "plus", email: options.usernameEmail }
            : { kind: "catchall", domain: options.usernameDomain })
        : generatePassword(options);
    clearStatus();
  } catch (error) {
    generatorOutput.value = "";
    showError(error);
  }
}

async function authorizeReprompt(): Promise<void> {
  if (!selectedItem) {
    return;
  }
  setBusy(repromptSubmit, true, t("checking"));
  clearStatus();
  try {
    const id = selectedItem.id;
    await request({
      type: "vault.authorize",
      id,
      masterPassword: repromptPassword.value,
    }, "done");
    repromptPassword.value = "";
    await showDetail(id);
    showStatus(t("protectedFieldsUnlocked"), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(repromptSubmit, false, t("unlockProtectedFields"));
  }
}

async function refreshTotp(): Promise<void> {
  if (!selectedItem?.hasTotp) {
    return;
  }
  try {
    const data = await request({ type: "vault.totp", id: selectedItem.id }, "totp");
    showTotp(data.code, data.remaining, data.period);
  } catch (error) {
    detailTotp.textContent = t("unavailable");
    totpTimer.textContent = "";
    totpExpiresAt = Number.NaN;
    showError(error);
  }
}

// Shows the code with a live countdown and fetches the next one when it expires.
function showTotp(code: string, remaining: number, period: number): void {
  detailTotp.textContent = formatCode(code);
  totpExpiresAt = Date.now() + remaining * 1000;
  restartCountdown(totpTimer, "totp-ring", period, remaining);
  tickTotp();
  startTicker();
}

// The countdown runs on the compositor; a negative delay starts it part-way through the period.
function restartCountdown(element: HTMLElement, animation: string, period: number, remaining: number): void {
  element.style.animation = "none";
  void element.offsetWidth;
  element.style.animation = `${animation} ${period}s linear ${remaining - period}s forwards`;
}

function startTicker(): void {
  ticker ??= window.setInterval(() => {
    const detail = tickTotp();
    const codes = tickCodes();
    if (!detail && !codes) {
      window.clearInterval(ticker);
      ticker = undefined;
    }
  }, 1000);
}

// False when the detail code is not shown.
function tickTotp(): boolean {
  if (views.detail.hidden || totpRow.hidden || !selectedItem?.hasTotp || Number.isNaN(totpExpiresAt)) return false;
  const seconds = Math.ceil((totpExpiresAt - Date.now()) / 1000);
  if (seconds <= 0) {
    totpExpiresAt = Number.POSITIVE_INFINITY; // One refresh at a time.
    void refreshTotp();
    return true;
  }
  totpTimer.textContent = String(seconds);
  totpTimer.setAttribute("aria-label", plural("secondsLeft", seconds));
  totpTimer.classList.toggle("expiring", seconds <= 5);
  return true;
}

function formatCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return code.length >= 6 ? `${code.slice(0, half)} ${code.slice(half)}` : code;
}

// Logins with an authenticator key. With the smart filter, a site that has codes shows only those.
async function loadAuthenticator(): Promise<void> {
  try {
    const data = await request({ type: "authenticator.list", ...(currentUrl ? { currentUrl } : {}) }, "authenticatorEntries");
    const all = data.entries;
    const matched = all.filter((entry) => entry.matched);
    const filtered = browserOptions.authenticatorSmartFilter && !showAllCodes && matched.length > 0;
    const entries = filtered ? matched : [...matched, ...all.filter((entry) => !entry.matched)];
    authenticatorContext.textContent = filtered ? t("codesForSite", all.length) : plural("codeCount", all.length);
    authenticatorContext.hidden = all.length === 0;
    // "View all" stays available whenever the list is narrowed, and switches back to this site.
    authenticatorAll.hidden = !browserOptions.authenticatorSmartFilter || matched.length === 0 || matched.length === all.length;
    authenticatorAll.textContent = t(filtered ? "viewAll" : "thisWebsite");
    authenticatorEmpty.hidden = all.length > 0;
    codeCards.clear();
    authenticatorList.replaceChildren(...entries.map(codeCard));
    for (const entry of entries) if (!entry.requiresReprompt) void refreshCode(entry.id);
    startTicker();
  } catch (error) {
    showError(error);
  }
}

function codeCard(entry: AuthenticatorEntry): HTMLElement {
  const card = document.createElement("article");
  card.className = "code-card";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "code-copy";
  copy.title = t(entry.requiresReprompt ? "openToConfirm" : "copyVerificationCode");
  const icon = document.createElement("span");
  icon.className = "item-icon";
  const title = entry.nickname || entry.name;
  icon.textContent = title.trim().charAt(0).toLocaleUpperCase() || "•";
  const favicon = siteFavicon(entry.uri);
  if (favicon) icon.append(favicon);
  const main = document.createElement("span");
  main.className = "item-main";
  const name = document.createElement("span");
  name.className = "item-name truncate";
  name.textContent = title;
  const meta = document.createElement("span");
  meta.className = "item-meta truncate";
  meta.textContent = [entry.nickname ? entry.name : entry.issuer !== entry.name ? entry.issuer : "", entry.account].filter(Boolean).join(" · ") || entry.uri || "";
  main.append(name, meta);
  const code = document.createElement("span");
  code.className = "secret totp-code";
  if (entry.requiresReprompt) {
    code.classList.add("locked");
    code.textContent = t("protected");
  }
  copy.append(icon, main, code);
  // copyItemTotp fetches a fresh code, and opens protected logins for the master password instead.
  copy.addEventListener("click", () => void copyItemTotp(entry));
  const actions = document.createElement("span");
  actions.className = "row-actions";
  // Fill only where the entry is mapped to this tab's site; the background checks it again.
  if (entry.matched && !entry.requiresReprompt) actions.append(rowIconButton("fill", t("fillIntoPage"), () => void fillCode(entry)));
  if (entry.editable) actions.append(rowIconButton("edit", t("editKey"), () => void openAuthenticatorEditor(entry)));
  const bar = document.createElement("span");
  bar.className = "code-bar";
  const seconds = document.createElement("span");
  seconds.className = "code-seconds";
  bar.append(document.createElement("span"), seconds);
  bar.hidden = entry.requiresReprompt;
  card.append(copy, actions, bar);
  if (!entry.requiresReprompt) codeCards.set(entry.id, { card, code, bar: bar.firstElementChild as HTMLElement, seconds, expiresAt: Number.POSITIVE_INFINITY });
  return card;
}

async function fillCode(entry: AuthenticatorEntry): Promise<void> {
  try {
    await request({ type: "authenticator.fill", id: entry.id });
    showStatus(t("codeFilled", entry.nickname || entry.name), "success");
  } catch (error) {
    showError(error);
  }
}

// Adds a key (no entry) or edits one. Protected logins need the master password first.
async function openAuthenticatorEditor(entry?: AuthenticatorEntry): Promise<void> {
  if (entry?.requiresReprompt) {
    await showDetail(entry.id);
    showStatus(t("confirmThenEditKey"), "neutral");
    return;
  }
  let secret = "";
  try {
    if (entry) secret = await savedKeySecret(entry.id);
  } catch (error) {
    showError(error);
    return;
  }
  editingEntry = entry ?? null;
  authenticatorForm.reset();
  authenticatorTargetField.hidden = Boolean(entry);
  authenticatorRemove.hidden = !entry;
  element("authenticator-scan").hidden = Boolean(entry);
  authenticatorSecret.required = true;
  authenticatorSecret.value = secret;
  authenticatorName.value = entry?.name ?? "";
  authenticatorNickname.value = entry?.nickname ?? "";
  authenticatorAccount.value = entry?.account ?? "";
  authenticatorWebsite.value = entry ? entry.uri ?? "" : editableCurrentUrl();
  authenticatorIssuer.value = entry?.issuer ?? "";
  authenticatorAlgorithm.value = entry?.algorithm ?? "SHA1";
  authenticatorDigits.value = String(entry && !entry.steam ? entry.digits : 6);
  authenticatorPeriod.value = String(entry?.period ?? 30);
  // Advanced settings open only when they differ from the usual SHA-1, 6 digits, 30 seconds.
  authenticatorForm.querySelector("details")!.open = Boolean(entry && !entry.steam &&
    (entry.algorithm !== "SHA1" || entry.digits !== 6 || entry.period !== 30));
  if (!entry) await loadKeyTargets();
  showView("authenticatorEditor");
  (entry ? authenticatorName : authenticatorSecret).focus();
}

// The other fields hold the key's settings, so the key field shows just the Base32 secret.
async function savedKeySecret(id: string): Promise<string> {
  const { totp } = await getItemDetail(id);
  try {
    return totp ? parseTotpKey(totp).secret : "";
  } catch {
    return totp ?? "";
  }
}

// Logins without a key that can take one: this site's first.
async function loadKeyTargets(): Promise<void> {
  try {
    const data = await request({ type: "vault.list", query: "", ...(currentUrl ? { currentUrl } : {}) }, "items");
    const targets = data.items.filter((item) => item.type === ItemType.Login && !item.hasTotp && item.editable && !item.requiresReprompt);
    keyTargets = new Map(targets.map((item) => [item.id, item]));
    authenticatorTarget.replaceChildren(
      new Option(t("newLogin"), ""),
      ...targets.map((item) => new Option(`${item.matched ? "● " : ""}${item.name}${item.username ? ` · ${item.username}` : ""}`, item.id)),
    );
  } catch {
    authenticatorTarget.replaceChildren(new Option(t("newLogin"), ""));
  }
}

// A pasted or scanned otpauth:// link fills the other fields. Errors never repeat the key.
function applyKeyDetails(quiet: boolean): boolean {
  const value = authenticatorSecret.value.trim();
  if (!value) return false;
  try {
    const key = parseTotpKey(value);
    if (/^(otpauth|steam):/i.test(value)) {
      authenticatorIssuer.value = key.issuer || authenticatorIssuer.value;
      authenticatorAccount.value = key.account || authenticatorAccount.value;
      authenticatorAlgorithm.value = key.algorithm;
      authenticatorDigits.value = String(key.steam ? 6 : key.digits);
      authenticatorPeriod.value = String(key.period);
      if (!authenticatorName.value) authenticatorName.value = key.issuer;
    }
    return true;
  } catch (error) {
    if (!quiet) throw error;
    showError(error);
    return false;
  }
}

interface DetectedBarcode { rawValue: string }
type BarcodeDetectorClass = new (options: { formats: string[] }) => { detect(image: ImageBitmap): Promise<DetectedBarcode[]> };

async function scanQrCode(): Promise<void> {
  try {
    const { link, count } = await readTotpQrCode();
    authenticatorSecret.value = link;
    applyKeyDetails(true);
    showStatus(t(count > 1 ? "qrReadFirstCheck" : "qrReadCheck"), "success");
  } catch (error) {
    showError(error);
  }
}

async function scanLoginTotp(): Promise<void> {
  try {
    const { link, count } = await readTotpQrCode();
    loginTotp.value = link;
    loginTotp.dispatchEvent(new Event("input")); // Clears a pending t("remove").
    showStatus(t(count > 1 ? "qrReadFirstSave" : "qrReadSave"), "success");
  } catch (error) {
    showError(error);
  }
}

// Reads a TOTP QR code from the visible part of the current tab, only when the user asks for it.
// ponytail: uses the browser's BarcodeDetector (macOS, ChromeOS); other systems paste the key instead.
async function readTotpQrCode(): Promise<{ link: string; count: number }> {
  const Detector = (window as unknown as { BarcodeDetector?: BarcodeDetectorClass }).BarcodeDetector;
  if (!Detector) throw new Error(t("qrUnsupported"));
  const image = await chrome.tabs.captureVisibleTab({ format: "png" }).catch(() => {
    throw new Error(t("qrCannotSeePage"));
  });
  const bitmap = await createImageBitmap(await (await fetch(image)).blob());
  const codes = await new Detector({ formats: ["qr_code"] }).detect(bitmap);
  bitmap.close();
  const links = codes.map((code) => code.rawValue).filter((value) => /^otpauth:\/\//i.test(value));
  if (links.length === 0) throw new Error(t("qrNotFound"));
  const valid = links.find((value) => {
    try {
      parseTotpKey(value);
      return true;
    } catch {
      return false;
    }
  });
  if (!valid) throw new Error(t("qrInvalid"));
  return { link: valid, count: links.length };
}

async function saveAuthenticatorEntry(): Promise<void> {
  setBusy(authenticatorSave, true, t("saving"));
  try {
    if (authenticatorSecret.value.trim()) applyKeyDetails(false);
    const entry: AuthenticatorWriteInput = {
      name: authenticatorName.value,
      nickname: authenticatorNickname.value,
      account: authenticatorAccount.value,
      website: authenticatorWebsite.value,
      issuer: authenticatorIssuer.value,
      algorithm: authenticatorAlgorithm.value as TotpAlgorithm,
      digits: Number(authenticatorDigits.value),
      period: Number(authenticatorPeriod.value),
      ...(authenticatorSecret.value.trim() ? { secret: authenticatorSecret.value } : {}),
    };
    const id = editingEntry?.id ?? (authenticatorTarget.value || undefined);
    await request({ type: "authenticator.save", ...(id ? { id } : {}), entry });
    const added = !editingEntry;
    editingEntry = null;
    showView("authenticator");
    await loadAuthenticator();
    showStatus(t(added ? "keyAdded" : "keyUpdated"), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(authenticatorSave, false, t("save"));
  }
}

async function removeAuthenticatorKey(): Promise<void> {
  if (!editingEntry) return;
  try {
    await request({ type: "authenticator.remove", id: editingEntry.id });
    editingEntry = null;
    showView("authenticator");
    await loadAuthenticator();
    showStatus(t("keyRemoved"), "success");
  } catch (error) {
    showError(error);
  }
}

async function readImportFile(input: HTMLInputElement): Promise<void> {
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  if (file.size > 262_144) {
    showError(new Error(t("fileTooLarge256")));
    return;
  }
  importText.value = await file.text();
  await checkImport(false);
}

// First a check (nothing saved), then the user confirms the import of the new keys.
async function checkImport(confirm: boolean): Promise<void> {
  try {
    if (!importText.value.trim()) throw new Error(t("pasteLinksFirst"));
    const data = await request({ type: "authenticator.import", text: importText.value, confirm }, "authenticatorImport");
    if (confirm) {
      importText.value = "";
      showView("authenticator");
      await loadAuthenticator();
      showStatus(plural("keysImported", data.imported), "success");
      return;
    }
    renderImportRows(data.rows);
  } catch (error) {
    showError(error);
  }
}

function renderImportRows(rows: ImportRow[]): void {
  const fresh = rows.filter((row) => row.status === "new").length;
  importRows.replaceChildren(...rows.map((row) => {
    const line = document.createElement("div");
    line.className = `import-row ${row.status}`;
    line.setAttribute("role", "listitem");
    const text = document.createElement("span");
    text.className = "truncate";
    text.textContent = row.label;
    text.title = row.reason ?? row.label;
    const badge = document.createElement("span");
    badge.className = "import-badge";
    badge.textContent = t(row.status === "new" ? "new" : row.status === "duplicate" ? "duplicate" : "invalid");
    line.append(text, badge);
    if (row.reason) {
      const reason = document.createElement("small");
      reason.textContent = row.reason;
      line.append(reason);
    }
    return line;
  }));
  importConfirm.hidden = fresh === 0;
  importConfirm.textContent = plural("importNewKeys", fresh);
  showStatus(t(fresh ? "checkThenImport" : "nothingNewToImport"), fresh ? "neutral" : "error");
}

async function exportKeys(): Promise<void> {
  setBusy(exportSubmit, true, t("exporting"));
  try {
    const data = await request({ type: "authenticator.export", masterPassword: exportPassword.value }, "authenticatorExport");
    exportPassword.value = "";
    saveFile(`firnkey-authenticator-${new Date().toISOString().slice(0, 10)}.txt`, new Blob([`${data.text}\n`], { type: "text/plain" }));
    showStatus(t("keysExported"), "success");
  } catch (error) {
    showError(error);
  } finally {
    setBusy(exportSubmit, false, t("exportKeys"));
  }
}

async function refreshCode(id: string): Promise<void> {
  const entry = codeCards.get(id);
  if (!entry) return;
  entry.expiresAt = Number.POSITIVE_INFINITY; // One refresh at a time.
  try {
    const data = await request({ type: "vault.totp", id }, "totp");
    entry.code.textContent = formatCode(data.code);
    entry.expiresAt = Date.now() + data.remaining * 1000;
    restartCountdown(entry.bar, "code-drain", data.period, data.remaining);
    tickCodes();
  } catch (error) {
    entry.code.textContent = t("unavailable");
    entry.seconds.textContent = "";
    showError(error);
  }
}

// False when the authenticator list is not shown.
function tickCodes(): boolean {
  if (currentView !== "authenticator") return false;
  for (const [id, entry] of codeCards) {
    if (entry.expiresAt === Number.POSITIVE_INFINITY) continue; // Loading, or the code could not be fetched.
    const seconds = Math.ceil((entry.expiresAt - Date.now()) / 1000);
    if (seconds <= 0) void refreshCode(id);
    else {
      entry.seconds.textContent = t("secondsShort", seconds);
      entry.card.classList.toggle("expiring", seconds <= 5);
    }
  }
  return true;
}

async function copyTotp(): Promise<void> {
  if (!selectedItem?.hasTotp) {
    return;
  }
  try {
    const data = await request({ type: "vault.totp", id: selectedItem.id }, "totp");
    await copySecret(data.code, t("codeCopied"), totpRow);
    showTotp(data.code, data.remaining, data.period);
  } catch (error) {
    showError(error);
  }
}

async function fill(id: string): Promise<void> {
  try {
    const data = await request({ type: "vault.fill", id }, "fill");
    showStatus(
      data.fields
        ? plural("fieldsFilled", data.fields)
        : t(data.username && data.password ? "filledUsernameAndPassword" : data.username ? "filledUsername" : "filledPassword"),
      "success",
    );
  } catch (error) {
    showError(error);
  }
}

async function syncVault(): Promise<void> {
  clearStatus();
  try {
    const data = await request({ type: "vault.sync" }, "sync");
    await refreshState();
    showStatus(plural("synced", data.itemCount), "success");
  } catch (error) {
    showError(error);
  }
}

async function lock(): Promise<void> {
  try {
    await request({ type: "auth.lock" });
    selectedItem = null;
    await refreshState();
  } catch (error) {
    showError(error);
  }
}

async function logout(): Promise<void> {
  try {
    await request({ type: "auth.logout" });
    selectedItem = null;
    masterPassword.value = "";
    unlockPassword.value = "";
    await refreshState();
  } catch (error) {
    showError(error);
  }
}

function populateTwoFactor(providers: number[]): void {
  twoFactorProvider.replaceChildren();
  for (const provider of providers.filter((value) => [0, 1, 2, 3, 7, 8].includes(value))) {
    const option = document.createElement("option");
    option.value = String(provider);
    option.textContent = providerName(provider);
    twoFactorProvider.append(option);
  }
  if (twoFactorProvider.options.length === 0) {
    throw new Error(t("twoStepUnsupported"));
  }
  updateTwoFactorControls();
}

function updateTwoFactorControls(): void {
  // Security key and Duo run in their own window instead of taking a typed code.
  const browserStep = twoFactorProvider.value === "2" || twoFactorProvider.value === "7";
  sendEmailCode.hidden = twoFactorProvider.value !== "1";
  twoFactorToken.hidden = twoFactorTokenLabel.hidden = browserStep;
  twoFactorToken.required = !browserStep && !twoFactorFields.hidden;
  if (browserStep) twoFactorToken.value = "";
}

async function requestEmailCode(): Promise<void> {
  setBusy(sendEmailCode, true, t("sending"));
  try {
    await request({
      type: "auth.sendEmailCode",
      baseUrl: normalizeServerEnvironment(serverUrl.value).baseUrl,
      email: email.value,
      masterPassword: masterPassword.value,
    }, "done");
    showStatus(t("emailCodeSent"), "success");
    twoFactorToken.focus();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(sendEmailCode, false, t("sendEmailCode"));
  }
}

function providerName(provider: number): string {
  return ({ 0: t("authenticatorApp"), 1: t("email"), 2: "Duo", 3: "YubiKey", 7: t("securityKeyWebauthn"), 8: t("recoveryCode") } as Record<number, string>)[provider] ?? t("twoFactorMethod", provider);
}

async function copySecret(value: string, message: string, field?: HTMLElement): Promise<void> {
  try {
    if (!value) {
      throw new Error(t("fieldEmpty"));
    }
    await navigator.clipboard.writeText(value);
    // A fingerprint, never the secret, lets the clear check that the clipboard still holds this copy.
    const digest = clipboardOwnOnly.checked
      ? new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.replace(/\r\n?/g, "\n")))).toBase64()
      : undefined;
    await request({ type: "clipboard.scheduleClear", ...(digest ? { digest } : {}) });
    showStatus(clipboardClearSeconds ? t("clipboardClearsIn", message, clipboardLabel(clipboardClearSeconds)) : message, "success");
    if (field) flashCopied(field);
  } catch (error) {
    showError(error);
  }
}

// The field's label reads "Copied" for a moment (see .copied in styles.css).
const copiedTimers = new WeakMap<HTMLElement, number>();
function flashCopied(field: HTMLElement): void {
  window.clearTimeout(copiedTimers.get(field));
  field.classList.add("copied");
  copiedTimers.set(field, window.setTimeout(() => field.classList.remove("copied"), 1200));
}

async function activeTabUrl(): Promise<string | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url;
  } catch {
    return undefined;
  }
}

// With `expected`, also checks which kind of response came back.
async function request<T extends ResponseData["type"] = ResponseData["type"]>(
  value: ExtensionRequest,
  expected?: T,
): Promise<Extract<ResponseData, { type: T }>> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) {
    throw new Error(t("backgroundNoResponse"));
  }
  if (!response.ok) {
    throw new Error(response.error);
  }
  if (expected && response.data.type !== expected) {
    throw new Error(t("unexpectedResponse"));
  }
  return response.data as Extract<ResponseData, { type: T }>;
}

// Settings is a menu of groups; each group opens as its own page, like Bitwarden.
function showSettingsGroup(group: HTMLElement | undefined, motion?: Motion): void {
  const next = group ?? settingsMenu;
  if (settingsPage === transferGroup && next !== transferGroup) resetTransfer();
  swapPage([settingsMenu, ...settingsGroups], settingsPage, next, motion);
  settingsPage = next;
  headerBack.hidden = !group;
  appTitle.textContent = group?.dataset.title ?? t("settings");
  views.settings.scrollTop = 0;
}

type Motion = "tab" | "push" | "pop" | "unlock" | "lock";

// Where the old page goes, where the new one comes from, and which of them moves on top.
const MOTIONS: Record<Exclude<Motion, "tab">, [leaveTo: Keyframe, enterFrom: Keyframe, top: "enter" | "leave"]> = {
  push: [{ transform: "translateX(-30%)", opacity: 0.6 }, { transform: "translateX(100%)" }, "enter"],
  pop: [{ transform: "translateX(100%)" }, { transform: "translateX(-30%)", opacity: 0.6 }, "leave"],
  unlock: [{ transform: "translateY(-32px)", opacity: 0 }, { transform: "scale(0.96)", opacity: 0 }, "enter"],
  lock: [{ transform: "scale(0.96)", opacity: 0 }, { transform: "translateY(-32px)", opacity: 0 }, "enter"],
};
const FADE: [Keyframe, Keyframe, "enter"] = [{ opacity: 0 }, { opacity: 0 }, "enter"];
const TABS: string[] = ["vault", "authenticator", "send", "generator", "settings"];

function viewMotion(from: keyof typeof views, to: keyof typeof views): Motion | undefined {
  if (from === to) return undefined;
  // Tabs are depth 0, an item is depth 1, its editor depth 2.
  const depth = (view: string) =>
    TABS.includes(view) ? 0 : ["detail", "authenticatorEditor", "authenticatorTransfer", "sendEditor"].includes(view) ? 1 : view === "editor" ? 2 : -1;
  if ((from === "locked" || from === "login") && to === "vault") return "unlock";
  if (to === "locked" && depth(from) >= 0) return "lock";
  const [a, b] = [TABS.indexOf(from), TABS.indexOf(to)];
  // Tabs are peers, not a hierarchy: they swap in place.
  if (a >= 0 && b >= 0) return "tab";
  if (depth(from) >= 0 && depth(to) >= 0) return depth(to) > depth(from) ? "push" : "pop";
  return undefined;
}

// Stops a page's transition and puts it back at rest.
function settle(page: HTMLElement): void {
  for (const running of page.getAnimations()) running.cancel();
  page.style.zIndex = "";
  page.inert = false;
}

// Shows `next` among `pages`. With a motion, the visible page slides out while `next` slides in;
// both share one grid cell meanwhile. A page caught mid-move starts from where it is on screen.
function swapPage(pages: HTMLElement[], previous: HTMLElement, next: HTMLElement, motion?: Motion): void {
  const animate = Boolean(motion) && previous !== next;
  for (const page of pages) {
    if (animate && (page === previous || page === next)) continue;
    if (page.inert && page !== next) continue; // Already sliding out; it hides itself when done.
    if (page !== next || page.inert) settle(page);
    page.hidden = page !== next;
  }
  if (!animate) return;
  const onScreen = (page: HTMLElement): Keyframe | undefined => {
    if (page.hidden || page.getAnimations().length === 0) return undefined;
    const style = getComputedStyle(page);
    return { transform: style.transform, opacity: Number(style.opacity) };
  };
  const leaveFrom = onScreen(previous) ?? REST;
  const enterFromNow = onScreen(next);
  settle(previous);
  settle(next);
  const fade = reducedMotion.matches || motion === "tab";
  const [leaveTo, enterFrom, top] = fade ? FADE : MOTIONS[motion as Exclude<Motion, "tab">];
  const timing = { duration: fade ? 150 : 350, easing: EASE };
  (top === "enter" ? next : previous).style.zIndex = "1";
  previous.hidden = false;
  previous.inert = true;
  next.hidden = false;
  next.animate([enterFromNow ?? { ...REST, ...enterFrom }, REST], timing).finished.then(
    () => (next.style.zIndex = ""),
    () => undefined,
  );
  previous.animate([leaveFrom, { ...REST, ...leaveTo }], timing).finished.then(() => {
    settle(previous);
    previous.hidden = true;
  }, () => undefined);
}

function showView(name: keyof typeof views): void {
  const previousName = currentView;
  const focused = document.activeElement as HTMLElement | null;
  currentView = name;
  swapPage(Object.values(views), views[previousName], views[name], viewMotion(previousName, name));
  const unlockedView = ["vault", "authenticator", "send", "sendEditor", "generator", "settings", "detail", "editor", "authenticatorEditor", "authenticatorTransfer"].includes(name);
  const mainTab = TABS.includes(name);
  document.body.classList.toggle("nav-hidden", !mainTab);
  bottomNav.hidden = !mainTab;
  addLogin.hidden = !mainTab;
  accountAvatar.hidden = !unlockedView;
  statePill.hidden = unlockedView;
  brandMark.hidden = unlockedView;
  headerBack.hidden = !["detail", "editor", "authenticatorEditor", "authenticatorTransfer", "sendEditor"].includes(name);
  subtitle.hidden = unlockedView;
  navVault.classList.toggle("active", name === "vault");
  navGenerator.classList.toggle("active", name === "generator");
  navAuthenticator.classList.toggle("active", name === "authenticator");
  navSend.classList.toggle("active", name === "send");
  navSettings.classList.toggle("active", name === "settings");
  accountAvatar.classList.toggle("active", name === "settings");
  for (const button of bottomNav.querySelectorAll("button")) {
    if (button.classList.contains("active")) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  appTitle.textContent = ({
    setup: "Firnkey",
    login: "Firnkey",
    locked: "Firnkey",
    vault: t("vault"),
    authenticator: t("authenticator"),
    send: t("send"),
    sendEditor: t("newSend"),
    generator: t("generator"),
    settings: t("settings"),
    detail: selectedItem ? TYPE_NAMES[selectedItem.type] : t("item"),
    editor: t(editingId ? "editItem" : "newItem"),
    authenticatorEditor: t(editingEntry ? "editKey" : "addKey"),
    authenticatorTransfer: t("importExport"),
  } satisfies Record<keyof typeof views, string>)[name];
  // Typed keys and the export password never outlive their page.
  if (previousName === "authenticatorEditor" && name !== previousName) authenticatorForm.reset();
  if (previousName === "authenticatorTransfer" && name !== previousName) {
    importText.value = "";
    exportPassword.value = "";
    importRows.replaceChildren();
  }
  if (previousName === "sendEditor" && name !== previousName) sendForm.reset();
  if (previousName === "settings" && name !== previousName) resetTransfer();
  if (name === "settings" && previousName !== "settings") showSettingsGroup(undefined);
  // The old page goes inert, which would drop keyboard focus onto the body; land on the new title.
  const focusLost = !focused || focused === document.body || views[previousName].contains(focused) || Boolean(focused.closest("[hidden]"));
  if (name !== previousName && focusLost) appTitle.focus({ preventScroll: true });
}

function markState(text: string, style: "neutral" | "success" | "error"): void {
  statePill.textContent = text;
  statePill.className = `pill ${style}`;
}

function serverLabel(baseUrl: string, version?: string): string {
  return version ? t("serverVersion", baseUrl, version) : baseUrl;
}

function accountInitials(accountEmail: string): string {
  // "john.doe@…" → "JD", "emre@…" → "EM".
  const parts = (accountEmail.split("@", 1)[0] ?? "").split(/[^a-z]+/i).filter(Boolean);
  const initials = parts.length > 1 ? parts[0]![0]! + parts[1]![0]! : parts[0]?.slice(0, 2) ?? "";
  return (initials || "FK").toLocaleUpperCase();
}

function setBusy(button: HTMLButtonElement, busy: boolean, label: string): void {
  button.disabled = busy;
  button.toggleAttribute("aria-busy", busy);
  button.textContent = label;
}

function clearStatus(): void {
  window.clearTimeout(statusTimer);
  for (const running of status.getAnimations()) running.cancel();
  status.textContent = "";
  status.className = "status";
}

// Success messages confirm and go; instructions and errors stay until the next action.
function showStatus(message: string, style: "neutral" | "success" | "error"): void {
  clearStatus();
  status.textContent = message;
  status.className = `status ${style === "success" ? "success-text" : style === "error" ? "error-text" : ""}`;
  const away: Keyframe = { opacity: 0, transform: reducedMotion.matches ? "none" : "translateY(6px)" };
  status.animate([away, REST], { duration: 200, easing: EASE });
  if (style !== "success") return;
  statusTimer = window.setTimeout(() => {
    status.animate([REST, away], { duration: 200, easing: EASE }).finished.then(clearStatus, () => undefined);
  }, 3_000);
}

function showError(error: unknown): void {
  showStatus(error instanceof Error ? error.message : t("unexpectedError"), "error");
}

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) {
    throw new Error(`Missing popup element #${id}`);
  }
  return value as T;
}
