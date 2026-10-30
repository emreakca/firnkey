// The window where the user decides about a website's passkey request. It is an extension page, so
// the website cannot read it, click it or see what is typed here.
import type { ExtensionRequest, ExtensionResponse, PasskeyPromptDetails, ResponseData } from "../shared/messages";
import { assertBiometricPrf } from "../shared/biometric";
import { fromBase64 } from "../crypto/bytes";
import { localizePage, t } from "../shared/i18n";

localizePage();

const id = location.hash.slice(1);
const element = <T extends HTMLElement>(name: string) => document.getElementById(name) as T;
const title = element<HTMLHeadingElement>("title");
const origin = element<HTMLParagraphElement>("origin");
const unlockSection = element<HTMLElement>("unlock");
const unlockPassword = element<HTMLInputElement>("unlock-password");
const unlockButton = element<HTMLButtonElement>("unlock-button");
const unlockBiometric = element<HTMLButtonElement>("unlock-biometric");
const verifyBiometric = element<HTMLButtonElement>("verify-biometric");
const chooseSection = element<HTMLElement>("choose");
const summary = element<HTMLParagraphElement>("summary");
const choices = element<HTMLDivElement>("choices");
const verify = element<HTMLLabelElement>("verify");
const verifyPassword = element<HTMLInputElement>("verify-password");
const confirmButton = element<HTMLButtonElement>("confirm");
const fallbackButton = element<HTMLButtonElement>("fallback");
const cancelButton = element<HTMLButtonElement>("cancel");
const status = element<HTMLParagraphElement>("status");

let details: PasskeyPromptDetails | null = null;

unlockButton.addEventListener("click", () => void unlock());
unlockPassword.addEventListener("keydown", (event) => { if (event.key === "Enter") void unlock(); });
confirmButton.addEventListener("click", () => void confirm());
unlockBiometric.addEventListener("click", () => void biometric(unlockBiometric));
verifyBiometric.addEventListener("click", () => void biometric(verifyBiometric));
verifyPassword.addEventListener("keydown", (event) => { if (event.key === "Enter") void confirm(); });
fallbackButton.addEventListener("click", () => void respond({ action: "fallback" }));
cancelButton.addEventListener("click", () => void respond({ action: "cancel" }));
choices.addEventListener("change", updateVerification);
void load();

async function load(): Promise<void> {
  try {
    const data = await request({ type: "passkey.details", id });
    if (data.type !== "passkeyDetails") return;
    details = data.details;
    render(details);
  } catch (error) {
    showError(error);
    chooseSection.hidden = true;
    unlockSection.hidden = true;
  }
}

function render(value: PasskeyPromptDetails): void {
  const create = value.kind === "create";
  title.textContent = t(create ? "savePasskey" : "signInWithPasskey");
  origin.textContent = value.origin;
  unlockSection.hidden = !value.locked;
  chooseSection.hidden = value.locked;
  unlockBiometric.hidden = !value.biometricCredentialId;
  if (value.locked) {
    unlockPassword.focus();
    return;
  }
  choices.replaceChildren();
  if (create && value.alreadySaved) {
    summary.textContent = t("passkeyAlreadySaved");
    confirmButton.hidden = true;
    fallbackButton.hidden = true;
    cancelButton.textContent = t("close");
    return;
  }
  const site = value.rpName || value.rpId;
  summary.textContent = !create
    ? t("choosePasskeyFor", value.rpId)
    : value.userName ? t("savePasskeyForAccount", value.userName, site) : t("savePasskeyOnSite", site);
  confirmButton.textContent = t(create ? "savePasskey" : "signIn");
  const options = create
    ? [{ value: "", label: t("newLogin"), detail: value.userName ?? "", reprompt: false },
      ...(value.targets ?? []).map((target) => ({ value: target.id, label: t("addTo", target.name), detail: target.username, reprompt: false }))]
    : (value.candidates ?? []).map((candidate) => ({ value: candidate.id, label: candidate.itemName, detail: candidate.userName, reprompt: candidate.reprompt }));
  options.forEach((option, index) => {
    const label = document.createElement("label");
    label.className = "choice";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "choice";
    input.value = option.value;
    input.checked = index === 0;
    input.dataset.reprompt = String(option.reprompt);
    const text = document.createElement("span");
    text.textContent = option.label;
    if (option.detail) {
      const detail = document.createElement("small");
      detail.textContent = option.detail;
      text.append(detail);
    }
    label.append(input, text);
    choices.append(label);
  });
  updateVerification();
  confirmButton.focus();
}

function selected(): HTMLInputElement | null {
  return choices.querySelector<HTMLInputElement>("input:checked");
}

function updateVerification(): void {
  const reprompt = selected()?.dataset.reprompt === "true";
  verify.hidden = !(details?.verificationRequired || reprompt);
  // Touch ID verifies the user for the site, but a protected item still needs the master password.
  verifyBiometric.hidden = !details?.verificationRequired || !details.biometricCredentialId || reprompt;
  if (!verify.hidden) verifyPassword.focus();
}

// Touch ID needs no extra window here: this window stays open while the OS prompt has focus.
async function biometric(button: HTMLButtonElement): Promise<void> {
  if (!details?.biometricCredentialId) return;
  button.disabled = true;
  try {
    const output = await assertBiometricPrf(fromBase64(details.biometricCredentialId));
    await request({ type: "passkey.biometric", id, prfOutput: output.toBase64() });
    output.fill(0);
    status.textContent = "";
    await load();
  } catch (error) {
    showError(error instanceof DOMException && error.name === "NotAllowedError" ? new Error(t("verificationCancelled")) : error);
  } finally {
    button.disabled = false;
  }
}

async function unlock(): Promise<void> {
  if (!unlockPassword.value) return;
  unlockButton.disabled = true;
  try {
    await request({ type: "passkey.unlock", id, masterPassword: unlockPassword.value });
    unlockPassword.value = "";
    status.textContent = "";
    await load();
  } catch (error) {
    showError(error);
  } finally {
    unlockButton.disabled = false;
  }
}

async function confirm(): Promise<void> {
  const choice = selected();
  if (!details || !choice) return;
  const masterPassword = verify.hidden ? undefined : verifyPassword.value;
  if (masterPassword === "") {
    verifyPassword.focus();
    return;
  }
  await respond(details.kind === "create"
    ? { action: "save", ...(choice.value ? { itemId: choice.value } : {}), ...(masterPassword ? { masterPassword } : {}) }
    : { action: "use", credentialId: choice.value, ...(masterPassword ? { masterPassword } : {}) });
}

async function respond(answer: Omit<Extract<ExtensionRequest, { type: "passkey.respond" }>, "type" | "id">): Promise<void> {
  for (const button of [confirmButton, fallbackButton, cancelButton]) button.disabled = true;
  try {
    await request({ type: "passkey.respond", id, ...answer });
    window.close(); // Firnkey also closes this window once the website has its answer.
  } catch (error) {
    verifyPassword.value = "";
    showError(error);
    for (const button of [confirmButton, fallbackButton, cancelButton]) button.disabled = false;
  }
}

async function request(value: ExtensionRequest): Promise<ResponseData> {
  const response = (await chrome.runtime.sendMessage(value)) as ExtensionResponse | undefined;
  if (!response) throw new Error("Firnkey is unavailable.");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

function showError(error: unknown): void {
  status.className = "status error-text";
  status.textContent = error instanceof Error ? error.message : t("somethingWentWrong");
}
