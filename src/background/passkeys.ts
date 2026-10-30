// Passkey requests from websites. Every decision happens in a Firnkey window the page cannot see,
// click or keylog; the origin comes from Chrome's sender info, never from the page.
import type {
  PasskeyCreateOptions,
  PasskeyGetOptions,
  PasskeyPageResult,
  PasskeyPromptDetails,
} from "../shared/messages";
import { readBiometricCredentialId } from "../shared/biometric";
import { createPasskey, credentialIdBase64Url, ES256, isValidRpId, signAssertion } from "../passkey/webauthn";
import type { VaultController } from "./vault-controller";

// Which page asked: the tab, the exact document (so a navigation never inherits a request), and the
// page script's own request ID (so its abort reaches only that request).
export interface PasskeySource {
  tabId: number;
  documentId: string;
  requestId: string;
}

interface PendingPrompt extends PasskeySource {
  id: string;
  origin: string;
  rpId: string;
  create?: PasskeyCreateOptions;
  get?: PasskeyGetOptions;
  verificationRequired: boolean;
  verified: boolean;
  // Protected (reprompt) items need the master password itself; Touch ID only counts as verification.
  passwordVerified: boolean;
  // Conditional (autofill) requests wait without a window until the user picks "Passkey" in the field menu.
  conditional: boolean;
  windowId?: number;
  resolve: (result: PasskeyPageResult) => void;
}

const FALLBACK = { fallback: true } as const;
const NEEDS_VERIFICATION = "This site asks you to verify it is you. Enter the password you use to unlock Firnkey.";

export class PasskeyPrompts {
  private readonly pending = new Map<string, PendingPrompt>();

  constructor(private readonly controller: VaultController) {
    // Closing the window counts as cancelling, like dismissing the browser's own passkey dialog.
    // A conditional request keeps waiting instead: the site's sign-in form is still there.
    chrome.windows.onRemoved.addListener((windowId) => {
      for (const prompt of this.pending.values()) {
        if (prompt.windowId !== windowId) continue;
        if (prompt.conditional) {
          delete prompt.windowId;
          prompt.verified = prompt.passwordVerified = false;
        } else {
          this.finish(prompt, { error: "NotAllowedError" });
        }
      }
    });
  }

  async create(source: PasskeySource, origin: string, options: PasskeyCreateOptions): Promise<PasskeyPageResult> {
    const rpId = (options.rpId ?? new URL(origin).hostname).toLowerCase();
    // Anything Firnkey cannot handle goes to the browser, which also reports invalid requests.
    if (!(await isValidRpId(rpId, origin)) || !options.algorithms.includes(ES256) || !(await this.signedIn())) return FALLBACK;
    return this.ask({ ...source, origin, rpId, create: options, conditional: false, verificationRequired: options.userVerification === "required" });
  }

  async get(source: PasskeySource, origin: string, options: PasskeyGetOptions): Promise<PasskeyPageResult> {
    const rpId = (options.rpId ?? new URL(origin).hostname).toLowerCase();
    if (!(await isValidRpId(rpId, origin)) || !(await this.signedIn())) return FALLBACK;
    // When unlocked and nothing matches, stay out of the way without showing anything.
    const state = await this.controller.getState();
    if (state.phase === "unlocked" && (await this.controller.passkeysFor(rpId, options.allowCredentials)).length === 0) {
      return FALLBACK;
    }
    return this.ask({
      ...source, origin, rpId, get: options, conditional: Boolean(options.conditional), verificationRequired: options.userVerification === "required",
    });
  }

  // The page gave up on its request (its AbortSignal fired, or the browser's own passkey answered first).
  abort(documentId: string, requestId: string): void {
    for (const prompt of this.pending.values()) {
      if (prompt.documentId === documentId && prompt.requestId === requestId) this.finish(prompt, { error: "NotAllowedError" });
    }
  }

  // Whether this document has a conditional request waiting for the user to pick "Passkey".
  offered(documentId: string | undefined): boolean {
    return [...this.pending.values()].some((prompt) => prompt.conditional && prompt.documentId === documentId);
  }

  // The user picked "Passkey" in Firnkey's field menu: open the usual window for the waiting request.
  async choose(documentId: string | undefined): Promise<void> {
    const prompt = [...this.pending.values()].find((open) => open.conditional && open.documentId === documentId);
    if (!prompt) throw new Error("This site is no longer asking for a passkey. Reload the page and try again.");
    if (prompt.windowId === undefined) await this.openWindow(prompt);
    else await chrome.windows.update(prompt.windowId, { focused: true });
  }

  async details(id: string): Promise<PasskeyPromptDetails> {
    const prompt = this.require(id);
    const locked = (await this.controller.getState()).phase !== "unlocked";
    const biometricCredentialId = await readBiometricCredentialId();
    const base: PasskeyPromptDetails = {
      ...(biometricCredentialId ? { biometricCredentialId } : {}),
      kind: prompt.create ? "create" : "get",
      origin: prompt.origin,
      rpId: prompt.rpId,
      locked,
      verificationRequired: prompt.verificationRequired && !prompt.verified,
      ...(prompt.create?.rpName ? { rpName: prompt.create.rpName } : {}),
      ...(prompt.create?.userName ? { userName: prompt.create.userName } : {}),
    };
    if (locked) return base;
    if (prompt.get) {
      const matches = await this.controller.passkeysFor(prompt.rpId, prompt.get.allowCredentials);
      if (matches.length === 0) this.finish(prompt, FALLBACK);
      return {
        ...base,
        candidates: matches.map(({ item, passkey }) => ({
          id: credentialIdBase64Url(passkey.credentialId),
          itemName: item.name,
          userName: passkey.userName ?? item.username,
          reprompt: item.reprompt,
        })),
      };
    }
    const targets = await this.controller.passkeyTargets(prompt.origin);
    return {
      ...base,
      alreadySaved: await this.alreadySaved(prompt),
      targets: targets.map((item) => ({ id: item.id, name: item.name, username: item.username })),
    };
  }

  async unlock(id: string, masterPassword: string): Promise<void> {
    const prompt = this.require(id);
    await this.controller.unlock(masterPassword);
    prompt.verified = prompt.passwordVerified = true; // Unlocking with the master password is user verification.
  }

  async biometric(id: string, prfOutput: Uint8Array): Promise<void> {
    const prompt = this.require(id);
    if ((await this.controller.getState()).phase === "unlocked") await this.controller.verifyBiometric(prfOutput);
    else await this.controller.unlockWithBiometric(prfOutput);
    prompt.verified = true;
  }

  async respond(
    id: string,
    response: { action: "save" | "use" | "fallback" | "cancel"; itemId?: string; credentialId?: string; masterPassword?: string },
  ): Promise<void> {
    const prompt = this.require(id);
    if (response.action === "fallback") return this.finish(prompt, FALLBACK);
    // The window closes itself, which puts a conditional request back to waiting.
    if (response.action === "cancel" && prompt.conditional) return;
    if (response.action === "cancel") {
      // Per WebAuthn, an excluded credential is only reported after the user has seen the prompt.
      return this.finish(prompt, { error: (await this.alreadySaved(prompt)) ? "InvalidStateError" : "NotAllowedError" });
    }
    if (response.masterPassword) {
      await this.controller.verifyMasterPassword(response.masterPassword);
      prompt.verified = prompt.passwordVerified = true;
    }

    if (prompt.get && response.action === "use") {
      const match = (await this.controller.passkeysFor(prompt.rpId, prompt.get.allowCredentials))
        .find(({ passkey }) => credentialIdBase64Url(passkey.credentialId) === response.credentialId);
      if (!match) throw new Error("That passkey is no longer available.");
      if (prompt.verificationRequired && !prompt.verified) throw new Error(NEEDS_VERIFICATION);
      if (match.item.reprompt && !prompt.passwordVerified) throw new Error("This passkey is protected. Enter your master password.");
      const asserted = await signAssertion(match.passkey, {
        origin: prompt.origin,
        challenge: prompt.get.challenge,
        userVerified: prompt.verified,
      });
      return this.finish(prompt, { asserted });
    }

    if (prompt.create && response.action === "save") {
      if (await this.alreadySaved(prompt)) return this.finish(prompt, { error: "InvalidStateError" });
      if (prompt.verificationRequired && !prompt.verified) throw new Error(NEEDS_VERIFICATION);
      const options = prompt.create;
      const { passkey, credential } = await createPasskey({
        origin: prompt.origin,
        rpId: prompt.rpId,
        userId: options.userId,
        challenge: options.challenge,
        userVerified: prompt.verified,
        ...(options.rpName ? { rpName: options.rpName } : {}),
        ...(options.userName ? { userName: options.userName } : {}),
        ...(options.userDisplayName ? { userDisplayName: options.userDisplayName } : {}),
      });
      // Report success only once the passkey is stored, so a failed save never leaves a dead credential.
      await this.controller.savePasskey(passkey, prompt.origin, response.itemId);
      return this.finish(prompt, { created: credential });
    }
    throw new Error("This passkey request cannot do that.");
  }

  private ask(prompt: Omit<PendingPrompt, "id" | "verified" | "passwordVerified" | "resolve">): Promise<PasskeyPageResult> {
    // A new request replaces an open one from the same tab, as the browser's own dialog does.
    for (const open of this.pending.values()) {
      if (open.tabId === prompt.tabId) this.finish(open, { error: "NotAllowedError" });
    }
    return new Promise((resolve) => {
      const pending: PendingPrompt = { ...prompt, id: crypto.randomUUID(), verified: false, passwordVerified: false, resolve };
      this.pending.set(pending.id, pending);
      if (pending.conditional) this.notifyOffer(pending, true);
      else void this.openWindow(pending).catch(() => this.finish(pending, FALLBACK));
    });
  }

  private async openWindow(prompt: PendingPrompt): Promise<void> {
    const window = await chrome.windows.create({
      url: chrome.runtime.getURL(`passkey/index.html#${prompt.id}`), type: "popup", width: 420, height: 600, focused: true,
    });
    if (window?.id !== undefined) prompt.windowId = window.id;
  }

  private finish(prompt: PendingPrompt, result: PasskeyPageResult): void {
    if (!this.pending.delete(prompt.id)) return;
    prompt.resolve(result);
    if (prompt.windowId !== undefined) void chrome.windows.remove(prompt.windowId).catch(() => undefined);
    if (prompt.conditional) this.notifyOffer(prompt, false);
  }

  // Tells the page's Firnkey field menu to show or drop its "Passkey" entry.
  private notifyOffer(prompt: PendingPrompt, offered: boolean): void {
    void chrome.tabs.sendMessage(prompt.tabId, { type: "firnkey.passkeyOffer", offered }, { documentId: prompt.documentId })
      .catch(() => undefined); // The field menu script may not have loaded yet; it asks on load instead.
  }

  private require(id: string): PendingPrompt {
    const prompt = this.pending.get(id);
    if (!prompt) throw new Error("This passkey request has ended. Try again on the website.");
    return prompt;
  }

  private async alreadySaved(prompt: PendingPrompt): Promise<boolean> {
    const excluded = prompt.create?.excludeCredentials ?? [];
    return excluded.length > 0 && (await this.controller.passkeysFor(prompt.rpId, excluded)).length > 0;
  }

  private async signedIn(): Promise<boolean> {
    const { phase } = await this.controller.getState();
    return phase === "locked" || phase === "unlocked";
  }
}
