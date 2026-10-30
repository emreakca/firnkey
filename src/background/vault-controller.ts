import { ApiError, VaultwardenClient } from "../api/vaultwarden-client";
import { deriveArgon2idMasterKey } from "../crypto/argon2-service";
import {
  decryptFile,
  decryptSymmetricBytes,
  deriveMasterPasswordHash,
  encryptFile,
  encryptSymmetricBytes,
  encryptSymmetricString,
  derivePbkdf2MasterKey,
  isSymmetricKey,
  kdfFingerprint,
  stretchMasterKey,
  sha256Base64,
} from "../crypto/bitwarden-crypto";
import { decodeUtf8, equalConstantTime, fromBase64, wipe } from "../crypto/bytes";
import { generateTotp, type TotpResult } from "../crypto/totp";
import { isWeakerKdf, KdfType, type KdfConfig } from "../shared/kdf";
import type { AuthLoginRequest, LoginOutcome, PublicAppState, VaultListRequest } from "../shared/messages";
import { clearEncryptedSync, readEncryptedSync, writeEncryptedSync } from "../shared/database";
import {
  accountId,
  clearAccountMetadata,
  forgetSavedAccount,
  readSavedAccounts,
  restoreSavedAccount,
  stashActiveAccount,
  clearAuthSession,
  getOrCreateDeviceIdentifier,
  readAccountMetadata,
  readAuthSession,
  readKdfPin,
  readServerSnapshot,
  updateSessionUserKey,
  writeAccountMetadata,
  writeAuthSession,
  writeKdfPin,
  type AccountMetadata,
  type AuthSession,
} from "../shared/storage";
import { decryptOrganizationKey, decryptVault, getVaultItemDetail, listVaultItems, matchesCurrentUrl } from "../vault/decrypt-vault";
import { ItemType, type Passkey, type VaultCollection, type VaultFolder, type VaultItem, type VaultItemDetail, type VaultItemSummary } from "../vault/models";
import { decryptSends, encryptSend, MAX_FILE_BYTES, type SendSummary, type SendWriteInput } from "../vault/send";
import { exportEncryptedJson, exportJson, parseImport, type ExportFormat } from "../vault/transfer";
import { arrayProp, asRecord, prop, stringProp } from "../shared/props";
import { credentialIdBase64Url } from "../passkey/webauthn";
import {
  createEncryptedCipher,
  createEncryptedItem,
  createEncryptedLogin,
  updateEncryptedItem,
  updateEncryptedLogin,
  type ItemWriteInput,
  type LoginWriteInput,
} from "../vault/encrypt-login";
import { cardFormValues, fillActiveTab, fillFormActiveTab, fillFormInTab, fillOtpInTab, identityFormValues } from "./fill";
import {
  authenticatorEntries,
  authenticatorKey,
  exportAuthenticator,
  knownSecrets,
  previewImport,
  type AuthenticatorEntry,
  type AuthenticatorWriteInput,
  type ImportRow,
} from "../vault/authenticator";
import { storedTotpKey } from "../crypto/totp";
import type { BrowserIntegrationOptions } from "../shared/settings";
import { clearBiometricUnlock, readBiometricCredentialId, unwrapBiometricUnlock, writeBiometricUnlock } from "../shared/biometric";
import { needsBrowserStep, runBrowserTwoFactor } from "./two-factor";

export class VaultController {
  private readonly client = new VaultwardenClient();
  private vaultCache: VaultItem[] | null = null;
  // Filled together with vaultCache; trash is never searched by fill, suggestions or passkeys.
  private trashCache: VaultItem[] = [];
  private folders: VaultFolder[] = [];
  private collections: VaultCollection[] = [];
  private sends: SendSummary[] = [];
  private decryptionFailures = 0;
  private readonly repromptAuthorizations = new Map<string, number>();
  private readonly pendingCaptures = new Map<number, PendingCapture>();
  // Login Firnkey filled per tab, so the next page's authenticator code can be filled for it.
  // ponytail: memory only, so a service-worker restart in between just means a suggestion, not autofill.
  private readonly recentFills = new Map<number, { itemId: string; until: number }>();
  private readonly pendingReady = chrome.storage.session.get("pendingSiteLogins").then((stored) => {
    for (const [tabId, pending] of (stored.pendingSiteLogins ?? []) as [number, PendingCapture][]) {
      if (pending.rememberUntil > Date.now()) this.pendingCaptures.set(tabId, pending);
    }
  });
  private sessionRevision = 0;
  private refreshTask: Promise<AuthSession> | null = null;
  private syncTask: Promise<{ itemCount: number; failures: number }> | null = null;

  async getState(): Promise<PublicAppState> {
    const [snapshot, account, session, biometricCredentialId, saved] = await Promise.all([
      readServerSnapshot(),
      readAccountMetadata(),
      readAuthSession(),
      readBiometricCredentialId(),
      readSavedAccounts(),
    ]);
    if (!snapshot) {
      return { phase: "setup" };
    }
    const accounts = saved.map(({ id, account: other }) => ({ id, email: other.email, baseUrl: other.baseUrl }));
    if (!account || !session) {
      return { phase: "signed-out", snapshot, accounts, ...(account ? { email: account.email } : {}) };
    }
    const signedIn = {
      snapshot,
      accounts,
      email: account.email,
      itemCount: account.itemCount ?? 0,
      ...(account.lastSync ? { lastSync: account.lastSync } : {}),
      ...(biometricCredentialId ? { biometricCredentialId } : {}),
    };
    return session.userKey
      ? { phase: "unlocked", ...signedIn, decryptionFailures: this.decryptionFailures }
      : { phase: "locked", ...signedIn };
  }

  async login(request: AuthLoginRequest): Promise<LoginOutcome> {
    if (!needsBrowserStep(request.twoFactorProvider) || request.twoFactorToken) return this.signIn(request);
    // The security key or Duo window closes the popup, so report the outcome from here.
    const opener = await chrome.windows.getLastFocused().catch(() => undefined);
    try {
      return await this.signIn(request);
    } catch (error) {
      const loginNotice = error instanceof Error ? error.message : String(error);
      await chrome.storage.session.set({ loginNotice }).catch(() => undefined);
      throw error;
    } finally {
      if (opener?.id !== undefined) await chrome.action.openPopup?.({ windowId: opener.id }).catch(() => undefined);
    }
  }

  private async signIn(request: AuthLoginRequest): Promise<LoginOutcome> {
    const email = normalizeEmail(request.email);
    if (!request.masterPassword) {
      throw new Error("Enter your master password.");
    }
    const { kdf: preloginKdf, masterKey, masterPasswordHash } = await this.prelogin(request.baseUrl, email, request.masterPassword);
    try {
      const deviceIdentifier = await getOrCreateDeviceIdentifier();
      const grant = async (twoFactorToken: string | undefined) => this.client.loginWithPassword({
        baseUrl: request.baseUrl,
        email,
        masterPasswordHash,
        deviceIdentifier,
        ...(request.twoFactorProvider === undefined
          ? {}
          : { twoFactorProvider: request.twoFactorProvider }),
        ...(twoFactorToken ? { twoFactorToken } : {}),
        ...(request.twoFactorRemember === undefined
          ? {}
          : { twoFactorRemember: request.twoFactorRemember }),
        ...(request.newDeviceOtp ? { newDeviceOtp: request.newDeviceOtp } : {}),
      });
      let login = await grant(request.twoFactorToken);
      // Security key and Duo: this first try returns a fresh challenge, answered in a window.
      if (login.kind === "two-factor" && needsBrowserStep(request.twoFactorProvider) && !request.twoFactorToken) {
        const details = login.providerDetails[String(request.twoFactorProvider)];
        login = await grant(await runBrowserTwoFactor(request.twoFactorProvider, details, request.baseUrl));
      }
      if (login.kind === "two-factor") {
        return {
          status: "two-factor",
          providers: login.providers,
          providerDetails: login.providerDetails,
        };
      }
      if (login.kind === "device-verification") {
        return { status: "device-verification", message: login.message };
      }
      if (kdfFingerprint(login.kdf) !== kdfFingerprint(preloginKdf)) {
        throw new Error("The server changed KDF parameters during login; refusing to continue.");
      }
      const stretchedMasterKey = await stretchMasterKey(masterKey);
      let userKey: Uint8Array;
      try {
        userKey = await decryptSymmetricBytes(login.wrappedUserKey, stretchedMasterKey);
      } finally {
        wipe(stretchedMasterKey);
      }
      if (!isSymmetricKey(userKey)) {
        wipe(userKey);
        throw new Error("The server returned an invalid encrypted account key.");
      }
      const expiresAt = login.expiresIn ? Date.now() + login.expiresIn * 1000 : undefined;
      await writeAuthSession({
        baseUrl: request.baseUrl,
        email,
        accessToken: login.accessToken,
        userKey: [...userKey],
        ...(login.refreshToken ? { refreshToken: login.refreshToken } : {}),
        ...(expiresAt === undefined ? {} : { accessTokenExpiresAt: expiresAt }),
      });
      await writeKdfPin(request.baseUrl, email, login.kdf);
      await writeAccountMetadata({
        baseUrl: request.baseUrl,
        email,
        kdf: login.kdf,
        wrappedUserKey: login.wrappedUserKey,
        ...(login.privateKey ? { privateKey: login.privateKey } : {}),
      });
      try {
        const result = await this.sync();
        // Signing in again to a switched-out account replaces its saved copy.
        await forgetSavedAccount(accountId({ baseUrl: request.baseUrl, email })).catch(() => undefined);
        return { status: "unlocked", itemCount: result.itemCount, failures: result.failures };
      } catch (error) {
        this.clearCache();
        await Promise.all([clearAuthSession(), clearAccountMetadata(), clearEncryptedSync(), this.clearPendingSiteLogins()]);
        throw error;
      } finally {
        wipe(userKey);
      }
    } finally {
      wipe(masterKey);
    }
  }

  async unlock(masterPassword: string): Promise<{ itemCount: number; failures: number }> {
    const [account, session] = await Promise.all([readAccountMetadata(), readAuthSession()]);
    if (!account || !session) {
      throw new Error("The account session has expired. Sign in again.");
    }
    return this.unlockWithUserKey(await unwrapUserKey(masterPassword, account), account);
  }

  async enableBiometricUnlock(credentialId: string, prfOutput: Uint8Array): Promise<void> {
    const [account, session] = await Promise.all([readAccountMetadata(), readAuthSession()]);
    if (!account || !session?.userKey) throw new Error("Unlock the vault before turning on biometric unlock.");
    const userKey = requireUserKey(session.userKey);
    try {
      await writeBiometricUnlock(credentialId, prfOutput, userKey, account);
    } finally {
      wipe(userKey);
      wipe(prfOutput);
    }
  }

  // Touch ID as user verification while unlocked: the PRF output must unwrap this session's key.
  async verifyBiometric(prfOutput: Uint8Array): Promise<void> {
    const [account, session] = await Promise.all([requireAccount(), requireSession()]);
    const sessionKey = requireUserKey(session.userKey);
    let candidate: Uint8Array | undefined;
    try {
      candidate = await unwrapBiometricUnlock(prfOutput, account).catch(() => undefined);
      if (!candidate || !equalConstantTime(candidate, sessionKey)) throw new Error("Touch ID did not match this account.");
    } finally {
      wipe(sessionKey);
      wipe(prfOutput);
      if (candidate) wipe(candidate);
    }
  }

  // Locks the current account, sets it aside, and brings back a saved one (locked).
  async switchAccount(id: string): Promise<void> {
    if (!(await readSavedAccounts()).some((entry) => entry.id === id)) throw new Error("That account is no longer saved in Firnkey.");
    await this.addAccount();
    await restoreSavedAccount(id);
  }

  // Sets the current account aside so another one can sign in.
  async addAccount(): Promise<void> {
    this.clearCache();
    await this.clearPendingSiteLogins();
    await stashActiveAccount();
    this.clearCache(); // Invalidate work that started while the account was moving.
  }

  // Deletes a switched-out account from this browser: its tokens, vault copy and Touch ID record.
  async removeAccount(id: string): Promise<void> {
    if (!(await readSavedAccounts()).some((entry) => entry.id === id)) throw new Error("That account is no longer saved in Firnkey.");
    await forgetSavedAccount(id);
  }

  async unlockWithBiometric(prfOutput: Uint8Array): Promise<{ itemCount: number; failures: number }> {
    const [account, session] = await Promise.all([readAccountMetadata(), readAuthSession()]);
    if (!account || !session) throw new Error("The account session has expired. Sign in again.");
    let userKey: Uint8Array;
    try {
      userKey = await unwrapBiometricUnlock(prfOutput, account);
    } catch {
      throw new Error("Biometric unlock did not match this account. Unlock with your master password.");
    } finally {
      wipe(prfOutput);
    }
    if (!isSymmetricKey(userKey)) {
      wipe(userKey);
      throw new Error("Biometric unlock did not match this account. Unlock with your master password.");
    }
    return this.unlockWithUserKey(userKey, account);
  }

  private async unlockWithUserKey(userKey: Uint8Array, account: AccountMetadata): Promise<{ itemCount: number; failures: number }> {
    try {
      await updateSessionUserKey(userKey);
      const items = await this.loadVault(userKey, account);
      return { itemCount: items.length, failures: this.decryptionFailures };
    } catch (error) {
      await updateSessionUserKey(null);
      throw error;
    } finally {
      wipe(userKey);
    }
  }

  async sendTwoFactorEmail(baseUrl: string, emailInput: string, masterPassword: string): Promise<void> {
    const email = normalizeEmail(emailInput);
    if (!masterPassword) {
      throw new Error("Enter your master password before requesting an email code.");
    }
    const { masterKey, masterPasswordHash } = await this.prelogin(baseUrl, email, masterPassword);
    wipe(masterKey);
    await this.client.sendTwoFactorEmail(baseUrl, email, masterPasswordHash, await getOrCreateDeviceIdentifier());
  }

  // Prelogin, the KDF downgrade check, the master key (the caller wipes it) and its password hash.
  private async prelogin(baseUrl: string, email: string, masterPassword: string) {
    const prelogin = await this.client.getPrelogin(baseUrl, email);
    await requireKdfNotDowngraded(baseUrl, email, prelogin.kdf);
    const masterKey = await deriveMasterKey(masterPassword, email, prelogin.kdf);
    try {
      return { kdf: prelogin.kdf, masterKey, masterPasswordHash: await deriveMasterPasswordHash(masterKey, masterPassword) };
    } catch (error) {
      wipe(masterKey);
      throw error;
    }
  }

  async lock(): Promise<void> {
    this.clearCache();
    try {
      await updateSessionUserKey(null);
    } finally {
      // Invalidate work that started while the stored key was being removed.
      this.clearCache();
    }
    await this.clearPendingSiteLogins();
  }

  async logout(): Promise<void> {
    this.clearCache();
    try {
      await Promise.all([clearAuthSession(), clearAccountMetadata(), clearEncryptedSync(), clearBiometricUnlock()]);
    } finally {
      this.clearCache();
    }
    await this.clearPendingSiteLogins();
  }

  async sync(): Promise<{ itemCount: number; failures: number }> {
    const revision = this.sessionRevision;
    const task = (this.syncTask ?? Promise.resolve()).catch(() => undefined).then(() => {
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      return this.performSync();
    });
    this.syncTask = task;
    try {
      return await task;
    } finally {
      if (this.syncTask === task) this.syncTask = null;
    }
  }

  private async performSync(): Promise<{ itemCount: number; failures: number }> {
    const revision = this.sessionRevision;
    let session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = session.userKey ? requireUserKey(session.userKey) : null;
    try {
      let payload;
      try {
        payload = await this.client.getSync(session.baseUrl, session.accessToken);
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401 || !session.refreshToken) {
          throw error;
        }
        session = await this.refreshSession(session);
        payload = await this.client.getSync(session.baseUrl, session.accessToken);
      }
      const account = await requireAccount();
      const decrypted = userKey ? await decryptVault(payload, userKey, account.privateKey) : null;
      const sends = userKey ? await decryptSends(payload.Sends ?? payload.sends, userKey, account.baseUrl) : [];
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      await writeEncryptedSync(payload);
      if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
      this.vaultCache = decrypted?.items ?? null;
      this.trashCache = decrypted?.trash ?? [];
      this.folders = decrypted?.folders ?? [];
      this.collections = decrypted?.collections ?? [];
      this.sends = sends;
      this.decryptionFailures = decrypted?.failures ?? 0;
      const updated: AccountMetadata = {
        ...account,
        lastSync: new Date().toISOString(),
        itemCount: decrypted?.items.length ?? account.itemCount ?? 0,
      };
      await writeAccountMetadata(updated);
      return { itemCount: updated.itemCount!, failures: this.decryptionFailures };
    } finally {
      if (userKey) wipe(userKey);
    }
  }

  async list(request: VaultListRequest): Promise<{ items: VaultItemSummary[]; folders: VaultFolder[]; collections: VaultCollection[] }> {
    const items = await this.requireVault();
    const { folder } = request;
    const lists = { folders: this.folders, collections: this.collections };
    if (folder === "trash") return { items: listVaultItems(this.trashCache, request.query), ...lists };
    const collection = folder?.startsWith("collection:") ? folder.slice(11) : undefined;
    const inFolder = collection
      ? items.filter((item) => item.collectionIds?.includes(collection))
      : folder ? items.filter((item) => (item.folderId ?? "none") === folder) : items;
    return { items: listVaultItems(inFolder, request.query, request.currentUrl), ...lists };
  }

  async detail(id: string, currentUrl?: string): Promise<VaultItemDetail> {
    const item = await this.findItem(id);
    return getVaultItemDetail(item, currentUrl, this.isRepromptAuthorized(item));
  }

  async fill(id: string): Promise<{ username: boolean; password: boolean; fields?: number }> {
    const item = await this.findItem(id);
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected item before filling it.");
    }
    if (item.type === ItemType.Card || item.type === ItemType.Identity) {
      const card = item.type === ItemType.Card;
      const fields = await fillFormActiveTab(card ? cardFormValues(item.card ?? {}) : identityFormValues(item.identity ?? {}), card);
      if (fields === 0) throw new Error(`No ${card ? "card" : "address or contact"} fields were found on this page.`);
      return { username: false, password: false, fields };
    }
    if (item.type !== ItemType.Login) throw new Error("Secure notes cannot be filled.");
    const { tabId, ...filled } = await fillActiveTab(item);
    if (filled.password) this.rememberFill(tabId, item.id);
    return filled;
  }

  async totp(id: string): Promise<TotpResult> {
    const item = await this.findItem(id);
    if (!item.totp) {
      throw new Error("This login does not have an authenticator key.");
    }
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected login first.");
    }
    return generateTotp(item.totp);
  }

  // With a collection, the login is created in that collection's organization.
  async createLogin(input: LoginWriteInput, passkey?: Passkey, collectionId?: string): Promise<void> {
    await this.serverWrite((session, userKey) => this.createCipher(session, userKey, (key) => createEncryptedLogin(input, key, passkey), collectionId));
  }

  async updateLogin(id: string, input: LoginWriteInput, passkey?: Passkey | null): Promise<void> {
    const item = await this.findItem(id);
    if (item.type !== ItemType.Login) throw new Error("This item is not a login.");
    await this.editCipher(item, (raw, baseKey) => updateEncryptedLogin(raw, input, baseKey, passkey));
  }

  async createItem(input: ItemWriteInput, collectionId?: string): Promise<void> {
    await this.serverWrite((session, userKey) => this.createCipher(session, userKey, (key) => createEncryptedItem(input, key), collectionId));
  }

  async updateItem(id: string, input: ItemWriteInput): Promise<void> {
    const item = await this.findItem(id);
    if (item.type !== input.type) throw new Error("The item type cannot be changed.");
    await this.editCipher(item, (raw, baseKey) => updateEncryptedItem(raw, input, baseKey));
  }

  // `encrypt` builds the cipher under the given key: the account key, or the collection's organization key.
  private async createCipher(
    session: AuthSession,
    userKey: Uint8Array,
    encrypt: (key: Uint8Array) => Promise<Record<string, unknown>>,
    collectionId?: string,
  ): Promise<void> {
    if (!collectionId) {
      await this.client.createCipher(session.baseUrl, session.accessToken, { ...(await encrypt(userKey)), ...encryptedFor(session.accessToken) });
      return;
    }
    const { organizationId } = this.writableCollection(collectionId);
    const orgKey = await this.organizationKey(organizationId, userKey);
    try {
      const cipher = { ...(await encrypt(orgKey)), organizationId, ...encryptedFor(session.accessToken) };
      await this.client.createOrganizationCipher(session.baseUrl, session.accessToken, cipher, [collectionId]);
    } finally {
      wipe(orgKey);
    }
  }

  private writableCollection(id: string): VaultCollection {
    const collection = this.collections.find((candidate) => candidate.id === id);
    if (!collection) throw new Error("That collection no longer exists. Sync and try again.");
    if (collection.readOnly) throw new Error("You can view this collection but not add items to it.");
    return collection;
  }

  // Moves a personal item into a collection. Its fields stay encrypted with its own item key; only that
  // key is re-wrapped with the organization key, like Bitwarden's "Move to organization".
  async moveToCollection(id: string, collectionId: string): Promise<void> {
    const item = await this.findItem(id);
    if (item.organizationId) throw new Error("This item already belongs to an organization.");
    if (!this.isRepromptAuthorized(item)) throw new Error("Confirm the master password for this protected item before moving it.");
    if (item.type === ItemType.SshKey) throw new Error("Move SSH keys in the web vault.");
    const { organizationId } = this.writableCollection(collectionId);
    await this.serverWrite(async (session, userKey) => {
      const raw = await this.client.getCipher(session.baseUrl, session.accessToken, id);
      const encryptedKey = stringProp(raw, "Key");
      // ponytail: items from before per-item keys would need every field re-encrypted; the web vault does that.
      if (!encryptedKey) throw new Error("This older item has no item key yet. Move it once in the web vault.");
      const current = item.type === ItemType.Login
        ? await updateEncryptedLogin(raw, { name: item.name, username: item.username, password: item.password, uri: item.uris[0]?.uri ?? "" }, userKey)
        : await updateEncryptedItem(raw, {
            type: item.type as ItemWriteInput["type"], name: item.name, notes: item.notes ?? "", favorite: item.favorite,
            ...(item.card ? { card: item.card } : {}), ...(item.identity ? { identity: item.identity } : {}),
          }, userKey);
      const itemKey = await decryptSymmetricBytes(encryptedKey, userKey);
      const orgKey = await this.organizationKey(organizationId, userKey);
      try {
        const cipher = {
          ...current, organizationId, key: await encryptSymmetricBytes(itemKey, orgKey), ...encryptedFor(session.accessToken),
        };
        await this.client.shareCipher(session.baseUrl, session.accessToken, id, cipher, [collectionId]);
      } finally {
        wipe(itemKey);
        wipe(orgKey);
      }
    });
  }

  // Re-encrypts the stored cipher with `encrypt` (given the raw cipher and its base key) and saves it.
  private async editCipher(
    item: VaultItem,
    encrypt: (raw: Record<string, unknown>, baseKey: Uint8Array) => Promise<Record<string, unknown>>,
  ): Promise<void> {
    if (!item.editable) throw new Error(READ_ONLY);
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected item before editing it.");
    }
    await this.serverWrite(async (session, userKey) => {
      const baseKey = await this.cipherKey(item, userKey);
      try {
        const raw = await this.client.getCipher(session.baseUrl, session.accessToken, item.id);
        const payload = { ...(await encrypt(raw, baseKey)), ...encryptedFor(session.accessToken) };
        await this.client.updateCipher(session.baseUrl, session.accessToken, item.id, payload);
      } finally {
        if (baseKey !== userKey) wipe(baseKey);
      }
    });
  }

  async trashItem(id: string): Promise<void> {
    const item = await this.findItem(id);
    if (!item.editable) throw new Error(READ_ONLY);
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Confirm the master password for this protected item before deleting it.");
    }
    await this.serverWrite((session) => this.client.trashCipher(session.baseUrl, session.accessToken, id));
  }

  async restoreItem(id: string): Promise<void> {
    await this.findTrashed(id);
    await this.serverWrite((session) => this.client.restoreCipher(session.baseUrl, session.accessToken, id));
  }

  async deleteForever(id: string): Promise<void> {
    await this.findTrashed(id);
    await this.serverWrite((session) => this.client.deleteCipher(session.baseUrl, session.accessToken, id));
  }

  async saveFolder(id: string | undefined, nameInput: string): Promise<void> {
    const name = nameInput.trim();
    if (!name || name.length > 1_000) throw new Error("Enter a folder name up to 1,000 characters.");
    await this.requireVault();
    if (id && !this.folders.some((folder) => folder.id === id)) throw new Error("That folder no longer exists.");
    await this.serverWrite(async (session, userKey) =>
      this.client.saveFolder(session.baseUrl, session.accessToken, await encryptSymmetricString(name, userKey), id));
  }

  // The server moves the folder's items to "No folder"; nothing is deleted with it.
  async deleteFolder(id: string): Promise<void> {
    await this.requireVault();
    if (!this.folders.some((folder) => folder.id === id)) throw new Error("That folder no longer exists.");
    await this.serverWrite((session) => this.client.deleteFolder(session.baseUrl, session.accessToken, id));
  }

  private async findTrashed(id: string): Promise<VaultItem> {
    await this.requireVault();
    const item = this.trashCache.find((candidate) => candidate.id === id);
    if (!item) throw new Error("That item is no longer in the trash.");
    if (!item.editable) throw new Error(READ_ONLY);
    return item;
  }

  // The account key for personal items; the organization key (a new copy to wipe) for organization items.
  private async cipherKey(item: VaultItem, userKey: Uint8Array): Promise<Uint8Array> {
    return item.organizationId ? this.organizationKey(item.organizationId, userKey) : userKey;
  }

  private async organizationKey(organizationId: string, userKey: Uint8Array): Promise<Uint8Array> {
    const [payload, account] = await Promise.all([readEncryptedSync(), requireAccount()]);
    if (!payload) throw new Error("Sync the vault and try again.");
    return decryptOrganizationKey(payload, userKey, account.privateKey, organizationId);
  }

  // The key an attachment's file is encrypted with (a copy the caller wipes).
  private async attachmentKey(raw: Record<string, unknown>, attachmentId: string, baseKey: Uint8Array): Promise<Uint8Array> {
    const encryptedItemKey = stringProp(raw, "Key");
    const itemKey = encryptedItemKey ? await decryptSymmetricBytes(encryptedItemKey, baseKey) : baseKey;
    try {
      const attachment = arrayProp(raw, "Attachments").map(asRecord).find((entry) => entry && prop(entry, "Id") === attachmentId);
      if (!attachment) throw new Error("That attachment no longer exists. Sync and try again.");
      const encryptedKey = stringProp(attachment, "Key");
      return encryptedKey ? await decryptSymmetricBytes(encryptedKey, itemKey) : itemKey.slice(); // Old attachments use the item key.
    } finally {
      if (encryptedItemKey) wipe(itemKey);
    }
  }

  // Decrypts an attachment for the popup to save. Returned as base64 because runtime messages carry JSON.
  async downloadAttachment(id: string, attachmentId: string): Promise<{ fileName: string; data: string }> {
    const item = await this.findItem(id);
    if (!this.isRepromptAuthorized(item)) throw new Error("Confirm the master password for this protected item first.");
    const attachment = item.attachments?.find((candidate) => candidate.id === attachmentId);
    if (!attachment) throw new Error("That attachment no longer exists. Sync and try again.");
    if (attachment.size > MAX_FILE_BYTES) throw new Error("This file is larger than 25 MB. Download it from the web vault.");
    return this.withSessionKey(async (session, userKey) => {
      const baseKey = await this.cipherKey(item, userKey);
      try {
        const [raw, encrypted] = await Promise.all([
          this.client.getCipher(session.baseUrl, session.accessToken, id),
          this.client.downloadAttachment(session.baseUrl, session.accessToken, id, attachmentId),
        ]);
        const key = await this.attachmentKey(raw, attachmentId, baseKey);
        try {
          const data = await decryptFile(encrypted, key);
          try {
            return { fileName: attachment.fileName, data: data.toBase64() };
          } finally {
            wipe(data);
          }
        } finally {
          wipe(key);
        }
      } finally {
        if (baseKey !== userKey) wipe(baseKey);
      }
    });
  }

  async addAttachment(id: string, fileNameInput: string, data: Uint8Array): Promise<void> {
    const item = await this.findItem(id);
    if (!item.editable) throw new Error(READ_ONLY);
    if (!this.isRepromptAuthorized(item)) throw new Error("Confirm the master password for this protected item first.");
    const fileName = fileNameInput.trim();
    if (!fileName || fileName.length > 255) throw new Error("The file name must be 1 to 255 characters.");
    if (data.length === 0) throw new Error("The file is empty.");
    if (data.length > MAX_FILE_BYTES) throw new Error("The file is too large (25 MB at most).");
    await this.serverWrite(async (session, userKey) => {
      const baseKey = await this.cipherKey(item, userKey);
      const raw = await this.client.getCipher(session.baseUrl, session.accessToken, id).catch((error: unknown) => {
        if (baseKey !== userKey) wipe(baseKey);
        throw error;
      });
      const encryptedItemKey = stringProp(raw, "Key");
      const itemKey = encryptedItemKey ? await decryptSymmetricBytes(encryptedItemKey, baseKey) : baseKey;
      const fileKey = crypto.getRandomValues(new Uint8Array(64));
      try {
        const encrypted = await encryptFile(data, fileKey);
        const encryptedName = await encryptSymmetricString(fileName, itemKey);
        const { attachmentId, url } = await this.client.createAttachment(session.baseUrl, session.accessToken, id, {
          key: await encryptSymmetricBytes(fileKey, itemKey),
          fileName: encryptedName,
          fileSize: encrypted.length,
        });
        try {
          await this.client.uploadFile(session.baseUrl, session.accessToken, url, encrypted, encryptedName);
        } catch (error) {
          // Do not leave an attachment entry without a file behind.
          await this.client.deleteAttachment(session.baseUrl, session.accessToken, id, attachmentId).catch(() => undefined);
          throw error;
        }
      } finally {
        wipe(fileKey);
        if (encryptedItemKey) wipe(itemKey);
        if (baseKey !== userKey) wipe(baseKey);
      }
    });
  }

  async deleteAttachment(id: string, attachmentId: string): Promise<void> {
    const item = await this.findItem(id);
    if (!item.editable) throw new Error(READ_ONLY);
    if (!this.isRepromptAuthorized(item)) throw new Error("Confirm the master password for this protected item first.");
    if (!item.attachments?.some((attachment) => attachment.id === attachmentId)) throw new Error("That attachment no longer exists.");
    await this.serverWrite((session) => this.client.deleteAttachment(session.baseUrl, session.accessToken, id, attachmentId));
  }

  async listSends(): Promise<SendSummary[]> {
    await this.requireVault();
    return this.sends;
  }

  // Returns the new Send's link, or null when it was created but the vault could not refresh.
  async createSend(input: SendWriteInput, file?: Uint8Array): Promise<string | null> {
    let id = "";
    await this.serverWrite(async (session, userKey) => {
      const { payload, file: encrypted } = await encryptSend(input, userKey, file);
      if (!encrypted) {
        id = await this.client.createSend(session.baseUrl, session.accessToken, payload);
        return;
      }
      const created = await this.client.createFileSend(session.baseUrl, session.accessToken, payload);
      id = created.id;
      try {
        await this.client.uploadFile(session.baseUrl, session.accessToken, created.url, encrypted, String((payload.file as { fileName: string }).fileName));
      } catch (error) {
        if (id) await this.client.deleteSend(session.baseUrl, session.accessToken, id).catch(() => undefined);
        throw error;
      }
    });
    return this.sends.find((send) => send.id === id)?.link ?? null;
  }

  async deleteSend(id: string): Promise<void> {
    await this.requireVault();
    if (!this.sends.some((send) => send.id === id)) throw new Error("That Send no longer exists.");
    await this.serverWrite((session) => this.client.deleteSend(session.baseUrl, session.accessToken, id));
  }

  // Personal items as a Bitwarden export, after the master password is confirmed.
  async exportVault(masterPassword: string, format: ExportFormat, filePassword?: string): Promise<string> {
    await this.verifyMasterPassword(masterPassword);
    const items = await this.requireVault();
    return format === "json"
      ? exportJson(items, this.folders)
      : exportEncryptedJson(items, this.folders, filePassword ?? "", deriveMasterKey);
  }

  // Without `confirm` only reads the file. Folders with a name that already exists are reused.
  async importVault(text: string, password: string | undefined, confirm: boolean): Promise<{ items: number; folders: number }> {
    const parsed = await parseImport(text, password, deriveMasterKey);
    const folderNames = [...new Set(parsed.flatMap((item) => (item.folder ? [item.folder] : [])))];
    const counts = { items: parsed.length, folders: folderNames.length };
    if (!confirm) return counts;
    await this.requireVault();
    const existing = new Map(this.folders.map((folder) => [folder.name, folder.id]));
    await this.serverWrite(async (session, userKey) => {
      const ciphers = [];
      for (const item of parsed) ciphers.push({ ...(await createEncryptedCipher(item, userKey)), ...encryptedFor(session.accessToken) });
      const folders = await Promise.all(folderNames.map(async (name) => ({
        name: await encryptSymmetricString(name, userKey),
        ...(existing.has(name) ? { id: existing.get(name) } : {}),
      })));
      const folderRelationships = parsed.flatMap((item, index) => (item.folder ? [{ key: index, value: folderNames.indexOf(item.folder) }] : []));
      await this.client.importCiphers(session.baseUrl, session.accessToken, { ciphers, folders, folderRelationships });
    });
    return counts;
  }

  // Runs `action` with an unlocked session's account key, wiped afterwards. Nothing is written.
  private async withSessionKey<T>(action: (session: AuthSession, userKey: Uint8Array) => Promise<T>): Promise<T> {
    const session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = requireUserKey(session.userKey);
    try {
      return await action(session, userKey);
    } finally {
      wipe(userKey);
    }
  }

  // Runs server writes with an unlocked session, then refreshes the vault (also after a partial
  // failure). Refresh failures never fail a committed write: the minute alarm retries them.
  private async serverWrite(action: (session: AuthSession, userKey: Uint8Array) => Promise<unknown>): Promise<void> {
    const session = await this.refreshSessionIfNeeded(await requireSession());
    const userKey = requireUserKey(session.userKey);
    try {
      await action(session, userKey);
    } finally {
      wipe(userKey);
      await this.sync().catch(() => undefined);
    }
  }

  async authenticatorList(currentUrl?: string): Promise<AuthenticatorEntry[]> {
    const items = await this.requireVault();
    // A protected login confirmed in the last minute shows its code like any other.
    return authenticatorEntries(items, currentUrl).map((entry) => ({
      ...entry,
      requiresReprompt: entry.requiresReprompt && !this.isRepromptAuthorized(items.find((item) => item.id === entry.id)!),
    }));
  }

  // Adds a key to a new login (no id), or edits/adds the key of an existing login.
  async saveAuthenticator(id: string | undefined, input: AuthenticatorWriteInput): Promise<void> {
    const item = id ? await this.findItem(id) : undefined;
    if (item && item.type !== ItemType.Login) throw new Error("Authenticator keys belong to logins.");
    const parameters = authenticatorKey(input, item?.totp);
    const login: LoginWriteInput = {
      name: input.name.trim() || parameters.issuer || parameters.account || "Authenticator",
      username: input.account,
      password: item?.password ?? "",
      uri: input.website,
      totp: storedTotpKey(parameters),
      nickname: input.nickname,
    };
    if (item) await this.updateLogin(item.id, login); // Checks edit rights and the master-password reprompt.
    else await this.createLogin(login);
  }

  // Removes the key; the login itself stays.
  async removeAuthenticator(id: string): Promise<void> {
    const item = await this.findItem(id);
    if (item.type !== ItemType.Login || !item.totp) throw new Error("This login has no authenticator key.");
    await this.updateLogin(id, { name: item.name, username: item.username, password: item.password, uri: item.uris[0]?.uri ?? "", totp: "", nickname: "" });
  }

  // Fills the current code into the active tab, only when the entry is mapped to that site.
  async fillAuthenticator(id: string): Promise<number> {
    const item = await this.findItem(id);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined || !tab.url || !/^https?:\/\//i.test(tab.url) || !matchesCurrentUrl(item, tab.url)) {
      throw new Error("This code is not mapped to the website in the current tab.");
    }
    if (httpsLoginOnHttp(item, tab.url)) {
      throw new Error("Refusing to fill an HTTPS login's code into an insecure HTTP page.");
    }
    const { code } = await this.totp(id); // Enforces the master-password reprompt.
    const filled = await fillOtpInTab(tab.id, code, [new URL(tab.url).origin]);
    if (filled === 0) throw new Error("No verification code field was found on this page.");
    return filled;
  }

  // Without `confirm` only checks the list. Never returns or logs a secret.
  async importAuthenticator(text: string, confirm: boolean): Promise<{ rows: ImportRow[]; imported: number }> {
    const { rows, entries } = previewImport(text, knownSecrets([...(await this.requireVault()), ...this.trashCache]));
    if (!confirm || entries.length === 0) return { rows, imported: 0 };
    let imported = 0;
    try {
      await this.serverWrite(async (session, userKey) => {
        for (const parameters of entries) {
          const login = { name: parameters.issuer || parameters.account || "Authenticator", username: parameters.account, password: "", uri: "", totp: storedTotpKey(parameters) };
          await this.createCipher(session, userKey, (key) => createEncryptedLogin(login, key));
          imported += 1;
        }
      });
    } catch (error) {
      if (imported === 0) throw error;
      throw new Error(`Imported ${imported} of ${entries.length} entries, then the server refused one: ${error instanceof Error ? error.message : String(error)}`);
    }
    return { rows, imported };
  }

  // Every key as otpauth:// links, after the master password is confirmed.
  async exportAuthenticator(masterPassword: string): Promise<string> {
    await this.verifyMasterPassword(masterPassword);
    const text = exportAuthenticator(await this.requireVault());
    if (!text) throw new Error("No logins have an authenticator key to export.");
    return text;
  }

  // Logins mapped to this page. Insecure pages never get HTTPS logins.
  async matchingLogins(url: string): Promise<VaultItemSummary[]> {
    const insecure = new URL(url).protocol === "http:";
    return listVaultItems(await this.requireVault(), "", url)
      .filter((item) => item.matched && !(insecure && item.uri?.startsWith("https://")));
  }

  async siteSuggestions(url: string): Promise<VaultItemSummary[]> {
    return (await this.matchingLogins(url)).slice(0, 10);
  }

  // Cards and identities have no website, so every page with card or address fields may offer them.
  // The page never sees this list: it is shown in a closed shadow root. Cards only on HTTPS pages.
  async siteFormItems(url: string): Promise<{ cards: VaultItemSummary[]; identities: VaultItemSummary[] }> {
    const items = listVaultItems(await this.requireVault(), "");
    const secure = new URL(url).protocol === "https:";
    return {
      cards: secure ? items.filter((item) => item.type === ItemType.Card) : [],
      identities: items.filter((item) => item.type === ItemType.Identity),
    };
  }

  async siteFillItem(id: string, url: string, tabId: number): Promise<number> {
    const item = await this.findItem(id);
    if (item.type !== ItemType.Card && item.type !== ItemType.Identity) throw new Error("Only cards and identities can be filled here.");
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Open Firnkey and confirm your master password to fill this item.");
    }
    const card = item.type === ItemType.Card;
    const fields = await fillFormInTab(tabId, url, card ? cardFormValues(item.card ?? {}) : identityFormValues(item.identity ?? {}), card);
    if (fields === 0) throw new Error(`No ${card ? "card" : "address or contact"} fields were found on this page.`);
    return fields;
  }

  async siteCredential(id: string, url: string, tabId?: number): Promise<{ username: string; password: string }> {
    const item = await this.findItem(id);
    if (!matchesCurrentUrl(item, url)) throw new Error("This login is not mapped to the current website.");
    if (httpsLoginOnHttp(item, url)) {
      throw new Error("Refusing to fill an HTTPS login into an insecure HTTP page.");
    }
    if (!this.isRepromptAuthorized(item)) {
      throw new Error("Open Firnkey and confirm the master password for this protected login.");
    }
    if (tabId !== undefined) this.rememberFill(tabId, item.id);
    return { username: item.username, password: item.password };
  }

  // A site's HTTP sign-in dialog: answered only when exactly one unprotected login matches, never
  // while locked, and never with an HTTPS login over plain HTTP.
  async basicAuthCredential(url: string): Promise<{ username: string; password: string } | null> {
    const items = await this.requireVault().catch(() => null);
    const matches = items?.filter((item) => item.type === ItemType.Login && item.password && matchesCurrentUrl(item, url)) ?? [];
    const item = matches.length === 1 ? matches[0]! : null;
    if (!item || item.reprompt) return null;
    if (httpsLoginOnHttp(item, url)) return null;
    return { username: item.username, password: item.password };
  }

  // Server and a fresh access token for the push-sync socket; null when signed out.
  async pushTarget(): Promise<{ baseUrl: string; email: string; accessToken: string } | null> {
    const session = await readAuthSession();
    if (!session) return null;
    const fresh = await this.refreshSessionIfNeeded(session);
    return { baseUrl: fresh.baseUrl, email: fresh.email, accessToken: fresh.accessToken };
  }

  // Authenticator code for a login the user picked on this website.
  async siteTotp(id: string, url: string): Promise<TotpResult> {
    const item = await this.findItem(id);
    if (!matchesCurrentUrl(item, url)) throw new Error("This login is not mapped to the current website.");
    if (httpsLoginOnHttp(item, url)) {
      throw new Error("Refusing to fill an HTTPS login's code into an insecure HTTP page.");
    }
    return this.totp(id);
  }

  // Code for the login Firnkey filled in this tab moments ago (the sign-in's second step). Nothing
  // otherwise: a page cannot pull codes for logins the user did not just choose to use there.
  async autoTotp(tabId: number, url: string): Promise<{ code: string; itemName: string } | null> {
    const recent = this.recentFills.get(tabId);
    if (!recent || recent.until <= Date.now()) return null;
    const item = (await this.requireVault()).find((candidate) => candidate.id === recent.itemId);
    if (!item?.totp || (!this.isRepromptAuthorized(item))) return null;
    try {
      return { code: (await this.siteTotp(item.id, url)).code, itemName: item.name };
    } catch {
      return null;
    }
  }

  forgetTab(tabId: number): void {
    this.recentFills.delete(tabId);
  }

  private rememberFill(tabId: number, itemId: string): void {
    // ponytail: three minutes covers a normal sign-in; make it a setting if slow 2FA pages miss it.
    this.recentFills.set(tabId, { itemId, until: Date.now() + 180_000 });
  }

  async inspectSiteLogin(
    tabId: number,
    url: string,
    username: string,
    password: string,
    options: BrowserIntegrationOptions,
    frameId = 0,
  ): Promise<({ id: string; expiresAt: number; action: "save" | "update" } & LoginWriteInput) | null> {
    await this.pendingReady;
    const fingerprint = await sha256Base64(JSON.stringify([new URL(url).origin, username, password]));
    const matches = (await this.requireVault()).filter((item) => matchesCurrentUrl(item, url));
    const previous = this.pendingCaptures.get(tabId);
    if (previous?.fingerprint === fingerprint && previous.rememberUntil > Date.now()) {
      return this.pendingSitePrompt(tabId, url, frameId);
    }
    if (matches.some((item) => item.username === username && item.password === password)) return null;
    const update = matches.find(
      (item) => item.username === username && item.editable && !item.reprompt,
    );
    if (update && !options.askUpdateLogin) return null;
    if (!update && !options.askAddLogin) return null;
    const name = update?.name ?? new URL(url).hostname.replace(/^www\./, "");
    const prompt = {
      id: crypto.randomUUID(),
      expiresAt: Date.now() + options.savePromptTimeoutSeconds * 1000,
      action: update ? "update" as const : "save" as const,
      name,
      username,
      password,
      // Updating must not swap the saved address for this page's full URL.
      uri: update?.uris[0]?.uri ?? url,
    };
    this.pendingCaptures.set(tabId, {
      ...prompt,
      url,
      username,
      password,
      ...(update ? { updateId: update.id } : {}),
      frameId,
      fingerprint,
      // ponytail: deduplicate a login flow for five minutes; use navigation tracking if flows need longer.
      rememberUntil: Date.now() + 300_000,
    });
    await this.persistPendingCaptures();
    return prompt;
  }

  async pendingSitePrompt(tabId: number, url: string, frameId = 0) {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (!pending || pending.frameId !== frameId || new URL(pending.url).origin !== new URL(url).origin) return null;
    if (pending.dismissed || pending.expiresAt <= Date.now()) {
      await this.dismissPendingSiteLogin(tabId, pending.id);
      return null;
    }
    return {
      id: pending.id,
      expiresAt: pending.expiresAt,
      action: pending.action,
      name: pending.name,
      username: pending.username,
      password: pending.password,
      uri: pending.uri,
    };
  }

  async savePendingSiteLogin(tabId: number, promptId: string, edited?: LoginWriteInput): Promise<void> {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (!pending || pending.dismissed || pending.id !== promptId || pending.expiresAt <= Date.now()) {
      throw new Error("The save prompt expired. Submit the login form again.");
    }
    if (pending.saving) throw new Error("This login is already being saved.");
    pending.saving = true;
    const input: LoginWriteInput = edited ?? {
      name: pending.name,
      username: pending.username,
      password: pending.password,
      uri: pending.uri,
    };
    try {
      if (pending.updateId) await this.updateLogin(pending.updateId, input);
      else await this.createLogin(input);
      await this.dismissPendingSiteLogin(tabId, promptId);
    } finally {
      pending.saving = false;
    }
  }

  // The user is working in the prompt: keep it saveable until the capture itself is forgotten.
  async holdPendingSiteLogin(tabId: number, promptId: string): Promise<void> {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (pending?.id !== promptId || pending.dismissed || pending.expiresAt <= Date.now()) return;
    pending.expiresAt = pending.rememberUntil;
    await this.persistPendingCaptures();
  }

  async dismissPendingSiteLogin(tabId: number, promptId: string): Promise<void> {
    await this.pendingReady;
    const pending = this.pendingCaptures.get(tabId);
    if (pending?.id !== promptId) return;
    pending.dismissed = true;
    pending.username = "";
    pending.password = "";
    await this.persistPendingCaptures();
  }

  async clearPendingSiteLogins(tabId?: number): Promise<void> {
    await this.pendingReady;
    if (tabId === undefined) this.pendingCaptures.clear();
    else this.pendingCaptures.delete(tabId);
    await this.persistPendingCaptures();
  }

  private async persistPendingCaptures(): Promise<void> {
    for (const [tabId, pending] of this.pendingCaptures) {
      if (pending.rememberUntil <= Date.now()) this.pendingCaptures.delete(tabId);
      else if (pending.expiresAt <= Date.now() && !pending.saving) {
        pending.dismissed = true;
        pending.username = "";
        pending.password = "";
      }
    }
    await chrome.storage.session.set({ pendingSiteLogins: [...this.pendingCaptures] });
  }

  async authorizeReprompt(id: string, masterPassword: string): Promise<void> {
    const item = await this.findItem(id);
    if (!item.reprompt) {
      return;
    }
    await this.verifyMasterPassword(masterPassword);
    this.repromptAuthorizations.set(id, Date.now() + 60_000);
  }

  // Throws unless the master password unwraps the same account key as the unlocked session.
  async verifyMasterPassword(masterPassword: string): Promise<void> {
    const [account, session] = await Promise.all([requireAccount(), requireSession()]);
    const sessionKey = requireUserKey(session.userKey);
    try {
      const candidate = await unwrapUserKey(masterPassword, account);
      const valid = equalConstantTime(candidate, sessionKey);
      wipe(candidate);
      if (!valid) {
        throw new Error("The master password is incorrect.");
      }
    } finally {
      wipe(sessionKey);
    }
  }

  // Passkeys for an RP. With an allow-list, only those credentials; without, only discoverable ones.
  async passkeysFor(rpId: string, allowCredentials: string[]): Promise<{ item: VaultItem; passkey: Passkey }[]> {
    const id = rpId.toLowerCase();
    return (await this.requireVault()).flatMap((item) => (item.passkeys ?? [])
      .filter((passkey) => passkey.rpId.toLowerCase() === id)
      .filter((passkey) => {
        if (allowCredentials.length === 0) return passkey.discoverable;
        try {
          return allowCredentials.includes(credentialIdBase64Url(passkey.credentialId));
        } catch {
          return false;
        }
      })
      .map((passkey) => ({ item, passkey })));
  }

  // Personal logins for this site that can take a new passkey (one passkey per login, like Bitwarden).
  async passkeyTargets(origin: string): Promise<VaultItem[]> {
    return (await this.requireVault()).filter((item) =>
      item.editable && !item.reprompt && !item.passkeys?.length && matchesCurrentUrl(item, origin));
  }

  async savePasskey(passkey: Passkey, origin: string, targetId?: string): Promise<void> {
    if (!targetId) {
      await this.createLogin({ name: passkey.rpName || passkey.rpId, username: passkey.userName ?? "", password: "", uri: origin }, passkey);
      return;
    }
    const item = (await this.passkeyTargets(origin)).find((candidate) => candidate.id === targetId);
    if (!item) throw new Error("That login can no longer store a passkey.");
    // Unchanged fields (and notes/favorite, which are omitted) are preserved by the update.
    await this.updateLogin(item.id, {
      name: item.name,
      username: item.username || (passkey.userName ?? ""),
      password: item.password,
      uri: item.uris[0]?.uri ?? origin,
    }, passkey);
  }

  // One passkey per login (like Bitwarden), so removing clears the login's passkeys. To replace one,
  // remove it and save a new one from the website.
  async removePasskey(id: string): Promise<void> {
    const item = await this.findItem(id);
    if (!item.passkeys?.length) throw new Error("This login has no passkey.");
    await this.updateLogin(id, { name: item.name, username: item.username, password: item.password, uri: item.uris[0]?.uri ?? "" }, null);
  }

  private async findItem(id: string): Promise<VaultItem> {
    const item = (await this.requireVault()).find((candidate) => candidate.id === id);
    if (!item) {
      throw new Error("The selected vault item no longer exists.");
    }
    return item;
  }

  private async requireVault(): Promise<VaultItem[]> {
    if (this.vaultCache) {
      return this.vaultCache;
    }
    const [account, session] = await Promise.all([requireAccount(), requireSession()]);
    const userKey = requireUserKey(session.userKey);
    try {
      return await this.loadVault(userKey, account);
    } finally {
      wipe(userKey);
    }
  }

  private async loadVault(userKey: Uint8Array, account: AccountMetadata): Promise<VaultItem[]> {
    const payload = await readEncryptedSync();
    if (!payload) {
      const result = await this.sync();
      if (!this.vaultCache) {
        throw new Error(`Vault sync completed with ${result.itemCount} items but no cache.`);
      }
      return this.vaultCache;
    }
    const decrypted = await decryptVault(payload, userKey, account.privateKey);
    const sends = await decryptSends(payload.Sends ?? payload.sends, userKey, account.baseUrl);
    this.vaultCache = decrypted.items;
    this.trashCache = decrypted.trash;
    this.folders = decrypted.folders;
    this.collections = decrypted.collections;
    this.sends = sends;
    this.decryptionFailures = decrypted.failures;
    if (account.itemCount !== decrypted.items.length) {
      await writeAccountMetadata({ ...account, itemCount: decrypted.items.length });
    }
    return decrypted.items;
  }

  private clearCache(): void {
    this.sessionRevision += 1;
    for (const item of [...(this.vaultCache ?? []), ...this.trashCache]) {
      item.username = "";
      item.password = "";
      delete item.totp;
      delete item.notes;
      delete item.passkeys;
      delete item.card;
      delete item.identity;
      delete item.sshKey;
      delete item.fields;
      delete item.passwordHistory;
      delete item.attachments;
    }
    this.vaultCache = null;
    this.trashCache = [];
    this.folders = [];
    this.collections = [];
    this.sends = [];
    this.decryptionFailures = 0;
    this.repromptAuthorizations.clear();
    this.recentFills.clear();
  }

  private isRepromptAuthorized(item: VaultItem): boolean {
    if (!item.reprompt) {
      return true;
    }
    const expiresAt = this.repromptAuthorizations.get(item.id) ?? 0;
    if (expiresAt <= Date.now()) {
      this.repromptAuthorizations.delete(item.id);
      return false;
    }
    return true;
  }

  private async refreshSessionIfNeeded(session: Awaited<ReturnType<typeof requireSession>>) {
    if (
      session.accessTokenExpiresAt !== undefined &&
      session.accessTokenExpiresAt <= Date.now() + 60_000 &&
      session.refreshToken
    ) {
      return this.refreshSession(session);
    }
    return session;
  }

  private async refreshSession(session: AuthSession): Promise<AuthSession> {
    if (this.refreshTask) return this.refreshTask;
    const task = this.performSessionRefresh(session);
    this.refreshTask = task;
    try {
      return await task;
    } finally {
      if (this.refreshTask === task) this.refreshTask = null;
    }
  }

  private async performSessionRefresh(session: AuthSession): Promise<AuthSession> {
    if (!session.refreshToken) {
      throw new Error("The account session expired. Sign in again.");
    }
    const revision = this.sessionRevision;
    const refreshed = await this.client.refreshAccessToken(session.baseUrl, session.refreshToken);
    if (revision !== this.sessionRevision) throw new Error("The account session changed during sync.");
    const updated = {
      ...session,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? session.refreshToken,
      ...(refreshed.expiresIn === undefined
        ? {}
        : { accessTokenExpiresAt: Date.now() + refreshed.expiresIn * 1000 }),
    };
    await writeAuthSession(updated);
    return updated;
  }
}

const READ_ONLY = "Your organization lets you view this item but not change it.";

interface PendingCapture {
  id: string;
  action: "save" | "update";
  name: string;
  url: string;
  uri: string;
  username: string;
  password: string;
  updateId?: string;
  expiresAt: number;
  frameId: number;
  fingerprint: string;
  rememberUntil: number;
  dismissed?: boolean;
  saving?: boolean;
}

// The account key that the master password unwraps; throws when it does not.
async function unwrapUserKey(masterPassword: string, account: AccountMetadata): Promise<Uint8Array> {
  const masterKey = await deriveMasterKey(masterPassword, account.email, account.kdf);
  const stretched = await stretchMasterKey(masterKey);
  wipe(masterKey);
  try {
    const userKey = await decryptSymmetricBytes(account.wrappedUserKey, stretched);
    if (isSymmetricKey(userKey)) return userKey;
    wipe(userKey);
  } catch {
    // Reported below.
  } finally {
    wipe(stretched);
  }
  throw new Error("The master password is incorrect.");
}

async function deriveMasterKey(
  password: string,
  email: string,
  kdf: KdfConfig,
): Promise<Uint8Array> {
  return kdf.type === KdfType.Pbkdf2Sha256
    ? derivePbkdf2MasterKey(password, email, kdf.iterations)
    : deriveArgon2idMasterKey(password, email, kdf);
}

// Current Vaultwarden requires writes to name the user whose key encrypted the cipher (the token's `sub`).
function encryptedFor(accessToken: string): { encryptedFor?: string } {
  try {
    const claims = JSON.parse(decodeUtf8(fromBase64(accessToken.split(".")[1] ?? ""))) as { sub?: unknown };
    return typeof claims.sub === "string" && claims.sub ? { encryptedFor: claims.sub } : {};
  } catch {
    return {}; // Older servers do not need the field.
  }
}

async function requireKdfNotDowngraded(baseUrl: string, email: string, kdf: KdfConfig): Promise<void> {
  const pinned = await readKdfPin(baseUrl, email);
  if (pinned && isWeakerKdf(kdf, pinned)) {
    throw new Error(
      "The server asked for weaker key-derivation settings than this account used before, so sign-in was refused. " +
        "If you lowered them yourself, remove and reinstall Firnkey to reset this check.",
    );
  }
}

// An HTTPS login must never be filled into a plain-HTTP page.
function httpsLoginOnHttp(item: VaultItem, url: string): boolean {
  return new URL(url).protocol === "http:" && item.uris.some(({ uri }) => /^https:\/\//i.test(uri));
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized || !normalized.includes("@") || /\s/.test(normalized)) {
    throw new Error("Enter a valid account email address.");
  }
  return normalized;
}

async function requireAccount(): Promise<AccountMetadata> {
  const account = await readAccountMetadata();
  if (!account) {
    throw new Error("No account is configured. Sign in first.");
  }
  return account;
}

async function requireSession() {
  const session = await readAuthSession();
  if (!session) {
    throw new Error("The account session has expired. Sign in again.");
  }
  return session;
}

function requireUserKey(value: number[] | undefined): Uint8Array {
  if (!value) {
    throw new Error("The vault is locked.");
  }
  const key = new Uint8Array(value);
  if (!isSymmetricKey(key)) {
    throw new Error("The session account key is invalid.");
  }
  return key;
}
