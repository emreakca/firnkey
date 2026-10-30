import { normalizeServerEnvironment } from "../shared/environment";
import { parseKdfConfig, type KdfConfig } from "../shared/kdf";
import { isRecord, numberProp, recordProp, stringProp } from "../shared/props";
import type { LoginResult, PasswordLoginInput, RefreshResult, SyncResponse } from "./models";

type Fetch = typeof fetch;

const BITWARDEN_PROTOCOL_VERSION = "2026.6.4";
const CLIENT_NAME = "browser";
const DEVICE_TYPE_CHROME_EXTENSION = "2";
const REQUEST_TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ServerConfigResponse {
  version?: unknown;
  object?: unknown;
}

export interface ServerCheckResult {
  baseUrl: string;
  serverVersion?: string;
}

export interface PreloginResult {
  kdf: KdfConfig;
  endpoint: "password" | "legacy";
}


export class VaultwardenClient {
  constructor(private readonly fetchImpl: Fetch = globalThis.fetch.bind(globalThis)) {}

  async checkServer(baseUrl: string): Promise<ServerCheckResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchJson(`${environment.apiUrl}/config`, { method: "GET" });
    if (!isRecord(response)) {
      throw new ApiError("The server config endpoint returned an invalid response.");
    }

    const config = response as ServerConfigResponse;
    const serverVersion = typeof config.version === "string" ? config.version : undefined;
    return {
      baseUrl: environment.baseUrl,
      ...(serverVersion === undefined ? {} : { serverVersion }),
    };
  }

  async getPrelogin(baseUrl: string, emailInput: string): Promise<PreloginResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const email = emailInput.trim().toLowerCase();
    if (!email || !email.includes("@") || /\s/.test(email)) {
      throw new Error("Enter a valid account email address.");
    }

    const body = JSON.stringify({ email });
    try {
      const response = await this.fetchJson(`${environment.identityUrl}/accounts/prelogin/password`, {
        method: "POST",
        body,
      });
      return { kdf: parseKdfConfig(response), endpoint: "password" };
    } catch (error) {
      if (!(error instanceof ApiError) || (error.status !== 404 && error.status !== 405)) {
        throw error;
      }
    }

    const legacyResponse = await this.fetchJson(`${environment.identityUrl}/accounts/prelogin`, {
      method: "POST",
      body,
    });
    return { kdf: parseKdfConfig(legacyResponse), endpoint: "legacy" };
  }

  async loginWithPassword(input: PasswordLoginInput): Promise<LoginResult> {
    const environment = normalizeServerEnvironment(input.baseUrl);
    const form = new URLSearchParams({
      grant_type: "password",
      username: input.email.trim().toLowerCase(),
      password: input.masterPasswordHash,
      scope: "api offline_access",
      client_id: CLIENT_NAME,
      deviceType: DEVICE_TYPE_CHROME_EXTENSION,
      deviceIdentifier: input.deviceIdentifier,
      deviceName: "Chrome",
    });
    if (input.twoFactorProvider !== undefined && input.twoFactorToken) {
      form.set("twoFactorProvider", String(input.twoFactorProvider));
      form.set("twoFactorToken", input.twoFactorToken);
      form.set("twoFactorRemember", input.twoFactorRemember ? "1" : "0");
    }
    if (input.newDeviceOtp) {
      form.set("newDeviceOtp", input.newDeviceOtp);
    }

    const response = await this.fetchRaw(`${environment.identityUrl}/connect/token`, {
      method: "POST",
      body: form.toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    });
    const payload = await parseJsonRecord(response);

    if (response.ok) {
      const accessToken = stringProp(payload, "access_token");
      const tokenType = stringProp(payload, "token_type");
      if (!accessToken || !tokenType) {
        throw new ApiError("The identity server returned an invalid access token response.");
      }
      const wrappedUserKey = extractWrappedUserKey(payload);
      if (!wrappedUserKey) {
        throw new ApiError("This account did not return a master-password wrapped user key.");
      }
      const kdf = parseIdentityKdf(payload);
      const refreshToken = stringProp(payload, "refresh_token");
      const privateKey = stringProp(payload, "PrivateKey");
      const expiresIn = numberProp(payload, "expires_in");
      return {
        kind: "success",
        accessToken,
        wrappedUserKey,
        kdf,
        ...(refreshToken === undefined ? {} : { refreshToken }),
        ...(privateKey === undefined ? {} : { privateKey }),
        ...(expiresIn === undefined ? {} : { expiresIn }),
      };
    }

    const providers = recordProp(payload, "TwoFactorProviders2");
    if (response.status === 400 && providers && Object.keys(providers).length > 0) {
      const providerDetails: Record<string, Record<string, unknown>> = {};
      for (const [key, value] of Object.entries(providers)) {
        if (isRecord(value)) providerDetails[key] = value;
      }
      return {
        kind: "two-factor",
        providers: Object.keys(providers)
          .map((value) => Number.parseInt(value, 10))
          .filter(Number.isInteger),
        providerDetails,
      };
    }

    const errorModel = recordProp(payload, "ErrorModel");
    const message = firstNonEmptyString(
      errorModel ? stringProp(errorModel, "Message") : undefined,
      stringProp(payload, "Message"),
      stringProp(payload, "error_description"),
    );
    if (response.status === 400 && message?.toLowerCase().includes("new device verification")) {
      return { kind: "device-verification", message };
    }
    throw new ApiError(message ?? `Login failed with HTTP ${response.status}.`, response.status);
  }

  async getSync(baseUrl: string, accessToken: string): Promise<SyncResponse> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchJson(`${environment.apiUrl}/sync?excludeDomains=true`, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!isRecord(response)) {
      throw new ApiError("The vault sync endpoint returned an invalid response.");
    }
    return response as SyncResponse;
  }

  async getCipher(baseUrl: string, accessToken: string, id: string): Promise<Record<string, unknown>> {
    return this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}`, "GET", undefined, true);
  }

  async createCipher(
    baseUrl: string,
    accessToken: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authenticated(baseUrl, accessToken, "/ciphers", "POST", payload, true);
  }

  async updateCipher(
    baseUrl: string,
    accessToken: string,
    id: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}`, "PUT", payload, true);
  }

  // A new organization item, assigned to collections.
  async createOrganizationCipher(
    baseUrl: string,
    accessToken: string,
    cipher: Record<string, unknown>,
    collectionIds: string[],
  ): Promise<void> {
    await this.authenticated(baseUrl, accessToken, "/ciphers/create", "POST", { cipher, collectionIds });
  }

  // Moves a personal item into an organization (its item key re-wrapped with the organization key).
  async shareCipher(
    baseUrl: string,
    accessToken: string,
    id: string,
    cipher: Record<string, unknown>,
    collectionIds: string[],
  ): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}/share`, "PUT", { cipher, collectionIds });
  }

  // `folders` reuse an existing folder when they carry its id; relationships map cipher index to folder index.
  async importCiphers(baseUrl: string, accessToken: string, payload: Record<string, unknown>): Promise<void> {
    await this.authenticated(baseUrl, accessToken, "/ciphers/import", "POST", payload);
  }

  // Returns the attachment's id and the API path its encrypted file is uploaded to.
  async createAttachment(
    baseUrl: string,
    accessToken: string,
    cipherId: string,
    request: { key: string; fileName: string; fileSize: number },
  ): Promise<{ attachmentId: string; url: string }> {
    const response = await this.authenticated(
      baseUrl, accessToken, `/ciphers/${encodeURIComponent(cipherId)}/attachment/v2`, "POST", { ...request, adminRequest: false }, true,
    );
    return { attachmentId: requiredResponseString(response, "AttachmentId"), url: requiredResponseString(response, "Url") };
  }

  async deleteAttachment(baseUrl: string, accessToken: string, cipherId: string, attachmentId: string): Promise<void> {
    await this.authenticated(
      baseUrl, accessToken, `/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`, "DELETE",
    );
  }

  // The attachment's encrypted bytes, through the download link the server hands out.
  async downloadAttachment(baseUrl: string, accessToken: string, cipherId: string, attachmentId: string): Promise<Uint8Array> {
    const response = await this.authenticated(
      baseUrl, accessToken, `/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`, "GET", undefined, true,
    );
    const link = new URL(requiredResponseString(response, "Url"), `${baseUrl}/`);
    // The link is only followed to this server, so a hostile response cannot make Firnkey fetch elsewhere.
    if (link.origin !== new URL(baseUrl).origin) throw new ApiError("The server returned a download link for another site.");
    const file = await this.fetchRaw(link.href, { method: "GET", headers: { Accept: "*/*" } });
    if (!file.ok) throw new ApiError(`The attachment download failed with HTTP ${file.status}.`, file.status);
    return new Uint8Array(await file.arrayBuffer());
  }

  // Posts an encrypted file to an upload path returned by the server ("/ciphers/…" or "/sends/…").
  async uploadFile(baseUrl: string, accessToken: string, path: string, data: Uint8Array, fileName: string): Promise<void> {
    if (!/^\/(ciphers|sends)(\/[\w-]+)+$/.test(path)) throw new ApiError("The server returned an invalid upload address.");
    const form = new FormData();
    form.append("data", new Blob([data.slice()], { type: "application/octet-stream" }), fileName);
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchRaw(`${environment.apiUrl}${path}`, {
      method: "POST",
      body: form,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) throw new ApiError(`The upload failed with HTTP ${response.status}.`, response.status);
  }

  async createSend(baseUrl: string, accessToken: string, payload: Record<string, unknown>): Promise<string> {
    return requiredResponseString(await this.authenticated(baseUrl, accessToken, "/sends", "POST", payload, true), "Id");
  }

  // A file Send is created first, then its encrypted file goes to the returned upload path.
  async createFileSend(baseUrl: string, accessToken: string, payload: Record<string, unknown>): Promise<{ url: string; id: string }> {
    const response = await this.authenticated(baseUrl, accessToken, "/sends/file/v2", "POST", payload, true);
    const send = recordProp(response, "SendResponse");
    return { url: requiredResponseString(response, "Url"), id: send ? stringProp(send, "Id") ?? "" : "" };
  }

  async deleteSend(baseUrl: string, accessToken: string, id: string): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/sends/${encodeURIComponent(id)}`, "DELETE");
  }

  // Soft delete: the cipher moves to the trash and can be restored.
  async trashCipher(baseUrl: string, accessToken: string, id: string): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}/delete`, "PUT");
  }

  async restoreCipher(baseUrl: string, accessToken: string, id: string): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}/restore`, "PUT");
  }

  async deleteCipher(baseUrl: string, accessToken: string, id: string): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/ciphers/${encodeURIComponent(id)}`, "DELETE");
  }

  // `name` is an EncString. Creates the folder without an id, renames it with one.
  async saveFolder(baseUrl: string, accessToken: string, name: string, id?: string): Promise<void> {
    const path = id ? `/folders/${encodeURIComponent(id)}` : "/folders";
    await this.authenticated(baseUrl, accessToken, path, id ? "PUT" : "POST", { name });
  }

  async deleteFolder(baseUrl: string, accessToken: string, id: string): Promise<void> {
    await this.authenticated(baseUrl, accessToken, `/folders/${encodeURIComponent(id)}`, "DELETE");
  }

  async refreshAccessToken(baseUrl: string, refreshToken: string): Promise<RefreshResult> {
    const environment = normalizeServerEnvironment(baseUrl);
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CLIENT_NAME,
      refresh_token: refreshToken,
    });
    const response = await this.fetchRaw(`${environment.identityUrl}/connect/token`, {
      method: "POST",
      body: form.toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    });
    const payload = await parseJsonRecord(response);
    if (!response.ok) {
      throw new ApiError("The account session expired. Sign in again.", response.status);
    }
    const accessToken = stringProp(payload, "access_token");
    if (!accessToken) {
      throw new ApiError("The identity server returned an invalid refresh response.");
    }
    const nextRefreshToken = stringProp(payload, "refresh_token");
    const expiresIn = numberProp(payload, "expires_in");
    return {
      accessToken,
      ...(nextRefreshToken === undefined ? {} : { refreshToken: nextRefreshToken }),
      ...(expiresIn === undefined ? {} : { expiresIn }),
    };
  }

  async sendTwoFactorEmail(
    baseUrl: string,
    email: string,
    masterPasswordHash: string,
    deviceIdentifier: string,
  ): Promise<void> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchRaw(`${environment.apiUrl}/two-factor/send-email-login`, {
      method: "POST",
      body: JSON.stringify({ email, masterPasswordHash, deviceIdentifier }),
    });
    if (!response.ok) {
      throw new ApiError(`Email verification request failed with HTTP ${response.status}.`, response.status);
    }
  }

  private async fetchJson(url: string, init: RequestInit): Promise<unknown> {
    const response = await this.fetchRaw(url, init);
    if (!response.ok) {
      throw new ApiError(`Server request failed with HTTP ${response.status}.`, response.status);
    }
    return parseJson(response);
  }

  // Without `parse` the response body is ignored (empty or not needed).
  private async authenticated(
    baseUrl: string,
    accessToken: string,
    path: string,
    method: "GET" | "POST" | "PUT" | "DELETE",
    payload?: Record<string, unknown>,
    parse = false,
  ): Promise<Record<string, unknown>> {
    const environment = normalizeServerEnvironment(baseUrl);
    const response = await this.fetchRaw(`${environment.apiUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${accessToken}` },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    });
    if (!response.ok) {
      throw new ApiError(`Server request failed with HTTP ${response.status}.`, response.status);
    }
    if (!parse) return {};
    const value = await parseJson(response);
    if (!isRecord(value)) throw new ApiError("The server returned an invalid cipher response.");
    return value;
  }

  private async fetchRaw(url: string, init: RequestInit): Promise<Response> {
    try {
      return await this.fetchImpl(url, {
        ...init,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          Accept: "application/json",
          // A multipart upload sets its own boundary header.
          ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json; charset=utf-8" }),
          "Bitwarden-Client-Name": CLIENT_NAME,
          "Bitwarden-Client-Version": BITWARDEN_PROTOCOL_VERSION,
          "Device-Type": DEVICE_TYPE_CHROME_EXTENSION,
          ...init.headers,
        },
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "TimeoutError") {
        throw new ApiError("The server request timed out.");
      }
      throw new ApiError("Could not connect to the server.");
    }
  }
}

async function parseJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ApiError("Server returned a non-JSON response.", response.status);
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError("Server returned malformed JSON.", response.status);
  }
}

async function parseJsonRecord(response: Response): Promise<Record<string, unknown>> {
  const value = await parseJson(response);
  if (!isRecord(value)) {
    throw new ApiError("The identity server returned an invalid response.", response.status);
  }
  return value;
}

function parseIdentityKdf(payload: Record<string, unknown>): KdfConfig {
  return parseKdfConfig({
    Kdf: payload.Kdf,
    KdfIterations: payload.KdfIterations,
    KdfMemory: payload.KdfMemory,
    KdfParallelism: payload.KdfParallelism,
  });
}

function extractWrappedUserKey(payload: Record<string, unknown>): string | undefined {
  const legacy = stringProp(payload, "Key");
  if (legacy) {
    return legacy;
  }
  const options = recordProp(payload, "UserDecryptionOptions");
  const unlock = options ? recordProp(options, "MasterPasswordUnlock") : undefined;
  return unlock ? stringProp(unlock, "MasterKeyEncryptedUserKey") : undefined;
}


function requiredResponseString(source: Record<string, unknown>, name: string): string {
  const value = stringProp(source, name);
  if (!value) throw new ApiError(`The server response is missing ${name}.`);
  return value;
}

function firstNonEmptyString(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => value !== undefined && value.trim().length > 0);
}
