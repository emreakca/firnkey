import type { KdfConfig } from "../shared/kdf";

export interface TwoFactorChallenge {
  kind: "two-factor";
  providers: number[];
  // Raw per-method data: an email hint, a WebAuthn challenge, a Duo AuthUrl.
  providerDetails: Record<string, Record<string, unknown>>;
}

export interface DeviceVerificationChallenge {
  kind: "device-verification";
  message: string;
}

export interface LoginSuccess {
  kind: "success";
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  wrappedUserKey: string;
  privateKey?: string;
  kdf: KdfConfig;
  // The master key's salt (the account email), from the master-password unlock options.
  salt?: string;
}

export type LoginResult = LoginSuccess | TwoFactorChallenge | DeviceVerificationChallenge;

export interface TwoFactorInput {
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: boolean;
}

export interface PasswordLoginInput extends TwoFactorInput {
  baseUrl: string;
  email: string;
  masterPasswordHash: string;
  deviceIdentifier: string;
  newDeviceOtp?: string;
  // Login with device: the approved request's id (masterPasswordHash then carries its access code).
  authRequest?: string;
}

export interface SsoLoginInput extends TwoFactorInput {
  baseUrl: string;
  code: string;
  codeVerifier: string;
  deviceIdentifier: string;
}

// approved: null while waiting, false when denied. `key` is RSA-encrypted to this request's public
// key: the user key, or the master key when `masterPasswordHash` is set (older approving apps).
export interface AuthRequestResponse {
  approved: boolean | null;
  key?: string;
  masterPasswordHash?: string;
}

export interface SyncResponse {
  Profile?: {
    Id?: unknown;
    Email?: unknown;
    PrivateKey?: unknown;
    Organizations?: unknown;
    OrganizationsNew?: unknown;
  };
  Ciphers?: unknown;
  Folders?: unknown;
  Collections?: unknown;
  Sends?: unknown;
  // Equivalent domains: the user's own groups and the server's global ones (with `excluded` flags).
  Domains?: unknown;
  Policies?: unknown;
  profile?: SyncResponse["Profile"];
  ciphers?: unknown;
  folders?: unknown;
  collections?: unknown;
  sends?: unknown;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}
