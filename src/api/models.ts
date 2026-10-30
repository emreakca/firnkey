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
}

export type LoginResult = LoginSuccess | TwoFactorChallenge | DeviceVerificationChallenge;

export interface PasswordLoginInput {
  baseUrl: string;
  email: string;
  masterPasswordHash: string;
  deviceIdentifier: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: boolean;
  newDeviceOtp?: string;
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
