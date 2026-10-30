// Bitwarden cipher types.
export const ItemType = { Login: 1, SecureNote: 2, Card: 3, Identity: 4, SshKey: 5 } as const;
export type ItemType = (typeof ItemType)[keyof typeof ItemType];

// Field names match Bitwarden's CardApi / IdentityApi (camelCase; the server may send PascalCase).
export const CARD_FIELDS = ["cardholderName", "brand", "number", "expMonth", "expYear", "code"] as const;
export const IDENTITY_FIELDS = [
  "title", "firstName", "middleName", "lastName", "username", "company", "email", "phone",
  "address1", "address2", "address3", "city", "state", "postalCode", "country",
  "ssn", "passportNumber", "licenseNumber",
] as const;
export const SSH_KEY_FIELDS = ["privateKey", "publicKey", "keyFingerprint"] as const;
export type CardData = Partial<Record<(typeof CARD_FIELDS)[number], string>>;
export type IdentityData = Partial<Record<(typeof IDENTITY_FIELDS)[number], string>>;
export type SshKeyData = Partial<Record<(typeof SSH_KEY_FIELDS)[number], string>>;

// Bitwarden FieldType: 0 text, 1 hidden, 2 boolean ("true"/"false"). Linked fields (3) are skipped.
export interface CustomField {
  name: string;
  value: string;
  hidden: boolean;
}

export interface PasswordHistoryEntry {
  password: string;
  lastUsedDate: string;
}

export interface VaultUri {
  uri: string;
  match?: number;
}

// A decrypted passkey in Bitwarden's `fido2Credentials` format (ES256 / P-256 only).
export interface Passkey {
  credentialId: string; // GUID, or "b64.<base64url>" for imported IDs
  keyValue: string; // base64url PKCS#8 private key
  rpId: string;
  userHandle?: string; // base64url
  userName?: string;
  userDisplayName?: string;
  rpName?: string;
  counter: number;
  discoverable: boolean;
  creationDate: string;
}

// File name decrypted; the file itself stays on the server until downloaded.
export interface Attachment {
  id: string;
  fileName: string;
  size: number;
  sizeName: string;
}

export interface VaultCollection {
  id: string;
  organizationId: string;
  organizationName: string;
  name: string;
  readOnly: boolean;
}

export interface VaultItem {
  id: string;
  type: ItemType;
  name: string;
  username: string;
  password: string;
  totp?: string;
  notes?: string;
  favorite: boolean;
  reprompt: boolean;
  organizationId?: string;
  // Personal items always; organization items when the server grants edit and the password is visible.
  editable: boolean;
  folderId?: string;
  uris: VaultUri[];
  passkeys?: Passkey[];
  card?: CardData;
  identity?: IdentityData;
  sshKey?: SshKeyData;
  fields?: CustomField[];
  passwordHistory?: PasswordHistoryEntry[];
  attachments?: Attachment[];
  collectionIds?: string[];
}

export interface VaultItemSummary {
  id: string;
  type: ItemType;
  name: string;
  username: string;
  // Card brand and last digits, or an identity's full name.
  subtitle?: string;
  hasTotp: boolean;
  favorite: boolean;
  requiresReprompt: boolean;
  editable: boolean;
  matched: boolean;
  uri?: string;
  folderId?: string;
}

export interface VaultFolder {
  id: string;
  name: string;
}

export interface VaultItemDetail extends VaultItemSummary {
  password: string;
  hasTotp: boolean;
  totp?: string;
  protected: boolean;
  notes?: string;
  uris: VaultUri[];
  card?: CardData;
  identity?: IdentityData;
  sshKey?: SshKeyData;
  fields?: CustomField[];
  passwordHistory?: PasswordHistoryEntry[];
  passkeys?: PasskeySummary[];
  attachments?: Attachment[];
  organizationId?: string;
  collectionIds?: string[];
}

// What the popup may see of a passkey: never the private key.
export type PasskeySummary = Pick<Passkey, "rpId" | "userName" | "creationDate">;
