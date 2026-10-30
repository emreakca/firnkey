# Architecture

## Runtime boundaries

Firnkey treats every browser execution context as a security and memory boundary:

1. The Manifest V3 service worker registers event listeners synchronously and dispatches to small
   feature modules.
2. The popup owns presentation only. It communicates through validated, typed messages and never
   accesses vault storage directly.
3. Manual popup fill uses a one-shot `chrome.scripting.executeScript` call after a user click.
   Optional inline integration is separately permissioned, disabled by default, and receives only
   summaries until the user selects one matched login.
4. Optional passkey support adds a tiny page-world script that wraps `navigator.credentials` and an
   isolated bridge that relays to the background. The background validates origin (from Chrome's
   sender info) and RP ID, and the user decides in a separate extension window.
5. Server ciphertext lives in IndexedDB. The session lives in trusted-context session storage, and
   a copy is AES-GCM wrapped under a non-extractable browser-profile key in a separate IndexedDB
   database so a browser restart comes back locked. That copy includes the account key only in the
   opt-in “until logout” mode. Lock removes the account key from both copies; logout removes all
   session material. Biometric unlock (`src/shared/biometric.ts`, run from the popup) wraps the account key with a WebAuthn PRF
   output from a platform passkey bound to the extension origin.
6. Argon2id applies Bitwarden's SHA-256 email-salt preprocessing and is isolated in an offscreen
   document that exists only for one derivation request. Its
   WASM code is absent from the service-worker startup bundle.

## Current milestone

The current personal-login MVP is:

```text
popup user gesture
  -> request exact server origin permission
  -> typed runtime message
  -> background Vaultwarden client
  -> GET /api/config
  -> POST /identity/accounts/prelogin/password
       fallback: /identity/accounts/prelogin
  -> validate KDF downgrade and resource limits
  -> derive master key (Web Crypto PBKDF2 or transient Argon2id)
  -> POST /identity/connect/token
  -> unwrap user key and GET /api/sync
  -> persist only server ciphertext
  -> decrypt a minimal login model in service-worker memory
  -> enforce ViewPassword and per-item master-password reprompt
  -> search/copy/TOTP or one-shot manual fill
  -> encrypt personal cipher fields under a random item key
  -> POST/PUT /api/ciphers and resync
  -> optional site script: matched picker and explicit save/update prompt
```

Organization items are edited (and trashed, restored or deleted) only when the server's `Edit` and
`ViewPassword` flags allow it. The organization key is unwrapped from the stored sync data for that
one write and wiped afterwards; the stored item key and organization ID are kept, so the server's
"organization mismatch" check passes. New items are always created as personal items.

New items can be created in a writable collection (`POST /api/ciphers/create`, encrypted under the
organization key). A personal item moves into a collection through `PUT /api/ciphers/{id}/share`:
its fields stay encrypted with its own item key, and only that key is re-wrapped with the
organization key.

Attachments and file Sends are encrypted in the service worker and uploaded with the `v2` flow (the
server returns an upload path, the encrypted file follows as multipart data). File contents cross
the popup boundary as base64 in runtime messages, which is why files are capped at 25 MB. Sends are
decrypted from the sync payload into name, link and counters only. Import parses the file in the
service worker and sends every item in one `POST /api/ciphers/import`.

Account switching keeps one active account in the usual storage slots. Switched-out accounts are
listed in `chrome.storage.local` (`savedAccounts`: metadata, server snapshot, wrapped biometric
record) with their tokens and encrypted vault copy in IndexedDB under `account:<server>\n<email>`.

## Storage policy

Persistent local metadata contains the server snapshot, account email, KDF configuration, and the
server-provided encrypted user key. Encrypted sync data is stored in IndexedDB. Master passwords and
decrypted vault items are never persisted. Server tokens persist only as AES-GCM ciphertext under a
non-extractable key scoped to the browser profile; the decrypted account key is session-only unless
the explicit “until logout” option adds it to that ciphertext.

Storage layers are separated into:

- settings: small, non-secret versioned values in `chrome.storage.local`;
- encrypted vault: server ciphertext and indexes in IndexedDB;
- session secrets: narrowly scoped unlock material cleared on lock and normally at browser-session
  end, with an explicit encrypted-persistence option for a trusted browser profile;
- content state: either a one-shot injected fill function or, after explicit broad-host permission,
  a small isolated login-form observer. Submitted plaintext is held only in service-worker memory,
  expires after two minutes, and is cleared on lock/logout.

## Bundle policy

Budgets are 250 KiB for background JavaScript, 200 KiB for popup JavaScript, 96 KiB for transient
Argon2, and 48 KiB for site integration. These are ceilings, not targets. Every feature must justify
entry-bundle residency or load separately.
