# Implementation roadmap

## Milestone 1 — server and prelogin foundation

- [x] Manifest V3 build and popup.
- [x] Optional per-origin server permission.
- [x] Environment normalization and server config verification.
- [x] Modern and legacy password-prelogin negotiation.
- [x] Defensive KDF validation.
- [x] Tests and bundle budgets.

## Milestone 2 — authenticated, read-only vault

- [x] PBKDF2 master-key derivation through Web Crypto.
- [x] Transient Argon2id offscreen/WASM context with explicit teardown.
- [x] Password grant and common code-based two-factor challenges.
- [x] Session-only unlock-key storage and lock cleanup.
- [x] Encrypted `/api/sync` persistence.
- [x] Compatible login-cipher decryption using known-answer fixtures.
- [x] Read-only vault list, search, and current-site matching.
- [x] `ViewPassword` enforcement and per-item master-password reprompt.
- [x] WebAuthn and Duo (Universal Prompt) two-step login flows.
- [x] Encryption v2/COSE account support (XChaCha20-Poly1305 user keys and type 7 data).

## Milestone 3 — core password manager

- [x] Personal login cipher create/update with per-item encryption keys and URI checksums.
- [x] Folders (filter, assign, create, rename, delete) and trash with restore and permanent delete.
- [x] Click-only manual autofill across page frames and open shadow roots.
- [x] Shortcut (Ctrl/Cmd+Shift+L) and right-click autofill, plus a toolbar count of matching logins.
- [x] Standard TOTP generation without exposing seeds to the popup, plus adding, replacing and
      removing a login's authenticator key in the editor (write-only: saved keys stay hidden).
- [x] Cards, identities, and secure notes: view, copy, create, edit, and popup fill for cards and
      identities (card fill on HTTPS pages only).
- [x] Custom fields and password history view.
- [x] Card and identity suggestions in the in-page field menu (cards on HTTPS pages only; fills
      every frame so split payment iframes are covered).
- [x] SSH key items (view and copy; edit in the web vault).
- [x] Opt-in save-login and changed-password prompts with memory-only pending capture.
- [x] Password, passphrase (EFF long wordlist), and username generators.
- [x] Configurable vault timeout: 1 minute to 24 hours of inactivity, computer lock, browser close,
      or encrypted until-logout persistence; a browser restart locks instead of signing out.
- [x] Biometric unlock (Touch ID / Windows Hello) through a WebAuthn PRF passkey, including the
      passkey window.
- [x] Configurable clipboard timeout and account switching.
- [x] Editing organization items (with the organization's edit and view-password permission).

## Milestone 4 — advanced browser integration

- [x] Field-anchored matched-login picker and dynamic form observation.
- [x] SPA, iframe manual fill, open-shadow-DOM detection, and HTTP downgrade handling.
- [x] Optional integrated Authenticator workspace (keys live in vault logins, so they sync and
      stay encrypted with the rest of the vault; QR scanning uses the browser's BarcodeDetector,
      which Chrome ships on macOS and ChromeOS):
  - Disabled by default and exposed as a Vault-adjacent bottom tab only when enabled in Settings.
  - Live TOTP cards with countdown progress, click-to-copy, and explicit fill into detected
    one-time-code fields.
  - QR enrollment from the visible page plus manual enrollment using a Base32 secret or validated
    `otpauth://totp/` URI.
  - Per-entry editing for name, optional nickname, account label, mapped website, issuer, and secret.
  - A separately configurable smart filter that shows entries mapped to the active domain when
    matches exist, falls back to all entries when none match, and always offers **View all**.
  - Newline-delimited `otpauth://totp/` import and export with validation, duplicate detection,
    preview/confirmation, and no secrets written to logs.
  - SHA-1, SHA-256, and SHA-512 parameters, configurable digit counts and periods, plus Steam-code
    compatibility where represented by the source URI.
  - Security gates for protected-item reprompt, explicit user-triggered QR capture/export, strict
    TOTP-only URI validation, domain-bound fill authorization, and clipboard clearing controls.
  - Compatibility fixtures and negative tests for malformed QR payloads, oversized imports,
    duplicate seeds, hostile labels, phishing-domain fill attempts, and lock/logout cleanup.
- [x] Passkey create/get bridge with RP ID and origin validation.
- [x] Basic-auth handling (opt-in) and adaptive notification sync (push over the notifications hub,
      polling only while the socket is down).
- [x] Attachments (download, upload, delete), text and file Sends (create, list, copy link, delete),
      Bitwarden JSON/CSV import and JSON export (plain or password-protected), and organization
      collections (filter, create in a collection, move a personal item into one).

## Milestone 5 — hardening and distribution

- [x] Differential compatibility suite against supported Vaultwarden releases (`pnpm compat`, in CI).
- [x] Automated Chrome process/heap regression tests (`pnpm check:memory`, in CI): idle service-worker
      and popup heap, extra renderer processes, no idle offscreen document, and worker growth over
      repeated popup opens.
- [x] Localization and accessibility review.
  - [x] Accessibility review: labelled controls, text contrast of at least 5:1, rows exposed as
        buttons, announced active tab and menu state, focus kept on page changes, and keyboard
        navigation of the in-page suggestion menu (checked in `scripts/check-site.mjs`).
  - [x] Localization: popup, passkey window, in-page menu and save prompt, context menu and manifest
        strings are `chrome.i18n` messages (`src/_locales/en`), with plural forms and a key check in
        `tests/i18n.test.ts`. Errors raised by the background and vault code are still English.
- [x] Dependency, license, SBOM, reproducibility, and trademark audit.
  - [x] License allowlist for shipped dependencies, CycloneDX SBOM, reproducible-build check
        (`pnpm audit:release`, in CI).
  - [x] Trademark review (name, icons, store listing): see [docs/STORE.md](STORE.md#trademark-review).
- [ ] Independent cryptography and browser-extension security audit (needs an outside reviewer).
- [x] Chrome Web Store privacy disclosures ([PRIVACY.md](../PRIVACY.md), [docs/STORE.md](STORE.md)) and
      release automation (tag `vX.Y.Z` → checks, reproducible zip, GitHub release, optional store
      upload).
