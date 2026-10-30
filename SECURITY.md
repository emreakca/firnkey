# Security policy

Firnkey is unaudited security software. Version 1.0.0 can authenticate, decrypt, create, and update
personal login ciphers, but it has not received an independent security audit and is not recommended
for critical production credentials.

## Current guarantees

- Master passwords exist only for the duration of a login or unlock request and are never written to
  persistent or session storage.
- Account email and non-secret KDF/unlock metadata are persisted locally after successful login.
- The decrypted account key uses `chrome.storage.session`, restricted to trusted extension contexts,
  and normally disappears at browser-session end. Access and refresh tokens are also kept AES-GCM
  encrypted under a non-extractable browser-profile key, so a browser restart locks the vault instead
  of signing out. Tokens alone cannot decrypt the vault.
- Vault timeout is configurable. Every option except “until logout” locks when the browser session
  ends; optional inactivity alarms support 1, 5, 15 or 30 minutes and 1, 2, 4, 8 or 24 hours, and
  “when the computer locks” uses the `idle` API. Explicit lock clears the account key immediately.
- Optional biometric unlock (Touch ID, Windows Hello) creates a platform passkey scoped to the
  extension's own origin. The account key is AES-GCM wrapped with that passkey's WebAuthn PRF output,
  which the authenticator releases only after user verification. The wrapped key and credential ID
  are stored locally and deleted on logout or when the option is turned off.
- The opt-in “keep unlocked until logout” mode AES-GCM encrypts the session under a non-extractable
  key stored in a browser-profile IndexedDB database. It improves convenience across browser restarts
  but weakens protection on a shared or compromised browser profile. In every other mode that record
  never contains the account key, and logout deletes it.
- Server sync data is persisted only in its server-encrypted form in IndexedDB. The minimal decrypted
  login model is cached in the service worker and cleared on lock, logout, or worker termination.
- Remote HTTP is rejected; HTTP is allowed only for loopback development.
- Live sync opens a WebSocket to the server's `/notifications/hub` with the access token as a query
  parameter (browsers cannot set WebSocket headers), as official clients do. Messages carry no vault
  data; any change only triggers a normal encrypted sync. While signed in, the socket's 20-second
  keep-alive also keeps the service worker running. Turning off Live sync in Settings closes the
  socket and falls back to a one-minute poll.
- Filling HTTP sign-in dialogs (basic auth) is off by default. Turning it on requests the
  `webRequest` and `webRequestAuthProvider` permissions plus website access. Firnkey answers only
  while unlocked, only when exactly one login without master-password reprompt matches, never on
  excluded domains or proxies, never with an HTTPS login over plain HTTP, and only once per request,
  so a rejected login shows the browser's own dialog.
- Autofill rejects HTTPS-mapped credentials on downgraded HTTP pages.
- Host permission is requested for the selected server origin through an explicit user gesture.
- Server KDF parameters are checked for downgrade and resource-exhaustion values before derivation
  (PBKDF2 needs at least 100,000 iterations). The strongest KDF seen for each server and account is
  remembered across logout, and a later sign-in with weaker settings is refused.
- Only authenticated ciphertext is accepted: type 2 MACs are verified before AES-CBC decryption, and
  encryption v2 (type 7) data must be a COSE_Encrypt0 message for XChaCha20-Poly1305 whose key ID
  matches the key. Unauthenticated type 0 data and other v2 algorithms are rejected. Firnkey does
  not yet verify a v2 account's signed security state, which official clients use to detect a server
  rolling an account back to older keys.
- Security key (WebAuthn) and Duo two-step login run in a small window. For a security key, Firnkey
  opens the server's own page and calls WebAuthn from an isolated content script, so the assertion is
  bound to the server's origin and the page's scripts cannot read or change it. For Duo, Firnkey
  only reads the code from Duo's redirect back to the server's `duo-redirect-connector.html`.
- Only Firnkey's own pages can call vault, account, and settings actions; the website script is
  limited to `site.*` requests, which are checked against the sending tab's origin.
- Copied values are cleared from the clipboard after the last copy: 30 seconds by default,
  configurable from 10 seconds to 5 minutes, or never. With the optional "Only clear what Firnkey
  copied" setting (clipboard-read permission), only a SHA-256 fingerprint of the copy is kept, in
  memory-only session storage, and the clipboard is cleared only if it still matches.
- Account switching locks the current account and sets it aside: its server tokens stay AES-GCM
  encrypted in IndexedDB (as for the active account) and its server-encrypted vault copy is kept,
  but the account key is never kept, so a switched-in account always starts locked.
- In the passkey window, Touch ID / Windows Hello unlocks the vault or, when already unlocked,
  counts as user verification only if the PRF output unwraps the same account key as the session.
  Items with master-password reprompt still require the master password.
- Argon2id uses Bitwarden's SHA-256 pre-hashed email salt and runs in a transient offscreen
  extension context that is closed after derivation.
- Login items with master-password reprompt enabled keep password, TOTP, and fill unavailable until
  the background revalidates the account key; authorization expires after 60 seconds. Organization
  `ViewPassword` restrictions are enforced during decryption. Organization items can be edited only
  when the server grants `Edit` and the password is visible (an edit with a hidden password would
  erase it); they are re-encrypted under the organization key, and the server still checks access.
- Broad website access is optional and disabled by default. When enabled, an isolated script detects
  login forms, offers website-matched entries, and captures a submitted credential for an explicit
  save/update decision. Pending plaintext is memory-only, expires after two minutes, and is cleared
  on lock/logout. In-page menus and prompts use closed shadow roots and ignore script-generated
  clicks. Against clickjacking, a click only counts after the overlay has been fully visible (per
  Chrome's IntersectionObserver v2: not covered, transparent, filtered or transformed) and unmoved
  for 500 ms. Save/update prompts are offered only for passwords the user typed (or Firnkey
  generated), so a page script cannot plant a password and fake an update prompt.
- Passkeys (opt-in with website integration): a page-world script wraps `navigator.credentials` in
  top-level HTTPS pages and relays requests through an isolated bridge that only accepts messages
  from its own window. The background takes the origin from Chrome's sender information, checks
  that the RP ID is the page host or a parent domain, and builds `clientDataJSON` itself. Every save
  or sign-in is confirmed in a separate Firnkey window that the page cannot read, click or keylog;
  `userVerification: "required"` and master-password-reprompt items need the master password there.
  Requests Firnkey cannot answer fall back to the browser. Passkeys are stored as encrypted
  `fido2Credentials` (Bitwarden format), report a signature counter of 0, and use "none"
  attestation with an all-zero AAGUID. A parent-domain RP ID is rejected when it is a public suffix
  (bundled Public Suffix List, refreshed with `pnpm update:psl`). Autofill-style (conditional)
  requests open no window until the user picks Firnkey's **Passkey** menu entry, and a request the
  page aborts closes its Firnkey window.
- Verification (TOTP) codes are offered in code fields only for logins mapped to the page, behind
  the same trusted, visible click as login fill. They are filled without a click only when
  Firnkey filled that same login in the same tab within the last three minutes (in memory,
  cleared on lock and tab close), so a page cannot collect codes for logins the user did not just
  use there. SMS, email, recovery and payment-card code fields are not treated as TOTP fields.
- The Authenticator tab fills a code only after a click, only when the entry's website matches the
  active tab (never an HTTPS entry into an HTTP page), and only into frames of that tab's origin.
  QR codes are read only when the user presses Scan, from a one-time capture of the visible tab.
  Keys from QR codes, links and imports must be `otpauth://totp/` (or Steam) with valid Base32,
  algorithm, digits and period; HOTP is refused, labels lose control and bidirectional-override
  characters, and imports are capped at 500 entries / 256 KB. Error messages and the import preview
  never contain a secret. Export requires the master password and writes a local text file.
- Attachments and file Sends are encrypted in the background (a random 64-byte key per file,
  Bitwarden's AES-CBC-HMAC file layout) before upload. Downloads follow only links to the account's
  own server origin, and upload paths from the server must look like `/ciphers/…` or `/sends/…`.
  Files are capped at 25 MB, and a decrypted file reaches the popup only after the item's
  master-password reprompt.
- A Send link carries the Send's key, like Bitwarden's; it is treated as a secret (clipboard clearing
  applies). Send passwords are stored only as Bitwarden's PBKDF2 hash.
- Vault export requires the master password and includes personal items only. The default format is
  encrypted with a file password (PBKDF2-SHA-256, 600,000 rounds, then the master-key stretch).
  Import reads the file in the background, shows a count, and writes nothing until confirmed.
- Moving an item into an organization re-wraps only its item key with the organization key; items
  without an item key are refused rather than re-encrypted field by field.
- Errors exposed to the popup do not include response bodies.
- Website icons are resolved with Chrome's local `_favicon` facility; Firnkey does not send saved
  vault URLs to a third-party favicon service.
- URI matching is directional and fail-closed: a child-domain credential cannot be offered to its
  parent domain, and unsupported match strategies never authorize fill or credential disclosure.

## Automated security checks

- GitHub CodeQL scans JavaScript and TypeScript on changes to `main`, pull requests, a weekly
  schedule, and manual dispatch using the `security-extended` query suite.
- Dependency Review blocks pull requests that introduce dependencies with known vulnerabilities of
  moderate severity or higher.
- Dependabot checks npm packages and GitHub Actions weekly. GitHub secret scanning is also enabled
  automatically for this public repository.

- CI runs `pnpm audit:release` (shipped dependencies must use permissive licenses, a CycloneDX SBOM
  is written, and two builds must be byte-identical) and `pnpm compat` against every supported
  server release.

Automation is a useful baseline, not a replacement for threat modeling, manual review, browser
integration testing, or an independent audit.

## Reporting

Do not include real vault contents, master passwords, access tokens, encryption keys, or server
logs containing secrets in a report. Until a private reporting channel is established, create a
minimal public issue that asks the maintainers for secure contact instructions.

## Required before production use

Critical production use remains blocked on broader compatibility fixtures, automated browser/heap
testing, a formal threat model, dependency/SBOM review, and an independent cryptography and extension
audit. Vault writes, save/fill integration, and passkeys require additional security review.
