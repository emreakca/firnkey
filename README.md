# Firnkey

Firnkey is a lightweight, open-source Manifest V3 password-manager extension for
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) and compatible Bitwarden API servers.
It is a community-built alternative for people who want a smaller browser client focused on the
core login workflow: search, site matching, fill, copy, create, edit, and save prompts.

Firnkey is based on [LeanVault](https://github.com/jsjain/vaultwarden-chrome-extension) by
Shubham Jain, released under GPL-3.0, and has been substantially extended since.

Firnkey is not a fork of the official Bitwarden browser extension. It implements compatible
protocol behavior independently and deliberately avoids pulling the official Angular application
and its full feature surface into the browser.

> [!IMPORTANT]
> Firnkey is an unofficial independent project. It is not associated with, sponsored by,
> endorsed by, or supported by Bitwarden, Bitwarden Inc., or the Vaultwarden project. Bitwarden is
> a trademark of Bitwarden Inc. Report Firnkey bugs to this repository, not to official Bitwarden
> or Vaultwarden support channels.

> [!WARNING]
> This is unaudited security software. Test it with a non-critical account before trusting it with
> important credentials, and review the documented security boundaries before regular use.

## Why Firnkey?

Vaultwarden provides a resource-efficient, self-hosted implementation of the Bitwarden-compatible
server API. Firnkey applies the same lightweight idea to the browser client: a small extension,
limited runtime permissions, no analytics, and independently loaded cryptography only when needed.

*Firn* is the old, compacted snow high in the Alps that slowly turns into glacier ice: quiet, solid
and out of reach. Like the edelweiß growing beside it, what lives up there is protected by where it is.

Version **1.0.0** is Firnkey's first release and provides:

- Custom Vaultwarden server URLs, including reverse-proxy subpaths.
- PBKDF2 and Bitwarden-compatible Argon2id authentication.
- Two-step login with authenticator, email, YubiKey OTP and recovery codes, plus security keys
  (WebAuthn) and Duo Universal Prompt in a small sign-in window.
- Accounts on Bitwarden encryption v1 and the newer encryption v2 (COSE, XChaCha20-Poly1305).
- Encrypted vault sync and authenticated login decryption, with live updates pushed through the
  server's notifications hub (Live sync, can be turned off) and a one-minute poll as fallback.
- Opt-in filling of browser sign-in dialogs (HTTP basic auth) when exactly one login matches.
- Fast vault search, field-anchored current-site suggestions, website favicons, copy, open-site,
  and iframe/open-shadow-root manual fill.
- Encrypted personal-login creation and editing with website mapping.
- Cards, identities, and secure notes: view, copy, create, and edit, plus filling cards (HTTPS only)
  and identities from the popup or from the in-page menu on card and address fields.
- Local cryptographic generators for passwords, passphrases (EFF long wordlist), and usernames
  (random word, plus-addressed email, or catch-all email). Password and passphrase preferences are
  shared with website fields.
- Organizations and collections: filter the vault by collection, create items in a collection you
  can write to, move a personal item into one, and edit organization items where the organization
  grants edit access and shows the password.
- Attachments: download, add (up to 25 MB) and delete files on any item you can edit. Files are
  encrypted in the background with their own key before upload.
- Send: share text or a file (up to 25 MB) through an end-to-end encrypted link that deletes itself
  after 1 to 30 days, with an optional password and view limit. Creating one copies its link.
- Import and export (Settings → Import & export): import Bitwarden JSON (plain or
  password-protected) and CSV files from Bitwarden, Chrome, Edge, Firefox or Safari; export personal
  items as Bitwarden JSON, protected by a file password or unencrypted, after confirming the master
  password.
- Several accounts, even on different servers: switch between them from Settings or the sign-in
  and unlock screens, or remove one from this browser.
- Optional website autofill, editable save/update prompts, and excluded-domain controls.
- Fill the matching login with Ctrl+Shift+L (Cmd+Shift+L on Mac) or the right-click menu; the
  toolbar icon shows how many logins match the current page.
- Verification (TOTP) codes: a live code in the popup, suggestions in code fields, and automatic
  filling on the next page right after Firnkey filled that site's login in the same tab. Add,
  replace or remove a login's authenticator key (Base32 or `otpauth://totp/` link) in the editor;
  a saved key is never shown in the popup. An optional Authenticator tab (Settings → Vault) lists
  every code with a countdown: click a card to copy it, or fill it into the page's code field when
  the entry belongs to that website. Add keys by scanning a QR code on the visible page (macOS and
  ChromeOS, through the browser's barcode reader), by pasting a Base32 key or `otpauth://totp/` link,
  or by importing a list of links; edit the name, nickname, account, website, issuer, algorithm
  (SHA-1/256/512), digits and period; export every key as `otpauth://` links after confirming the
  master password. Steam keys (`steam://` or issuer Steam) make 5-character codes. Each key lives in
  a vault login, so it syncs like the rest of the vault. By default a site with codes shows only
  those, with **View all** one click away.
- Optional passkeys ("Ask to save and use passkeys"): save and sign in with ES256 passkeys stored in
  Bitwarden's format, with fallback to the browser's own passkeys. On sites that offer passkey
  autofill, a **Passkey** entry appears in Firnkey's field menu next to the browser's own offer.
  Passkeys inside frames are left to the browser.
- Master-password reprompt handling and organization `ViewPassword` enforcement.
- Configurable locking: 1 minute to 24 hours of inactivity, computer lock, browser close, or
  encrypted device persistence until explicit lock/logout.
- Optional unlock with Touch ID / Windows Hello after the first sign-in (WebAuthn PRF passkey),
  also in the passkey window, where it doubles as the "verify it's you" step websites can ask for.
- Configurable clipboard clearing: 10 seconds to 5 minutes after the last copy, or never. Optionally
  (with clipboard-read permission) only clears when the clipboard still holds Firnkey's copy.

## Install from source

Requirements: Node.js 26+ and pnpm.

```sh
git clone https://github.com/emreakca/firnkey.git
cd firnkey
git checkout v1.0.0
pnpm install
pnpm verify
```

Then:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the generated `dist/` directory.
4. After each update, confirm the version shown in Firnkey **Settings**.

Every test build increments the extension version so a successful Chrome reload is visible.

See the [v1.0.0 release notes](docs/releases/v1.0.0.md) for the feature and security summary.

## Security model

- The master password is used only during login, unlock, or protected-item confirmation and is
  never persisted.
- The default unlock mode keeps the account key in trusted Chrome session storage until the browser
  closes. Server tokens are kept encrypted, so a restart locks the vault rather than signing out.
- “Keep unlocked until logout” is opt-in. It encrypts the session with AES-GCM under a
  non-extractable key held in this browser profile's IndexedDB. This is convenient but less safe on
  a shared or compromised browser profile.
- Server vault ciphertext is cached in IndexedDB; decrypted vault items remain in service-worker
  memory.
- Website integration is optional and disabled until the user grants website access.
- Favicons come from Chrome's local favicon facility, not from a third-party icon service.
- Remote HTTP servers are rejected except for loopback development.
- There is no analytics, telemetry, or remotely hosted executable code.
- URI matching is directional and fail-closed so credentials saved for a child domain are not
  exposed to its parent domain.

CodeQL, dependency review, Dependabot, and GitHub's public-repository secret scanning provide an
automated security baseline. These checks do not replace an independent security audit.

See [SECURITY.md](SECURITY.md), [PRIVACY.md](PRIVACY.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for details. Releases and store answers are described in [docs/STORE.md](docs/STORE.md).

## Compatibility boundaries

The current MVP supports standard master-password accounts using Bitwarden encryption v1 or v2
(XChaCha20-Poly1305 keys; the newer XAES-256-GCM and AES-GCM suites are not supported yet). It does
not yet support custom-field and SSH key editing, multiple-URI editing, editing Sends, changing an
organization item's collections, or Vaultwarden's legacy Duo iframe prompt (`DUO_USE_IFRAME`).

`pnpm compat` runs the background code against Vaultwarden 1.34.3, 1.35.8, 1.36.0 and 1.37.4 in
throwaway Docker containers (sign-in, edits, attachments, Sends, import/export, organizations).

## Contributing

Issues and pull requests are welcome. For security-sensitive reports, do not include real vault
contents, master passwords, tokens, encryption keys, or logs containing secrets. See
[SECURITY.md](SECURITY.md) before reporting a vulnerability.

### Translations

Every popup, passkey-window and in-page string lives in `src/_locales/en/messages.json`; Chrome
shows the browser's language when a translation exists and English otherwise. To add a language,
copy that file to `src/_locales/<code>/messages.json` (for example `de` or `pt_BR`), translate each
`message`, and set `languageCode` to the language's BCP 47 code. `$1`, `$2` are filled in at run
time; keep them. Counted messages come as `name_one` and `name_other`; add `name_few` or `name_many`
where the language needs them. `pnpm test` checks that every key the code uses exists.

## License

The passphrase generator uses the [EFF long wordlist](https://www.eff.org/dice) by the Electronic
Frontier Foundation, licensed under CC BY 3.0 US.

Firnkey is released under [GPL-3.0-only](LICENSE). It is a modified version of
[LeanVault](https://github.com/jsjain/vaultwarden-chrome-extension), Copyright © 2026 Shubham Jain,
also GPL-3.0-only; Firnkey changes since October 2026 are Copyright © 2026 emreakca. The compatible protocol and referenced product
names do not imply affiliation with their respective projects or trademark owners.
