# Chrome Web Store listing and privacy practices

Copy these answers into the Developer Dashboard. Keep them in step with [PRIVACY.md](../PRIVACY.md)
and `src/manifest.json`: a new permission needs a justification here before release.

## Listing

- **Name:** Firnkey
- **Summary:** A lightweight, open-source client for Vaultwarden-compatible servers.
- **Category:** Productivity → Tools
- **Privacy policy URL:** `https://github.com/emreakca/firnkey/blob/main/PRIVACY.md`
- **Homepage / support URL:** `https://github.com/emreakca/firnkey`

### Description

Write the detailed description in your own words, and end it with:

> Firnkey is an independent project, not affiliated with or endorsed by Bitwarden, Inc. or the
> Vaultwarden project. Bitwarden is a trademark of Bitwarden, Inc.

Screenshots must show Firnkey only: no Bitwarden logos, web vault pages, or official apps.

## Trademark review

Reviewed 2026-10-30 against Bitwarden's
[trademark guidelines](https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md),
which forbid its marks in another product's name, domain or logo but allow true references to
Bitwarden products. This is a project check, not legal advice.

- **Name.** "Firnkey" contains neither "Bitwarden" nor "Vaultwarden". A web search found no other
  password product of that name; no USPTO/EUIPO clearance search was done, so do one before
  registering the name. "Vault" alone is common (HashiCorp Vault, Zoho Vault) and not distinctive.
- **Icons.** `src/assets/firnkey-icon.svg` and `src/icons/` are an original grey safe-dial design,
  unlike Bitwarden's blue shield. No third-party logos ship in the package.
- **Store listing and UI.** The name is Firnkey; "Vaultwarden-compatible", "Bitwarden JSON" and
  "Bitwarden-compatible" describe true compatibility and file formats. The README and the
  description above carry the disclaimer.
- **Open item.** The repository is named `vaultwarden-chrome-extension`, which can read as an
  official Vaultwarden project. Consider renaming it to `firnkey` (GitHub keeps redirects), then
  update the URLs here, in `PRIVACY.md` and in `package.json`.

## Privacy practices tab

### Single purpose

Firnkey is a password manager for a self-hosted Vaultwarden or Bitwarden-compatible server: it
signs in to the server the user chooses, shows and edits the user's encrypted vault, and fills
logins, cards, identities, one-time codes, and passkeys into websites.

### Permission justifications

| Permission | Justification |
| --- | --- |
| `storage` | Stores the server address, settings, the encrypted vault cache, and session keys in this browser profile. |
| `activeTab` | Fills the item the user picks into the current tab, and reads the visible tab only when the user chooses to scan an authenticator QR code. |
| `scripting` | Injects the fill script into the active tab when the user fills, and registers the optional website-integration script after the user grants website access. |
| `offscreen` | Runs Argon2id key derivation in a worker and clears the clipboard, which a service worker cannot do. |
| `alarms` | Locks the vault after the chosen inactivity timeout, clears copied secrets after the clipboard timeout, and schedules background sync. |
| `idle` | Locks the vault when the computer locks, if the user chose that timeout. |
| `clipboardWrite` | Copies usernames, passwords, codes, and Send links when the user asks. |
| `favicon` | Shows website icons from Chrome's local favicon cache instead of a third-party icon service. |
| `contextMenus` | Adds a right-click "fill" action for the current page. |
| Optional `webRequest`, `webRequestAuthProvider` | Requested only when the user enables basic-auth fill, to answer HTTP sign-in dialogs with a saved login. |
| Optional `clipboardRead` | Requested only when the user enables it, so Firnkey clears the clipboard only if it still holds what Firnkey copied. |
| Optional host permission: server origin | Requested at setup for the single server the user enters, to talk to its API. |
| Optional host permissions `https://*/*`, `http://*/*` | Requested only when the user turns on website integration, for in-page suggestions, save prompts, and passkeys on any site the user visits. |

### Remote code

**No, I am not using remote code.** All JavaScript and WebAssembly (Argon2id) is bundled in the
package; the manifest CSP is `script-src 'self' 'wasm-unsafe-eval'`.

### Data usage

Check these categories. Firnkey handles them only to provide the password manager, and sends
them only to the user's own server, encrypted where they are vault data:

- [x] Personally identifiable information (account email; identity items)
- [x] Authentication information (master-password-derived hash at login, stored passwords, passkeys, one-time-code keys)
- [x] Financial and payment information (card items the user stores)
- [x] Personal communications (text and file Sends the user creates)
- [x] Website content (form fields read to fill and to offer saving a typed login)
- [x] Web history (the active tab's address, used to match logins; saved only with a login)
- [ ] Health information
- [ ] Location
- [ ] User activity (no click, scroll, or keystroke tracking; only typed login fields when save prompts are on, covered above)

Certify all three statements:

- [x] I do not sell or transfer user data to third parties, outside of the approved use cases.
- [x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes.

## Releasing

1. Bump `version` in both `package.json` and `src/manifest.json`, and add `docs/releases/vX.Y.Z.md`.
2. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` checks the tag matches both versions, runs every check, and
   publishes a GitHub release with `firnkey-X.Y.Z.zip`, the SBOM, and `SHA256SUMS`.
4. If the store variables and secrets below are set, it also uploads the zip and submits it for
   review. Otherwise upload the zip from the release in the Developer Dashboard.

Store upload settings (repository **Settings → Secrets and variables → Actions**):

| Name | Kind | Value |
| --- | --- | --- |
| `CWS_PUBLISHER_ID` | variable | Developer Dashboard → Publisher → Settings |
| `CWS_ITEM_ID` | variable | The extension's store item ID |
| `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET` | secrets | A Google Cloud OAuth client with the Chrome Web Store API enabled |
| `CWS_REFRESH_TOKEN` | secret | Refresh token for scope `https://www.googleapis.com/auth/chromewebstore` (OAuth Playground) |
