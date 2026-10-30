# Chrome Web Store listing and privacy practices

Copy these answers into the Developer Dashboard. Keep them in step with [PRIVACY.md](../PRIVACY.md)
and `src/manifest.json`: a new permission needs a justification here before release.

## Listing

- **Name:** Firnkey
- **Summary:** A lightweight, open-source password manager for your self-hosted server.
- **Category:** Productivity → Tools
- **Privacy policy URL:** `https://github.com/emreakca/firnkey/blob/main/PRIVACY.md`
- **Homepage / support URL:** `https://github.com/emreakca/firnkey`

### Description (English, default)

```text
Firnkey is a small, fast password manager for your own self-hosted server. It works with any server that speaks the Bitwarden API. Your vault stays on the server you choose and is encrypted and decrypted only on your device. No Firnkey account, no tracking, no telemetry.

WHAT IT DOES
• Sign in to any server URL, including reverse-proxy subpaths; PBKDF2 and Argon2id.
• Two-step login: authenticator app, email, YubiKey OTP, security keys (WebAuthn) and Duo.
• Fill logins, cards and identities right in the page, with suggestions in the field. Several accounts on one site: the one you pick stays first and its password fills on the next step.
• Offers to save cards and addresses you type into a form.
• SSH keys: generate, add and edit.
• Offers to save new logins and to update changed passwords.
• Passkeys: create and use them on websites, stored in your vault.
• One-time codes (TOTP) with automatic fill on the next page.
• Password and passphrase generator. Its history remembers every password you copied or used, and on which website, encrypted and only in your browser.
• Password history on every login, so an earlier password is never lost.
• Live sync through your server's notifications hub, folders, favorites, Send, import and export.
• Lock on a timer, when the computer locks, or keep unlocked until log out; Touch ID unlock.

PRIVACY
Firnkey talks only to your server. Website access is off until you turn on website integration. The source code is open under GPL-3.0: https://github.com/emreakca/firnkey

Firnkey is an independent project, not affiliated with or endorsed by Bitwarden, Inc. Bitwarden is a trademark of Bitwarden, Inc.
```

### Description (German)

Add under **Store listing → Add language → Deutsch**, with summary
*Schlanker Open-Source-Passwortmanager für deinen selbst gehosteten Server.*

```text
Firnkey ist ein kleiner, schneller Passwortmanager für deinen eigenen, selbst gehosteten Server. Er funktioniert mit jedem Server, der die Bitwarden-API spricht. Dein Tresor bleibt auf dem Server deiner Wahl und wird nur auf deinem Gerät ver- und entschlüsselt. Kein Firnkey-Konto, kein Tracking, keine Telemetrie.

FUNKTIONEN
• Anmeldung bei jeder Server-Adresse, auch hinter Reverse-Proxy-Pfaden; PBKDF2 und Argon2id.
• Zwei-Faktor-Anmeldung: Authenticator-App, E-Mail, YubiKey OTP, Sicherheitsschlüssel (WebAuthn) und Duo.
• Logins, Karten und Identitäten direkt auf der Seite ausfüllen, mit Vorschlägen im Eingabefeld. Mehrere Konten auf einer Website: Das gewählte bleibt oben, sein Passwort wird im nächsten Schritt ausgefüllt.
• Bietet an, eingegebene Karten und Adressen zu speichern.
• SSH-Schlüssel erzeugen, hinzufügen und bearbeiten.
• Bietet an, neue Logins zu speichern und geänderte Passwörter zu aktualisieren.
• Passkeys auf Websites erstellen und verwenden, gespeichert in deinem Tresor.
• Einmalcodes (TOTP), auf der nächsten Seite automatisch ausgefüllt.
• Passwort- und Passphrasen-Generator. Sein Verlauf merkt sich jedes kopierte oder verwendete Passwort und auf welcher Website es entstand, verschlüsselt und nur in deinem Browser.
• Passwortverlauf für jeden Login, damit ein früheres Passwort nie verloren geht.
• Live-Synchronisation über den Benachrichtigungs-Hub deines Servers, Ordner, Favoriten, Send, Import und Export.
• Sperre nach Zeit, beim Sperren des Computers oder erst beim Abmelden; Entsperren mit Touch ID.

DATENSCHUTZ
Firnkey kommuniziert nur mit deinem Server. Zugriff auf Websites ist aus, bis du die Website-Integration einschaltest. Der Quellcode ist offen unter GPL-3.0: https://github.com/emreakca/firnkey

Firnkey ist ein unabhängiges Projekt und steht in keiner Verbindung zu Bitwarden, Inc. Bitwarden ist eine Marke von Bitwarden, Inc.
```

### Graphic assets

All in [`docs/store/`](store/). They show Firnkey with demo data only (fictional sites and
accounts, no Bitwarden logos, web vault pages or official apps). After UI changes, rebuild them
with `pnpm build && node scripts/store-assets.mjs`.

| Store field | File | Size |
| --- | --- | --- |
| Store icon | `src/icons/icon-128.png` (96 px artwork, 16 px transparent padding) | 128×128 |
| Screenshots (upload in this order) | `screenshot-1-vault.png`, `screenshot-2-site.png`, `screenshot-3-item.png`, `screenshot-4-generator.png` | 1280×800 |
| Small promo tile | `promo-small-440x280.png` | 440×280 |
| Marquee promo tile (optional) | `promo-marquee-1400x560.png` | 1400×560 |

The German listing uses the same set from [`docs/store/de/`](store/de/) (German UI and captions);
rebuild them with `node scripts/store-assets.mjs de`.

## Trademark review

Reviewed 2026-10-30 against Bitwarden's
[trademark guidelines](https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md),
which forbid its marks in another product's name, domain or logo but allow true references to
Bitwarden products. This is a project check, not legal advice.

- **Name.** "Firnkey" does not contain "Bitwarden". A web search found no other
  password product of that name, and on 2026-10-30 the Austrian Patent Office (see.ip) and EUIPO
  registers held no "Firnkey" mark. The name is not registered by this project either.
- **Icons.** `src/assets/firnkey-icon*.svg` and `src/icons/` are an original design (an edelweiss
  with a keyhole on an Alpine night-blue tile), unlike Bitwarden's blue shield. No third-party logos
  ship in the package.
- **Store listing and UI.** The name is Firnkey and the UI speaks of "your server". The description
  names the Bitwarden API once, as a true compatibility statement, and "Bitwarden
  JSON" names a file format. The README and the
  description above carry the disclaimer.

## Privacy practices tab

### Single purpose

Firnkey is a password manager for a self-hosted password server: it
signs in to the server the user chooses, shows and edits the user's encrypted vault, and fills
logins, cards, identities, one-time codes, and passkeys into websites.

### Permission justifications

| Permission | Justification |
| --- | --- |
| `storage` | Stores the server address, settings, the encrypted vault cache, the encrypted generator history, and session keys in this browser profile. |
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
- [x] Authentication information (master-password-derived hash at login, stored passwords, passkeys, one-time-code keys, generator history kept encrypted in the browser)
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
| `COMPAT_IMAGE` | variable | Docker image (without a tag) of the server the compatibility suite in CI runs against |
