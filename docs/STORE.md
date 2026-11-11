# Chrome Web Store listing and privacy practices

Copy these answers into the Developer Dashboard. Keep them in step with [PRIVACY.md](../PRIVACY.md)
and `src/manifest.json`: a new permission needs a justification here before release.

## Listing

- **Name:** Firnkey
- **Summary:** A lightweight, open-source password manager for Vaultwarden and other self-hosted Bitwarden-compatible servers.
- **Category:** Productivity → Tools
- **Privacy policy URL:** `https://github.com/emreakca/firnkey/blob/main/PRIVACY.md`
- **Homepage URL:** `https://www.firnkey.com/`
- **Support URL:** `https://github.com/emreakca/firnkey/issues`

### Description (English, default)

```text
Firnkey is a small, fast password manager for your own self-hosted server: a lightweight alternative to the Bitwarden browser extension. It works with Vaultwarden and any other server that speaks the Bitwarden API. Your vault stays on the server you choose and is encrypted and decrypted only on your device. No Firnkey account, no tracking, no telemetry.

WHAT IT DOES
• Sign in to any server URL, including reverse-proxy subpaths; PBKDF2 and Argon2id.
• Two-step login: authenticator app, email, YubiKey OTP, security keys (WebAuthn) and Duo.
• Fill logins, cards and identities right in the page, with suggestions in the field. Several accounts on one site: the one you pick stays first and its password fills on the next step.
• Offers to save cards and addresses you type into a form.
• SSH keys: generate, add, edit, and fill the public key into "Add SSH key" forms.
• Offers to save new logins and to update changed passwords.
• Passkeys: create and use them on websites, stored in your vault.
• One-time codes (TOTP) with automatic fill on the next page.
• Password and passphrase generator. Its history remembers every password you copied or used, and on which website, encrypted and only in your browser.
• Password history on every login, so an earlier password is never lost.
• Live sync through your server's notifications hub, folders, favorites, Send, import and export.
• Lock on a timer, when the computer locks, or keep unlocked until log out; Touch ID or PIN unlock.
• Archive, clone, per-website match rules, equivalent domains and organization policies.
• Password health: weak, reused and (optional) breached passwords.

PRIVACY
Firnkey talks only to your server, to Have I Been Pwned only if you turn on the breach check (just the first 5 characters of a password hash are sent), and to SimpleLogin or addy.io only when you create an email alias there. Website access is off until you turn on website integration. The source code is open under GPL-3.0: https://github.com/emreakca/firnkey

Firnkey is an independent project, not affiliated with or endorsed by Bitwarden, Inc. or the Vaultwarden project. Bitwarden is a trademark of Bitwarden, Inc.
```

### Description (German)

Add under **Store listing → Add language → Deutsch**, with summary
*Schlanker Open-Source-Passwortmanager für Vaultwarden und andere selbst gehostete, Bitwarden-kompatible Server.*

```text
Firnkey ist ein kleiner, schneller Passwortmanager für deinen eigenen, selbst gehosteten Server: eine schlanke Alternative zur Bitwarden-Browsererweiterung. Er funktioniert mit Vaultwarden und jedem anderen Server, der die Bitwarden-API spricht. Dein Tresor bleibt auf dem Server deiner Wahl und wird nur auf deinem Gerät ver- und entschlüsselt. Kein Firnkey-Konto, kein Tracking, keine Telemetrie.

FUNKTIONEN
• Anmeldung bei jeder Server-Adresse, auch hinter Reverse-Proxy-Pfaden; PBKDF2 und Argon2id.
• Zwei-Faktor-Anmeldung: Authenticator-App, E-Mail, YubiKey OTP, Sicherheitsschlüssel (WebAuthn) und Duo.
• Logins, Karten und Identitäten direkt auf der Seite ausfüllen, mit Vorschlägen im Eingabefeld. Mehrere Konten auf einer Website: Das gewählte bleibt oben, sein Passwort wird im nächsten Schritt ausgefüllt.
• Bietet an, eingegebene Karten und Adressen zu speichern.
• SSH-Schlüssel erzeugen, hinzufügen, bearbeiten und den öffentlichen Schlüssel in „SSH-Schlüssel hinzufügen“-Formulare eintragen.
• Bietet an, neue Logins zu speichern und geänderte Passwörter zu aktualisieren.
• Passkeys auf Websites erstellen und verwenden, gespeichert in deinem Tresor.
• Einmalcodes (TOTP), auf der nächsten Seite automatisch ausgefüllt.
• Passwort- und Passphrasen-Generator. Sein Verlauf merkt sich jedes kopierte oder verwendete Passwort und auf welcher Website es entstand, verschlüsselt und nur in deinem Browser.
• Passwortverlauf für jeden Login, damit ein früheres Passwort nie verloren geht.
• Live-Synchronisation über den Benachrichtigungs-Hub deines Servers, Ordner, Favoriten, Send, Import und Export.
• Sperre nach Zeit, beim Sperren des Computers oder erst beim Abmelden; Entsperren mit Touch ID oder PIN.
• Archiv, Duplizieren, Erkennungsregeln je Website, gleichwertige Domains und Organisationsrichtlinien.
• Passwort-Check: schwache, mehrfach verwendete und (optional) geleakte Passwörter.

DATENSCHUTZ
Firnkey kommuniziert nur mit deinem Server, mit Have I Been Pwned nur, wenn du den Leak-Check einschaltest (gesendet werden nur die ersten 5 Zeichen eines Passwort-Hashes), und mit SimpleLogin oder addy.io nur, wenn du dort einen E-Mail-Alias erstellst. Zugriff auf Websites ist aus, bis du die Website-Integration einschaltest. Der Quellcode ist offen unter GPL-3.0: https://github.com/emreakca/firnkey

Firnkey ist ein unabhängiges Projekt und steht in keiner Verbindung zu Bitwarden, Inc. oder dem Vaultwarden-Projekt. Bitwarden ist eine Marke von Bitwarden, Inc.
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
  names the Bitwarden API and Vaultwarden as true compatibility statements, calls Firnkey an
  alternative to the Bitwarden browser extension (a true reference to a Bitwarden product), and
  "Bitwarden JSON" names a file format. The README and the
  description above carry the disclaimer.

## Privacy practices tab

### Single purpose

Firnkey is a password manager for a self-hosted password server: it
signs in to the server the user chooses, shows and edits the user's encrypted vault, and fills
logins, cards, identities, SSH public keys, one-time codes, and passkeys into websites.

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
| `favicon` | Shows website icons from Chrome's local favicon cache when the server's icon service is turned off or has none. |
| `contextMenus` | Adds a right-click "fill" action for the current page. |
| Optional `webRequest`, `webRequestAuthProvider` | Requested only when the user enables basic-auth fill, to answer HTTP sign-in dialogs with a saved login. |
| Optional `clipboardRead` | Requested only when the user enables it, so Firnkey clears the clipboard only if it still holds what Firnkey copied. |
| Optional host permission: server origin | Requested at setup for the single server the user enters, to talk to its API. |
| Optional host permissions `https://*/*`, `http://*/*` | Requested only when the user turns on website integration, for in-page suggestions, save prompts, and passkeys on any site the user visits. |
| Optional host permission `https://api.pwnedpasswords.com/*` | Requested only when the user turns on the breach check, to look up the first 5 characters of each password's SHA-1 hash with Have I Been Pwned. |
| Optional host permissions `https://app.simplelogin.io/*`, `https://app.addy.io/*` | Requested only when the user creates an email alias with that service in the username generator. |

### Remote code

**No, I am not using remote code.** All JavaScript and WebAssembly (Argon2id) is bundled in the
package; the manifest CSP is `script-src 'self' 'wasm-unsafe-eval'`.

### Data usage

Check these categories. Firnkey handles them only to provide the password manager, and sends
them only to the user's own server, encrypted where they are vault data. With the optional breach
check on, Have I Been Pwned also receives a 5-character prefix of each password's SHA-1 hash; when
the user creates an email alias, SimpleLogin or addy.io receive the user's API key and the page's host:

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

## Firefox (addons.mozilla.org)

`pnpm build:firefox` writes `dist-firefox/`, and each release attaches `firnkey-firefox-X.Y.Z.zip`.
Listed at https://addons.mozilla.org/en-US/firefox/addon/firnkey/ with the same summary and
description as above. Notes for each upload:

- **Add-on ID**: `firnkey@emreakca.github.io` (in `scripts/build.mjs`). It cannot change once the
  add-on is listed, so pick the final one first.
- **Source code**: the bundles are minified, so AMO asks for the source. Upload the tagged source
  archive with the build steps: Node.js 26, `pnpm install --frozen-lockfile`, `pnpm build:firefox`.
- **Data collection**: the manifest declares authentication, personal, financial, personal
  communications, website content and browsing activity data, matching the Chrome answers above.
  All of it goes only to the user's own server (and the opt-in services listed above).
- **Linter**: `npx web-ext lint -s dist-firefox` reports no errors. Its warnings are `innerHTML`
  writes of fixed icons and escaped translated text in the in-page menu; reviewers may ask about them.
- **Differences** from Chrome: no biometric unlock and no QR scanning; Argon2id runs in the
  background page.

The store descriptions above exist in English and German only; the extension itself ships 27
languages.

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
