# Firnkey privacy policy

Firnkey is a password-manager extension that connects to a self-hosted password
server **that you choose**. It has no Firnkey-operated servers, accounts, analytics, telemetry, or
advertising. The developers never receive your data.

## What Firnkey handles

| Data | Why | Where it goes |
| --- | --- | --- |
| Server address and account email | To sign in and show which account is active | Stored in this browser profile; sent only to your server |
| Master password | To derive your keys at login, unlock, and protected-item confirmation | Never stored or sent; your server receives only a derived hash at login |
| Vault contents (logins, cards, identities, notes, SSH keys, attachments, Sends, authenticator keys) | To show, fill, copy, create, and edit your items | Encrypted on your device before it is sent to your server; the encrypted copy is cached in this browser profile |
| Website address of the active tab | To suggest matching logins and to set a new login's website | Used on your device; saved to your vault only when you save a login |
| Login, payment and address form fields on websites | To fill items you pick and, if you enable save prompts, to offer saving a login, card or address you typed | Read on the page, held in extension memory for at most five minutes or until you save or dismiss; saved items are encrypted and sent to your server |
| Visible page image (only when you choose **Scan QR code**) | To read an authenticator QR code | Processed on your device, then discarded |
| Generator history (passwords you copy or use from the generator, when, and the host of the page you were on) | So you can recover a generated password you have not saved yet | Encrypted with your account key and stored only in this browser profile; never sent; deleted on log out or with **Clear generator history** |
| PIN (only if you set one) | To unlock without the master password | Never stored or sent. A key derived from it wraps your account key, kept in memory until the browser closes, or in this browser profile if you choose to keep PIN unlock after a restart |
| The first 5 characters of the SHA-1 hash of each login password (only if you turn on the breach check) | To find passwords that appear in known data breaches | Sent to Have I Been Pwned (api.pwnedpasswords.com), which returns every breached hash with that prefix; the match is made on your device and kept in memory only. The password itself is never sent |
| Email forwarder API key and the host of the active tab (only when you click **Create alias**) | To create an email alias with SimpleLogin or addy.io, noted with the website it is for | Sent to the service you chose (app.simplelogin.io or app.addy.io). The key is encrypted with your account key and stored only in this browser profile; deleted on log out |
| Clipboard (only if you enable the option) | To clear copied secrets only if the clipboard still holds what Firnkey copied | Compared on your device as a hash; never stored or sent |

Website integration (field menus, save prompts, passkeys, basic-auth fill) is off until you turn it
on and grant website access. Website icons are requested from your server's icon service by the
host name of each saved website; your server fetches the site's favicon and caches it. Turn off
**Show website icons** to use only Chrome's own local favicon cache instead. All code ships inside
the extension; nothing is downloaded and executed at run time.

## Third parties

Firnkey talks only to your server, to Have I Been Pwned's password API if you turn on the
breach check (see above; under their terms at <https://haveibeenpwned.com/API/v3>), and to
SimpleLogin or addy.io when you create an email alias with them (under your account's terms there). If your server requires Duo or a security key for two-step
login, Firnkey opens your server's sign-in page, which may contact Duo under your server's own
terms. SSO sign-in opens your server's page for its identity provider in the same way. If your
server is set to use an external icon service, its icon address redirects there. Firnkey does not sell or transfer your data, use it for advertising or credit decisions, or
use it for anything other than the password-manager features above.

## Your control

- **Lock** clears decrypted data from memory; **Log out** removes the account, its cached vault and
  its generator history from this browser.
- Removing the extension deletes everything it stored in this browser.
- Your server operator controls data stored on the server.

## Contact

Questions or concerns: open an issue at
<https://github.com/emreakca/firnkey/issues>, or report security problems as
described in [SECURITY.md](SECURITY.md).
