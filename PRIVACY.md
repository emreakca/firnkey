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
| Clipboard (only if you enable the option) | To clear copied secrets only if the clipboard still holds what Firnkey copied | Compared on your device as a hash; never stored or sent |

Website integration (field menus, save prompts, passkeys, basic-auth fill) is off until you turn it
on and grant website access. Favicons come from Chrome's own local favicon cache, not a third-party
service. All code ships inside the extension; nothing is downloaded and executed at run time.

## Third parties

Firnkey talks only to your server. If your server requires Duo or a security key for two-step
login, Firnkey opens your server's sign-in page, which may contact Duo under your server's own
terms. Firnkey does not sell or transfer your data, use it for advertising or credit decisions, or
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
