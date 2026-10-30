// Two-step login methods that need a web page: WebAuthn (security key) and Duo Universal Prompt.
// Both run in a small window. Focusing it closes the toolbar popup, so the background worker
// finishes signing in on its own (see VaultController.login).
import { t } from "../shared/i18n";

export const WEBAUTHN_PROVIDER = 7;
export const DUO_PROVIDER = 2;
const TIMEOUT_MS = 5 * 60_000;

export function needsBrowserStep(provider: number | undefined): provider is number {
  return provider === WEBAUTHN_PROVIDER || provider === DUO_PROVIDER;
}

export async function runBrowserTwoFactor(
  provider: number,
  details: Record<string, unknown> | undefined,
  baseUrl: string,
): Promise<string> {
  if (provider === WEBAUTHN_PROVIDER) {
    if (!details || typeof details.challenge !== "string") {
      throw new Error("The server did not offer a security key challenge. Check its DOMAIN setting.");
    }
    return inWindow(`${baseUrl}/`, (tabId, done) => {
      let started = false;
      const start = (status: string | undefined) => {
        if (started || status !== "complete") return;
        started = true;
        chrome.scripting
          .executeScript({ target: { tabId }, func: assertSecurityKey, args: [details, t("securityKeyBanner")] })
          .then(([result]) => {
            const answer = result?.result as { token?: string; error?: string } | undefined;
            done(answer?.token ? { token: answer.token } : { error: answer?.error ?? "Security key verification failed." });
          }, (error: unknown) => done({ error: error instanceof Error ? error.message : String(error) }));
      };
      const onUpdated = (id: number, change: chrome.tabs.OnUpdatedInfo) => id === tabId && start(change.status);
      chrome.tabs.onUpdated.addListener(onUpdated);
      void chrome.tabs.get(tabId).then((tab) => start(tab.status), () => undefined);
      return () => chrome.tabs.onUpdated.removeListener(onUpdated);
    });
  }
  if (provider === DUO_PROVIDER) {
    const authUrl = details && (details.AuthUrl ?? details.authUrl);
    if (typeof authUrl !== "string" || !authUrl.startsWith("https://")) {
      // Vaultwarden's legacy Duo iframe (DUO_USE_IFRAME) has no AuthUrl; Duo retired that prompt.
      throw new Error("The server did not return a Duo Universal Prompt link.");
    }
    const server = new URL(baseUrl).origin;
    return inWindow(authUrl, (tabId, done) => {
      // Duo returns to the server's duo-redirect-connector.html with duo_code and state. Chrome
      // only reports that URL because Firnkey holds the server's host permission.
      const onUpdated = (id: number, change: chrome.tabs.OnUpdatedInfo) => {
        if (id !== tabId || !change.url) return;
        const url = new URL(change.url);
        if (url.origin !== server || !url.pathname.endsWith("/duo-redirect-connector.html")) return;
        const code = url.searchParams.get("duo_code") ?? url.searchParams.get("code");
        const state = url.searchParams.get("state");
        done(code && state ? { token: `${code}|${state}` } : { error: "Duo did not complete the sign-in." });
      };
      chrome.tabs.onUpdated.addListener(onUpdated);
      return () => chrome.tabs.onUpdated.removeListener(onUpdated);
    });
  }
  throw new Error("This two-step login method is not supported.");
}

type Outcome = { token: string } | { error: string };

function inWindow(url: string, watch: (tabId: number, done: (outcome: Outcome) => void) => () => void): Promise<string> {
  return new Promise((resolve, reject) => {
    let finish = (_outcome: Outcome) => undefined as void;
    void chrome.windows.create({ url, type: "popup", width: 520, height: 680, focused: true }).then((window) => {
      const tabId = window?.tabs?.[0]?.id;
      if (window?.id === undefined || tabId === undefined) return reject(new Error("Could not open the sign-in window."));
      const stopWatching = watch(tabId, (outcome) => finish(outcome));
      const onRemoved = (closed: number) => closed === window.id && finish({ error: "Two-step login was cancelled." });
      chrome.windows.onRemoved.addListener(onRemoved);
      // ponytail: the worker is idle while the user is in the window; a cheap API call every 20s keeps it alive.
      const keepAlive = setInterval(() => void chrome.runtime.getPlatformInfo(), 20_000);
      const timeout = setTimeout(() => finish({ error: "Two-step login timed out." }), TIMEOUT_MS);
      finish = (outcome) => {
        finish = () => undefined;
        stopWatching();
        chrome.windows.onRemoved.removeListener(onRemoved);
        clearInterval(keepAlive);
        clearTimeout(timeout);
        void chrome.windows.remove(window.id!).catch(() => undefined);
        if ("token" in outcome) resolve(outcome.token);
        else reject(new Error(outcome.error));
      };
    }, reject);
  });
}

// Injected into the server's own page (isolated world), so the assertion is for the server's RP ID
// and the page's scripts cannot see or alter it. Must be self-contained: it is serialized.
async function assertSecurityKey(options: Record<string, unknown>, bannerText: string): Promise<{ token?: string; error?: string }> {
  const decode = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
  const encode = (value: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const banner = document.createElement("div");
  banner.textContent = bannerText;
  banner.style.cssText = "position:fixed;inset:0 0 auto 0;z-index:2147483647;padding:16px;font:600 15px system-ui;text-align:center;background:#175ddc;color:#fff";
  document.documentElement.append(banner);
  try {
    const allow = Array.isArray(options.allowCredentials) ? (options.allowCredentials as { id?: unknown; transports?: unknown }[]) : [];
    const extensions = options.extensions as { appid?: unknown } | null | undefined;
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: decode(String(options.challenge)),
        ...(typeof options.rpId === "string" ? { rpId: options.rpId } : {}),
        ...(typeof options.timeout === "number" ? { timeout: options.timeout } : {}),
        userVerification: (options.userVerification as UserVerificationRequirement | undefined) ?? "discouraged",
        allowCredentials: allow
          .filter((entry) => typeof entry.id === "string")
          .map((entry) => ({
            type: "public-key" as const,
            id: decode(entry.id as string),
            ...(Array.isArray(entry.transports) ? { transports: entry.transports as AuthenticatorTransport[] } : {}),
          })),
        ...(typeof extensions?.appid === "string" ? { extensions: { appid: extensions.appid } } : {}),
      },
    })) as PublicKeyCredential | null;
    if (!credential) return { error: "No security key answered." };
    const response = credential.response as AuthenticatorAssertionResponse;
    // Vaultwarden and Bitwarden both read "clientDataJson" (lower-case "son").
    return {
      token: JSON.stringify({
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        extensions: credential.getClientExtensionResults(),
        response: {
          authenticatorData: encode(response.authenticatorData),
          clientDataJson: encode(response.clientDataJSON),
          signature: encode(response.signature),
        },
      }),
    };
  } catch (error) {
    return { error: error instanceof DOMException && error.name === "NotAllowedError" ? "Security key verification was cancelled or timed out." : String(error) };
  } finally {
    banner.remove();
  }
}
