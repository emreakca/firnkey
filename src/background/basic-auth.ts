// Answers a site's HTTP sign-in dialog (basic/digest auth) with its matching login. Works only after
// the user opts in, which grants webRequest + webRequestAuthProvider (webRequestBlocking on Firefox)
// and website access.
import { isUrlExcluded, readBrowserIntegrationOptions } from "../shared/settings";

type Credential = { username: string; password: string };

export function installBasicAuth(credentialFor: (url: string) => Promise<Credential | null>): void {
  // Requests Firnkey already answered: a second challenge means the saved login was rejected,
  // so the browser shows its dialog instead of looping.
  const answered = new Set<string>();
  let installed = false;

  const install = () => {
    if (installed || !chrome.webRequest?.onAuthRequired) return;
    installed = true;
    const answer = async (details: chrome.webRequest.OnAuthRequiredDetails): Promise<chrome.webRequest.BlockingResponse> => {
      if (details.isProxy || answered.has(details.requestId)) return {};
      const credential = await lookup(details.url).catch(() => null);
      if (!credential) return {};
      answered.add(details.requestId);
      setTimeout(() => answered.delete(details.requestId), 60_000);
      return { authCredentials: credential };
    };
    // Chrome answers through a callback ("asyncBlocking"); Firefox takes a promise ("blocking").
    if (__FIREFOX__) {
      chrome.webRequest.onAuthRequired.addListener(answer as never, { urls: ["<all_urls>"] }, ["blocking"]);
    } else {
      chrome.webRequest.onAuthRequired.addListener(
        (details, callback) => void answer(details).then((response) => callback?.(response)),
        { urls: ["<all_urls>"] },
        ["asyncBlocking"],
      );
    }
  };

  const lookup = async (url: string): Promise<Credential | null> => {
    const options = await readBrowserIntegrationOptions();
    if (!options.fillBasicAuth || isUrlExcluded(url, options)) return null;
    return credentialFor(url);
  };

  install();
  chrome.permissions.onAdded.addListener(install);
}
