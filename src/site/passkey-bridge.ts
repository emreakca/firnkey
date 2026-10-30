// Isolated-world relay between Firnkey's page script and the background. The background takes the
// origin from Chrome's sender info, so nothing the page posts here can change which site is asking.
window.addEventListener("message", (event) => {
  const data = event.data as { firnkey?: string; id?: unknown; kind?: unknown; options?: unknown } | null;
  // Only this window's own scripts produce source === window; other frames and openers cannot.
  if (event.source !== window || typeof data?.id !== "string") return;
  const id = data.id;
  if (data.firnkey === "passkey-abort") {
    try {
      void chrome.runtime.sendMessage({ type: "site.passkeyAbort", id }).catch(() => undefined);
    } catch {
      // The extension was reloaded or removed: there is no request left to cancel.
    }
    return;
  }
  if (data.firnkey !== "passkey-request") return;
  const reply = (result: unknown) => window.postMessage({ firnkey: "passkey-response", id, result }, location.origin);
  try {
    chrome.runtime
      .sendMessage({ type: data.kind === "create" ? "site.passkeyCreate" : "site.passkeyGet", id, options: data.options })
      .then((response: { ok?: boolean; data?: { result?: unknown } } | undefined) =>
        reply(response?.ok && response.data?.result ? response.data.result : { fallback: true }))
      .catch(() => reply({ fallback: true }));
  } catch {
    reply({ fallback: true }); // The extension was reloaded or removed: let the browser handle it.
  }
});
